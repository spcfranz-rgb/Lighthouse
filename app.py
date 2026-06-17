# CRITICAL: Monkey patching must occur before ANY other imports to make standard libraries async-compatible
import eventlet
eventlet.monkey_patch()

import os
import time
import socket
import sqlite3
import subprocess
import threading
import io
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import requests
import ipaddress
import paho.mqtt.client as mqtt
import imagehash
from PIL import Image
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from urllib.parse import urlparse
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, abort, flash, Response, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_socketio import SocketIO

app = Flask(__name__)

# Tell Flask it is behind a reverse proxy (NGINX)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Initialize WebSockets with the eventlet async worker
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# --- SECURITY HARDENING: SESSIONS ---
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    print("WARNING: SECRET_KEY environment variable is missing. Using insecure development key.")
    app.secret_key = 'cctv-super-secret-key-change-me'
    
app.config['SESSION_COOKIE_HTTPONLY'] = True 
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('REQUIRE_HTTPS', 'False').lower() == 'true'

# ==========================================
# AUTHENTICATION & GLOBALS
# ==========================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
DB_PATH = '/app/data/cctv.db'
FORCE_CHECK_FLAG = '/app/data/force_check.flag'

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['role'])
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def trigger_monitor_check():
    """Drops an IPC flag to immediately wake up the background monitor process."""
    try:
        open(FORCE_CHECK_FLAG, 'w').close()
    except Exception:
        pass

# ==========================================
# DATABASE INITIALIZATION
# ==========================================
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    try:
        conn.execute("PRAGMA journal_mode=WAL;") # Enable Write-Ahead Logging for concurrency
    except sqlite3.OperationalError:
        pass
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS switches (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, ip TEXT, status TEXT DEFAULT 'UNKNOWN')")
    cursor.execute("CREATE TABLE IF NOT EXISTS cameras (id INTEGER PRIMARY KEY AUTOINCREMENT, switch_id INTEGER, name TEXT UNIQUE, ip TEXT, stream_url TEXT, status TEXT DEFAULT 'UNKNOWN', FOREIGN KEY(switch_id) REFERENCES switches(id))")
    cursor.execute("CREATE TABLE IF NOT EXISTS event_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, device_type TEXT, device_name TEXT, status TEXT)")
    
    try:
        cursor.execute("ALTER TABLE cameras ADD COLUMN manufacturer TEXT DEFAULT 'Other'")
        cursor.execute("ALTER TABLE cameras ADD COLUMN username TEXT DEFAULT ''")
        cursor.execute("ALTER TABLE cameras ADD COLUMN password TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
        
    try:
        cursor.execute("ALTER TABLE switches ADD COLUMN silenced_until REAL DEFAULT 0")
        cursor.execute("ALTER TABLE cameras ADD COLUMN silenced_until REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT)")
    
    cursor.execute("SELECT count(*) FROM settings")
    if cursor.fetchone()[0] == 0:
        settings = [
            ('mqtt_broker', os.environ.get('DEFAULT_MQTT_BROKER', '192.168.1.50')),
            ('mqtt_port', os.environ.get('DEFAULT_MQTT_PORT', '1883')),
            ('mqtt_prefix', os.environ.get('DEFAULT_MQTT_PREFIX', 'zabbix/cctv')),
            ('check_interval', os.environ.get('DEFAULT_CHECK_INTERVAL', '60'))
        ]
        cursor.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", settings)
        
    cursor.execute("SELECT count(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
        default_pass = os.environ.get('DEFAULT_ADMIN_PASS', 'admin')
        default_hash = generate_password_hash(default_pass)
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')", (default_user, default_hash))
    
    if os.path.exists(FORCE_CHECK_FLAG):
        try: os.remove(FORCE_CHECK_FLAG)
        except OSError: pass

    conn.commit()
    conn.close()
    print("Database initialized.")

# ==========================================
# BACKGROUND MONITORING & NETWORK TASKS
# ==========================================
def is_pingable(target):
    response = subprocess.call(['ping', '-c', '1', '-W', '2', target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return response == 0

def is_port_open(target, port, timeout=2):
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except OSError:
        return False

def is_stream_active(url):
    try:
        response = subprocess.call(['ffprobe', '-rtsp_transport', 'tcp', '-v', 'error', '-i', url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        return response == 0
    except subprocess.TimeoutExpired:
        return False

def get_snapshot_bytes(ip, mfg, user, pwd, stream_url):
    if mfg and mfg != 'Other':
        url = None
        auth_in_url = False
        
        if mfg == 'Hikvision': url = f"http://{ip}/ISAPI/Streaming/channels/101/picture"
        elif mfg in ['Dahua', 'Amcrest']: url = f"http://{ip}/cgi-bin/snapshot.cgi?chn=1"
        elif mfg == 'Axis': url = f"http://{ip}/axis-cgi/jpg/image.cgi"
        elif mfg == 'Foscam': 
            url = f"http://{ip}/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2&usr={user}&pwd={pwd}"
            auth_in_url = True
        elif mfg == 'Hanwha': url = f"http://{ip}/stw-cgi/video.cgi?msubmenu=snapshot&action=view&Profile=1"
            
        if url:
            try:
                if auth_in_url:
                    resp = requests.get(url, timeout=3)
                else:
                    resp = requests.get(url, auth=HTTPDigestAuth(user, pwd), timeout=3)
                    if resp.status_code != 200:
                        resp = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=3)
                if resp.status_code == 200 and 'image' in resp.headers.get('Content-Type', ''):
                    return resp.content
            except Exception:
                pass 
                
    try:
        cmd = ['ffmpeg', '-y', '-rtsp_transport', 'tcp', '-i', stream_url, '-vframes', '1', '-f', 'image2pipe', '-vcodec', 'mjpeg', '-']
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        if process.returncode == 0:
            return process.stdout
    except Exception:
        pass
    return None

def threaded_camera_check(cam):
    """Worker function to check network status concurrently without blocking."""
    cam_up = is_pingable(cam['ip']) or is_port_open(cam['ip'], 554) or is_port_open(cam['ip'], 80)
    stream_ok = False
    snap_bytes = None
    if cam_up:
        stream_ok = is_stream_active(cam['stream_url'])
        if stream_ok:
            snap_bytes = get_snapshot_bytes(cam['ip'], cam['manufacturer'], cam['username'], cam['password'], cam['stream_url'])
    return cam['id'], cam_up, stream_ok, snap_bytes

def monitor_loop():
    print("Starting concurrent background monitoring thread...")
    previous_hashes = {} 
    
    while True:
        try:
            conn = get_db()
            cursor = conn.cursor()
            now = time.time()
            
            def set_status(table, item_id, item_name, dev_type, old_status, new_status):
                if old_status != new_status:
                    if old_status != 'UNKNOWN':
                        cursor.execute("INSERT INTO event_logs (timestamp, device_type, device_name, status) VALUES (?, ?, ?, ?)", (now, dev_type, item_name, new_status))
                    cursor.execute(f"UPDATE {table} SET status = ? WHERE id = ?", (new_status, item_id))
                    
                    # Direct, zero-latency dispatch to connected WebSockets
                    socketio.emit('state_change', {
                        'type': table, 'id': item_id, 'name': item_name,
                        'status': new_status, 'device_type': dev_type, 'timestamp': now
                    })
            
            cursor.execute("SELECT key, value FROM settings")
            settings_dict = {row['key']: row['value'] for row in cursor.fetchall()}
            broker = settings_dict.get('mqtt_broker', '127.0.0.1')
            port = int(settings_dict.get('mqtt_port', 1883))
            prefix = settings_dict.get('mqtt_prefix', 'zabbix/cctv')
            interval = int(settings_dict.get('check_interval', 60))
            
            client = mqtt.Client("camera_monitor_service")
            try: client.connect(broker, port, 60)
            except Exception: pass
            
            # 1. PROCESS SWITCHES & THEIR ATTACHED CAMERAS
            cursor.execute("SELECT * FROM switches")
            switches = cursor.fetchall()
            
            for switch in switches:
                switch_id, switch_name, switch_ip, s_until = switch['id'], switch['name'], switch['ip'], switch['silenced_until']
                silenced = s_until > now
                is_up = is_pingable(switch_ip) or is_port_open(switch_ip, 80) or is_port_open(switch_ip, 443)
                
                switch_payload = "MAINTENANCE" if silenced else ("UP" if is_up else "OFFLINE")
                client.publish(f"{prefix}/{switch_name}/ping", switch_payload, retain=True)
                
                if is_up:
                    new_s_stat = 'UP' if not silenced else 'UP (Silenced)'
                    set_status('switches', switch_id, switch_name, 'Switch', switch['status'], new_s_stat)
                    
                    cursor.execute("SELECT * FROM cameras WHERE switch_id = ?", (switch_id,))
                    cameras = cursor.fetchall()
                    
                    # Concurrently fetch network data for all cameras on this switch
                    camera_results = {}
                    with ThreadPoolExecutor(max_workers=20) as executor:
                        futures = {executor.submit(threaded_camera_check, dict(cam)): cam for cam in cameras}
                        for future in futures:
                            c_id, cam_up, stream_ok, snap_bytes = future.result()
                            camera_results[c_id] = (cam_up, stream_ok, snap_bytes)
                    
                    for cam in cameras:
                        cam_id, cam_name, cam_silenced = cam['id'], cam['name'], (cam['silenced_until'] > now)
                        cam_up, stream_ok, snap_bytes = camera_results[cam_id]
                        is_frozen = False
                        
                        if cam_up:
                            if stream_ok and snap_bytes:
                                try:
                                    img = Image.open(io.BytesIO(snap_bytes))
                                    current_hash = imagehash.average_hash(img)
                                    last_hash = previous_hashes.get(cam_id)
                                    if last_hash is not None and (current_hash - last_hash) <= 2:
                                        is_frozen = True
                                    previous_hashes[cam_id] = current_hash
                                except Exception: pass
                            
                            if cam_silenced:
                                client.publish(f"{prefix}/{cam_name}/ping", "MAINTENANCE", retain=True)
                                client.publish(f"{prefix}/{cam_name}/stream", "MAINTENANCE", retain=True)
                                if is_frozen: set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'FROZEN (Silenced)')
                                else: set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'UP (Silenced)' if stream_ok else 'STREAM ERR (Silenced)')
                            else:
                                client.publish(f"{prefix}/{cam_name}/ping", "UP", retain=True)
                                if is_frozen:
                                    client.publish(f"{prefix}/{cam_name}/stream", "FROZEN", retain=True)
                                    set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Frozen)')
                                else:
                                    client.publish(f"{prefix}/{cam_name}/stream", "UP" if stream_ok else "STREAM_ERROR", retain=True)
                                    set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'UP' if stream_ok else 'DOWN (Stream Error)')
                        else:
                            if cam_silenced:
                                client.publish(f"{prefix}/{cam_name}/ping", "MAINTENANCE", retain=True)
                                client.publish(f"{prefix}/{cam_name}/stream", "MAINTENANCE", retain=True)
                                set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Silenced)')
                            else:
                                client.publish(f"{prefix}/{cam_name}/ping", "OFFLINE", retain=True)
                                client.publish(f"{prefix}/{cam_name}/stream", "OFFLINE", retain=True)
                                set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Offline)')
                else:
                    new_s_stat = 'DOWN' if not silenced else 'DOWN (Silenced)'
                    set_status('switches', switch_id, switch_name, 'Switch', switch['status'], new_s_stat)
                    
                    cursor.execute("SELECT * FROM cameras WHERE switch_id = ?", (switch_id,))
                    cameras = cursor.fetchall()
                    for cam in cameras:
                        new_c_stat = 'UNREACHABLE (Switch Down)' if not silenced else 'UNREACHABLE (Silenced)'
                        set_status('cameras', cam['id'], cam['name'], 'Camera', cam['status'], new_c_stat)

            # 2. PROCESS STANDALONE CAMERAS
            cursor.execute("SELECT * FROM cameras WHERE switch_id IS NULL OR switch_id = ''")
            standalone_cameras = cursor.fetchall()
            
            # Concurrently fetch network data for standalone cameras
            standalone_results = {}
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(threaded_camera_check, dict(cam)): cam for cam in standalone_cameras}
                for future in futures:
                    c_id, cam_up, stream_ok, snap_bytes = future.result()
                    standalone_results[c_id] = (cam_up, stream_ok, snap_bytes)
                    
            for cam in standalone_cameras:
                cam_id, cam_name, cam_silenced = cam['id'], cam['name'], (cam['silenced_until'] > now)
                cam_up, stream_ok, snap_bytes = standalone_results[cam_id]
                is_frozen = False
                
                if cam_up:
                    if stream_ok and snap_bytes:
                        try:
                            img = Image.open(io.BytesIO(snap_bytes))
                            current_hash = imagehash.average_hash(img)
                            last_hash = previous_hashes.get(cam_id)
                            if last_hash is not None and (current_hash - last_hash) <= 2:
                                is_frozen = True
                            previous_hashes[cam_id] = current_hash
                        except Exception: pass
                            
                    if cam_silenced:
                        client.publish(f"{prefix}/{cam_name}/ping", "MAINTENANCE", retain=True)
                        client.publish(f"{prefix}/{cam_name}/stream", "MAINTENANCE", retain=True)
                        if is_frozen: set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'FROZEN (Silenced)')
                        else: set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'UP (Silenced)' if stream_ok else 'STREAM ERR (Silenced)')
                    else:
                        client.publish(f"{prefix}/{cam_name}/ping", "UP", retain=True)
                        if is_frozen:
                            client.publish(f"{prefix}/{cam_name}/stream", "FROZEN", retain=True)
                            set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Frozen)')
                        else:
                            client.publish(f"{prefix}/{cam_name}/stream", "UP" if stream_ok else "STREAM_ERROR", retain=True)
                            set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'UP' if stream_ok else 'DOWN (Stream Error)')
                else:
                    if cam_silenced:
                        client.publish(f"{prefix}/{cam_name}/ping", "MAINTENANCE", retain=True)
                        client.publish(f"{prefix}/{cam_name}/stream", "MAINTENANCE", retain=True)
                        set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Silenced)')
                    else:
                        client.publish(f"{prefix}/{cam_name}/ping", "OFFLINE", retain=True)
                        client.publish(f"{prefix}/{cam_name}/stream", "OFFLINE", retain=True)
                        set_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Offline)')

            # 3. AUTO-PRUNE OLD LOGS (Older than 7 Days)
            seven_days_ago = time.time() - (7 * 24 * 3600)
            cursor.execute("DELETE FROM event_logs WHERE timestamp < ?", (seven_days_ago,))

            conn.commit()
            conn.close()
            client.disconnect()
            
        except Exception as e:
            print(f"Error in monitor loop: {e}")
            time.sleep(10)
            continue
            
        # 4. INTERRUPTIBLE SLEEP CYCLE
        for _ in range(interval):
            if os.path.exists(FORCE_CHECK_FLAG):
                try: os.remove(FORCE_CHECK_FLAG)
                except OSError: pass
                break
            time.sleep(1)

# ==========================================
# FLASK WEB ROUTES
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['username'], user['role'])
            login_user(user_obj)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    now = time.time()
    conn = get_db()
    switches = conn.execute("SELECT *, (silenced_until > ?) as is_silenced FROM switches", (now,)).fetchall()
    
    cameras = conn.execute("""
        SELECT c.*, s.name as switch_name, (c.silenced_until > ?) as is_silenced 
        FROM cameras c 
        LEFT JOIN switches s ON c.switch_id = s.id
    """, (now,)).fetchall()
    
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings_dict = {row['key']: row['value'] for row in cursor.fetchall()}
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    
    return render_template('index.html', switches=switches, cameras=cameras, settings=settings_dict, users=users)

@app.route('/history')
@login_required
def history():
    conn = get_db()
    logs = conn.execute("SELECT * FROM event_logs ORDER BY timestamp DESC LIMIT 500").fetchall()
    conn.close()
    return render_template('history.html', logs=logs)

@app.route('/api/logs')
@login_required
def api_logs():
    conn = get_db()
    logs = conn.execute("SELECT * FROM event_logs ORDER BY timestamp DESC LIMIT 500").fetchall()
    conn.close()
    return jsonify([dict(row) for row in logs])

@app.route('/export_logs')
@login_required
def export_logs():
    conn = get_db()
    logs = conn.execute("SELECT * FROM event_logs ORDER BY timestamp DESC").fetchall()
    conn.close()
    
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Timestamp (UTC)', 'Device Type', 'Device Name', 'Status'])
    for log in logs:
        dt_string = datetime.utcfromtimestamp(log['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        cw.writerow([dt_string, log['device_type'], log['device_name'], log['status']])
        
    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=cctv_event_logs.csv"})

@app.route('/api/status')
@login_required
def api_status():
    conn = get_db()
    switches = conn.execute("SELECT id, status FROM switches").fetchall()
    cameras = conn.execute("SELECT id, status FROM cameras").fetchall()
    conn.close()
    
    status_data = {}
    for s in switches:
        status_data[f"switch_{s['id']}"] = s['status']
    for c in cameras:
        status_data[f"camera_{c['id']}"] = c['status']
        
    return jsonify(status_data)

@app.route('/toggle_silence/<device_type>/<int:id>', methods=['POST'])
@login_required
@admin_required
def toggle_silence(device_type, id):
    hours = float(request.form.get('hours', 0))
    silence_until = time.time() + (hours * 3600) if hours > 0 else 0
    conn = get_db()
    if device_type == 'switch': conn.execute("UPDATE switches SET silenced_until = ? WHERE id = ?", (silence_until, id))
    elif device_type == 'camera': conn.execute("UPDATE cameras SET silenced_until = ? WHERE id = ?", (silence_until, id))
    conn.commit()
    conn.close()
    trigger_monitor_check()
    return jsonify({'success': True})

@app.route('/api/ping', methods=['POST'])
@login_required
@admin_required
def manual_ping():
    ip = request.form.get('ip')
    if not ip: return jsonify({'success': False, 'output': 'No IP address provided.'})
    try:
        cmd = ['ping', '-c', '4', '-W', '2', ip]
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if process.returncode == 0: return jsonify({'success': True, 'output': process.stdout})
        else: return jsonify({'success': False, 'output': process.stdout or process.stderr or 'Ping failed.'})
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'output': 'Ping command timed out.'})
    except Exception as e:
        return jsonify({'success': False, 'output': str(e)})

@app.route('/update_settings', methods=['POST'])
@login_required
@admin_required
def update_settings():
    conn = get_db()
    conn.execute("UPDATE settings SET value = ? WHERE key = 'mqtt_broker'", (request.form['mqtt_broker'],))
    conn.execute("UPDATE settings SET value = ? WHERE key = 'mqtt_port'", (request.form['mqtt_port'],))
    conn.execute("UPDATE settings SET value = ? WHERE key = 'mqtt_prefix'", (request.form['mqtt_prefix'],))
    conn.execute("UPDATE settings SET value = ? WHERE key = 'check_interval'", (request.form['check_interval'],))
    conn.commit()
    conn.close()
    trigger_monitor_check()
    flash('Settings updated. Immediate network scan triggered.', 'success')
    return redirect(url_for('index'))

@app.route('/test_alert', methods=['POST'])
@login_required
@admin_required
def test_alert():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings_dict = {row['key']: row['value'] for row in cursor.fetchall()}
    conn.close()
    
    broker = settings_dict.get('mqtt_broker', '127.0.0.1')
    port = int(settings_dict.get('mqtt_port', 1883))
    prefix = settings_dict.get('mqtt_prefix', 'zabbix/cctv')
    
    try:
        client = mqtt.Client("camera_monitor_test")
        client.connect(broker, port, 5)
        test_topic = f"{prefix}/test_device/ping"
        client.publish(test_topic, "TEST_PING", retain=False)
        client.disconnect()
        flash(f'Success! Test alert sent to {test_topic}', 'success')
    except Exception as e:
        flash(f'MQTT Error: Could not reach broker at {broker}:{port}. ({str(e)})', 'danger')
    return redirect(url_for('index'))

@app.route('/add_switch', methods=['POST'])
@login_required
@admin_required
def add_switch():
    conn = get_db()
    try:
        conn.execute("INSERT INTO switches (name, ip) VALUES (?, ?)", (request.form['name'], request.form['ip']))
        conn.commit()
        trigger_monitor_check()
        flash('Switch added.', 'success')
    except sqlite3.IntegrityError: flash('Error: A switch with that name already exists.', 'danger')
    finally: conn.close()
    return redirect(url_for('index'))

@app.route('/edit_switch/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_switch(id):
    conn = get_db()
    if request.method == 'POST':
        try:
            conn.execute("UPDATE switches SET name = ?, ip = ? WHERE id = ?", (request.form['name'], request.form['ip'], id))
            conn.commit()
            trigger_monitor_check()
            flash('Switch updated.', 'success')
            conn.close()
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Error: A switch with that name already exists.', 'danger')
            
    switch = conn.execute("SELECT * FROM switches WHERE id = ?", (id,)).fetchone()
    conn.close()
    return render_template('edit_switch.html', switch=switch)

@app.route('/delete_switch/<int:id>')
@login_required
@admin_required
def delete_switch(id):
    conn = get_db()
    conn.execute("DELETE FROM cameras WHERE switch_id = ?", (id,))
    conn.execute("DELETE FROM switches WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    trigger_monitor_check()
    flash('Switch deleted.', 'success')
    return redirect(url_for('index'))

@app.route('/add_camera', methods=['POST'])
@login_required
@admin_required
def add_camera():
    switch_id = request.form.get('switch_id')
    switch_id = switch_id if switch_id else None

    conn = get_db()
    try:
        conn.execute("""INSERT INTO cameras (switch_id, name, ip, stream_url, manufacturer, username, password) VALUES (?, ?, ?, ?, ?, ?, ?)""", 
                     (switch_id, request.form['name'], request.form['ip'], request.form['stream_url'], request.form.get('manufacturer', 'Other'), request.form.get('username', ''), request.form.get('password', '')))
        conn.commit()
        trigger_monitor_check()
        flash('Camera added.', 'success')
    except sqlite3.IntegrityError: flash('Error: A camera with that name already exists.', 'danger')
    finally: conn.close()
    return redirect(url_for('index'))

@app.route('/edit_camera/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_camera(id):
    conn = get_db()
    if request.method == 'POST':
        switch_id = request.form.get('switch_id')
        switch_id = switch_id if switch_id else None 

        try:
            conn.execute("""UPDATE cameras SET switch_id = ?, name = ?, ip = ?, stream_url = ?, manufacturer = ?, username = ?, password = ? WHERE id = ?""", 
                         (switch_id, request.form['name'], request.form['ip'], request.form['stream_url'], request.form.get('manufacturer', 'Other'), request.form.get('username', ''), request.form.get('password', ''), id))
            conn.commit()
            trigger_monitor_check()
            flash('Camera updated.', 'success')
            conn.close()
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Error: A camera with that name already exists.', 'danger')
    
    camera = conn.execute("SELECT * FROM cameras WHERE id = ?", (id,)).fetchone()
    switches = conn.execute("SELECT * FROM switches").fetchall()
    conn.close()
    return render_template('edit_camera.html', camera=camera, switches=switches)

@app.route('/delete_camera/<int:id>')
@login_required
@admin_required
def delete_camera(id):
    conn = get_db()
    conn.execute("DELETE FROM cameras WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    trigger_monitor_check()
    flash('Camera deleted.', 'success')
    return redirect(url_for('index'))

@app.route('/add_user', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    role = request.form['role']
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        conn.commit()
        flash('User added.', 'success')
    except sqlite3.IntegrityError: flash('Username already exists.', 'danger')
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete_user/<int:id>')
@login_required
@admin_required
def delete_user(id):
    if id == current_user.id:
        flash('You cannot delete yourself.', 'danger')
        return redirect(url_for('index'))
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash('User deleted.', 'success')
    return redirect(url_for('index'))

@app.route('/snapshot/<int:id>')
@login_required
def snapshot(id):
    conn = get_db()
    camera = conn.execute("SELECT stream_url, ip, manufacturer, username, password FROM cameras WHERE id = ?", (id,)).fetchone()
    conn.close()
    if not camera: return "Camera not found", 404
    snap_bytes = get_snapshot_bytes(camera['ip'], camera['manufacturer'], camera['username'], camera['password'], camera['stream_url'])
    if snap_bytes: return Response(snap_bytes, mimetype='image/jpeg')
    else: return "Failed to grab snapshot", 500

# ==========================================
# WEB UI TUNNELING (REVERSE PROXY)
# ==========================================
def proxy_request(device_type, device_id, req_path, method, headers, data, cookies):
    conn = get_db()
    if device_type == 'switch': device = conn.execute("SELECT ip FROM switches WHERE id = ?", (device_id,)).fetchone()
    elif device_type == 'camera': device = conn.execute("SELECT ip FROM cameras WHERE id = ?", (device_id,)).fetchone()
    else: return "Invalid device type", 404
    conn.close()

    if not device: return "Device not found", 404

    try:
        resolved_ip = socket.gethostbyname(device['ip'])
        ip_obj = ipaddress.ip_address(resolved_ip)
        if not ip_obj.is_private or ip_obj.is_loopback:
             return "Security Policy Violation: Target domain resolves to a non-local or restricted IP.", 403
    except socket.gaierror: return f"DNS Error: Could not resolve hostname '{device['ip']}'", 400
    except ValueError: return "Invalid IP or Hostname format.", 400

    query_string = request.query_string.decode('utf-8')
    full_req_path = f"{req_path}?{query_string}" if query_string else req_path
    
    # SECURITY FIX: Construct the URL using the validated resolved IP, NOT the raw input domain
    target_url = f"http://{resolved_ip}/{full_req_path.lstrip('/')}"
    clean_headers = {k: v for k, v in headers if k.lower() not in ['host', 'origin', 'referer', 'accept-encoding']}
    
    # Inject the original Host header so the end device accepts the connection if it relies on vhosts
    clean_headers['Host'] = device['ip']
    
    try:
        resp = requests.request(method=method, url=target_url, headers=clean_headers, data=data, cookies=cookies, allow_redirects=False, stream=True, timeout=15)
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        for i, (name, value) in enumerate(resp_headers):
            if name.lower() == 'location':
                if value.startswith(f"http://{device['ip']}"): value = value.replace(f"http://{device['ip']}", f"/tunnel/{device_type}/{device_id}")
                elif value.startswith(f"http://{resolved_ip}"): value = value.replace(f"http://{resolved_ip}", f"/tunnel/{device_type}/{device_id}")
                elif value.startswith('/'): value = f"/tunnel/{device_type}/{device_id}{value}"
                resp_headers[i] = (name, value)
        return Response(resp.iter_content(chunk_size=10*1024), resp.status_code, resp_headers)
    except requests.exceptions.RequestException as e:
        return f"Tunnel Error connecting to {device['ip']}: {str(e)}", 502

@app.route('/tunnel/<device_type>/<int:device_id>/', defaults={'req_path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/tunnel/<device_type>/<int:device_id>/<path:req_path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def tunnel(device_type, device_id, req_path):
    return proxy_request(device_type, device_id, req_path, request.method, request.headers, request.get_data(), request.cookies)

@app.errorhandler(404)
def proxy_absolute_paths(e):
    if not current_user.is_authenticated: return "404 - Not Found", 404
    referer = request.headers.get('Referer')
    if referer:
        parsed_referer = urlparse(referer)
        parts = parsed_referer.path.split('/')
        if len(parts) >= 4 and parts[1] == 'tunnel':
            return proxy_request(parts[2], parts[3], request.path, request.method, request.headers, request.get_data(), request.cookies)
    return "404 - Not Found", 404
