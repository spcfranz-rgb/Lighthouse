import os
import time
import socket
import sqlite3
import subprocess
import threading
import requests
import ipaddress
import paho.mqtt.client as mqtt
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from urllib.parse import urlparse
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, abort, flash, Response, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- SECURITY HARDENING: SESSIONS ---
app.secret_key = os.environ.get('SECRET_KEY', 'cctv-super-secret-key') 
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
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS switches (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, ip TEXT, status TEXT DEFAULT 'UNKNOWN'
    )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cameras (
        id INTEGER PRIMARY KEY AUTOINCREMENT, switch_id INTEGER, name TEXT UNIQUE, 
        ip TEXT, stream_url TEXT, status TEXT DEFAULT 'UNKNOWN',
        FOREIGN KEY(switch_id) REFERENCES switches(id)
    )""")
    
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

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT
    )""")
    
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
# BACKGROUND MONITORING TASK
# ==========================================
def is_pingable(ip):
    response = subprocess.call(['ping', '-c', '1', '-W', '2', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return response == 0

def is_port_open(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False

def is_stream_active(url):
    try:
        response = subprocess.call(
            ['ffprobe', '-rtsp_transport', 'tcp', '-v', 'error', '-i', url],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10
        )
        return response == 0
    except subprocess.TimeoutExpired:
        return False

def monitor_loop():
    print("Starting background monitoring thread...")
    while True:
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute("SELECT key, value FROM settings")
            settings_dict = {row['key']: row['value'] for row in cursor.fetchall()}
            broker = settings_dict.get('mqtt_broker', '127.0.0.1')
            port = int(settings_dict.get('mqtt_port', 1883))
            prefix = settings_dict.get('mqtt_prefix', 'zabbix/cctv')
            interval = int(settings_dict.get('check_interval', 60))
            
            client = mqtt.Client("camera_monitor_service")
            try:
                client.connect(broker, port, 60)
            except Exception:
                pass
            
            # 1. PROCESS SWITCHES & THEIR ATTACHED CAMERAS
            cursor.execute("SELECT * FROM switches")
            switches = cursor.fetchall()
            now = time.time()
            
            for switch in switches:
                switch_id, switch_name, switch_ip, s_until = switch['id'], switch['name'], switch['ip'], switch['silenced_until']
                silenced = s_until > now
                
                is_up = is_pingable(switch_ip) or is_port_open(switch_ip, 80) or is_port_open(switch_ip, 443)
                
                # STRING UPDATES FOR SWITCH
                switch_payload = "MAINTENANCE" if silenced else ("UP" if is_up else "OFFLINE")
                client.publish(f"{prefix}/{switch_name}/ping", switch_payload, retain=True)
                
                if is_up:
                    cursor.execute("UPDATE switches SET status = ? WHERE id = ?", ('UP' if not silenced else 'UP (Silenced)', switch_id))
                    
                    cursor.execute("SELECT * FROM cameras WHERE switch_id = ?", (switch_id,))
                    cameras = cursor.fetchall()
                    
                    for cam in cameras:
                        cam_id, cam_name, cam_ip, stream_url, c_until = cam['id'], cam['name'], cam['ip'], cam['stream_url'], cam['silenced_until']
                        cam_silenced = c_until > now
                        
                        cam_up = is_pingable(cam_ip) or is_port_open(cam_ip, 554) or is_port_open(cam_ip, 80)
                        
                        if cam_up:
                            stream_ok = is_stream_active(stream_url)
                            if cam_silenced:
                                client.publish(f"{prefix}/{cam_name}/ping", "MAINTENANCE", retain=True)
                                client.publish(f"{prefix}/{cam_name}/stream", "MAINTENANCE", retain=True)
                                cursor.execute("UPDATE cameras SET status = ? WHERE id = ?", ('UP (Silenced)' if stream_ok else 'STREAM ERR (Silenced)', cam_id))
                            else:
                                # STRING UPDATES FOR HEALTHY CAMERA
                                client.publish(f"{prefix}/{cam_name}/ping", "UP", retain=True)
                                client.publish(f"{prefix}/{cam_name}/stream", "UP" if stream_ok else "STREAM_ERROR", retain=True)
                                cursor.execute("UPDATE cameras SET status = ? WHERE id = ?", ('UP' if stream_ok else 'DOWN (Stream Error)', cam_id))
                        else:
                            if cam_silenced:
                                client.publish(f"{prefix}/{cam_name}/ping", "MAINTENANCE", retain=True)
                                client.publish(f"{prefix}/{cam_name}/stream", "MAINTENANCE", retain=True)
                                cursor.execute("UPDATE cameras SET status = ? WHERE id = ?", ('DOWN (Silenced)', cam_id))
                            else:
                                # STRING UPDATES FOR DEAD CAMERA
                                client.publish(f"{prefix}/{cam_name}/ping", "OFFLINE", retain=True)
                                client.publish(f"{prefix}/{cam_name}/stream", "OFFLINE", retain=True)
                                cursor.execute("UPDATE cameras SET status = ? WHERE id = ?", ('DOWN (Offline)', cam_id))
                else:
                    cursor.execute("UPDATE switches SET status = ? WHERE id = ?", ('DOWN' if not silenced else 'DOWN (Silenced)', switch_id))
                    cursor.execute("UPDATE cameras SET status = ? WHERE switch_id = ?", ('UNREACHABLE (Switch Down)' if not silenced else 'UNREACHABLE (Silenced)', switch_id))

            # 2. PROCESS STANDALONE CAMERAS
            cursor.execute("SELECT * FROM cameras WHERE switch_id IS NULL OR switch_id = ''")
            standalone_cameras = cursor.fetchall()
            for cam in standalone_cameras:
                cam_id, cam_name, cam_ip, stream_url, c_until = cam['id'], cam['name'], cam['ip'], cam['stream_url'], cam['silenced_until']
                cam_silenced = c_until > now
                
                cam_up = is_pingable(cam_ip) or is_port_open(cam_ip, 554) or is_port_open(cam_ip, 80)
                
                if cam_up:
                    stream_ok = is_stream_active(stream_url)
                    if cam_silenced:
                        client.publish(f"{prefix}/{cam_name}/ping", "MAINTENANCE", retain=True)
                        client.publish(f"{prefix}/{cam_name}/stream", "MAINTENANCE", retain=True)
                        cursor.execute("UPDATE cameras SET status = ? WHERE id = ?", ('UP (Silenced)' if stream_ok else 'STREAM ERR (Silenced)', cam_id))
                    else:
                        # STRING UPDATES FOR HEALTHY STANDALONE
                        client.publish(f"{prefix}/{cam_name}/ping", "UP", retain=True)
                        client.publish(f"{prefix}/{cam_name}/stream", "UP" if stream_ok else "STREAM_ERROR", retain=True)
                        cursor.execute("UPDATE cameras SET status = ? WHERE id = ?", ('UP' if stream_ok else 'DOWN (Stream Error)', cam_id))
                else:
                    if cam_silenced:
                        client.publish(f"{prefix}/{cam_name}/ping", "MAINTENANCE", retain=True)
                        client.publish(f"{prefix}/{cam_name}/stream", "MAINTENANCE", retain=True)
                        cursor.execute("UPDATE cameras SET status = ? WHERE id = ?", ('DOWN (Silenced)', cam_id))
                    else:
                        # STRING UPDATES FOR DEAD STANDALONE
                        client.publish(f"{prefix}/{cam_name}/ping", "OFFLINE", retain=True)
                        client.publish(f"{prefix}/{cam_name}/stream", "OFFLINE", retain=True)
                        cursor.execute("UPDATE cameras SET status = ? WHERE id = ?", ('DOWN (Offline)', cam_id))

            conn.commit()
            conn.close()
            client.disconnect()
            
        except Exception as e:
            print(f"Error in monitor loop: {e}")
            time.sleep(10)
            continue
            
        # 3. INTERRUPTIBLE SLEEP CYCLE
        for _ in range(interval):
            if os.path.exists(FORCE_CHECK_FLAG):
                try:
                    os.remove(FORCE_CHECK_FLAG)
                except OSError:
                    pass
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
    if device_type == 'switch':
        conn.execute("UPDATE switches SET silenced_until = ? WHERE id = ?", (silence_until, id))
    elif device_type == 'camera':
        conn.execute("UPDATE cameras SET silenced_until = ? WHERE id = ?", (silence_until, id))
    conn.commit()
    conn.close()
    
    trigger_monitor_check()
    return jsonify({'success': True})

@app.route('/api/ping', methods=['POST'])
@login_required
@admin_required
def manual_ping():
    ip = request.form.get('ip')
    if not ip:
        return jsonify({'success': False, 'output': 'No IP address provided.'})
    try:
        cmd = ['ping', '-c', '4', '-W', '2', ip]
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if process.returncode == 0:
            return jsonify({'success': True, 'output': process.stdout})
        else:
            return jsonify({'success': False, 'output': process.stdout or process.stderr or 'Ping failed.'})
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
        # UPDATED PAYLOAD FOR THE TEST BUTTON
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
    conn.execute("INSERT INTO switches (name, ip) VALUES (?, ?)", (request.form['name'], request.form['ip']))
    conn.commit()
    conn.close()
    
    trigger_monitor_check()
    flash('Switch added.', 'success')
    return redirect(url_for('index'))

@app.route('/edit_switch/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_switch(id):
    conn = get_db()
    if request.method == 'POST':
        conn.execute("UPDATE switches SET name = ?, ip = ? WHERE id = ?", (request.form['name'], request.form['ip'], id))
        conn.commit()
        conn.close()
        
        trigger_monitor_check()
        flash('Switch updated.', 'success')
        return redirect(url_for('index'))
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
    conn.execute("""
        INSERT INTO cameras (switch_id, name, ip, stream_url, manufacturer, username, password) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (switch_id, request.form['name'], request.form['ip'], 
          request.form['stream_url'], request.form.get('manufacturer', 'Other'),
          request.form.get('username', ''), request.form.get('password', '')))
    conn.commit()
    conn.close()
    
    trigger_monitor_check()
    flash('Camera added.', 'success')
    return redirect(url_for('index'))

@app.route('/edit_camera/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_camera(id):
    conn = get_db()
    if request.method == 'POST':
        switch_id = request.form.get('switch_id')
        switch_id = switch_id if switch_id else None 

        conn.execute("""
            UPDATE cameras SET switch_id = ?, name = ?, ip = ?, stream_url = ?, 
            manufacturer = ?, username = ?, password = ? WHERE id = ?
        """, (switch_id, request.form['name'], request.form['ip'], 
              request.form['stream_url'], request.form.get('manufacturer', 'Other'),
              request.form.get('username', ''), request.form.get('password', ''), id))
        conn.commit()
        conn.close()
        
        trigger_monitor_check()
        flash('Camera updated.', 'success')
        return redirect(url_for('index'))
    
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
    except sqlite3.IntegrityError:
        flash('Username already exists.', 'danger')
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
    
    if not camera:
        return "Camera not found", 404
        
    mfg = camera['manufacturer']
    ip = camera['ip']
    user = camera['username']
    pwd = camera['password']
    
    if mfg and mfg != 'Other':
        url = None
        auth_in_url = False
        
        if mfg == 'Hikvision':
            url = f"http://{ip}/ISAPI/Streaming/channels/101/picture"
        elif mfg in ['Dahua', 'Amcrest']:
            url = f"http://{ip}/cgi-bin/snapshot.cgi?chn=1"
        elif mfg == 'Axis':
            url = f"http://{ip}/axis-cgi/jpg/image.cgi"
        elif mfg == 'Foscam':
            url = f"http://{ip}/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2&usr={user}&pwd={pwd}"
            auth_in_url = True
        elif mfg == 'Hanwha':
            url = f"http://{ip}/stw-cgi/video.cgi?msubmenu=snapshot&action=view&Profile=1"
            
        if url:
            try:
                if auth_in_url:
                    resp = requests.get(url, timeout=3)
                else:
                    resp = requests.get(url, auth=HTTPDigestAuth(user, pwd), timeout=3)
                    if resp.status_code != 200:
                        resp = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=3)
                        
                if resp.status_code == 200 and 'image' in resp.headers.get('Content-Type', ''):
                    return Response(resp.content, mimetype='image/jpeg')
            except Exception as e:
                print(f"HTTP Snapshot failed for {ip}: {e}. Falling back to FFmpeg.")

    try:
        cmd = ['ffmpeg', '-y', '-rtsp_transport', 'tcp', '-i', camera['stream_url'], '-vframes', '1', '-f', 'image2pipe', '-vcodec', 'mjpeg', '-']
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        if process.returncode == 0:
            return Response(process.stdout, mimetype='image/jpeg')
        else:
            return f"Failed to grab snapshot", 500
    except subprocess.TimeoutExpired:
        return "Timeout reaching camera", 504
    except Exception as e:
        return str(e), 500

# ==========================================
# WEB UI TUNNELING (REVERSE PROXY)
# ==========================================
def proxy_request(device_type, device_id, req_path, method, headers, data, cookies):
    conn = get_db()
    if device_type == 'switch':
        device = conn.execute("SELECT ip FROM switches WHERE id = ?", (device_id,)).fetchone()
    elif device_type == 'camera':
        device = conn.execute("SELECT ip FROM cameras WHERE id = ?", (device_id,)).fetchone()
    else:
        return "Invalid device type", 404
    conn.close()

    if not device:
        return "Device not found", 404

    try:
        ip_obj = ipaddress.ip_address(device['ip'])
        if not ip_obj.is_private or ip_obj.is_loopback:
             return "Security Policy Violation: Target IP is not a valid local device.", 403
    except ValueError:
        return "Invalid IP Address format.", 400

    query_string = request.query_string.decode('utf-8')
    full_req_path = f"{req_path}?{query_string}" if query_string else req_path
    target_url = f"http://{device['ip']}/{full_req_path.lstrip('/')}"
    clean_headers = {k: v for k, v in headers if k.lower() not in ['host', 'origin', 'referer', 'accept-encoding']}
    
    try:
        resp = requests.request(
            method=method, url=target_url, headers=clean_headers, data=data,
            cookies=cookies, allow_redirects=False, stream=True, timeout=15
        )
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        
        for i, (name, value) in enumerate(resp_headers):
            if name.lower() == 'location':
                if value.startswith(f"http://{device['ip']}"):
                    value = value.replace(f"http://{device['ip']}", f"/tunnel/{device_type}/{device_id}")
                elif value.startswith('/'):
                    value = f"/tunnel/{device_type}/{device_id}{value}"
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
    if not current_user.is_authenticated:
        return "404 - Not Found", 404

    referer = request.headers.get('Referer')
    if referer:
        parsed_referer = urlparse(referer)
        parts = parsed_referer.path.split('/')
        if len(parts) >= 4 and parts[1] == 'tunnel':
            device_type = parts[2]
            device_id = parts[3]
            return proxy_request(device_type, device_id, request.path, request.method, request.headers, request.get_data(), request.cookies)
    
    return "404 - Not Found", 404
