import os
import time
import sqlite3
import subprocess
import threading
import paho.mqtt.client as mqtt
import requests
from urllib.parse import urlparse
from flask import Response
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, abort, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Secret key is required for Flask-Login session cookies
app.secret_key = os.environ.get('SECRET_KEY', 'cctv-super-secret-key') 
DB_PATH = '/app/data/cctv.db'

# ==========================================
# AUTHENTICATION SETUP
# ==========================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
            abort(403) # Forbidden
        return f(*args, **kwargs)
    return decorated_function

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
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT
    )""")
    
    # Insert Default Settings via Environment Variables
    cursor.execute("SELECT count(*) FROM settings")
    if cursor.fetchone()[0] == 0:
        settings = [
            ('mqtt_broker', os.environ.get('DEFAULT_MQTT_BROKER', '192.168.1.50')),
            ('mqtt_port', os.environ.get('DEFAULT_MQTT_PORT', '1883')),
            ('mqtt_prefix', os.environ.get('DEFAULT_MQTT_PREFIX', 'zabbix/cctv')),
            ('check_interval', os.environ.get('DEFAULT_CHECK_INTERVAL', '60'))
        ]
        cursor.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", settings)
        
    # Insert Default Admin Account via Environment Variables
    cursor.execute("SELECT count(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
        default_pass = os.environ.get('DEFAULT_ADMIN_PASS', 'admin')
        default_hash = generate_password_hash(default_pass)
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')", (default_user, default_hash))
    
    conn.commit()
    conn.close()
    print("Database initialized.")

# ==========================================
# BACKGROUND MONITORING TASK (Unchanged)
# ==========================================
def is_pingable(ip):
    response = subprocess.call(['ping', '-c', '1', '-W', '2', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return response == 0

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
            except Exception as e:
                pass
            
            cursor.execute("SELECT id, name, ip FROM switches")
            switches = cursor.fetchall()
            
            for switch in switches:
                switch_id, switch_name, switch_ip = switch['id'], switch['name'], switch['ip']
                
                if is_pingable(switch_ip):
                    client.publish(f"{prefix}/{switch_name}/ping", 1, retain=True)
                    cursor.execute("UPDATE switches SET status = 'UP' WHERE id = ?", (switch_id,))
                    
                    cursor.execute("SELECT id, name, ip, stream_url FROM cameras WHERE switch_id = ?", (switch_id,))
                    cameras = cursor.fetchall()
                    
                    for cam in cameras:
                        cam_id, cam_name, cam_ip, stream_url = cam['id'], cam['name'], cam['ip'], cam['stream_url']
                        
                        if is_pingable(cam_ip):
                            client.publish(f"{prefix}/{cam_name}/ping", 1, retain=True)
                            if is_stream_active(stream_url):
                                client.publish(f"{prefix}/{cam_name}/stream", 1, retain=True)
                                cursor.execute("UPDATE cameras SET status = 'UP' WHERE id = ?", (cam_id,))
                            else:
                                client.publish(f"{prefix}/{cam_name}/stream", 0, retain=True)
                                cursor.execute("UPDATE cameras SET status = 'DOWN (Stream Error)' WHERE id = ?", (cam_id,))
                        else:
                            client.publish(f"{prefix}/{cam_name}/ping", 0, retain=True)
                            client.publish(f"{prefix}/{cam_name}/stream", 0, retain=True)
                            cursor.execute("UPDATE cameras SET status = 'DOWN (Offline)' WHERE id = ?", (cam_id,))
                else:
                    client.publish(f"{prefix}/{switch_name}/ping", 0, retain=True)
                    cursor.execute("UPDATE switches SET status = 'DOWN' WHERE id = ?", (switch_id,))
                    cursor.execute("UPDATE cameras SET status = 'UNREACHABLE (Switch Down)' WHERE switch_id = ?", (switch_id,))

            conn.commit()
            conn.close()
            client.disconnect()
            
            time.sleep(interval)
        except Exception as e:
            print(f"Error in monitor loop: {e}")
            time.sleep(10)

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
            flash('Invalid username or password')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    conn = get_db()
    switches = conn.execute("SELECT * FROM switches").fetchall()
    cameras = conn.execute("""
        SELECT c.*, s.name as switch_name 
        FROM cameras c JOIN switches s ON c.switch_id = s.id
    """).fetchall()
    
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings_dict = {row['key']: row['value'] for row in cursor.fetchall()}
    
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    
    return render_template('index.html', switches=switches, cameras=cameras, settings=settings_dict, users=users)

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
    return redirect(url_for('index'))

@app.route('/add_switch', methods=['POST'])
@login_required
@admin_required
def add_switch():
    conn = get_db()
    conn.execute("INSERT INTO switches (name, ip) VALUES (?, ?)", (request.form['name'], request.form['ip']))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/add_camera', methods=['POST'])
@login_required
@admin_required
def add_camera():
    conn = get_db()
    conn.execute("INSERT INTO cameras (switch_id, name, ip, stream_url) VALUES (?, ?, ?, ?)", 
                 (request.form['switch_id'], request.form['name'], request.form['ip'], request.form['stream_url']))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete_camera/<int:id>')
@login_required
@admin_required
def delete_camera(id):
    conn = get_db()
    conn.execute("DELETE FROM cameras WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete_switch/<int:id>')
@login_required
@admin_required
def delete_switch(id):
    conn = get_db()
    conn.execute("DELETE FROM cameras WHERE switch_id = ?", (id,))
    conn.execute("DELETE FROM switches WHERE id = ?", (id,))
    conn.commit()
    conn.close()
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
    except sqlite3.IntegrityError:
        pass # Username already exists
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete_user/<int:id>')
@login_required
@admin_required
def delete_user(id):
    # Prevent deleting yourself
    if id == current_user.id:
        return redirect(url_for('index'))
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

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

    # Reconstruct the query string (e.g., ?action=login)
    query_string = request.query_string.decode('utf-8')
    full_req_path = f"{req_path}?{query_string}" if query_string else req_path
    
    target_url = f"http://{device['ip']}/{full_req_path.lstrip('/')}"
    
    # Clean headers to prevent proxy loops or hostname mismatches
    clean_headers = {k: v for k, v in headers if k.lower() not in ['host', 'origin', 'referer', 'accept-encoding']}
    
    try:
        # stream=True ensures large files don't crash the container RAM
        resp = requests.request(
            method=method,
            url=target_url,
            headers=clean_headers,
            data=data,
            cookies=cookies,
            allow_redirects=False,
            stream=True,
            timeout=15
        )
        
        # Remove hop-by-hop headers
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [(name, value) for (name, value) in resp.raw.headers.items()
                        if name.lower() not in excluded_headers]
        
        # Rewrite the Location header so redirects stay inside our tunnel
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
    """
    Magic Referer Hack: Catches absolute path requests from legacy UIs 
    and securely proxies them to the correct device.
    """
    if not current_user.is_authenticated:
        return "404 - Not Found", 404

    referer = request.headers.get('Referer')
    if referer:
        parsed_referer = urlparse(referer)
        parts = parsed_referer.path.split('/')
        # Identify if the user is currently viewing a tunnel page
        if len(parts) >= 4 and parts[1] == 'tunnel':
            device_type = parts[2]
            device_id = parts[3]
            return proxy_request(device_type, device_id, request.path, request.method, request.headers, request.get_data(), request.cookies)
    
    return "404 - Not Found", 404

if __name__ == '__main__':
    init_db()
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
    app.run(host='0.0.0.0', port=5000, debug=False)
