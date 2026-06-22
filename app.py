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
import json
import hashlib
import base64
import re
import atexit
import signal
from datetime import datetime
import eventlet.greenpool

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import ipaddress
import paho.mqtt.client as mqtt
import imagehash
from PIL import Image
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from urllib.parse import urlparse
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, abort, flash, Response, jsonify, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_socketio import SocketIO
from authlib.integrations.flask_client import OAuth
from cryptography.fernet import Fernet
from getmac import get_mac_address

app = Flask(__name__)

# Tell Flask it is behind a reverse proxy (NGINX/Headscale)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Limit uploads to 2 Megabytes to prevent RAM exhaustion DoS attacks (CSV Bombing)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# Initialize WebSockets with the eventlet async worker (Logs muted to hide Errno 9 disconnects)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', logger=False, engineio_logger=False)

# --- GLOBAL TEMPLATE VARIABLES (CO-BRANDING) ---
LOCAL_COMPANY_LOGO = None
LOCAL_CUSTOMER_LOGO = None

@app.context_processor
def inject_globals():
    return {
        'company_logo': LOCAL_COMPANY_LOGO,
        'customer_logo': LOCAL_CUSTOMER_LOGO
    }

# --- SECURITY HARDENING: SESSIONS & ENCRYPTION ---
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    print("WARNING: SECRET_KEY environment variable is missing. Using insecure development key.")
    app.secret_key = 'cctv-super-secret-key-change-me'
    
app.config['SESSION_COOKIE_HTTPONLY'] = True 
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('REQUIRE_HTTPS', 'False').lower() == 'true'

def get_cipher():
    """Derives a secure 32-byte Fernet key from the Flask SECRET_KEY."""
    key_bytes = app.secret_key.encode('utf-8')
    fernet_key = base64.urlsafe_b64encode(hashlib.sha256(key_bytes).digest())
    return Fernet(fernet_key)

def encrypt_pwd(pwd):
    """Encrypts plaintext passwords for database storage."""
    if not pwd: return ''
    return get_cipher().encrypt(pwd.encode('utf-8')).decode('utf-8')

def decrypt_pwd(pwd):
    """Decrypts database passwords into memory. Falls back to plaintext for legacy migration."""
    if not pwd: return ''
    try:
        return get_cipher().decrypt(pwd.encode('utf-8')).decode('utf-8')
    except Exception:
        # If it looks like a Fernet token but failed, the SECRET_KEY is wrong/lost.
        if pwd.startswith('gAAAAA'):
            print("ERROR: Database decryption failed! Secret Key mismatch.")
            return '' 
        # Otherwise, safely assume it is a legacy plaintext password
        return pwd

# --- AUTHENTIK OIDC SETUP ---
oauth = OAuth(app)
AUTHENTIK_URL = os.environ.get('AUTHENTIK_URL')

if AUTHENTIK_URL:
    oauth.register(
        name='authentik',
        client_id=os.environ.get('AUTHENTIK_CLIENT_ID'),
        client_secret=os.environ.get('AUTHENTIK_CLIENT_SECRET'),
        server_metadata_url=f"{AUTHENTIK_URL.rstrip('/')}/application/o/cctv-dashboard/.well-known/openid-configuration",
        client_kwargs={'scope': 'openid profile email'}
    )

# ==========================================
# AUTHENTICATION & GLOBALS
# ==========================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- DATABASE PATHS ---
DB_PATH_DISK = '/app/data/cctv.db'        # Persistent SD Card Storage
DB_PATH_RAM = '/app/data_ram/cctv.db'     # High-Speed RAM Storage
FORCE_CHECK_FLAG = '/app/data_ram/force_check.flag'

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
        if current_user.role != 'admin': abort(403)
        return f(*args, **kwargs)
    return decorated_function

def operator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'operator']: abort(403)
        return f(*args, **kwargs)
    return decorated_function

def trigger_monitor_check():
    try: open(FORCE_CHECK_FLAG, 'w').close()
    except Exception: pass

# ==========================================
# DATABASE INITIALIZATION & RAM SYNC
# ==========================================
def init_ram_db():
    """Safely loads the physical database into RAM on container boot using SQLite API."""
    os.makedirs(os.path.dirname(DB_PATH_RAM), exist_ok=True)
    os.makedirs(os.path.dirname(DB_PATH_DISK), exist_ok=True)
    
    if os.path.exists(DB_PATH_DISK) and not os.path.exists(DB_PATH_RAM):
        print("Restoring database from physical disk to RAM...")
        try:
            disk_conn = sqlite3.connect(DB_PATH_DISK)
            ram_conn = sqlite3.connect(DB_PATH_RAM)
            with ram_conn:
                disk_conn.backup(ram_conn)
            disk_conn.close()
            ram_conn.close()
        except Exception as e:
            print(f"Boot restoration failed: {e}")

def get_db():
    """All active connections point exclusively to the RAM disk."""
    os.makedirs(os.path.dirname(DB_PATH_RAM), exist_ok=True)
    conn = sqlite3.connect(DB_PATH_RAM, check_same_thread=False, timeout=30)
    try: conn.execute("PRAGMA journal_mode=WAL;")
    except sqlite3.OperationalError: pass
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    init_ram_db() # Ensure RAM disk is populated first
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
    except sqlite3.OperationalError: pass
        
    try:
        cursor.execute("ALTER TABLE switches ADD COLUMN silenced_until REAL DEFAULT 0")
        cursor.execute("ALTER TABLE cameras ADD COLUMN silenced_until REAL DEFAULT 0")
    except sqlite3.OperationalError: pass

    try:
        cursor.execute("ALTER TABLE switches ADD COLUMN mac_address TEXT DEFAULT ''")
        cursor.execute("ALTER TABLE cameras ADD COLUMN mac_address TEXT DEFAULT ''")
    except sqlite3.OperationalError: pass

    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT)")
    
    cursor.execute("SELECT count(*) FROM settings")
    if cursor.fetchone()[0] == 0:
        settings = [
            ('mqtt_broker', os.environ.get('DEFAULT_MQTT_BROKER', '127.0.0.1')),
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
    print("Database initialized in RAM.")

def sync_db_loop():
    """Background thread that safely dumps the RAM database back to the SD card every 5 minutes."""
    print("Starting background SQLite sync thread...")
    while True:
        time.sleep(300) # Wait 5 minutes
        if os.path.exists(DB_PATH_RAM):
            try:
                source = sqlite3.connect(DB_PATH_RAM)
                dest = sqlite3.connect(DB_PATH_DISK)
                with dest:
                    source.backup(dest)
                dest.close()
                source.close()
            except Exception as e:
                print(f"Failed to sync database to disk: {e}")

def graceful_shutdown(*args):
    """Fires when Docker stops the container to save the RAM disk to the SD Card."""
    print("Container shutting down. Forcing final database sync to disk...")
    if os.path.exists(DB_PATH_RAM):
        try:
            source = sqlite3.connect(DB_PATH_RAM)
            dest = sqlite3.connect(DB_PATH_DISK)
            with dest: source.backup(dest)
            dest.close()
            source.close()
            print("Final sync complete. Safe to exit.")
        except Exception as e: print(f"Emergency Sync Failed: {e}")

atexit.register(graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)

def log_prune_loop():
    """Background thread to safely prune old logs once a day."""
    print("Starting daily database pruning thread...")
    while True:
        time.sleep(86400) # Sleep for 24 hours
        try:
            conn = get_db()
            seven_days_ago = time.time() - (7 * 24 * 3600)
            conn.execute("DELETE FROM event_logs WHERE timestamp < ?", (seven_days_ago,))
            conn.commit()
            conn.close()
            print("Successfully pruned logs older than 7 days.")
        except Exception as e:
            print(f"Failed to prune logs: {e}")

# ==========================================
# BACKGROUND MONITORING & NETWORK TASKS
# ==========================================

# --- CPU THROTTLE ---
# Restrict CPU-heavy ffmpeg tasks to 2 concurrent threads to prevent ARM meltdown
SNAPSHOT_SEMAPHORE = eventlet.semaphore.Semaphore(2)

def is_valid_target(target):
    """Sanitizes user input to prevent Argument Injection and DoS."""
    if not target: return False
    target = str(target).strip()
    if target.startswith('-'): return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError: pass
    if re.match(r'^[A-Za-z0-9_.-]+$', target): return True
    return False

def is_pingable(target):
    response = subprocess.call(['ping', '-c', '1', '-W', '2', target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return response == 0

def is_port_open(target, port, timeout=2):
    try:
        with socket.create_connection((target, port), timeout=timeout): return True
    except OSError: return False

def is_stream_active(url):
    try:
        response = subprocess.call(['ffprobe', '-rtsp_transport', 'tcp', '-v', 'error', '-i', url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        return response == 0
    except subprocess.TimeoutExpired: return False

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
                if auth_in_url: resp = requests.get(url, timeout=3)
                else:
                    resp = requests.get(url, auth=HTTPDigestAuth(user, pwd), timeout=3)
                    if resp.status_code != 200:
                        resp = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=3)
                if resp.status_code == 200 and 'image' in resp.headers.get('Content-Type', ''): return resp.content
            except Exception: pass 
                
    try:
        cmd = ['ffmpeg', '-y', '-rtsp_transport', 'tcp', '-i', stream_url, '-vframes', '1', '-f', 'image2pipe', '-vcodec', 'mjpeg', '-']
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        if process.returncode == 0: return process.stdout
    except Exception: pass
    return None

def threaded_camera_check(cam):
    cam_up = is_pingable(cam['ip']) or is_port_open(cam['ip'], 554) or is_port_open(cam['ip'], 80)
    stream_ok = False
    snap_bytes = None
    mac = cam.get('mac_address', '')
    
    if cam_up:
        # ARP Sweep for MAC Address (Requires Docker Host Network Mode)
        if not mac:
            fetched_mac = get_mac_address(ip=cam['ip'])
            if fetched_mac:
                mac = fetched_mac.upper()
                conn = get_db()
                conn.execute("UPDATE cameras SET mac_address = ? WHERE id = ?", (mac, cam['id']))
                conn.commit()
                conn.close()

        stream_ok = is_stream_active(cam['stream_url'])
        if stream_ok:
            # SECURE THE CPU: Threads must acquire this lock before decoding video
            with SNAPSHOT_SEMAPHORE:
                snap_bytes = get_snapshot_bytes(cam['ip'], cam['manufacturer'], cam['username'], cam['password'], cam['stream_url'])
                
    return cam['id'], cam_up, stream_ok, snap_bytes

def monitor_loop():
    print("Starting concurrent background monitoring thread...")
    previous_hashes = {} 
    
    conn = get_db()
    settings_dict = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
    conn.close()
    broker = settings_dict.get('mqtt_broker', '127.0.0.1')
    port = int(settings_dict.get('mqtt_port', 1883))
    prefix = settings_dict.get('mqtt_prefix', 'zabbix/cctv')
    interval = int(settings_dict.get('check_interval', 60))
    
    client = mqtt.Client("camera_monitor_service")
    try:
        client.connect(broker, port, 60)
        client.loop_start()
    except Exception as e:
        print(f"Initial MQTT connection failed: {e}")
        
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
                    socketio.emit('state_change', {
                        'type': table, 'id': item_id, 'name': item_name,
                        'status': new_status, 'device_type': dev_type, 'timestamp': now
                    })
            
            cursor.execute("SELECT key, value FROM settings")
            dynamic_settings = {row['key']: row['value'] for row in cursor.fetchall()}
            interval = int(dynamic_settings.get('check_interval', 60))
            
            # PROCESS SWITCHES
            cursor.execute("SELECT * FROM switches")
            switches = cursor.fetchall()
            
            for switch in switches:
                switch_id, switch_name, switch_ip = switch['id'], switch['name'], switch['ip']
                s_until, mac = switch['silenced_until'], switch.get('mac_address', '')
                silenced = s_until > now
                is_up = is_pingable(switch_ip) or is_port_open(switch_ip, 80) or is_port_open(switch_ip, 443)
                
                switch_payload = "MAINTENANCE" if silenced else ("UP" if is_up else "OFFLINE")
                client.publish(f"{prefix}/{switch_name}/ping", switch_payload, retain=True)
                
                if is_up:
                    if not mac:
                        fetched_mac = get_mac_address(ip=switch_ip)
                        if fetched_mac:
                            conn.execute("UPDATE switches SET mac_address = ? WHERE id = ?", (fetched_mac.upper(), switch_id))
                            
                    new_s_stat = 'UP' if not silenced else 'UP (Silenced)'
                    set_status('switches', switch_id, switch_name, 'Switch', switch['status'], new_s_stat)
                    
                    cursor.execute("SELECT * FROM cameras WHERE switch_id = ?", (switch_id,))
                    cameras = cursor.fetchall()
                    
                    camera_list = []
                    for c in cameras:
                        cd = dict(c)
                        cd['password'] = decrypt_pwd(cd['password'])
                        camera_list.append(cd)
                        
                    camera_results = {}
                    pool = eventlet.greenpool.GreenPool(size=20)
                    for c_id, cam_up, stream_ok, snap_bytes in pool.imap(threaded_camera_check, camera_list):
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
                                    if last_hash is not None and (current_hash - last_hash) <= 2: is_frozen = True
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

            # PROCESS STANDALONE CAMERAS
            cursor.execute("SELECT * FROM cameras WHERE switch_id IS NULL OR switch_id = ''")
            standalone_cameras = cursor.fetchall()
            
            standalone_list = []
            for c in standalone_cameras:
                cd = dict(c)
                cd['password'] = decrypt_pwd(cd['password'])
                standalone_list.append(cd)
                
            standalone_results = {}
            standalone_pool = eventlet.greenpool.GreenPool(size=20)
            for c_id, cam_up, stream_ok, snap_bytes in standalone_pool.imap(threaded_camera_check, standalone_list):
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
                            if last_hash is not None and (current_hash - last_hash) <= 2: is_frozen = True
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

            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error in monitor loop: {e}")
            time.sleep(10)
            continue
            
        for _ in range(interval):
            if os.path.exists(FORCE_CHECK_FLAG):
                try: os.remove(FORCE_CHECK_FLAG)
                except OSError: pass
                break
            time.sleep(1)

# ==========================================
# FLASK WEB ROUTES
# ==========================================
@app.route('/local_logo/<filename>')
def serve_local_logo(filename):
    return send_from_directory('/app/data/logos', filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    fallback = request.args.get('fallback') == 'true'
    
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
            flash('Invalid local username or password', 'danger')
            return render_template('login.html', fallback=True, sso_configured=bool(AUTHENTIK_URL))

    if AUTHENTIK_URL and not fallback:
        try:
            requests.get(f"{AUTHENTIK_URL.rstrip('/')}/-/health/ready/", timeout=1.5)
            redirect_uri = url_for('auth_callback', _external=True)
            return oauth.authentik.authorize_redirect(redirect_uri)
        except requests.RequestException:
            flash('Authentik SSO server is unreachable. Emergency Local Access enabled.', 'warning')
            fallback = True

    return render_template('login.html', fallback=fallback, sso_configured=bool(AUTHENTIK_URL))

@app.route('/auth/callback')
def auth_callback():
    try:
        token = oauth.authentik.authorize_access_token()
        user_info = oauth.authentik.parse_id_token(token)
    except Exception as e:
        flash(f'SSO Login Failed: {str(e)}', 'danger')
        return redirect(url_for('login', fallback='true'))
    
    username = user_info.get('preferred_username') or user_info.get('name') or user_info.get('email')
    groups = user_info.get('groups', [])
    role = 'user'
    if 'cctv-admins' in groups: role = 'admin'
    elif 'cctv-operators' in groups: role = 'operator'
        
    conn = get_db()
    db_user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not db_user:
        cursor = conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, 'SSO_MANAGED', role))
        user_id = cursor.lastrowid
    else:
        user_id = db_user['id']
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        
    conn.commit()
    conn.close()
    
    login_user(User(user_id, username, role))
    return redirect(url_for('index'))

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
    return Response(si.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=cctv_event_logs.csv"})

@app.route('/export_config')
@login_required
@admin_required
def export_config():
    conn = get_db()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Device_Type', 'Parent_Switch', 'Device_Name', 'IP_Address', 'Stream_URL', 'Manufacturer', 'Username', 'Password'])
    
    switches = conn.execute("SELECT name, ip FROM switches").fetchall()
    for s in switches: cw.writerow(['Switch', '', s['name'], s['ip'], '', '', '', ''])
        
    cameras = conn.execute("""
        SELECT c.name, c.ip, c.stream_url, c.manufacturer, c.username, c.password, s.name as switch_name 
        FROM cameras c LEFT JOIN switches s ON c.switch_id = s.id
    """).fetchall()
    
    for c in cameras:
        parent = c['switch_name'] if c['switch_name'] else 'None'
        cw.writerow(['Camera', parent, c['name'], c['ip'], c['stream_url'], c['manufacturer'], c['username'], decrypt_pwd(c['password'])])
        
    conn.close()
    return Response(si.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=cctv_config.csv"})

@app.route('/download_template')
@login_required
@admin_required
def download_template():
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Device_Type', 'Parent_Switch', 'Device_Name', 'IP_Address', 'Stream_URL', 'Manufacturer', 'Username', 'Password'])
    cw.writerow(['Switch', '', 'Core-Switch-01', '192.168.1.5', '', '', '', ''])
    cw.writerow(['Switch', '', 'Edge-PoE-North', '10.0.0.15', '', '', '', ''])
    cw.writerow(['Camera', 'Core-Switch-01', 'Lobby-Cam-01', '192.168.1.100', 'rtsp://192.168.1.100:554/stream1', 'Hanwha', 'admin', 'SecurePassword123'])
    cw.writerow(['Camera', 'Edge-PoE-North', 'Parking-PTZ', '10.0.0.20', 'rtsp://10.0.0.20:554/cam/realmonitor', 'Dahua', 'admin', 'SecurePassword123'])
    cw.writerow(['Camera', 'None', 'Standalone-WiFi-Cam', '192.168.5.50', 'rtsp://192.168.5.50:554/11', 'Other', '', ''])
    return Response(si.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=cctv_import_template.csv"})

@app.route('/import_config', methods=['POST'])
@login_required
@admin_required
def import_config():
    if 'file' not in request.files:
        flash('No file uploaded.', 'danger')
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('index'))

    try:
        content = file.read().decode('utf-8-sig')
        si = io.StringIO(content)
        reader = csv.DictReader(si)
        rows = list(reader)
        conn = get_db()
        switch_map = {}
        for row in conn.execute("SELECT id, name FROM switches").fetchall(): switch_map[row['name']] = row['id']
            
        for row in rows:
            dtype = row.get('Device_Type', '').strip().lower()
            if dtype == 'switch':
                name = row.get('Device_Name', '').strip()
                ip = row.get('IP_Address', '').strip()
                if name:
                    existing = conn.execute("SELECT id FROM switches WHERE name = ?", (name,)).fetchone()
                    if existing:
                        conn.execute("UPDATE switches SET ip = ? WHERE id = ?", (ip, existing['id']))
                        switch_map[name] = existing['id']
                    else:
                        cursor = conn.execute("INSERT INTO switches (name, ip) VALUES (?, ?)", (name, ip))
                        switch_map[name] = cursor.lastrowid
                        
        for row in rows:
            dtype = row.get('Device_Type', '').strip().lower()
            if dtype == 'camera':
                parent_switch = row.get('Parent_Switch', '').strip()
                name = row.get('Device_Name', '').strip()
                ip = row.get('IP_Address', '').strip()
                url = row.get('Stream_URL', '').strip()
                mfg = row.get('Manufacturer', '').strip() or 'Other'
                user = row.get('Username', '').strip()
                pwd = encrypt_pwd(row.get('Password', '').strip())
                
                if not name: continue
                    
                switch_id = None
                if parent_switch and parent_switch.lower() != 'none':
                    switch_id = switch_map.get(parent_switch)
                    if not switch_id:
                        cursor = conn.execute("INSERT INTO switches (name, ip) VALUES (?, ?)", (parent_switch, '0.0.0.0'))
                        switch_id = cursor.lastrowid
                        switch_map[parent_switch] = switch_id

                existing = conn.execute("SELECT id FROM cameras WHERE name = ?", (name,)).fetchone()
                if existing:
                    conn.execute("""UPDATE cameras SET switch_id=?, ip=?, stream_url=?, manufacturer=?, username=?, password=? WHERE id=?""",
                                 (switch_id, ip, url, mfg, user, pwd, existing['id']))
                else:
                    conn.execute("""INSERT INTO cameras (switch_id, name, ip, stream_url, manufacturer, username, password) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                 (switch_id, name, ip, url, mfg, user, pwd))

        conn.commit()
        conn.close()
        trigger_monitor_check()
        flash('CSV Configuration imported successfully. Devices have been merged.', 'success')
    except Exception as e:
        flash(f'Error importing CSV: Invalid format or missing headers. ({str(e)})', 'danger')

    return redirect(url_for('index'))

@app.route('/api/scan_network', methods=['POST'])
@login_required
@admin_required
def scan_network():
    subnet = request.form.get('subnet')
    if not subnet: return jsonify({'success': False, 'error': 'No subnet provided.'})
        
    try: network = ipaddress.ip_network(subnet, strict=False)
    except ValueError: return jsonify({'success': False, 'error': 'Invalid subnet format. Use CIDR notation (e.g., 192.168.1.0/24)'})

    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > 1024: return jsonify({'success': False, 'error': 'Subnet too large. Please scan a /22 or smaller.'})

    def check_rtsp_port(ip):
        try:
            with socket.create_connection((ip, 554), timeout=1.5): return ip
        except (socket.timeout, ConnectionRefusedError, OSError): return None

    discovered_ips = []
    pool = eventlet.greenpool.GreenPool(size=100)
    for result in pool.imap(check_rtsp_port, hosts):
        if result: discovered_ips.append(result)

    conn = get_db()
    existing_cameras = [row['ip'] for row in conn.execute("SELECT ip FROM cameras").fetchall()]
    conn.close()
    
    new_discoveries = [ip for ip in discovered_ips if ip not in existing_cameras]

    return jsonify({
        'success': True, 
        'discovered': new_discoveries,
        'total_found': len(discovered_ips),
        'already_added': len(discovered_ips) - len(new_discoveries)
    })

@app.route('/api/add_cameras_bulk', methods=['POST'])
@login_required
@admin_required
def add_cameras_bulk():
    data = request.json
    if not data or not data.get('ips'): return jsonify({'success': False, 'error': 'No IP addresses selected.'})

    ips = data['ips']
    switch_id = data.get('switch_id') or None
    mfg = data.get('manufacturer', 'Other')
    user = data.get('username', '')
    pwd = encrypt_pwd(data.get('password', ''))

    conn = get_db()
    added_count = 0
    errors = []

    for ip in ips:
        name = f"AutoCam-{ip.replace('.', '-')}"
        stream_url = f"rtsp://{ip}:554/live"
        try:
            conn.execute("""INSERT INTO cameras (switch_id, name, ip, stream_url, manufacturer, username, password) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)""", 
                         (switch_id, name, ip, stream_url, mfg, user, pwd))
            added_count += 1
        except sqlite3.IntegrityError: errors.append(ip)

    conn.commit()
    conn.close()
    trigger_monitor_check()
    return jsonify({'success': True, 'added': added_count, 'errors': errors})

@app.route('/toggle_silence/<device_type>/<int:id>', methods=['POST'])
@login_required
@operator_required
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
@operator_required
def manual_ping():
    ip = request.form.get('ip')
    
    # --- SECURITY PATCH: Validate Input to prevent Argument Injection ---
    if not is_valid_target(ip): 
        return jsonify({'success': False, 'output': 'Security Error: Invalid IP address or hostname format.'})
    
    try:
        cmd = ['ping', '-c', '4', '-W', '2', ip.strip()]
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if process.returncode == 0: return jsonify({'success': True, 'output': process.stdout})
        else: return jsonify({'success': False, 'output': process.stdout or process.stderr or 'Ping failed.'})
    except subprocess.TimeoutExpired: return jsonify({'success': False, 'output': 'Ping command timed out.'})
    except Exception as e: return jsonify({'success': False, 'output': str(e)})

@app.route('/api/traceroute', methods=['POST'])
@login_required
@operator_required
def run_traceroute():
    target = request.form.get('target')
    
    # --- SECURITY PATCH: Validate Input to prevent Argument Injection ---
    if not is_valid_target(target): 
        return jsonify({'success': False, 'error': 'Security Error: Invalid IP address or hostname format.'})

    def execute_trace():
        try:
            cmd = ['traceroute', '-w', '2', '-m', '30', '-q', '1', target.strip()]
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
            
            if process.returncode == 0:
                socketio.emit('traceroute_result', {'success': True, 'output': process.stdout})
            else:
                error_msg = process.stderr.strip() or process.stdout.strip() or "Unknown execution error."
                socketio.emit('traceroute_result', {'success': False, 'error': error_msg})
                
        except subprocess.TimeoutExpired:
            socketio.emit('traceroute_result', {'success': False, 'error': 'Traceroute timed out after 60 seconds.'})
        except Exception as e:
            socketio.emit('traceroute_result', {'success': False, 'error': f'System Error: {str(e)}'})

    threading.Thread(target=execute_trace).start()
    return jsonify({'status': 'running'})

# --- NATIVE OOKLA SPEEDTEST INTEGRATION ---
@app.route('/api/speedtest', methods=['POST'])
@login_required
@operator_required
def run_speedtest():
    def execute_test():
        try:
            # We explicitly accept the license to prevent the headless container from freezing
            cmd = ['speedtest', '--accept-license', '--accept-gdpr', '-f', 'json']
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
            
            if process.returncode == 0:
                data = json.loads(process.stdout)
                
                # Convert bytes per second to Megabits per second
                download = round((data['download']['bandwidth'] * 8) / 1000000, 2)
                upload = round((data['upload']['bandwidth'] * 8) / 1000000, 2)
                ping = round(data['ping']['latency'], 1)
                isp = data.get('isp', 'Unknown')
                
                socketio.emit('speedtest_result', {
                    'success': True, 
                    'download': f"{download} Mbps", 
                    'upload': f"{upload} Mbps", 
                    'ping': f"{ping} ms", 
                    'isp': isp
                })
            else: 
                error_msg = process.stderr.strip() or process.stdout.strip() or "Unknown execution error."
                socketio.emit('speedtest_result', {'success': False, 'error': f'Speedtest CLI Error: {error_msg}'})
                
        except subprocess.TimeoutExpired: 
            socketio.emit('speedtest_result', {'success': False, 'error': 'Speedtest timed out after 60 seconds.'})
        except Exception as e: 
            socketio.emit('speedtest_result', {'success': False, 'error': str(e)})

    threading.Thread(target=execute_test).start()
    return jsonify({'status': 'running'})

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
    except Exception as e: flash(f'MQTT Error: Could not reach broker at {broker}:{port}. ({str(e)})', 'danger')
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
        except sqlite3.IntegrityError: flash('Error: A switch with that name already exists.', 'danger')
            
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
                     (switch_id, request.form['name'], request.form['ip'], request.form['stream_url'], request.form.get('manufacturer', 'Other'), request.form.get('username', ''), encrypt_pwd(request.form.get('password', ''))))
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
                         (switch_id, request.form['name'], request.form['ip'], request.form['stream_url'], request.form.get('manufacturer', 'Other'), request.form.get('username', ''), encrypt_pwd(request.form.get('password', '')), id))
            conn.commit()
            trigger_monitor_check()
            flash('Camera updated.', 'success')
            conn.close()
            return redirect(url_for('index'))
        except sqlite3.IntegrityError: flash('Error: A camera with that name already exists.', 'danger')
    
    camera = conn.execute("SELECT * FROM cameras WHERE id = ?", (id,)).fetchone()
    if camera:
        camera = dict(camera)
        camera['password'] = decrypt_pwd(camera['password']) # Decrypt for the HTML form display
        
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
    
    pwd = decrypt_pwd(camera['password'])
    snap_bytes = get_snapshot_bytes(camera['ip'], camera['manufacturer'], camera['username'], pwd, camera['stream_url'])
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
        if not ip_obj.is_private or ip_obj.is_loopback: return "Security Policy Violation: Target domain resolves to a non-local or restricted IP.", 403
    except socket.gaierror: return f"DNS Error: Could not resolve hostname '{device['ip']}'", 400
    except ValueError: return "Invalid IP or Hostname format.", 400

    query_string = request.query_string.decode('utf-8')
    full_req_path = f"{req_path}?{query_string}" if query_string else req_path
    
    # Strip headers that break proxying
    clean_headers = {k: v for k, v in headers if k.lower() not in ['host', 'origin', 'referer', 'accept-encoding']}
    clean_headers['Host'] = device['ip']
    
    # Default to standard HTTP
    target_url = f"http://{resolved_ip}/{full_req_path.lstrip('/')}"
    
    try:
        # 1. Attempt standard HTTP request
        resp = requests.request(method=method, url=target_url, headers=clean_headers, data=data, cookies=cookies, allow_redirects=False, stream=True, timeout=10, verify=False)
        
        # 2. Transparent HTTPS Upgrade
        if resp.status_code in [301, 302, 307, 308]:
            loc = resp.headers.get('Location', '')
            if loc.startswith(f"https://{device['ip']}") or loc.startswith(f"https://{resolved_ip}"):
                target_url = f"https://{resolved_ip}/{full_req_path.lstrip('/')}"
                resp = requests.request(method=method, url=target_url, headers=clean_headers, data=data, cookies=cookies, allow_redirects=False, stream=True, timeout=10, verify=False)
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        
        # 3. HTTP Header Rewrite
        for i, (name, value) in enumerate(resp_headers):
            if name.lower() == 'location':
                parsed = urlparse(value)
                if parsed.hostname in [device['ip'], resolved_ip]:
                    new_loc = f"/tunnel/{device_type}/{device_id}{parsed.path}"
                    if parsed.query: new_loc += f"?{parsed.query}"
                    resp_headers[i] = (name, new_loc)
                elif not parsed.hostname and value.startswith('/'):
                    resp_headers[i] = (name, f"/tunnel/{device_type}/{device_id}{value}")

        # 4. Aggressive Deep-Payload IP Scrubbing & Gravity Well
        content_type = resp.headers.get('Content-Type', '').lower()
        if 'text/html' in content_type or 'javascript' in content_type or 'json' in content_type:
            payload = resp.content.decode('utf-8', errors='ignore')
            
            # Scrub absolute protocol wrappers (Includes WebSockets ws:// and wss://)
            payload = re.sub(rf"(https?|wss?)://{re.escape(device['ip'])}(:\d+)?", f"http://{request.host}/tunnel/{device_type}/{device_id}", payload)
            payload = re.sub(rf"(https?|wss?):\\/\\/{re.escape(device['ip'])}(:\d+)?", f"http:\\/\\/{request.host}/tunnel/{device_type}/{device_id}", payload)
            
            # Replace naked IPs dynamically built in JS variables
            payload = re.sub(rf"\b{re.escape(device['ip'])}\b", f"{request.host}/tunnel/{device_type}/{device_id}", payload)
            
            # INJECT BASE TAG: Forces all relative links to stay inside the tunnel automatically
            if 'text/html' in content_type:
                base_tag = f'<base href="/tunnel/{device_type}/{device_id}/">\n'
                payload = re.sub(r'(<head[^>]*>)', rf'\1\n{base_tag}', payload, flags=re.IGNORECASE)
            
            return Response(payload, resp.status_code, resp_headers)
        else:
            # Stream binary data (Video, Images, Firmware files) untouched for max performance
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

# ==========================================
# APPLICATION STARTUP & INITIALIZATION
# ==========================================
def init_logos():
    global LOCAL_COMPANY_LOGO, LOCAL_CUSTOMER_LOGO
    
    logo_dir = '/app/data/logos'
    os.makedirs(logo_dir, exist_ok=True)
    
    def process_logo(env_var, filename):
        val = os.environ.get(env_var, '').strip()
        if not val: return None
        
        filepath = os.path.join(logo_dir, filename)
        serve_path = f"/local_logo/{filename}"
        
        if val.startswith('http://') or val.startswith('https://'):
            try:
                resp = requests.get(val, timeout=5)
                if resp.status_code == 200:
                    with open(filepath, 'wb') as f:
                        f.write(resp.content)
                    return f"{serve_path}?t={int(time.time())}"
            except Exception as e:
                print(f"Notice: Could not fetch fresh {env_var}. Attempting offline fallback. ({e})")
            
            if os.path.exists(filepath):
                return f"{serve_path}?t={int(os.path.getmtime(filepath))}"
            
            return val
            
        return val

    LOCAL_COMPANY_LOGO = process_logo('COMPANY_LOGO_URL', 'company_logo.png')
    LOCAL_CUSTOMER_LOGO = process_logo('CUSTOMER_LOGO_URL', 'customer_logo.png')


# ==========================================
# GUNICORN / FLASK BOOTLOADER
# ==========================================
try:
    init_db()
    init_logos()
    
    os.makedirs('/app/data', exist_ok=True)
    lock_file = '/app/data_ram/monitor.lock'
    if not os.path.exists(lock_file):
        open(lock_file, 'w').close()
        
        # Spawn the completely isolated background workers
        socketio.start_background_task(monitor_loop)
        socketio.start_background_task(sync_db_loop)
        socketio.start_background_task(log_prune_loop)
        
except Exception as e:
    print(f"Startup initialization error: {e}")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
