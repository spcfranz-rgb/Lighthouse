# CRITICAL: Monkey patching must occur before ANY other imports
import struct
import select
import eventlet
eventlet.monkey_patch()
import eventlet.tpool

eventlet.tpool.set_num_threads(100)
import os
import sys
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
import smtplib
import secrets
from contextlib import closing
from email.message import EmailMessage
from datetime import datetime
import eventlet.greenpool
from eventlet.event import Event

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import ipaddress
import paho.mqtt.client as mqtt
import imagehash
from PIL import Image
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from urllib.parse import urlparse, urljoin, urlencode
from functools import wraps

# --- ONVIF Integration ---
from onvif import ONVIFCamera

from flask import Flask, g, has_app_context, request, redirect, url_for, abort, jsonify, Response, send_from_directory, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_socketio import SocketIO
from authlib.integrations.flask_client import OAuth
from cryptography.fernet import Fernet

L7_WORKER_POOL = eventlet.greenpool.GreenPool(size=20)
L7_QUEUE = eventlet.queue.Queue()

app = Flask(__name__, static_folder='static')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# --- SECURITY: CONFIGURATION & HARD-FAIL ---
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    print("CRITICAL: SECRET_KEY environment variable is not set. Aborting.")
    sys.exit(1)
app.secret_key = secret_key

db_key_env = os.environ.get('DB_ENCRYPTION_KEY')
if not db_key_env:
    print("CRITICAL: DB_ENCRYPTION_KEY environment variable is not set. Aborting.")
    sys.exit(1)

csrf = CSRFProtect(app)
app.config['SESSION_COOKIE_HTTPONLY'] = True 
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('REQUIRE_HTTPS', 'False').lower() == 'true'
app.config['SESSION_COOKIE_NAME'] = 'lighthouse_session'

# --- SECURITY: STRICT AIR-GAPPED CSP ---
@app.after_request
def apply_csp(response):
    # CRITICAL FIX: Do not apply strict CSP to tunneled legacy device UI.
    # Legacy hardware relies heavily on inline scripts, framesets, and unsafe-eval.
    if request.path.startswith('/tunnel/'):
        return response

    csp = (
        "default-src 'self'; "
        "script-src 'self'; " 
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob: http: https:; "
        "connect-src 'self' ws: wss:; "
        "media-src 'self' blob:; "
        "object-src 'none';"
    )
    response.headers['Content-Security-Policy'] = csp
    return response

socketio = SocketIO(app, async_mode='eventlet', logger=False, engineio_logger=False)

LOCAL_COMPANY_LOGO = None
LOCAL_CUSTOMER_LOGO = None

def get_cipher():
    key_bytes = db_key_env.encode('utf-8')
    fernet_key = base64.urlsafe_b64encode(hashlib.sha256(key_bytes).digest())
    return Fernet(fernet_key)

def encrypt_pwd(pwd):
    if not pwd: return ''
    return get_cipher().encrypt(pwd.encode('utf-8')).decode('utf-8')

def decrypt_pwd(pwd):
    if not pwd: return ''
    try:
        return get_cipher().decrypt(pwd.encode('utf-8')).decode('utf-8')
    except Exception:
        if pwd.startswith('gAAAAA'):
            print("ERROR: Database decryption failed! Secret Key mismatch.")
            return '' 
        return pwd

# ==========================================
# OPENID CONNECT (OIDC) / MULTI-TENANT SSO
# ==========================================
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

AZURE_TENANT_ID = os.environ.get('AZURE_TENANT_ID')
if AZURE_TENANT_ID:
    oauth.register(
        name='microsoft',
        client_id=os.environ.get('AZURE_CLIENT_ID'),
        client_secret=os.environ.get('AZURE_CLIENT_SECRET'),
        server_metadata_url=f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/v2.0/.well-known/openid-configuration",
        client_kwargs={'scope': 'openid profile email'}
    )

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
if GOOGLE_CLIENT_ID:
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid profile email'}
    )

OKTA_DOMAIN = os.environ.get('OKTA_DOMAIN')
if OKTA_DOMAIN:
    oauth.register(
        name='okta',
        client_id=os.environ.get('OKTA_CLIENT_ID'),
        client_secret=os.environ.get('OKTA_CLIENT_SECRET'),
        server_metadata_url=f"https://{OKTA_DOMAIN.rstrip('/')}/.well-known/openid-configuration",
        client_kwargs={'scope': 'openid profile email groups'}
    )

KEYCLOAK_URL = os.environ.get('KEYCLOAK_URL')
KEYCLOAK_REALM = os.environ.get('KEYCLOAK_REALM')
if KEYCLOAK_URL and KEYCLOAK_REALM:
    oauth.register(
        name='keycloak',
        client_id=os.environ.get('KEYCLOAK_CLIENT_ID'),
        client_secret=os.environ.get('KEYCLOAK_CLIENT_SECRET'),
        server_metadata_url=f"{KEYCLOAK_URL.rstrip('/')}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration",
        client_kwargs={'scope': 'openid profile email'}
    )
# ==========================================
# DATABASE & CONNECTION POOLING
# ==========================================
DB_PATH_DISK = '/app/data/cctv.db'        
DB_PATH_RAM = '/app/data_ram/cctv.db'     
force_check_event = Event()

class RequestDBWrapper:
    """Wraps the SQLite connection to prevent premature closure during a Flask request lifecycle."""
    def __init__(self, conn):
        self._conn = conn
        
    def __getattr__(self, name):
        return getattr(self._conn, name)
        
    def __enter__(self):
        return self._conn.__enter__()
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._conn.__exit__(exc_type, exc_val, exc_tb)
        
    def close(self):
        # Ignore premature closes from `contextlib.closing` in routes
        pass 
        
    def force_close(self):
        # Called only by Flask teardown
        self._conn.close()

def get_db():
    """Returns a request-scoped connection if in a Flask request, otherwise a standalone connection."""
    if has_app_context():
        if 'db' not in g:
            os.makedirs(os.path.dirname(DB_PATH_RAM), exist_ok=True)
            conn = sqlite3.connect(DB_PATH_RAM, check_same_thread=False, timeout=10)
            try: conn.execute("PRAGMA journal_mode=WAL;")
            except sqlite3.OperationalError: pass
            conn.row_factory = sqlite3.Row
            g.db = RequestDBWrapper(conn)
        return g.db
        
    # Fallback for background Eventlet threads (manual close required)
    conn = sqlite3.connect(DB_PATH_RAM, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.force_close()

def log_audit(device_type, device_name, status):
    try:
        conn = get_db()
        conn.execute("INSERT INTO event_logs (timestamp, device_type, device_name, status) VALUES (?, ?, ?, ?)",
                     (time.time(), device_type, device_name, status))
        conn.commit()
        # Clean up ONLY if this was spawned by an Eventlet background thread
        if not has_app_context():
            conn.close() 
    except Exception: pass

# ==========================================
# AUTHENTICATION & GLOBALS 
# ==========================================
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user: return User(user['id'], user['username'], user['role'])
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin': return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def operator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'operator']: return jsonify({'error': 'Operator access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def trigger_monitor_check():
    global force_check_event
    if not force_check_event.ready():
        force_check_event.send(True)

@app.before_request
def manage_idle_timeout():
    if request.endpoint in ['serve_spa', 'serve_local_logo'] or request.path.startswith('/tunnel/'):
        if current_user.is_authenticated:
            session['last_active'] = time.time()
        return 
        
    if current_user.is_authenticated:
        now = time.time()
        last_active = session.get('last_active', now)
        
        conn = get_db()
        idle_row = conn.execute("SELECT value FROM settings WHERE key = 'inactive_timeout'").fetchone()
        idle_mins = int(idle_row['value']) if idle_row else 20
        
        if idle_mins > 0 and (now - last_active) > (idle_mins * 60):
            log_audit('System', current_user.username, 'Auto-logged out (Idle Timeout)')
            logout_user()
            session.pop('last_active', None)
            return jsonify({'error': 'Session expired due to inactivity'}), 401
            
        session['last_active'] = now

# ==========================================
# DATABASE INITIALIZATION
# ==========================================
def init_ram_db():
    os.makedirs(os.path.dirname(DB_PATH_RAM), exist_ok=True)
    os.makedirs(os.path.dirname(DB_PATH_DISK), exist_ok=True)
    if os.path.exists(DB_PATH_DISK) and not os.path.exists(DB_PATH_RAM):
        try:
            disk_conn = sqlite3.connect(DB_PATH_DISK)
            ram_conn = sqlite3.connect(DB_PATH_RAM)
            with ram_conn: disk_conn.backup(ram_conn)
            disk_conn.close()
            ram_conn.close()
        except Exception as e: print(f"Boot restoration failed: {e}")

def init_db():
    try:
        init_ram_db() 
        conn = sqlite3.connect(DB_PATH_RAM, timeout=10)
        cursor = conn.cursor()
        
        cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS switches (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, ip TEXT, status TEXT DEFAULT 'UNKNOWN')")
        cursor.execute("CREATE TABLE IF NOT EXISTS nvrs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, ip TEXT, status TEXT DEFAULT 'UNKNOWN')")
        cursor.execute("CREATE TABLE IF NOT EXISTS cameras (id INTEGER PRIMARY KEY AUTOINCREMENT, switch_id INTEGER, name TEXT UNIQUE, ip TEXT, stream_url TEXT, status TEXT DEFAULT 'UNKNOWN', FOREIGN KEY(switch_id) REFERENCES switches(id))")
        cursor.execute("CREATE TABLE IF NOT EXISTS event_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, device_type TEXT, device_name TEXT, status TEXT)")
        
        try: cursor.execute("ALTER TABLE cameras ADD COLUMN manufacturer TEXT DEFAULT 'Other'")
        except sqlite3.OperationalError: pass
        try: cursor.execute("ALTER TABLE cameras ADD COLUMN username TEXT DEFAULT ''")
        except sqlite3.OperationalError: pass
        try: cursor.execute("ALTER TABLE cameras ADD COLUMN password TEXT DEFAULT ''")
        except sqlite3.OperationalError: pass
        try: cursor.execute("ALTER TABLE switches ADD COLUMN silenced_until REAL DEFAULT 0")
        except sqlite3.OperationalError: pass
        try: cursor.execute("ALTER TABLE nvrs ADD COLUMN silenced_until REAL DEFAULT 0")
        except sqlite3.OperationalError: pass
        try: cursor.execute("ALTER TABLE cameras ADD COLUMN silenced_until REAL DEFAULT 0")
        except sqlite3.OperationalError: pass
        try: cursor.execute("ALTER TABLE switches ADD COLUMN mac_address TEXT DEFAULT ''")
        except sqlite3.OperationalError: pass
        try: cursor.execute("ALTER TABLE nvrs ADD COLUMN mac_address TEXT DEFAULT ''")
        except sqlite3.OperationalError: pass
        try: cursor.execute("ALTER TABLE cameras ADD COLUMN mac_address TEXT DEFAULT ''")
        except sqlite3.OperationalError: pass
        
        cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT)")
        
        cursor.execute("SELECT count(*) FROM settings")
        if cursor.fetchone()[0] == 0:
            settings = [
                ('mqtt_broker', os.environ.get('DEFAULT_MQTT_BROKER', '127.0.0.1')),
                ('mqtt_port', os.environ.get('DEFAULT_MQTT_PORT', '1883')),
                ('mqtt_prefix', os.environ.get('DEFAULT_MQTT_PREFIX', 'zabbix/cctv')),
                ('check_interval', os.environ.get('DEFAULT_CHECK_INTERVAL', '60')),
                ('inactive_timeout', '20'),
                ('smtp_host', ''),     
                ('smtp_port', '587'),  
                ('smtp_user', ''),     
                ('smtp_pass', ''),     
                ('smtp_target', ''),
                ('st_interval', '0'),
                ('st_alert_dl', '0'),
                ('st_alert_ul', '0'),
                ('st_alert_ping', '0')
            ]
            cursor.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", settings)
            
        cursor.execute("SELECT count(*) FROM users")
        if cursor.fetchone()[0] == 0:
            default_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
            default_pass = os.environ.get('DEFAULT_ADMIN_PASS')
            if not default_pass:
                default_pass = secrets.token_urlsafe(16)
                print(f"\n======================================================\n"
                      f"CRITICAL: NO ADMIN_PASS PROVIDED. SECURE FALLBACK USED.\n"
                      f"Temporary Local Username: {default_user}\n"
                      f"Temporary Local Password: {default_pass}\n"
                      f"======================================================\n")
            
            default_hash = generate_password_hash(default_pass)
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')", (default_user, default_hash))
        
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(f"CRITICAL ERROR: Database initialization failed (Check for lingering file locks or zombie containers): {e}")
        raise

def _perform_disk_sync():
    if os.path.exists(DB_PATH_RAM):
        try:
            source = sqlite3.connect(DB_PATH_RAM)
            dest = sqlite3.connect(DB_PATH_DISK)
            dest.execute("PRAGMA journal_mode=DELETE;")
            with dest: 
                source.backup(dest)
            dest.close()
            source.close()
        except Exception as e: 
            print(f"Disk sync failed: {e}")

_disk_sync_timer = None

def force_disk_sync():
    global _disk_sync_timer
    if _disk_sync_timer is not None:
        _disk_sync_timer.cancel()
    
    def _execute_sync():
        global _disk_sync_timer
        _disk_sync_timer = None
        eventlet.tpool.execute(_perform_disk_sync)

    _disk_sync_timer = eventlet.spawn_after(2.0, _execute_sync)

def sync_db_loop():
    while True:
        eventlet.sleep(300) 
        eventlet.tpool.execute(_perform_disk_sync)

def graceful_shutdown(*args):
    _perform_disk_sync()

atexit.register(graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)

def log_prune_loop():
    while True:
        eventlet.sleep(86400) 
        try:
            with closing(sqlite3.connect(DB_PATH_RAM)) as conn:
                seven_days_ago = time.time() - (7 * 24 * 3600)
                conn.execute("DELETE FROM event_logs WHERE timestamp < ?", (seven_days_ago,))
                conn.commit()
            force_disk_sync()
        except Exception: pass

# ==========================================
# BACKGROUND MONITORING & NETWORK TASKS
# ==========================================
SNAPSHOT_SEMAPHORE = eventlet.semaphore.Semaphore(4)
L7_POOL = eventlet.greenpool.GreenPool(size=15)
previous_hashes = {}
mqtt_client = None
mqtt_prefix_global = 'zabbix/cctv'

def get_primary_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None

def get_local_subnet():
    ip = get_primary_ip()
    return f"{ip.rsplit('.', 1)[0]}.0/24" if ip else "192.168.1.0/24"

def is_valid_target(target):
    if not target: return False
    target = str(target).strip()
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    if len(target) > 255: return False
    if target[-1] == ".": target = target[:-1]
    allowed = re.compile(r"(?!-)[A-Z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in target.split("."))

def _icmp_checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def is_pingable(target, timeout=1.5):
    try:
        dest_addr = socket.gethostbyname(target)
    except socket.gaierror:
        return False
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except PermissionError:
        response = eventlet.tpool.execute(subprocess.call, ['ping', '-c', '1', '-W', str(int(timeout)), target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return response == 0
    try:
        my_ID = (os.getpid() ^ threading.get_ident()) & 0xFFFF
        header = struct.pack("bbHHh", 8, 0, 0, my_ID, 1)
        data = struct.pack("d", time.time()) 
        my_checksum = _icmp_checksum(header + data)
        header = struct.pack("bbHHh", 8, 0, socket.htons(my_checksum), my_ID, 1)
        my_socket.sendto(header + data, (dest_addr, 1))
        time_left = timeout
        while True:
            started_select = time.time()
            what_ready = select.select([my_socket], [], [], time_left)
            how_long_in_select = (time.time() - started_select)
            if what_ready[0] == []: return False
            rec_packet, addr = my_socket.recvfrom(1024)
            icmp_header = rec_packet[20:28]
            icmp_type, code, checksum, packet_ID, sequence = struct.unpack("bbHHh", icmp_header)
            if icmp_type == 0 and packet_ID == my_ID: return True
            time_left = time_left - how_long_in_select
            if time_left <= 0: return False
    except Exception: return False
    finally: my_socket.close()

def is_port_open(target, port, timeout=2):
    try:
        with socket.create_connection((target, port), timeout=timeout): return True
    except OSError: return False

def is_stream_active(url):
    cmd = ['ffprobe', '-rtsp_transport', 'tcp', '-v', 'error', '-i', url]
    try:
        result = subprocess.run( 
            cmd, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL, 
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False

def get_mac_address(ip):
    try:
        with open('/proc/net/arp', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac != "00:00:00:00:00:00": return mac.upper()
    except FileNotFoundError: pass
    return None

def get_camlan_arp_table():
    arp_entries = []
    try:
        with open('/proc/net/arp', 'r') as f:
            lines = f.readlines()[1:] 
            for line in lines:
                parts = line.split()
                if len(parts) >= 6:
                    ip, mac, interface = parts[0], parts[3], parts[5]
                    if mac != "00:00:00:00:00:00": arp_entries.append({"ip": ip, "mac": mac.upper(), "interface": interface})
    except FileNotFoundError: pass
    return arp_entries

def _run_ffmpeg_snapshot(stream_url):
    cmd = ['ffmpeg', '-y', '-rtsp_transport', 'tcp', '-i', stream_url, '-vframes', '1', '-f', 'image2pipe', '-vcodec', 'mjpeg', '-']
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        try:
            stdout, _ = proc.communicate(timeout=5)
            if proc.returncode == 0:
                return stdout
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
        except Exception:
            proc.kill()
            proc.communicate()
    return None

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
                    digest_auth = HTTPDigestAuth(user, pwd) if (user and pwd) else None
                    basic_auth = HTTPBasicAuth(user, pwd) if (user and pwd) else None
                    resp = requests.get(url, auth=digest_auth, timeout=3)
                    if resp.status_code == 401 and user and pwd:
                        resp = requests.get(url, auth=basic_auth, timeout=3)
                if resp.status_code == 200 and 'image' in resp.headers.get('Content-Type', ''): return resp.content
            except Exception: pass 
    return eventlet.tpool.execute(_run_ffmpeg_snapshot, stream_url)

# --- STAGE 2: DECOUPLED L7 PROBE ---
def perform_l7_camera_check(cam, cam_silenced, last_hash, check_time):
    global previous_hashes, mqtt_client, mqtt_prefix_global
    cam_id = cam['id']
    cam_name = cam['name']
    auth_url = cam['stream_url']
    pwd = decrypt_pwd(cam['password'])
    
    if cam.get('username') and pwd and '@' not in auth_url and auth_url.startswith('rtsp://'):
        auth_url = f"rtsp://{cam['username']}:{pwd}@{auth_url[7:]}"

    stream_ok = is_stream_active(auth_url)
    snap_bytes = None
    is_frozen = False
    
    if stream_ok:
        with SNAPSHOT_SEMAPHORE:
            snap_bytes = get_snapshot_bytes(cam['ip'], cam['manufacturer'], cam.get('username'), pwd, auth_url)
            
    if stream_ok and snap_bytes:
        try:
            img = Image.open(io.BytesIO(snap_bytes))
            current_hash = imagehash.average_hash(img)
            if last_hash is not None and cam['status'] == 'UP' and (current_hash - last_hash) <= 2: 
                is_frozen = True
            previous_hashes[cam_id] = current_hash
        except Exception: pass
    else: 
        previous_hashes.pop(cam_id, None)

    if cam_silenced:
        if mqtt_client and mqtt_client.is_connected():
            mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/ping", "MAINTENANCE", retain=True)
            mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "MAINTENANCE", retain=True)
        new_status = 'FROZEN (Silenced)' if is_frozen else ('UP (Silenced)' if stream_ok else 'STREAM ERR (Silenced)')
    else:
        if mqtt_client and mqtt_client.is_connected():
            mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/ping", "UP", retain=True)
            mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "FROZEN" if is_frozen else ("UP" if stream_ok else "STREAM_ERROR"), retain=True)
        new_status = 'DOWN (Frozen)' if is_frozen else ('UP' if stream_ok else 'DOWN (Stream Error)')
        
    with closing(get_db()) as conn:
        curr_row = conn.execute("SELECT status FROM cameras WHERE id = ?", (cam_id,)).fetchone()
        curr_status = curr_row['status'] if curr_row else cam['status']
        
        if curr_status != new_status:
            with conn:
                if new_status != 'UNKNOWN':
                    conn.execute("INSERT INTO event_logs (timestamp, device_type, device_name, status) VALUES (?, ?, ?, ?)", (check_time, 'Camera', cam_name, new_status))
                conn.execute("UPDATE cameras SET status = ? WHERE id = ?", (new_status, cam_id))
            
            socketio.emit('state_change', {
                'type': 'cameras', 'id': cam_id, 'name': cam_name,
                'status': new_status, 'device_type': 'Camera', 'timestamp': check_time
            })
            
            if 'DOWN' in new_status or 'ERR' in new_status:
                if not mqtt_client or not mqtt_client.is_connected():
                    send_failover_email(f"FAILOVER ALERT: {cam_name} is {new_status}", f"The Camera '{cam_name}' transitioned to a critical state ({new_status}).\n\nThis alert was routed via SMTP because the primary MQTT connection to Zabbix is currently offline.")

def send_failover_email(subject, body):
    with closing(get_db()) as conn:
        settings = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
        
    if not settings.get('smtp_host') or not settings.get('smtp_target'): return 
    
    def _send(stgs):
        try:
            msg = EmailMessage()
            msg.set_content(body)
            msg['Subject'] = subject
            msg['From'] = stgs.get('smtp_user') or 'lighthouse@edge-gateway'
            msg['To'] = stgs['smtp_target']
            server = smtplib.SMTP(stgs['smtp_host'], int(stgs.get('smtp_port', 587)))
            server.starttls()
            if stgs.get('smtp_user') and stgs.get('smtp_pass'): server.login(stgs['smtp_user'], stgs['smtp_pass'])
            server.send_message(msg)
            server.quit()
            log_audit('System', 'Email Failover', f'Sent email: {subject}')
        except Exception as e:
            log_audit('System', 'Email Failover', f'Failed to send email: {str(e)}')
    eventlet.spawn_n(_send, settings)

def automated_speedtest_loop():
    global mqtt_client, mqtt_prefix_global
    eventlet.sleep(30)
    last_run = 0
    while True:
        eventlet.sleep(60)
        try:
            with closing(get_db()) as conn:
                settings_dict = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
            
            st_interval = float(settings_dict.get('st_interval', 0))
            if st_interval > 0 and (time.time() - last_run) >= (st_interval * 3600):
                last_run = time.time()
                env = os.environ.copy()
                env['HOME'] = '/app/data_ram'
                cmd = ['speedtest', '--accept-license', '--accept-gdpr', '-f', 'json']
                primary_ip = get_primary_ip()
                if primary_ip: cmd.extend(['-i', primary_ip])
                process = eventlet.tpool.execute(subprocess.run, cmd, capture_output=True, text=True, timeout=60, env=env)
                if process.returncode == 0:
                    data = None
                    for line in reversed(process.stdout.splitlines()):
                        line = line.strip()
                        if line.startswith('{') and line.endswith('}'):
                            try: data = json.loads(line); break
                            except Exception: continue
                    if data and 'download' in data:
                        download = round((data['download']['bandwidth'] * 8) / 1000000, 2)
                        upload = round((data['upload']['bandwidth'] * 8) / 1000000, 2)
                        ping = round(data['ping']['latency'], 1)
                        server_string = f"{data.get('server', {}).get('name', 'Unknown')} ({data.get('server', {}).get('location', 'Unknown')})"
                        now = time.time()
                        
                        if mqtt_client and mqtt_client.is_connected():
                            try:
                                mqtt_client.publish(f"{mqtt_prefix_global}/gateway/speedtest_download", str(download), retain=True)
                                mqtt_client.publish(f"{mqtt_prefix_global}/gateway/speedtest_upload", str(upload), retain=True)
                                mqtt_client.publish(f"{mqtt_prefix_global}/gateway/speedtest_ping", str(ping), retain=True)
                            except Exception: pass
                            
                        with closing(get_db()) as conn:
                            log_status = f"DL: {download} Mbps | UL: {upload} Mbps | Ping: {ping} ms"
                            conn.execute("INSERT INTO event_logs (timestamp, device_type, device_name, status) VALUES (?, ?, ?, ?)", (now, 'Gateway', 'Auto-Speedtest', log_status))
                            st_alert_dl = float(settings_dict.get('st_alert_dl', 0))
                            st_alert_ul = float(settings_dict.get('st_alert_ul', 0))
                            st_alert_ping = float(settings_dict.get('st_alert_ping', 0))
                            alerts = []
                            if st_alert_dl > 0 and download < st_alert_dl: alerts.append(f"DL {download} < {st_alert_dl} Mbps")
                            if st_alert_ul > 0 and upload < st_alert_ul: alerts.append(f"UL {upload} < {st_alert_ul} Mbps")
                            if st_alert_ping > 0 and ping > st_alert_ping: alerts.append(f"Ping {ping} > {st_alert_ping} ms")
                            
                            if alerts:
                                alert_text = "WARNING: " + " | ".join(alerts)
                                conn.execute("INSERT INTO event_logs (timestamp, device_type, device_name, status) VALUES (?, ?, ?, ?)", (now, 'Gateway', 'Speedtest Alert', alert_text))
                                if mqtt_client and mqtt_client.is_connected(): mqtt_client.publish(f"{mqtt_prefix_global}/gateway/speedtest_alert", alert_text, retain=True)
                                else: send_failover_email("WAN Auto-Speedtest Alert", f"The automated gateway speed test breached configured thresholds:\n\n{alert_text}\n\nTarget Server: {server_string}")
                            else:
                                if mqtt_client and mqtt_client.is_connected(): mqtt_client.publish(f"{mqtt_prefix_global}/gateway/speedtest_alert", "OK", retain=True)
                                
                            st_data = json.dumps({'download': download, 'upload': upload, 'ping': ping, 'isp': data.get('isp', 'Unknown'), 'server': server_string, 'timestamp': now})
                            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('latest_speedtest', ?)", (st_data,))
                            conn.commit()
                            
                        force_disk_sync()
                        socketio.emit('speedtest_result', {'success': True, 'download': f"{download} Mbps", 'upload': f"{upload} Mbps", 'ping': f"{ping} ms", 'isp': data.get('isp', 'Unknown'), 'server': server_string, 'timestamp': now})
        except Exception as e: print(f"Automated speedtest loop error: {e}")

def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def l7_worker_loop():
    while True:
        try:
            cam, cam_silenced, last_hash, check_time = L7_QUEUE.get()
            L7_WORKER_POOL.spawn_n(
                perform_l7_camera_check, 
                cam, cam_silenced, last_hash, check_time
            )
        except Exception as e:
            print(f"L7 Worker Error: {e}")

def monitor_loop():
    global force_check_event, mqtt_client, mqtt_prefix_global

    while True:
        now = time.time()
        # Capture current ARP state once per loop
        current_arp_map = {entry['mac']: entry['ip'] for entry in get_camlan_arp_table()}
        
        with closing(sqlite3.connect(DB_PATH_RAM, timeout=10)) as conn:
            conn.row_factory = sqlite3.Row
            
            try:
                settings = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
                interval = int(settings.get('check_interval', 60))
                
                switches = [dict(r) for r in conn.execute("SELECT * FROM switches").fetchall()]
                nvrs = [dict(r) for r in conn.execute("SELECT * FROM nvrs").fetchall()]
                cameras = [dict(r) for r in conn.execute("SELECT * FROM cameras").fetchall()]
                
                pending_db_updates = []
                pending_mac_updates = []
                pending_ip_updates = [] # Stores (new_ip, dev_id, table_name)

                probe_pool = eventlet.greenpool.GreenPool(size=100)

                def probe_network_target(dev_type, dev):
                    timeout = 1.5 if is_local_ip(dev['ip']) else 3.0
                    if dev_type == 'camera':
                        return is_pingable(dev['ip'], timeout=1.5) or is_port_open(dev['ip'], 554, timeout=1.5) or is_port_open(dev['ip'], 80, timeout=1.5)
                    elif dev_type == 'switch':
                        return is_pingable(dev['ip'], timeout=timeout) or is_port_open(dev['ip'], 80, timeout=timeout)
                    else:
                        return is_pingable(dev['ip'], timeout=1.5) or is_port_open(dev['ip'], 80, timeout=1.5)

                switch_status = list(probe_pool.imap(lambda d: probe_network_target('switch', d), switches))
                nvr_status = list(probe_pool.imap(lambda d: probe_network_target('nvr', d), nvrs))
                camera_status = list(probe_pool.imap(lambda d: probe_network_target('camera', d), cameras))

                # Process Switches
                for i, switch in enumerate(switches):
                    # Drift detection
                    if switch.get('mac_address') and switch['mac_address'] in current_arp_map:
                        if current_arp_map[switch['mac_address']] != switch['ip']:
                            pending_ip_updates.append((current_arp_map[switch['mac_address']], switch['id'], 'switches'))
                            switch['ip'] = current_arp_map[switch['mac_address']]
                    
                    is_up = switch_status[i]
                    mac = switch.get('mac_address') or ''
                    if is_up and not mac and is_local_ip(switch['ip']):
                        fetched_mac = get_mac_address(switch['ip'])
                        if fetched_mac: pending_mac_updates.append(('switches', fetched_mac.upper(), switch['id']))
        
                    new_status = 'UP' if is_up else 'DOWN'
                    if switch.get('silenced_until', 0) > now: new_status += " (Silenced)"
                    if switch['status'] != new_status:
                        pending_db_updates.append((now, 'Switch', switch['name'], new_status, 'switches', switch['id']))
                    if mqtt_client and mqtt_client.is_connected(): mqtt_client.publish(f"{mqtt_prefix_global}/{switch['name']}/ping", new_status, retain=True)

                # Process NVRs
                for i, nvr in enumerate(nvrs):
                    # Drift detection
                    if nvr.get('mac_address') and nvr['mac_address'] in current_arp_map:
                        if current_arp_map[nvr['mac_address']] != nvr['ip']:
                            pending_ip_updates.append((current_arp_map[nvr['mac_address']], nvr['id'], 'nvrs'))
                            nvr['ip'] = current_arp_map[nvr['mac_address']]

                    is_up = nvr_status[i]
                    new_status = 'UP' if is_up else 'DOWN'
                    if nvr.get('silenced_until', 0) > now: new_status += " (Silenced)"
                    if nvr['status'] != new_status:
                        pending_db_updates.append((now, 'NVR', nvr['name'], new_status, 'nvrs', nvr['id']))
                    if mqtt_client and mqtt_client.is_connected(): mqtt_client.publish(f"{mqtt_prefix_global}/{nvr['name']}/ping", new_status, retain=True)

                # Process Cameras
                for i, cam in enumerate(cameras):
                    # --- ADDED: Auto-populate missing MAC addresses ---
                    mac = cam.get('mac_address') or ''
                    if not mac and is_local_ip(cam['ip']):
                        fetched_mac = get_mac_address(cam['ip'])
                        if fetched_mac: 
                            pending_mac_updates.append(('cameras', fetched_mac.upper(), cam['id']))
                    # Drift detection
                    if cam.get('mac_address') and cam['mac_address'] in current_arp_map:
                        if current_arp_map[cam['mac_address']] != cam['ip']:
                            pending_ip_updates.append((current_arp_map[cam['mac_address']], cam['id'], 'cameras'))
                            cam['ip'] = current_arp_map[cam['mac_address']]

                    if camera_status[i]:
                        L7_QUEUE.put((cam, cam.get('silenced_until', 0) > now, previous_hashes.get(cam['id']), now))
                        new_status = cam['status'] 
                    else:
                        new_status = 'DOWN (Offline)'
                        if cam.get('silenced_until', 0) > now: new_status = 'DOWN (Silenced)'

                    if cam['status'] != new_status:
                        pending_db_updates.append((now, 'Camera', cam['name'], new_status, 'cameras', cam['id']))

                # Apply Database Updates
                with conn:
                    # Execute IP drifts
                    for (new_ip, item_id, table) in pending_ip_updates:
                        conn.execute(f"UPDATE {table} SET ip = ? WHERE id = ?", (new_ip, item_id))
                    
                    # Update logs and status
                    for (t_stamp, dev_type, item_name, new_status, table, item_id) in pending_db_updates:
                        conn.execute("INSERT INTO event_logs (timestamp, device_type, device_name, status) VALUES (?, ?, ?, ?)", (t_stamp, dev_type, item_name, new_status))
                        conn.execute(f"UPDATE {table} SET status = ? WHERE id = ?", (new_status, item_id))
                    
                    # Update missing MAC addresses
                    for (table, mac, item_id) in pending_mac_updates:
                        conn.execute(f"UPDATE {table} SET mac_address = ? WHERE id = ?", (mac, item_id))
                    
                    # UI Notifications
                    for update in pending_db_updates:
                        socketio.emit('state_change', {'type': update[4], 'id': update[5], 'status': update[3]})

            except Exception as e:
                print(f"Monitor loop iteration failed: {e}")

        try:
            with eventlet.Timeout(interval): force_check_event.wait()
        except eventlet.Timeout:
            force_check_event = Event()

# ==========================================
# WEBRTC (MEDIAMTX) INTEGRATION
# ==========================================
MEDIAMTX_API = "http://127.0.0.1:9997/v3/config/paths"

def sync_mediamtx_cameras():
    try:
        with closing(get_db()) as conn:
            cameras = conn.execute("SELECT id, stream_url, username, password FROM cameras").fetchall()
            
        resp = requests.get(MEDIAMTX_API, timeout=3)
        current_paths = resp.json().get('items', {}) if resp.status_code == 200 else {}
        configured_cam_ids = set()
        for cam in cameras:
            cam_id = f"cam_{cam['id']}"
            configured_cam_ids.add(cam_id)
            auth_url = cam['stream_url']
            pwd = decrypt_pwd(cam['password'])
            if cam['username'] and pwd and '@' not in auth_url and auth_url.startswith('rtsp://'):
                auth_url = f"rtsp://{cam['username']}:{pwd}@{auth_url[7:]}"
            payload = {"source": auth_url, "sourceOnDemand": True, "runOnDemandCloseAfter": "10s"}
            if cam_id not in current_paths: requests.post(f"{MEDIAMTX_API}/{cam_id}", json=payload, timeout=3)
            elif current_paths[cam_id].get('source') != auth_url: requests.patch(f"{MEDIAMTX_API}/{cam_id}", json=payload, timeout=3)
        for path_name in current_paths:
            if path_name.startswith("cam_") and path_name not in configured_cam_ids:
                requests.delete(f"{MEDIAMTX_API}/{path_name}", timeout=3)
    except Exception as e: print(f"MediaMTX Sync Error: {e}")

@app.route('/api/webrtc/<int:cam_id>/whep', methods=['POST'])
@login_required
@operator_required
def webrtc_whep(cam_id):
    try:
        sdp_offer = request.data
        if not sdp_offer: return jsonify({'error': "Missing SDP offer"}), 400
        resp = requests.post(
            f"http://127.0.0.1:8189/cam_{cam_id}/whep", 
            data=sdp_offer,
            headers={"Content-Type": "application/sdp"},
            timeout=5
        )
        if resp.status_code == 201: return Response(resp.content, mimetype='application/sdp')
        else: return jsonify({'error': f"MediaMTX rejected offer: {resp.text}"}), 502
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"WebRTC Relay Offline: {str(e)}"}), 502

def probe_onvif_camera(ip, user, pwd):
    for port in [80, 8080, 8899]:
        try:
            cam = ONVIFCamera(ip, port, user, pwd)
            dev_info = cam.devicemgmt.GetDeviceInformation()
            make = getattr(dev_info, 'Manufacturer', 'Unknown')
            model = getattr(dev_info, 'Model', '')
            mac = None
            try:
                net_info = cam.devicemgmt.GetNetworkInterfaces()
                if net_info and len(net_info) > 0: mac = net_info[0].Info.HwAddress.upper()
            except Exception: pass
            stream_url = None
            try:
                media_service = cam.create_media_service()
                profiles = media_service.GetProfiles()
                if profiles:
                    req = media_service.create_type('GetStreamUri')
                    req.ProfileToken = profiles[0].token
                    req.StreamSetup = {'Stream': 'RTP-Unicast', 'Transport': {'Protocol': 'RTSP'}}
                    res = media_service.GetStreamUri(req)
                    stream_url = res.Uri
            except Exception: pass
            return {"success": True, "make": make, "model": model, "mac": mac, "stream_url": stream_url}
        except Exception: continue
    return {"success": False, "error": "ONVIF negotiation failed on all standard ports."}

# ==========================================
# FLASK SPA & JSON API ROUTES
# ==========================================

@app.route('/api/v1/devices/refresh_mac', methods=['POST'])
@login_required
@admin_required
def refresh_mac():
    data = request.get_json()
    device_type = data.get('type') # 'switches', 'nvrs', or 'cameras'
    device_id = data.get('id')
    
    if device_type not in ['switches', 'nvrs', 'cameras']:
        return jsonify({'success': False, 'message': 'Invalid device type'}), 400

    with closing(get_db()) as conn:
        device = conn.execute(f"SELECT ip FROM {device_type} WHERE id = ?", (device_id,)).fetchone()
    
    if not device: return jsonify({'success': False, 'message': 'Device not found'}), 404
    
    # Force ARP entry creation via quick UDP probe
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.sendto(b'\x00', (device['ip'], 53535))
        s.close()
        eventlet.sleep(0.5) # Wait briefly for ARP reply
    except Exception: pass
    
    mac = get_mac_address(device['ip'])
    
    if mac:
        with closing(get_db()) as conn:
            conn.execute(f"UPDATE {device_type} SET mac_address = ? WHERE id = ?", (mac, device_id))
            conn.commit()
        force_disk_sync()
        return jsonify({'success': True, 'mac': mac})
    
    return jsonify({'success': False, 'message': 'Could not resolve MAC. Device might be offline.'})

@app.route('/api/v1/history', methods=['GET'])
@login_required
def api_get_history():
    """Fetches the latest 500 system event logs for the frontend."""
    try:
        with closing(get_db()) as conn:
            logs = conn.execute(
                "SELECT * FROM event_logs ORDER BY timestamp DESC LIMIT 500"
            ).fetchall()
            
        return jsonify([dict(row) for row in logs])
    except Exception as e:
        return jsonify({'error': f"Failed to fetch logs: {str(e)}"}), 500

@app.route('/api/v1/system/export', methods=['GET'])
@login_required
@admin_required
def export_config():
    devices = []
    with closing(get_db()) as conn:
        for table in ['switches', 'nvrs', 'cameras']:
            for row in conn.execute(f"SELECT *, '{table}' as dev_type FROM {table}").fetchall():
                d = dict(row)
                d.pop('status', None)
                devices.append(d)
                
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=['dev_type', 'id', 'name', 'ip', 'switch_id', 'stream_url', 'manufacturer', 'username', 'password', 'silenced_until', 'mac_address'])
    cw.writeheader()
    cw.writerows(devices)
    return Response(si.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=lighthouse_config.csv'})

@app.route('/api/v1/system/import/analyze', methods=['POST'])
@login_required
@admin_required
def import_analyze():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded.'}), 400
    try:
        file_stream = request.files['file'].stream.read().decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(file_stream))
        imported_devices = [row for row in reader]
        if not imported_devices:
            return jsonify({'success': False, 'message': 'CSV appears empty or malformed.'}), 400
            
        with closing(get_db()) as conn:
            existing_switches = {row['id']: dict(row) for row in conn.execute("SELECT * FROM switches").fetchall()}
            existing_nvrs = {row['id']: dict(row) for row in conn.execute("SELECT * FROM nvrs").fetchall()}
            existing_cameras = {row['id']: dict(row) for row in conn.execute("SELECT * FROM cameras").fetchall()}
            
        analysis = {'conflicts': [], 'clean_inserts': []}
        for row in imported_devices:
            dev_type = row.get('dev_type')
            try: dev_id = int(row.get('id', 0))
            except ValueError: continue
            if not dev_type or not dev_id: continue
            exists = False
            existing_data = None
            if dev_type == 'switch' and dev_id in existing_switches:
                exists = True
                existing_data = existing_switches[dev_id]
            elif dev_type == 'nvr' and dev_id in existing_nvrs:
                exists = True
                existing_data = existing_nvrs[dev_id]
            elif dev_type == 'camera' and dev_id in existing_cameras:
                exists = True
                existing_data = existing_cameras[dev_id]
            if exists:
                analysis['conflicts'].append({'type': dev_type, 'id': dev_id, 'name': row.get('name', 'Unknown'), 'incoming': row, 'existing': existing_data})
            else:
                analysis['clean_inserts'].append({'type': dev_type, 'data': row})
        return jsonify({'success': True, 'analysis': analysis})
    except Exception as e:
        return jsonify({'success': False, 'message': f"Parse error: {str(e)}"}), 500

@app.route('/api/v1/system/import/apply', methods=['POST'])
@login_required
@admin_required
def import_apply():
    payload = request.get_json()
    resolved_conflicts = payload.get('resolved_conflicts', [])
    clean_inserts = payload.get('clean_inserts', [])
    
    try:
        with closing(get_db()) as conn:
            with conn:
                def cast_device(dev):
                    return {
                        "id": int(dev['id']),
                        "name": dev['name'],
                        "ip": dev['ip'],
                        "switch_id": int(dev['switch_id']) if dev.get('switch_id') else None,
                        "stream_url": dev.get('stream_url', ''),
                        "manufacturer": dev.get('manufacturer', 'Other'),
                        "username": dev.get('username', ''),
                        "password": dev.get('password', ''),
                        "silenced_until": float(dev.get('silenced_until', 0)) if dev.get('silenced_until') else 0,
                        "mac_address": dev.get('mac_address', '')
                    }
                for item in clean_inserts:
                    dev = cast_device(item['data'])
                    if item['type'] == 'switch':
                        conn.execute("INSERT INTO switches (id, name, ip, silenced_until, mac_address) VALUES (?, ?, ?, ?, ?)", 
                                     (dev['id'], dev['name'], dev['ip'], dev['silenced_until'], dev['mac_address']))
                    elif item['type'] == 'nvr':
                        conn.execute("INSERT INTO nvrs (id, name, ip, silenced_until, mac_address) VALUES (?, ?, ?, ?, ?)", 
                                     (dev['id'], dev['name'], dev['ip'], dev['silenced_until'], dev['mac_address']))
                    elif item['type'] == 'camera':
                        pwd = encrypt_pwd(dev['password']) if dev['password'] else ''
                        conn.execute("INSERT INTO cameras (id, switch_id, name, ip, stream_url, manufacturer, username, password, silenced_until, mac_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                     (dev['id'], dev['switch_id'], dev['name'], dev['ip'], dev['stream_url'], dev['manufacturer'], dev['username'], pwd, dev['silenced_until'], dev['mac_address']))
                for item in resolved_conflicts:
                    dev = cast_device(item['data'])
                    if item['type'] == 'switch':
                        conn.execute("UPDATE switches SET name=?, ip=?, silenced_until=?, mac_address=? WHERE id=?", 
                                     (dev['name'], dev['ip'], dev['silenced_until'], dev['mac_address'], dev['id']))
                    elif item['type'] == 'nvr':
                        conn.execute("UPDATE nvrs SET name=?, ip=?, silenced_until=?, mac_address=? WHERE id=?", 
                                     (dev['name'], dev['ip'], dev['silenced_until'], dev['mac_address'], dev['id']))
                    elif item['type'] == 'camera':
                        pwd = encrypt_pwd(dev['password']) if dev['password'] else ''
                        if pwd:
                            conn.execute("UPDATE cameras SET switch_id=?, name=?, ip=?, stream_url=?, manufacturer=?, username=?, password=?, silenced_until=?, mac_address=? WHERE id=?", 
                                         (dev['switch_id'], dev['name'], dev['ip'], dev['stream_url'], dev['manufacturer'], dev['username'], pwd, dev['silenced_until'], dev['mac_address'], dev['id']))
                        else:
                            conn.execute("UPDATE cameras SET switch_id=?, name=?, ip=?, stream_url=?, manufacturer=?, username=?, silenced_until=?, mac_address=? WHERE id=?", 
                                         (dev['switch_id'], dev['name'], dev['ip'], dev['stream_url'], dev['manufacturer'], dev['username'], dev['silenced_until'], dev['mac_address'], dev['id']))
        force_disk_sync()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': f"Merge failed: {str(e)}"}), 500

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_spa(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    referer = request.headers.get('Referer')
    if referer:
        parsed_referer = urlparse(referer)
        parts = parsed_referer.path.split('/')
        if len(parts) >= 4 and parts[1] == 'tunnel':
            if current_user.is_authenticated and current_user.role in ['admin', 'operator']:
                return tunnel(parts[2], parts[3], '/' + path)
    return send_from_directory(app.static_folder, 'index.html')
    
@app.route('/api/v1/auth/status', methods=['GET'])
def auth_status():
    token = generate_csrf()
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True, 
            'user': {'id': current_user.id, 'username': current_user.username, 'role': current_user.role},
            'csrf_token': token
        })
    return jsonify({'authenticated': False, 'csrf_token': token}), 401

@app.route('/api/v1/auth/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    with closing(get_db()) as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
    if user and check_password_hash(user['password'], password):
        login_user(User(user['id'], user['username'], user['role']))
        log_audit('System', username, 'User Logged In (Local API)')
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

@app.route('/login/sso/<provider>')
def login_sso(provider):
    client = oauth.create_client(provider)
    if not client: return redirect('/login?fallback=true')
    try: return client.authorize_redirect(url_for('auth_callback', provider=provider, _external=True))
    except Exception:
        log_audit('System', 'SSO Failover', f'{provider.capitalize()} SSO Server Unreachable')
        return redirect('/login?fallback=true')

@app.route('/auth/callback/<provider>')
def auth_callback(provider):
    client = oauth.create_client(provider)
    if not client: return redirect('/login?fallback=true')
    try:
        token = client.authorize_access_token()
        user_info = client.parse_id_token(token)
    except Exception: return redirect('/login?fallback=true')
    username = user_info.get('preferred_username') or user_info.get('upn') or user_info.get('name') or user_info.get('email')
    role = 'user' 
    if provider == 'authentik':
        groups = user_info.get('groups', [])
        if 'cctv-admins' in groups: role = 'admin'
        elif 'cctv-operators' in groups: role = 'operator'
    elif provider == 'microsoft':
        roles = user_info.get('roles', [])
        if 'Admin' in roles: role = 'admin'
        elif 'Operator' in roles: role = 'operator'
    elif provider == 'okta':
        groups = user_info.get('groups', [])
        if 'cctv-admins' in groups: role = 'admin'
        elif 'cctv-operators' in groups: role = 'operator'
    elif provider == 'keycloak':
        realm_access = user_info.get('realm_access', {})
        roles = realm_access.get('roles', [])
        if 'cctv-admin' in roles: role = 'admin'
        elif 'cctv-operator' in roles: role = 'operator'
    elif provider == 'google' and username and username.endswith('@yourcompany.com'):
        role = 'operator' 
        
    with closing(get_db()) as conn:
        db_user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not db_user:
            cursor = conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, f'SSO_{provider.upper()}', role))
            user_id = cursor.lastrowid
        else:
            user_id = db_user['id']
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()
        
    force_disk_sync()
    login_user(User(user_id, username, role))
    log_audit('System', username, f'User Logged In ({provider.capitalize()} SSO)')
    return redirect('/')

@app.route('/api/v1/auth/logout', methods=['POST'])
@login_required
def api_logout():
    log_audit('System', current_user.username, 'User Logged Out')
    logout_user()
    session.pop('last_active', None)
    return jsonify({'success': True})

@app.route('/api/v1/system/init', methods=['GET'])
@login_required
def api_system_init():
    now = time.time()
    with closing(get_db()) as conn:
        switches = conn.execute("SELECT *, (IFNULL(silenced_until, 0) > ?) as is_silenced FROM switches", (now,)).fetchall()
        nvrs = conn.execute("SELECT *, (IFNULL(silenced_until, 0) > ?) as is_silenced FROM nvrs", (now,)).fetchall()
        cameras = conn.execute("""
            SELECT c.*, s.name as switch_name, 
                   ((IFNULL(c.silenced_until, 0) > ?) OR (IFNULL(s.silenced_until, 0) > ?)) as is_silenced 
            FROM cameras c LEFT JOIN switches s ON c.switch_id = s.id
        """, (now, now)).fetchall()
        settings_dict = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
        users = conn.execute("SELECT id, username, role FROM users").fetchall()
        
    latest_speedtest = None
    if 'latest_speedtest' in settings_dict:
        try: latest_speedtest = json.loads(settings_dict['latest_speedtest'])
        except Exception: pass
    client_accessed_host = request.host.split(':')[0]
    webrtc_config = {
        'iceServers': [
            {'urls': f"stun:{client_accessed_host}:3478"},
            {'urls': f"turn:{client_accessed_host}:3478", 'username': 'lighthouse', 'credential': 'lighthouse_webrtc'}
        ]
    }
    return jsonify({
        'switches': [dict(s) for s in switches],
        'nvrs': [dict(n) for n in nvrs],
        'cameras': [dict(c) for c in cameras],
        'settings': settings_dict,
        'users': [dict(u) for u in users],
        'default_subnet': get_local_subnet(),
        'latest_speedtest': latest_speedtest,
        'logos': { 'company': LOCAL_COMPANY_LOGO, 'customer': LOCAL_CUSTOMER_LOGO },
        'webrtc_config': webrtc_config 
    })

@app.route('/api/v1/switches', methods=['POST'])
@login_required
@admin_required
def add_switch():
    data = request.get_json()
    name = data.get('name')
    try:
        with closing(get_db()) as conn:
            conn.execute("INSERT INTO switches (name, ip) VALUES (?, ?)", (name, data.get('ip')))
            conn.commit()
        log_audit('User', current_user.username, f'Added new switch: {name}')
        force_disk_sync()
        trigger_monitor_check()
        return jsonify({'success': True, 'message': 'Switch added.'})
    except sqlite3.IntegrityError: return jsonify({'success': False, 'message': 'Switch name already exists.'}), 400

@app.route('/api/v1/switches/<int:id>', methods=['PUT', 'DELETE'])
@login_required
@admin_required
def edit_delete_switch(id):
    if request.method == 'PUT':
        data = request.get_json()
        name = data.get('name')
        try:
            with closing(get_db()) as conn:
                conn.execute("UPDATE switches SET name = ?, ip = ? WHERE id = ?", (name, data.get('ip'), id))
                conn.commit()
            log_audit('User', current_user.username, f'Edited switch config: {name}')
            force_disk_sync()
            trigger_monitor_check()
            return jsonify({'success': True, 'message': 'Switch updated.'})
        except sqlite3.IntegrityError: return jsonify({'success': False, 'message': 'Name exists.'}), 400
    elif request.method == 'DELETE':
        with closing(get_db()) as conn:
            row = conn.execute("SELECT name FROM switches WHERE id = ?", (id,)).fetchone()
            name = row['name'] if row else "Unknown"
            conn.execute("DELETE FROM cameras WHERE switch_id = ?", (id,))
            conn.execute("DELETE FROM switches WHERE id = ?", (id,))
            conn.commit()
        log_audit('User', current_user.username, f'Deleted switch: {name}')
        force_disk_sync()
        trigger_monitor_check()
        return jsonify({'success': True, 'message': 'Switch deleted.'})

@app.route('/api/v1/nvrs', methods=['POST'])
@login_required
@admin_required
def add_nvr():
    data = request.get_json()
    if not is_local_ip(data.get('ip')):
        return jsonify({'success': False, 'message': 'NVRs must use local LAN IP addresses.'}), 400
        
    name = data.get('name')
    try:
        with closing(get_db()) as conn:
            conn.execute("INSERT INTO nvrs (name, ip) VALUES (?, ?)", (name, data.get('ip')))
            conn.commit()
        log_audit('User', current_user.username, f'Added new NVR: {name}')
        force_disk_sync()
        trigger_monitor_check()
        return jsonify({'success': True, 'message': 'NVR added.'})
    except sqlite3.IntegrityError: return jsonify({'success': False, 'message': 'NVR name already exists.'}), 400

@app.route('/api/v1/nvrs/<int:id>', methods=['PUT', 'DELETE'])
@login_required
@admin_required
def edit_delete_nvr(id):
    if request.method == 'PUT':
        data = request.get_json()
        if not is_local_ip(data.get('ip')):
            return jsonify({'success': False, 'message': 'NVRs must use local LAN IP addresses.'}), 400
            
        name = data.get('name')
        try:
            with closing(get_db()) as conn:
                conn.execute("UPDATE nvrs SET name = ?, ip = ? WHERE id = ?", (name, data.get('ip'), id))
                conn.commit()
            log_audit('User', current_user.username, f'Edited NVR config: {name}')
            force_disk_sync()
            trigger_monitor_check()
            return jsonify({'success': True, 'message': 'NVR updated.'})
        except sqlite3.IntegrityError: return jsonify({'success': False, 'message': 'Name exists.'}), 400
    elif request.method == 'DELETE':
        with closing(get_db()) as conn:
            row = conn.execute("SELECT name FROM nvrs WHERE id = ?", (id,)).fetchone()
            name = row['name'] if row else "Unknown"
            conn.execute("DELETE FROM nvrs WHERE id = ?", (id,))
            conn.commit()
        log_audit('User', current_user.username, f'Deleted NVR: {name}')
        force_disk_sync()
        trigger_monitor_check()
        return jsonify({'success': True, 'message': 'NVR deleted.'})

@app.route('/api/v1/cameras', methods=['POST'])
@login_required
@admin_required
def add_camera():
    data = request.get_json()
    if not is_local_ip(data.get('ip')):
        return jsonify({'success': False, 'message': 'Cameras must use local LAN IP addresses.'}), 400
        
    switch_id = data.get('switch_id') or None
    name = data.get('name')
    try:
        with closing(get_db()) as conn:
            conn.execute("""INSERT INTO cameras (switch_id, name, ip, stream_url, manufacturer, username, password) VALUES (?, ?, ?, ?, ?, ?, ?)""", 
                         (switch_id, name, data.get('ip'), data.get('stream_url'), data.get('manufacturer', 'Other'), data.get('username', ''), encrypt_pwd(data.get('password', ''))))
            conn.commit()
        eventlet.spawn_n(sync_mediamtx_cameras)
        log_audit('User', current_user.username, f'Added new camera: {name}')
        force_disk_sync()
        trigger_monitor_check()
        return jsonify({'success': True, 'message': 'Camera added.'})
    except sqlite3.IntegrityError: return jsonify({'success': False, 'message': 'Camera name already exists.'}), 400

@app.route('/api/v1/cameras/<int:id>', methods=['PUT', 'DELETE'])
@login_required
@admin_required
def edit_delete_camera(id):
    if request.method == 'PUT':
        data = request.get_json()
        if not is_local_ip(data.get('ip')):
            return jsonify({'success': False, 'message': 'Cameras must use local LAN IP addresses.'}), 400
            
        switch_id = data.get('switch_id') or None 
        name = data.get('name')
        try:
            with closing(get_db()) as conn:
                pwd_update = data.get('password', '').strip()
                if pwd_update:
                    conn.execute("""UPDATE cameras SET switch_id = ?, name = ?, ip = ?, stream_url = ?, manufacturer = ?, username = ?, password = ? WHERE id = ?""", 
                                 (switch_id, name, data.get('ip'), data.get('stream_url'), data.get('manufacturer', 'Other'), data.get('username', ''), encrypt_pwd(pwd_update), id))
                else:
                    conn.execute("""UPDATE cameras SET switch_id = ?, name = ?, ip = ?, stream_url = ?, manufacturer = ?, username = ? WHERE id = ?""", 
                                 (switch_id, name, data.get('ip'), data.get('stream_url'), data.get('manufacturer', 'Other'), data.get('username', ''), id))
                conn.commit()
            eventlet.spawn_n(sync_mediamtx_cameras)
            log_audit('User', current_user.username, f'Edited camera config: {name}')
            force_disk_sync()
            trigger_monitor_check()
            return jsonify({'success': True, 'message': 'Camera updated.'})
        except sqlite3.IntegrityError: return jsonify({'success': False, 'message': 'Name exists.'}), 400
    elif request.method == 'DELETE':
        with closing(get_db()) as conn:
            row = conn.execute("SELECT name FROM cameras WHERE id = ?", (id,)).fetchone()
            name = row['name'] if row else "Unknown"
            conn.execute("DELETE FROM cameras WHERE id = ?", (id,))
            conn.commit()
        eventlet.spawn_n(sync_mediamtx_cameras)
        log_audit('User', current_user.username, f'Deleted camera: {name}')
        force_disk_sync()
        trigger_monitor_check()
        return jsonify({'success': True, 'message': 'Camera deleted.'})

@app.route('/api/v1/users', methods=['POST'])
@login_required
@admin_required
def api_add_user():
    data = request.get_json()
    username = data.get('username')
    password = generate_password_hash(data.get('password'))
    role = data.get('role')
    try:
        with closing(get_db()) as conn:
            conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
            conn.commit()
        log_audit('User', current_user.username, f'Provisioned new account for: {username}')
        force_disk_sync()
        return jsonify({'success': True, 'message': 'User added.'})
    except sqlite3.IntegrityError: return jsonify({'success': False, 'message': 'Username exists.'}), 400

@app.route('/api/v1/users/<int:id>', methods=['DELETE'])
@login_required
@admin_required
def api_delete_user(id):
    if id == current_user.id: return jsonify({'success': False, 'message': 'Cannot delete yourself.'}), 400
    with closing(get_db()) as conn:
        row = conn.execute("SELECT username FROM users WHERE id = ?", (id,)).fetchone()
        uname = row['username'] if row else "Unknown"
        conn.execute("DELETE FROM users WHERE id = ?", (id,))
        conn.commit()
    log_audit('User', current_user.username, f'Deleted account: {uname}')
    force_disk_sync()
    return jsonify({'success': True, 'message': 'User deleted.'})

@app.route('/api/v1/settings', methods=['PUT'])
@login_required
@admin_required
def api_update_settings():
    data = request.get_json()
    with closing(get_db()) as conn:
        for key, val in data.items():
            if key in ['mqtt_broker', 'mqtt_port', 'mqtt_prefix', 'check_interval', 'inactive_timeout', 'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'smtp_target', 'st_interval', 'st_alert_dl', 'st_alert_ul', 'st_alert_ping']:
                conn.execute("UPDATE settings SET value = ? WHERE key = ?", (str(val), key))
        conn.commit()
    log_audit('User', current_user.username, 'Updated Global Gateway Settings') 
    force_disk_sync()
    trigger_monitor_check()
    return jsonify({'success': True, 'message': 'Settings updated.'})

@app.route('/api/v1/devices/silence', methods=['POST'])
@login_required
@operator_required
def api_toggle_silence():
    data = request.get_json()
    device_type = data.get('type')
    dev_id = data.get('id')
    hours = float(data.get('hours', 0))
    silence_until = time.time() + (hours * 3600) if hours > 0 else 0
    device_name = "Unknown"
    table_name = ""
    with closing(get_db()) as conn:
        if device_type == 'switch':
            table_name = "switches"
            conn.execute("UPDATE switches SET silenced_until = ? WHERE id = ?", (silence_until, dev_id))
            row = conn.execute("SELECT name FROM switches WHERE id = ?", (dev_id,)).fetchone()
            if row: device_name = row['name']
        elif device_type == 'nvr':
            table_name = "nvrs"
            conn.execute("UPDATE nvrs SET silenced_until = ? WHERE id = ?", (silence_until, dev_id))
            row = conn.execute("SELECT name FROM nvrs WHERE id = ?", (dev_id,)).fetchone()
            if row: device_name = row['name']
        elif device_type == 'camera':
            table_name = "cameras"
            conn.execute("UPDATE cameras SET silenced_until = ? WHERE id = ?", (silence_until, dev_id))
            row = conn.execute("SELECT name FROM cameras WHERE id = ?", (dev_id,)).fetchone()
            if row: device_name = row['name']
        conn.commit()
        
    if hours == 0:
        socketio.emit('state_change', {
            'type': table_name, 'id': dev_id, 'name': device_name,
            'status': 'EVALUATING...', 'device_type': device_type.capitalize(), 'timestamp': time.time()
        })
    action_text = f"Silenced {device_type} '{device_name}' for {hours}h" if hours > 0 else f"Removed silence from {device_type} '{device_name}'"
    log_audit('User', current_user.username, action_text)
    force_disk_sync()
    trigger_monitor_check()
    return jsonify({'success': True})

@app.route('/api/network/arp', methods=['GET'])
@login_required
@operator_required
def fetch_arp_table():
    log_audit('User', current_user.username, 'Initiated Active L2 ARP sweep')
    try:
        subnet = get_local_subnet()
        network = ipaddress.ip_network(subnet, strict=False)
        def force_arp_resolution(ip_str):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setblocking(False)
                s.sendto(b'\x00', (ip_str, 53535))
                s.close()
            except Exception: pass
        hosts = [str(ip) for ip in network.hosts()]
        pool = eventlet.greenpool.GreenPool(size=254)
        for _ in pool.imap(force_arp_resolution, hosts): pass 
        eventlet.sleep(0.5)
        devices = get_camlan_arp_table()
        return jsonify({"status": "success", "count": len(devices), "interface_scanned": "Physical Host Interfaces", "devices": devices}), 200
    except Exception as e: return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/scan_network', methods=['POST'])
@login_required
@admin_required
def scan_network():
    data = request.get_json()
    subnet = data.get('subnet')
    if not subnet: return jsonify({'success': False, 'error': 'No subnet provided.'})
    try: network = ipaddress.ip_network(subnet, strict=False)
    except ValueError: return jsonify({'success': False, 'error': 'Invalid subnet format.'})
    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > 1024: return jsonify({'success': False, 'error': 'Subnet too large. Please scan a /22 or smaller.'})
    log_audit('User', current_user.username, f'Initiated network subnet scan on {subnet}')
    def check_rtsp_port(ip):
        try:
            with socket.create_connection((ip, 554), timeout=1.5): return ip
        except Exception: return None
    discovered_ips = []
    pool = eventlet.greenpool.GreenPool(size=100)
    for result in pool.imap(check_rtsp_port, hosts):
        if result: discovered_ips.append(result)
        
    with closing(get_db()) as conn:
        existing_cameras = [row['ip'] for row in conn.execute("SELECT ip FROM cameras").fetchall()]
    new_discoveries = [ip for ip in discovered_ips if ip not in existing_cameras]
    return jsonify({'success': True, 'discovered': new_discoveries, 'total_found': len(discovered_ips), 'already_added': len(discovered_ips) - len(new_discoveries)})

@app.route('/api/add_cameras_bulk', methods=['POST'])
@login_required
@admin_required
def add_cameras_bulk():
    data = request.json
    if not data or not data.get('ips'): return jsonify({'success': False, 'error': 'No IP addresses selected.'})
    ips = data['ips']
    switch_id = data.get('switch_id') or None
    fallback_mfg = data.get('manufacturer', 'Other')
    user = data.get('username', '')
    raw_pwd = data.get('password', '')
    pwd = encrypt_pwd(raw_pwd)
    added_count, errors = 0, []
    def process_camera(ip):
        onvif_data = eventlet.tpool.execute(probe_onvif_camera, ip, user, raw_pwd)
        mfg = fallback_mfg
        stream_url = f"rtsp://{ip}:554/live"
        name = f"AutoCam-{ip.replace('.', '-')}"
        mac = None
        if onvif_data.get('success'):
            mfg = onvif_data.get('make', fallback_mfg)
            model = onvif_data.get('model', '')
            if model: name = f"{mfg}-{model}-{ip.split('.')[-1]}"
            if onvif_data.get('stream_url'): stream_url = onvif_data['stream_url']
            if onvif_data.get('mac'): mac = onvif_data['mac']
        return (ip, name, stream_url, mfg, mac)
    pool = eventlet.greenpool.GreenPool(size=20)
    results = pool.imap(process_camera, ips)
    
    with closing(get_db()) as conn:
        for ip, name, stream_url, mfg, mac in results:
            try:
                conn.execute("""INSERT INTO cameras (switch_id, name, ip, stream_url, manufacturer, username, password, mac_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (switch_id, name, ip, stream_url, mfg, user, pwd, mac or ''))
                added_count += 1
            except sqlite3.IntegrityError: errors.append(ip)
        conn.commit()
        
    eventlet.spawn_n(sync_mediamtx_cameras)
    force_disk_sync()
    trigger_monitor_check()
    log_audit('User', current_user.username, f'Bulk added {added_count} cameras (Deep ONVIF Scan)')
    return jsonify({'success': True, 'added': added_count, 'errors': errors})

@app.route('/api/ping', methods=['POST'])
@login_required
@operator_required
def manual_ping():
    data = request.get_json()
    ip = data.get('ip')
    if not is_valid_target(ip): return jsonify({'success': False, 'output': 'Security Error: Invalid target format.'})
    try:
        cmd = ['ping', '-c', '4', '-W', '2', ip.strip()]
        process = eventlet.tpool.execute(subprocess.run, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        return jsonify({'success': process.returncode == 0, 'output': process.stdout or process.stderr or 'Ping failed.'})
    except Exception as e: return jsonify({'success': False, 'output': str(e)})

@app.route('/api/traceroute', methods=['POST'])
@login_required
@operator_required
def run_traceroute():
    data = request.get_json()
    target = data.get('target')
    sid = data.get('sid')
    if not is_valid_target(target): return jsonify({'success': False, 'error': 'Security Error: Invalid target format.'})
    def execute_trace():
        try:
            cmd = ['traceroute', '-w', '2', '-m', '30', '-q', '1', target.strip()]
            process = eventlet.tpool.execute(subprocess.run, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
            if process.returncode == 0: socketio.emit('traceroute_result', {'success': True, 'output': process.stdout}, to=sid)
            else: socketio.emit('traceroute_result', {'success': False, 'error': process.stderr.strip() or process.stdout.strip()}, to=sid)
        except subprocess.TimeoutExpired: socketio.emit('traceroute_result', {'success': False, 'error': 'Traceroute timed out.'}, to=sid)
        except Exception as e: socketio.emit('traceroute_result', {'success': False, 'error': str(e)}, to=sid)
    eventlet.spawn(execute_trace)
    return jsonify({'status': 'running'})

@app.route('/api/speedtest', methods=['POST'])
@login_required
@operator_required
def run_speedtest():
    data = request.get_json()
    sid = data.get('sid')
    log_audit('User', current_user.username, 'Initiated WAN Speedtest (Manual)')
    def execute_test():
        try:
            env = os.environ.copy()
            env['HOME'] = '/app/data_ram'
            cmd = ['speedtest', '--accept-license', '--accept-gdpr', '-f', 'json']
            primary_ip = get_primary_ip()
            if primary_ip: cmd.extend(['-i', primary_ip])
            process = eventlet.tpool.execute(subprocess.run, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60, env=env)
            data = None
            for line in reversed(process.stdout.splitlines()):
                line = line.strip()
                if line.startswith('{') and line.endswith('}'):
                    try: data = json.loads(line); break
                    except Exception: continue
            if process.returncode == 0 and data and 'download' in data:
                download = round((data['download']['bandwidth'] * 8) / 1000000, 2)
                upload = round((data['upload']['bandwidth'] * 8) / 1000000, 2)
                ping = round(data['ping']['latency'], 1)
                server_string = f"{data.get('server', {}).get('name', 'Unknown')} ({data.get('server', {}).get('location', 'Unknown')})"
                now = time.time()
                try:
                    with closing(get_db()) as conn:
                        log_status = f"DL: {download} Mbps | UL: {upload} Mbps | Ping: {ping} ms"
                        conn.execute("INSERT INTO event_logs (timestamp, device_type, device_name, status) VALUES (?, ?, ?, ?)", (now, 'Gateway', 'Speedtest (Manual)', log_status))
                        st_data = json.dumps({'download': download, 'upload': upload, 'ping': ping, 'isp': data.get('isp', 'Unknown'), 'server': server_string, 'timestamp': now})
                        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('latest_speedtest', ?)", (st_data,))
                        conn.commit()
                    force_disk_sync()
                except Exception as e: print(f"DB Error saving speedtest: {e}")
                socketio.emit('speedtest_result', {'success': True, 'download': f"{download} Mbps", 'upload': f"{upload} Mbps", 'ping': f"{ping} ms", 'isp': data.get('isp', 'Unknown'), 'server': server_string, 'timestamp': now}, to=sid)
            else: 
                err_msg = "Unknown execution error."
                if data and 'error' in data: err_msg = data['error']
                elif process.stderr: err_msg = process.stderr.strip()
                try:
                    fallback_cmd = ['speedtest', '--accept-license', '--accept-gdpr', '-L', '-f', 'json']
                    if primary_ip: fallback_cmd.extend(['-i', primary_ip])
                    fallback = eventlet.tpool.execute(subprocess.run, fallback_cmd, capture_output=True, text=True, timeout=10, env=env)
                    fb_data = None
                    for line in reversed(fallback.stdout.splitlines()):
                        line = line.strip()
                        if line.startswith('{') and line.endswith('}'):
                            try: fb_data = json.loads(line); break
                            except Exception: continue
                    servers = fb_data.get('servers', []) if fb_data else []
                    if servers: err_msg += " | Available Nearby Servers: " + ", ".join([f"{s['name']} ({s['location']})" for s in servers[:3]])
                except Exception: pass
                socketio.emit('speedtest_result', {'success': False, 'error': err_msg}, to=sid)
        except Exception as e: socketio.emit('speedtest_result', {'success': False, 'error': str(e)}, to=sid)
    eventlet.spawn(execute_test)
    return jsonify({'status': 'running'})

@app.route('/api/snapshot/<int:id>')
@login_required
def snapshot(id):
    with closing(get_db()) as conn:
        camera = conn.execute("SELECT stream_url, ip, manufacturer, username, password FROM cameras WHERE id = ?", (id,)).fetchone()
    if not camera: return jsonify({'error': "Camera not found"}), 404
    pwd = decrypt_pwd(camera['password'])
    snap_bytes = get_snapshot_bytes(camera['ip'], camera['manufacturer'], camera['username'], pwd, camera['stream_url'])
    if snap_bytes: return Response(snap_bytes, mimetype='image/jpeg')
    else: return jsonify({'error': "Failed to grab snapshot"}), 500

@csrf.exempt
@app.route('/tunnel/<device_type>/<int:device_id>/', defaults={'req_path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/tunnel/<device_type>/<int:device_id>/<path:req_path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@login_required
@operator_required
def tunnel(device_type, device_id, req_path):
    with closing(get_db()) as conn:
        if device_type == 'switch': device = conn.execute("SELECT ip FROM switches WHERE id = ?", (device_id,)).fetchone()
        elif device_type == 'nvr': device = conn.execute("SELECT ip FROM nvrs WHERE id = ?", (device_id,)).fetchone()
        elif device_type == 'camera': device = conn.execute("SELECT ip FROM cameras WHERE id = ?", (device_id,)).fetchone()
        else: return "Invalid device type", 404
        
        if not device: return "Device not found", 404
    
    try:
        resolved_ip = socket.gethostbyname(device['ip'])
        ip_obj = ipaddress.ip_address(resolved_ip)
        if not ip_obj.is_private or ip_obj.is_loopback: return "Security Policy Violation", 403
    except socket.gaierror: return f"DNS Error: Could not resolve hostname '{device['ip']}'", 400
    except ValueError: return "Invalid IP or Hostname format.", 400

    target_scheme = request.args.get('__scheme', 'http')

    # Allow proprietary embedded UI headers through
    EXCLUDED_REQ_HEADERS = {
        'host', 'content-length', 'connection', 'cookie', 
        'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-real-ip',
        'accept-encoding' 
    }
    
    clean_headers = {k: v for k, v in request.headers.items() if k.lower() not in EXCLUDED_REQ_HEADERS}
    clean_headers['Host'] = resolved_ip 
    
    # Aggressively Spoof Origin and Referer
    clean_headers.pop('origin', None)
    clean_headers.pop('Origin', None)
    clean_headers.pop('referer', None)
    clean_headers.pop('Referer', None)

    if request.headers.get('Origin'):
        clean_headers['Origin'] = f"{target_scheme}://{resolved_ip}"
        
    if request.headers.get('Referer'):
        original_ref = request.headers.get('Referer')
        parsed_ref = urlparse(original_ref)
        ref_path = parsed_ref.path.replace(f"/tunnel/{device_type}/{device_id}", "", 1)
        if not ref_path.startswith('/'): 
            ref_path = '/' + ref_path
        clean_headers['Referer'] = f"{target_scheme}://{resolved_ip}{ref_path}"
        
    target_url = f"{target_scheme}://{resolved_ip}/{req_path.lstrip('/')}"
    
    # [FIX]: Safely extract query parameters preserving array values for Vue apps
    original_args = [(k, v) for k, v in request.args.items(multi=True) if k != '__scheme']
    query_string = urlencode(original_args)
    if query_string: target_url += f"?{query_string}"

    # [FIX]: Scrub our newly named Flask session, allowing the device's native cookies through
    clean_cookies = {k: v for k, v in request.cookies.items() if k != 'lighthouse_session'}

    try:
        resp = requests.request(
            method=request.method, 
            url=target_url, 
            headers=clean_headers, 
            data=request.get_data(), 
            cookies=clean_cookies,
            allow_redirects=False, 
            stream=True, 
            timeout=10, 
            verify=False
        )
        
        excluded_headers = [
            'content-encoding', 'content-length', 'transfer-encoding', 
            'connection', 'x-frame-options', 'content-security-policy', 
            'strict-transport-security'
        ]
        
        resp_headers = []
        tunnel_base = f"/tunnel/{device_type}/{device_id}"

        for name, value in resp.raw.headers.items():
            if name.lower() in excluded_headers:
                continue
            
            if name.lower() == 'set-cookie':
                # Strip hardcoded Domain constraints the device might try to set
                value = re.sub(r'(?i);\s*domain=[^;]+', '', value)
                
                # Strip Secure flags if you are testing locally over HTTP
                if not request.is_secure:
                    value = re.sub(r'(?i);\s*secure', '', value)

                if re.search(r'(?i)path=[^;]+', value):
                    value = re.sub(r'(?i)path=[^;]+', f'Path={tunnel_base}', value)
                else:
                    value += f"; Path={tunnel_base}"

            elif name.lower() == 'location':
                absolute_loc = urljoin(target_url, value)
                parsed = urlparse(absolute_loc)
                
                if parsed.hostname in [device['ip'], resolved_ip]:
                    new_loc = f"{tunnel_base}{parsed.path}"
                    
                    params = []
                    if parsed.scheme == 'https' and target_scheme == 'http':
                        params.append('__scheme=https')
                        
                    if parsed.query: params.append(parsed.query)
                    if params: new_loc += "?" + "&".join(params)
                    
                    value = new_loc

            resp_headers.append((name, value))

        # Pass OPTIONS preflight headers cleanly
        if request.method == 'OPTIONS':
            return Response('', status=resp.status_code, headers=resp_headers)

        content_type = resp.headers.get('Content-Type', '').lower()
        if 'text/html' in content_type or 'javascript' in content_type or 'json' in content_type:
            payload = resp.content.decode('utf-8', errors='ignore')
            payload = re.sub(rf"(https?|wss?)://{re.escape(device['ip'])}(:\d+)?", f"http://{request.host}{tunnel_base}", payload)
            payload = payload.replace(device['ip'], f"{request.host}{tunnel_base}")
            if 'text/html' in content_type:
                base_tag = f'<base href="{tunnel_base}/">\n'
                payload = re.sub(r'(<head[^>]*>)', rf'\1\n{base_tag}', payload, flags=re.IGNORECASE)
            return Response(payload, resp.status_code, resp_headers)
        else:
            return Response(resp.iter_content(chunk_size=10*1024), resp.status_code, resp_headers)
    except requests.exceptions.RequestException as e: 
        return f"Tunnel Error: {str(e)}", 502

@csrf.exempt
@app.errorhandler(404)
def proxy_absolute_paths(e):
    if not current_user.is_authenticated: return jsonify({'error': 'Not Found'}), 404
    if current_user.role not in ['admin', 'operator']: return jsonify({'error': 'Forbidden'}), 403 
    referer = request.headers.get('Referer')
    if referer:
        parsed_referer = urlparse(referer)
        parts = parsed_referer.path.split('/')
        if len(parts) >= 4 and parts[1] == 'tunnel':
            return tunnel(parts[2], parts[3], request.path)
    return jsonify({'error': 'Not Found'}), 404

def init_logos():
    global LOCAL_COMPANY_LOGO, LOCAL_CUSTOMER_LOGO
    logo_dir = '/app/data/logos'
    os.makedirs(logo_dir, exist_ok=True)
    def process_logo(env_var, filename):
        val = os.environ.get(env_var, '').strip()
        if not val: return None
        filepath = os.path.join(logo_dir, filename)
        serve_path = f"/static/logos/{filename}" 
        if val.startswith('http://') or val.startswith('https://'):
            try:
                resp = requests.get(val, timeout=5)
                if resp.status_code == 200:
                    with open(filepath, 'wb') as f: f.write(resp.content)
                    return f"{serve_path}?t={int(time.time())}"
            except Exception: pass
            if os.path.exists(filepath): return f"{serve_path}?t={int(os.path.getmtime(filepath))}"
            return val
        return val
    LOCAL_COMPANY_LOGO = process_logo('COMPANY_LOGO_URL', 'company_logo.png')
    LOCAL_CUSTOMER_LOGO = process_logo('CUSTOMER_LOGO_URL', 'customer_logo.png')

@app.route('/static/logos/<filename>')
def serve_local_logo(filename):
    return send_from_directory('/app/data/logos', filename)

try:
    init_db()
    init_logos()
    os.makedirs('/app/data', exist_ok=True)
    
    # Initialize hardened MQTT Client
    mqtt_user = os.environ.get('MQTT_USER')
    mqtt_pass = os.environ.get('MQTT_PASS')
    mqtt_client = mqtt.Client()
    if mqtt_user and mqtt_pass:
        mqtt_client.username_pw_set(mqtt_user, mqtt_pass)
        
    try:
        mqtt_client.connect(os.environ.get('DEFAULT_MQTT_BROKER', '127.0.0.1'), 
                            int(os.environ.get('DEFAULT_MQTT_PORT', 1883)), 60)
        mqtt_client.loop_start()
    except Exception as e:
        print(f"MQTT startup/auth failed: {e}")

    socketio.start_background_task(monitor_loop)
    socketio.start_background_task(l7_worker_loop)
    socketio.start_background_task(automated_speedtest_loop)
    socketio.start_background_task(sync_db_loop)
    socketio.start_background_task(log_prune_loop)
    eventlet.spawn_n(sync_mediamtx_cameras)
except Exception as e: 
    print(f"Startup initialization error: {e}")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
