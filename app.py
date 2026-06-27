# CRITICAL: Monkey patching must occur before ANY other imports
import eventlet
eventlet.monkey_patch()
import eventlet.tpool

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
import smtplib
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
from urllib.parse import urlparse
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, abort, flash, Response, jsonify, send_from_directory, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_socketio import SocketIO
from authlib.integrations.flask_client import OAuth
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# --- SECURITY: CSRF PROTECTION & SESSIONS ---
app.secret_key = os.environ.get('SECRET_KEY', 'cctv-super-secret-key-change-me')
db_key_env = os.environ.get('DB_ENCRYPTION_KEY', app.secret_key)

csrf = CSRFProtect(app)
app.config['SESSION_COOKIE_HTTPONLY'] = True 
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('REQUIRE_HTTPS', 'False').lower() == 'true'

# --- SECURITY: CONTENT SECURITY POLICY (CSP) ---
@app.after_request
def apply_csp(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: blob: http: https:; "
        "connect-src 'self' ws: wss: data: https://cdn.jsdelivr.net https://cdn.socket.io; "
        "object-src 'self' ws: wss:;"
    )
    response.headers['Content-Security-Policy'] = csp
    return response

# Initialize WebSockets
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', logger=False, engineio_logger=False)

LOCAL_COMPANY_LOGO = None
LOCAL_CUSTOMER_LOGO = None

@app.context_processor
def inject_globals():
    return {
        'company_logo': LOCAL_COMPANY_LOGO,
        'customer_logo': LOCAL_CUSTOMER_LOGO
    }

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
# DATABASE & LOGGING HELPERS
# ==========================================
DB_PATH_DISK = '/app/data/cctv.db'        
DB_PATH_RAM = '/app/data_ram/cctv.db'     
force_check_event = Event()

def get_db():
    os.makedirs(os.path.dirname(DB_PATH_RAM), exist_ok=True)
    conn = sqlite3.connect(DB_PATH_RAM, check_same_thread=False, timeout=30)
    try: conn.execute("PRAGMA journal_mode=WAL;")
    except sqlite3.OperationalError: pass
    conn.row_factory = sqlite3.Row
    return conn

def log_audit(device_type, device_name, status):
    try:
        conn = get_db()
        conn.execute("INSERT INTO event_logs (timestamp, device_type, device_name, status) VALUES (?, ?, ?, ?)",
                     (time.time(), device_type, device_name, status))
        conn.commit()
        conn.close()
    except Exception: pass

# ==========================================
# AUTHENTICATION & GLOBALS
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
    if user: return User(user['id'], user['username'], user['role'])
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
    global force_check_event
    if not force_check_event.ready():
        force_check_event.send(True)

@app.before_request
def manage_idle_timeout():
    if request.endpoint in ['static', 'serve_local_logo'] or request.path.startswith('/tunnel/'):
        if current_user.is_authenticated:
            session['last_active'] = time.time()
        return 
        
    if current_user.is_authenticated:
        now = time.time()
        last_active = session.get('last_active', now)
        
        conn = get_db()
        idle_row = conn.execute("SELECT value FROM settings WHERE key = 'idle_timeout'").fetchone()
        conn.close()
        
        idle_mins = int(idle_row['value']) if idle_row else 20
        
        if (now - last_active) > (idle_mins * 60):
            log_audit('System', current_user.username, 'Auto-logged out (Idle Timeout)')
            logout_user()
            session.pop('last_active', None)
            flash('You have been automatically logged out due to inactivity.', 'warning')
            return redirect(url_for('login'))
            
        session['last_active'] = now

# ==========================================
# DATABASE INITIALIZATION & RAM SYNC
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
    init_ram_db() 
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS switches (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, ip TEXT, status TEXT DEFAULT 'UNKNOWN')")
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
    try: cursor.execute("ALTER TABLE cameras ADD COLUMN silenced_until REAL DEFAULT 0")
    except sqlite3.OperationalError: pass
    try: cursor.execute("ALTER TABLE switches ADD COLUMN mac_address TEXT DEFAULT ''")
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
            ('idle_timeout', '20'),
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
    else:
        try: cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('idle_timeout', '20')")
        except sqlite3.OperationalError: pass
        try:
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_host', '')")
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_port', '587')")
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_user', '')")
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_pass', '')")
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('smtp_target', '')")
        except sqlite3.OperationalError: pass
        try:
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('st_interval', '0')")
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('st_alert_dl', '0')")
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('st_alert_ul', '0')")
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('st_alert_ping', '0')")
        except sqlite3.OperationalError: pass
        
    cursor.execute("SELECT count(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
        default_pass = os.environ.get('DEFAULT_ADMIN_PASS', 'admin')
        default_hash = generate_password_hash(default_pass)
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')", (default_user, default_hash))
    
    conn.commit()
    conn.close()

def _perform_disk_sync():
    """Executes the SQLite backup via C-API. MUST be run in a tpool thread to prevent Eventlet blocking."""
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

def force_disk_sync():
    """Fires a non-blocking background task to flush RAM to the SD card immediately on CRUD updates."""
    eventlet.spawn_n(eventlet.tpool.execute, _perform_disk_sync)

def sync_db_loop():
    """Standard 5-minute interval sync for high-frequency telemetry/logs."""
    while True:
        time.sleep(300) 
        eventlet.tpool.execute(_perform_disk_sync)

def graceful_shutdown(*args):
    """Ensures final writes are flushed to SD card on container SIGTERM."""
    _perform_disk_sync()

atexit.register(graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)

def log_prune_loop():
    while True:
        time.sleep(86400) 
        try:
            conn = get_db()
            seven_days_ago = time.time() - (7 * 24 * 3600)
            conn.execute("DELETE FROM event_logs WHERE timestamp < ?", (seven_days_ago,))
            conn.commit()
            conn.close()
            force_disk_sync()
        except Exception: pass

# ==========================================
# BACKGROUND MONITORING & NETWORK TASKS
# ==========================================
SNAPSHOT_SEMAPHORE = eventlet.semaphore.Semaphore(4)
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
    if target.startswith('-'): return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError: pass
    if re.match(r'^[A-Za-z0-9_.-]+$', target): return True
    return False

def is_pingable(target):
    response = subprocess.call(['ping', '-c', '1', '-W', '1', target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return response == 0

def is_port_open(target, port, timeout=2):
    try:
        with socket.create_connection((target, port), timeout=timeout): return True
    except OSError: return False

def is_stream_active(url):
    try:
        response = eventlet.tpool.execute(subprocess.call, ['ffprobe', '-rtsp_transport', 'tcp', '-v', 'error', '-i', url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        return response == 0
    except Exception: return False

def get_mac_address(ip):
    try:
        with open('/proc/net/arp', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac != "00:00:00:00:00:00":
                        return mac.upper()
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
                    if mac != "00:00:00:00:00:00":
                        arp_entries.append({"ip": ip, "mac": mac.upper(), "interface": interface})
    except FileNotFoundError: pass
    return arp_entries

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
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            try:
                stdout, _ = proc.communicate(timeout=5)
                if proc.returncode == 0: 
                    return stdout
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
    except Exception: pass
    return None

def threaded_camera_check(cam):
    cam_up = is_pingable(cam['ip']) or is_port_open(cam['ip'], 554) or is_port_open(cam['ip'], 80)
    stream_ok, snap_bytes, fetched_mac = False, None, None
    mac = cam.get('mac_address', '')
    
    if cam_up:
        if not mac:
            new_mac = get_mac_address(cam['ip'])
            if new_mac: fetched_mac = new_mac.upper()

        auth_url = cam['stream_url']
        if cam.get('username') and cam.get('password') and '@' not in auth_url and auth_url.startswith('rtsp://'):
            auth_url = f"rtsp://{cam['username']}:{cam['password']}@{auth_url[7:]}"

        stream_ok = is_stream_active(auth_url)
        if stream_ok:
            with SNAPSHOT_SEMAPHORE:
                snap_bytes = get_snapshot_bytes(cam['ip'], cam['manufacturer'], cam['username'], cam['password'], auth_url)
                
    return cam['id'], cam_up, stream_ok, snap_bytes, fetched_mac

def send_failover_email(subject, body):
    conn = get_db()
    settings = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
    conn.close()
    
    if not settings.get('smtp_host') or not settings.get('smtp_target'):
        return 
        
    def _send(stgs):
        try:
            msg = EmailMessage()
            msg.set_content(body)
            msg['Subject'] = subject
            msg['From'] = stgs.get('smtp_user') or 'lighthouse@edge-gateway'
            msg['To'] = stgs['smtp_target']
            
            server = smtplib.SMTP(stgs['smtp_host'], int(stgs.get('smtp_port', 587)))
            server.starttls()
            if stgs.get('smtp_user') and stgs.get('smtp_pass'):
                server.login(stgs['smtp_user'], stgs['smtp_pass'])
            server.send_message(msg)
            server.quit()
            log_audit('System', 'Email Failover', f'Sent email: {subject}')
        except Exception as e:
            log_audit('System', 'Email Failover', f'Failed to send email: {str(e)}')
            
    eventlet.spawn_n(_send, settings)

def automated_speedtest_loop():
    global mqtt_client, mqtt_prefix_global
    time.sleep(30)
    last_run = 0
    
    while True:
        time.sleep(60)
        try:
            conn = get_db()
            settings_dict = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
            conn.close()
            
            st_interval = float(settings_dict.get('st_interval', 0))
            
            if st_interval > 0 and (time.time() - last_run) >= (st_interval * 3600):
                last_run = time.time()
                
                env = os.environ.copy()
                env['HOME'] = '/app/data_ram'
                
                cmd = ['speedtest', '--accept-license', '--accept-gdpr', '-f', 'json']
                primary_ip = get_primary_ip()
                if primary_ip:
                    cmd.extend(['-i', primary_ip])
                
                process = eventlet.tpool.execute(
                    subprocess.run, cmd, capture_output=True, text=True, timeout=60, env=env
                )
                
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
                        
                        conn = get_db()
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
                            
                            if mqtt_client and mqtt_client.is_connected():
                                mqtt_client.publish(f"{mqtt_prefix_global}/gateway/speedtest_alert", alert_text, retain=True)
                            else:
                                send_failover_email("WAN Auto-Speedtest Alert", f"The automated gateway speed test breached configured thresholds:\n\n{alert_text}\n\nTarget Server: {server_string}")
                        else:
                            if mqtt_client and mqtt_client.is_connected():
                                mqtt_client.publish(f"{mqtt_prefix_global}/gateway/speedtest_alert", "OK", retain=True)
                            
                        st_data = json.dumps({'download': download, 'upload': upload, 'ping': ping, 'isp': data.get('isp', 'Unknown'), 'server': server_string, 'timestamp': now})
                        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('latest_speedtest', ?)", (st_data,))
                        conn.commit()
                        conn.close()
                        force_disk_sync()
                        
                        socketio.emit('speedtest_result', {'success': True, 'download': f"{download} Mbps", 'upload': f"{upload} Mbps", 'ping': f"{ping} ms", 'isp': data.get('isp', 'Unknown'), 'server': server_string, 'timestamp': now})
        except Exception as e:
            print(f"Automated speedtest loop error: {e}")

def monitor_loop():
    global force_check_event, mqtt_client, mqtt_prefix_global
    previous_hashes = {} 
    
    conn = get_db()
    settings_dict = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
    conn.close()
    broker = settings_dict.get('mqtt_broker', '127.0.0.1')
    port = int(settings_dict.get('mqtt_port', 1883))
    mqtt_prefix_global = settings_dict.get('mqtt_prefix', 'zabbix/cctv')
    
    mqtt_client = mqtt.Client("camera_monitor_service")
    
    def on_connect(client, userdata, flags, rc):
        if rc == 0: log_audit('System', 'MQTT Broker', 'UP (Connected)')
        else: log_audit('System', 'MQTT Broker', f'ERR (Connection Refused: {rc})')

    def on_disconnect(client, userdata, rc):
        if rc != 0:
            log_audit('System', 'MQTT Broker', 'DOWN (Unexpected Disconnect)')
            send_failover_email("CRITICAL: Lighthouse MQTT Disconnected", "The edge gateway has lost its connection to the Zabbix MQTT broker. Camera failover alerts will now route via email.")

    mqtt_client.on_connect = on_connect
    mqtt_client.on_disconnect = on_disconnect

    try:
        mqtt_client.connect(broker, port, 60)
        mqtt_client.loop_start()
    except Exception as e: 
        log_audit('System', 'MQTT Broker', f'DOWN (Initial Connection Failed)')
        send_failover_email("CRITICAL: Lighthouse MQTT Offline", "The edge gateway failed to connect to the Zabbix broker on boot. Email failover engaged.")
        
    while True:
        now = time.time()
        
        try:
            is_mqtt_up = mqtt_client.is_connected() if mqtt_client else False
            socketio.emit('gateway_status', {'mqtt': is_mqtt_up, 'ui': True})

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM settings")
            dynamic_settings = {row['key']: row['value'] for row in cursor.fetchall()}
            interval = int(dynamic_settings.get('check_interval', 60))
            
            # ARCHITECT FIX: Self-Healing WebRTC check.
            # If time modulo 5 mins hits, sync MediaMTX to catch independent sidecar reboots.
            if int(now) % 300 < int(interval):
                eventlet.spawn_n(sync_mediamtx_cameras)
            
            cursor.execute("SELECT * FROM switches")
            switches = [dict(row) for row in cursor.fetchall()]
            
            cursor.execute("SELECT * FROM cameras")
            all_cameras = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            pending_db_updates = []
            pending_mac_updates = []

            def queue_status(table, item_id, item_name, dev_type, old_status, new_status):
                if old_status != new_status:
                    pending_db_updates.append((now, dev_type, item_name, new_status, table, item_id))
                    socketio.emit('state_change', {
                        'type': table, 'id': item_id, 'name': item_name,
                        'status': new_status, 'device_type': dev_type, 'timestamp': now
                    })
                    
                    if 'DOWN' in new_status or 'UNREACHABLE' in new_status or 'ERR' in new_status:
                        if not mqtt_client.is_connected():
                            send_failover_email(f"FAILOVER ALERT: {item_name} is {new_status}", f"The {dev_type} '{item_name}' transitioned to a critical state ({new_status}).\n\nThis alert was routed via SMTP because the primary MQTT connection to Zabbix is currently offline.")

            cameras_by_switch = {}
            standalone_cameras = []
            for c in all_cameras:
                if c['switch_id']: cameras_by_switch.setdefault(c['switch_id'], []).append(c)
                else: standalone_cameras.append(c)

            for switch in switches:
                switch_id, switch_name, switch_ip = switch['id'], switch['name'], switch['ip']
                s_until, mac = switch['silenced_until'] or 0, switch['mac_address'] or ''
                silenced = s_until > now
                is_up = is_pingable(switch_ip) or is_port_open(switch_ip, 80) or is_port_open(switch_ip, 443)
                
                switch_payload = "MAINTENANCE" if silenced else ("UP" if is_up else "OFFLINE")
                mqtt_client.publish(f"{mqtt_prefix_global}/{switch_name}/ping", switch_payload, retain=True)
                
                if is_up:
                    if not mac:
                        fetched_mac = get_mac_address(switch_ip)
                        if fetched_mac: pending_mac_updates.append(('switches', fetched_mac.upper(), switch_id))
                            
                    new_s_stat = 'UP' if not silenced else 'UP (Silenced)'
                    queue_status('switches', switch_id, switch_name, 'Switch', switch['status'], new_s_stat)
                    
                    camera_list = cameras_by_switch.get(switch_id, [])
                    camera_dicts_for_pool = [dict(c, password=decrypt_pwd(c['password'])) for c in camera_list]
                    camera_results = {}
                    
                    pool = eventlet.greenpool.GreenPool(size=20)
                    for c_id, cam_up, stream_ok, snap_bytes, fetched_mac in pool.imap(threaded_camera_check, camera_dicts_for_pool):
                        camera_results[c_id] = (cam_up, stream_ok, snap_bytes)
                        if fetched_mac: pending_mac_updates.append(('cameras', fetched_mac.upper(), c_id))
                    
                    for cam in camera_list:
                        c_until = cam['silenced_until'] or 0
                        cam_silenced = (c_until > now) or silenced
                        cam_id, cam_name = cam['id'], cam['name']
                        cam_up, stream_ok, snap_bytes = camera_results[cam_id]
                        is_frozen = False
                        
                        if cam_up:
                            if stream_ok and snap_bytes:
                                try:
                                    img = Image.open(io.BytesIO(snap_bytes))
                                    current_hash = imagehash.average_hash(img)
                                    last_hash = previous_hashes.get(cam_id)
                                    if last_hash is not None and cam['status'] == 'UP' and (current_hash - last_hash) <= 2: 
                                        is_frozen = True
                                    previous_hashes[cam_id] = current_hash
                                except Exception: pass
                            else: previous_hashes.pop(cam_id, None)
                            
                            if cam_silenced:
                                mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/ping", "MAINTENANCE", retain=True)
                                mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "MAINTENANCE", retain=True)
                                if is_frozen: queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'FROZEN (Silenced)')
                                else: queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'UP (Silenced)' if stream_ok else 'STREAM ERR (Silenced)')
                            else:
                                mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/ping", "UP", retain=True)
                                if is_frozen:
                                    mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "FROZEN", retain=True)
                                    queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Frozen)')
                                else:
                                    mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "UP" if stream_ok else "STREAM_ERROR", retain=True)
                                    queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'UP' if stream_ok else 'DOWN (Stream Error)')
                        else:
                            if cam_silenced:
                                mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/ping", "MAINTENANCE", retain=True)
                                mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "MAINTENANCE", retain=True)
                                queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Silenced)')
                            else:
                                mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/ping", "OFFLINE", retain=True)
                                mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "OFFLINE", retain=True)
                                queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Offline)')
                else:
                    new_s_stat = 'DOWN' if not silenced else 'DOWN (Silenced)'
                    queue_status('switches', switch_id, switch_name, 'Switch', switch['status'], new_s_stat)
                    for cam in cameras_by_switch.get(switch_id, []):
                        c_until = cam['silenced_until'] or 0
                        cam_silenced = (c_until > now) or silenced
                        if cam_silenced:
                            mqtt_client.publish(f"{mqtt_prefix_global}/{cam['name']}/ping", "MAINTENANCE", retain=True)
                            mqtt_client.publish(f"{mqtt_prefix_global}/{cam['name']}/stream", "MAINTENANCE", retain=True)
                            new_c_stat = 'UNREACHABLE (Silenced)'
                        else:
                            mqtt_client.publish(f"{mqtt_prefix_global}/{cam['name']}/ping", "OFFLINE", retain=True)
                            mqtt_client.publish(f"{mqtt_prefix_global}/{cam['name']}/stream", "OFFLINE", retain=True)
                            new_c_stat = 'UNREACHABLE (Switch Down)'
                        queue_status('cameras', cam['id'], cam['name'], 'Camera', cam['status'], new_c_stat)

            standalone_results = {}
            if standalone_cameras:
                pool = eventlet.greenpool.GreenPool(size=20)
                standalone_dicts = [dict(c, password=decrypt_pwd(c['password'])) for c in standalone_cameras]
                for c_id, cam_up, stream_ok, snap_bytes, fetched_mac in pool.imap(threaded_camera_check, standalone_dicts):
                    standalone_results[c_id] = (cam_up, stream_ok, snap_bytes)
                    if fetched_mac: pending_mac_updates.append(('cameras', fetched_mac.upper(), c_id))

            for cam in standalone_cameras:
                c_until = cam['silenced_until'] or 0
                cam_id, cam_name, cam_silenced = cam['id'], cam['name'], (c_until > now)
                
                cam_up, stream_ok, snap_bytes = standalone_results.get(cam_id, (False, False, None))
                is_frozen = False
                
                if cam_up:
                    if stream_ok and snap_bytes:
                        try:
                            img = Image.open(io.BytesIO(snap_bytes))
                            current_hash = imagehash.average_hash(img)
                            last_hash = previous_hashes.get(cam_id)
                            if last_hash is not None and cam['status'] == 'UP' and (current_hash - last_hash) <= 2: 
                                is_frozen = True
                            previous_hashes[cam_id] = current_hash
                        except Exception: pass
                    else: previous_hashes.pop(cam_id, None)
                            
                    if cam_silenced:
                        mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/ping", "MAINTENANCE", retain=True)
                        mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "MAINTENANCE", retain=True)
                        if is_frozen: queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'FROZEN (Silenced)')
                        else: queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'UP (Silenced)' if stream_ok else 'STREAM ERR (Silenced)')
                    else:
                        mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/ping", "UP", retain=True)
                        if is_frozen:
                            mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "FROZEN", retain=True)
                            queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Frozen)')
                        else:
                            mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "UP" if stream_ok else "STREAM_ERROR", retain=True)
                            queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'UP' if stream_ok else 'DOWN (Stream Error)')
                else:
                    if cam_silenced:
                        mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/ping", "MAINTENANCE", retain=True)
                        mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "MAINTENANCE", retain=True)
                        queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Silenced)')
                    else:
                        mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/ping", "OFFLINE", retain=True)
                        mqtt_client.publish(f"{mqtt_prefix_global}/{cam_name}/stream", "OFFLINE", retain=True)
                        queue_status('cameras', cam_id, cam_name, 'Camera', cam['status'], 'DOWN (Offline)')

            if pending_db_updates or pending_mac_updates:
                conn = get_db()
                with conn:
                    for (t_stamp, dev_type, item_name, new_status, table, item_id) in pending_db_updates:
                        if new_status != 'UNKNOWN':
                            conn.execute("INSERT INTO event_logs (timestamp, device_type, device_name, status) VALUES (?, ?, ?, ?)", (t_stamp, dev_type, item_name, new_status))
                        conn.execute(f"UPDATE {table} SET status = ? WHERE id = ?", (new_status, item_id))
                    
                    for table, mac, item_id in pending_mac_updates:
                        conn.execute(f"UPDATE {table} SET mac_address = ? WHERE id = ?", (mac, item_id))
                conn.close()

        except Exception as e: 
            print(f"Monitor loop iteration failed: {e}")
            time.sleep(10)
            
        try:
            with eventlet.Timeout(interval): force_check_event.wait()
        except eventlet.Timeout: pass 
            
        if force_check_event.ready(): force_check_event = Event()

# ==========================================
# WEBRTC (MEDIAMTX) INTEGRATION
# ==========================================
MEDIAMTX_API = "http://127.0.0.1:9997/v3/config/paths"

def sync_mediamtx_cameras():
    """Synchronizes the SQLite camera state with the MediaMTX WebRTC relay."""
    try:
        conn = get_db()
        cameras = conn.execute("SELECT id, stream_url, username, password FROM cameras").fetchall()
        conn.close()

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

            payload = {
                "source": auth_url,
                "sourceOnDemand": True,
                "runOnDemandCloseAfter": "10s"
            }

            if cam_id not in current_paths:
                requests.post(f"{MEDIAMTX_API}/{cam_id}", json=payload, timeout=3)
            elif current_paths[cam_id].get('source') != auth_url:
                requests.patch(f"{MEDIAMTX_API}/{cam_id}", json=payload, timeout=3)

        for path_name in current_paths:
            if path_name.startswith("cam_") and path_name not in configured_cam_ids:
                requests.delete(f"{MEDIAMTX_API}/{path_name}", timeout=3)

    except Exception as e:
        print(f"MediaMTX Sync Error: {e}")

@app.route('/api/webrtc/<int:cam_id>/whep', methods=['POST'])
@login_required
@operator_required
def webrtc_whep(cam_id):
    try:
        sdp_offer = request.data
        if not sdp_offer: return "Missing SDP offer", 400

        resp = requests.post(
            f"http://127.0.0.1:8189/cam_{cam_id}/whep", 
            data=sdp_offer,
            headers={"Content-Type": "application/sdp"},
            timeout=5
        )
        
        if resp.status_code == 201: return Response(resp.content, mimetype='application/sdp')
        else: return f"MediaMTX rejected offer: {resp.text}", 502

    except requests.exceptions.RequestException as e:
        return f"WebRTC Relay Offline: {str(e)}", 502

# ==========================================
# FLASK WEB ROUTES
# ==========================================
@app.route('/local_logo/<filename>')
def serve_local_logo(filename):
    return send_from_directory('/app/data/logos', filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            login_user(User(user['id'], user['username'], user['role']))
            log_audit('System', username, 'User Logged In (Local)')
            return redirect(url_for('index'))
        else:
            flash('Invalid local username or password', 'danger')
            return redirect(url_for('login', fallback='true'))

    fallback = request.args.get('fallback') == 'true'
    return render_template('login.html', 
                           fallback=fallback, 
                           authentik_active=bool(AUTHENTIK_URL),
                           microsoft_active=bool(AZURE_TENANT_ID),
                           google_active=bool(GOOGLE_CLIENT_ID),
                           okta_active=bool(OKTA_DOMAIN),
                           keycloak_active=bool(KEYCLOAK_URL))

@app.route('/login/sso/<provider>')
def login_sso(provider):
    client = oauth.create_client(provider)
    if not client:
        flash(f'{provider.capitalize()} SSO is not configured on this gateway.', 'warning')
        return redirect(url_for('login', fallback='true'))
        
    try:
        return client.authorize_redirect(url_for('auth_callback', provider=provider, _external=True))
    except Exception as e:
        print(f"SSO Route Error ({provider}): {str(e)}")
        log_audit('System', 'SSO Failover', f'{provider.capitalize()} SSO Server Unreachable')
        flash(f'The {provider.capitalize()} SSO server is currently unreachable. Please use local emergency access.', 'danger')
        return redirect(url_for('login', fallback='true'))

@app.route('/auth/callback/<provider>')
def auth_callback(provider):
    client = oauth.create_client(provider)
    if not client:
        flash(f'Invalid SSO provider: {provider}', 'danger')
        return redirect(url_for('login', fallback='true'))
        
    try:
        token = client.authorize_access_token()
        user_info = client.parse_id_token(token)
    except Exception as e:
        flash(f'SSO Login Failed: {str(e)}', 'danger')
        return redirect(url_for('login', fallback='true'))
    
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
        
    elif provider == 'google':
        if username and username.endswith('@yourcompany.com'):
            role = 'operator' 

    conn = get_db()
    db_user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not db_user:
        cursor = conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, f'SSO_{provider.upper()}', role))
        user_id = cursor.lastrowid
    else:
        user_id = db_user['id']
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        
    conn.commit()
    conn.close()
    force_disk_sync()
    
    login_user(User(user_id, username, role))
    log_audit('System', username, f'User Logged In ({provider.capitalize()} SSO)')
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    log_audit('System', current_user.username, 'User Logged Out')
    logout_user()
    session.pop('last_active', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    now = time.time()
    conn = get_db()
    switches = conn.execute("SELECT *, (IFNULL(silenced_until, 0) > ?) as is_silenced FROM switches", (now,)).fetchall()
    cameras = conn.execute("""
        SELECT c.*, s.name as switch_name, 
               ((IFNULL(c.silenced_until, 0) > ?) OR (IFNULL(s.silenced_until, 0) > ?)) as is_silenced 
        FROM cameras c LEFT JOIN switches s ON c.switch_id = s.id
    """, (now, now)).fetchall()
    
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings_dict = {row['key']: row['value'] for row in cursor.fetchall()}
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    
    latest_speedtest = None
    if 'latest_speedtest' in settings_dict:
        try: latest_speedtest = json.loads(settings_dict['latest_speedtest'])
        except Exception: pass
        
    default_subnet = get_local_subnet()
    
    return render_template('index.html', switches=switches, cameras=cameras, settings=settings_dict, users=users, default_subnet=default_subnet, latest_speedtest=latest_speedtest)
    
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
    
    log_audit('User', current_user.username, 'Exported Event Logs CSV')
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
    log_audit('User', current_user.username, 'Exported System Configuration CSV')
    return Response(si.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=cctv_config.csv"})

@app.route('/download_template')
@login_required
@admin_required
def download_template():
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Device_Type', 'Parent_Switch', 'Device_Name', 'IP_Address', 'Stream_URL', 'Manufacturer', 'Username', 'Password'])
    cw.writerow(['Switch', '', 'Core-Switch-01', '192.168.1.5', '', '', '', ''])
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
                name, ip = row.get('Device_Name', '').strip(), row.get('IP_Address', '').strip()
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
                if existing: conn.execute("""UPDATE cameras SET switch_id=?, ip=?, stream_url=?, manufacturer=?, username=?, password=? WHERE id=?""", (switch_id, ip, url, mfg, user, pwd, existing['id']))
                else: conn.execute("""INSERT INTO cameras (switch_id, name, ip, stream_url, manufacturer, username, password) VALUES (?, ?, ?, ?, ?, ?, ?)""", (switch_id, name, ip, url, mfg, user, pwd))

        conn.commit()
        conn.close()
        
        eventlet.spawn_n(sync_mediamtx_cameras)
        force_disk_sync()
        trigger_monitor_check()
        log_audit('User', current_user.username, 'Imported configuration via CSV')
        flash('CSV Configuration imported successfully.', 'success')
    except Exception as e: flash(f'Error importing CSV: {str(e)}', 'danger')
    return redirect(url_for('index'))

@app.route('/api/network/arp', methods=['GET'])
@login_required
@operator_required
def fetch_arp_table():
    log_audit('User', current_user.username, 'Initiated native L2 ARP scan')
    try:
        subnet = get_local_subnet()
        try:
            bcast = str(ipaddress.IPv4Network(subnet, strict=False).broadcast_address)
            eventlet.tpool.execute(subprocess.run, ['ping', '-c', '2', '-W', '1', '-b', bcast], timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception: pass
        
        devices = get_camlan_arp_table()
        return jsonify({"status": "success", "count": len(devices), "interface_scanned": "All Interfaces", "devices": devices}), 200
    except Exception as e: return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/scan_network', methods=['POST'])
@login_required
@admin_required
def scan_network():
    subnet = request.form.get('subnet')
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

    conn = get_db()
    existing_cameras = [row['ip'] for row in conn.execute("SELECT ip FROM cameras").fetchall()]
    conn.close()
    
    new_discoveries = [ip for ip in discovered_ips if ip not in existing_cameras]
    return jsonify({'success': True, 'discovered': new_discoveries, 'total_found': len(discovered_ips), 'already_added': len(discovered_ips) - len(new_discoveries)})

@app.route('/api/add_cameras_bulk', methods=['POST'])
@login_required
@admin_required
def add_cameras_bulk():
    data = request.json
    if not data or not data.get('ips'): return jsonify({'success': False, 'error': 'No IP addresses selected.'})

    ips, switch_id = data['ips'], data.get('switch_id') or None
    mfg, user, pwd = data.get('manufacturer', 'Other'), data.get('username', ''), encrypt_pwd(data.get('password', ''))

    conn = get_db()
    added_count, errors = 0, []
    for ip in ips:
        name = f"AutoCam-{ip.replace('.', '-')}"
        stream_url = f"rtsp://{ip}:554/live"
        try:
            conn.execute("""INSERT INTO cameras (switch_id, name, ip, stream_url, manufacturer, username, password) VALUES (?, ?, ?, ?, ?, ?, ?)""", (switch_id, name, ip, stream_url, mfg, user, pwd))
            added_count += 1
        except sqlite3.IntegrityError: errors.append(ip)

    conn.commit()
    conn.close()
    
    eventlet.spawn_n(sync_mediamtx_cameras)
    force_disk_sync()
    trigger_monitor_check()
    log_audit('User', current_user.username, f'Bulk added {added_count} cameras')
    return jsonify({'success': True, 'added': added_count, 'errors': errors})

@app.route('/toggle_silence/<device_type>/<int:id>', methods=['POST'])
@login_required
@operator_required
def toggle_silence(device_type, id):
    hours = float(request.form.get('hours', 0))
    silence_until = time.time() + (hours * 3600) if hours > 0 else 0
    conn = get_db()
    
    device_name = "Unknown"
    if device_type == 'switch':
        conn.execute("UPDATE switches SET silenced_until = ? WHERE id = ?", (silence_until, id))
        row = conn.execute("SELECT name FROM switches WHERE id = ?", (id,)).fetchone()
        if row: device_name = row['name']
    elif device_type == 'camera':
        conn.execute("UPDATE cameras SET silenced_until = ? WHERE id = ?", (silence_until, id))
        row = conn.execute("SELECT name FROM cameras WHERE id = ?", (id,)).fetchone()
        if row: device_name = row['name']
        
    conn.commit()
    conn.close()
    
    action_text = f"Silenced {device_type} '{device_name}' for {hours}h" if hours > 0 else f"Removed silence from {device_type} '{device_name}'"
    log_audit('User', current_user.username, action_text)
    force_disk_sync()
    trigger_monitor_check()
    
    return jsonify({'success': True})

@app.route('/api/ping', methods=['POST'])
@login_required
@operator_required
def manual_ping():
    ip = request.form.get('ip')
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
    target = request.form.get('target')
    sid = request.form.get('sid')
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
    sid = request.form.get('sid')
    log_audit('User', current_user.username, 'Initiated WAN Speedtest (Manual)')
    
    def execute_test():
        try:
            env = os.environ.copy()
            env['HOME'] = '/app/data_ram'
            
            cmd = ['speedtest', '--accept-license', '--accept-gdpr', '-f', 'json']
            primary_ip = get_primary_ip()
            if primary_ip:
                cmd.extend(['-i', primary_ip])
            
            process = eventlet.tpool.execute(subprocess.run, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60, env=env)
            
            data = None
            for line in reversed(process.stdout.splitlines()):
                line = line.strip()
                if line.startswith('{') and line.endswith('}'):
                    try:
                        data = json.loads(line)
                        break
                    except Exception: continue
            
            if process.returncode == 0 and data and 'download' in data:
                download = round((data['download']['bandwidth'] * 8) / 1000000, 2)
                upload = round((data['upload']['bandwidth'] * 8) / 1000000, 2)
                ping = round(data['ping']['latency'], 1)
                server_string = f"{data.get('server', {}).get('name', 'Unknown')} ({data.get('server', {}).get('location', 'Unknown')})"
                
                now = time.time()
                try:
                    conn = get_db()
                    log_status = f"DL: {download} Mbps | UL: {upload} Mbps | Ping: {ping} ms"
                    conn.execute("INSERT INTO event_logs (timestamp, device_type, device_name, status) VALUES (?, ?, ?, ?)", (now, 'Gateway', 'Speedtest (Manual)', log_status))
                    
                    st_data = json.dumps({'download': download, 'upload': upload, 'ping': ping, 'isp': data.get('isp', 'Unknown'), 'server': server_string, 'timestamp': now})
                    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('latest_speedtest', ?)", (st_data,))
                    conn.commit()
                    conn.close()
                    force_disk_sync()
                except Exception as e: print(f"DB Error saving speedtest: {e}")

                socketio.emit('speedtest_result', {'success': True, 'download': f"{download} Mbps", 'upload': f"{upload} Mbps", 'ping': f"{ping} ms", 'isp': data.get('isp', 'Unknown'), 'server': server_string, 'timestamp': now}, to=sid)
            else: 
                err_msg = "Unknown execution error."
                if data and 'error' in data: err_msg = data['error']
                elif process.stderr: err_msg = process.stderr.strip()
                
                try:
                    fallback_cmd = ['speedtest', '--accept-license', '--accept-gdpr', '-L', '-f', 'json']
                    if primary_ip:
                        fallback_cmd.extend(['-i', primary_ip])
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
        except Exception as e: 
            socketio.emit('speedtest_result', {'success': False, 'error': str(e)}, to=sid)

    eventlet.spawn(execute_test)
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
    conn.execute("UPDATE settings SET value = ? WHERE key = 'idle_timeout'", (request.form.get('idle_timeout', 20),))
    
    conn.execute("UPDATE settings SET value = ? WHERE key = 'smtp_host'", (request.form.get('smtp_host', ''),))
    conn.execute("UPDATE settings SET value = ? WHERE key = 'smtp_port'", (request.form.get('smtp_port', '587'),))
    conn.execute("UPDATE settings SET value = ? WHERE key = 'smtp_user'", (request.form.get('smtp_user', ''),))
    
    new_pass = request.form.get('smtp_pass', '')
    if new_pass: conn.execute("UPDATE settings SET value = ? WHERE key = 'smtp_pass'", (new_pass,))
    
    conn.execute("UPDATE settings SET value = ? WHERE key = 'smtp_target'", (request.form.get('smtp_target', ''),))
    
    conn.execute("UPDATE settings SET value = ? WHERE key = 'st_interval'", (request.form.get('st_interval', '0'),))
    conn.execute("UPDATE settings SET value = ? WHERE key = 'st_alert_dl'", (request.form.get('st_alert_dl', '0'),))
    conn.execute("UPDATE settings SET value = ? WHERE key = 'st_alert_ul'", (request.form.get('st_alert_ul', '0'),))
    conn.execute("UPDATE settings SET value = ? WHERE key = 'st_alert_ping'", (request.form.get('st_alert_ping', '0'),))
    
    conn.commit()
    conn.close()
    log_audit('User', current_user.username, 'Updated Global Gateway Settings (MQTT/SMTP/Alerts)') 
    force_disk_sync()
    trigger_monitor_check()
    flash('Settings updated.', 'success')
    return redirect(url_for('index'))

@app.route('/test_alert', methods=['POST'])
@login_required
@admin_required
def test_alert():
    global mqtt_client, mqtt_prefix_global
    if mqtt_client and mqtt_client.is_connected():
        try:
            mqtt_client.publish(f"{mqtt_prefix_global}/test_device/ping", "TEST_PING", retain=False)
            log_audit('User', current_user.username, 'Triggered test MQTT alert')
            flash(f'Test alert sent via active MQTT connection.', 'success')
        except Exception as e: 
            flash(f'MQTT Error: {str(e)}', 'danger')
    else:
        conn = get_db()
        settings_dict = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings").fetchall()}
        conn.close()
        try:
            client = mqtt.Client("camera_monitor_test")
            client.connect(settings_dict.get('mqtt_broker', '127.0.0.1'), int(settings_dict.get('mqtt_port', 1883)), 5)
            client.publish(f"{settings_dict.get('mqtt_prefix', 'zabbix/cctv')}/test_device/ping", "TEST_PING", retain=False)
            client.disconnect()
            log_audit('User', current_user.username, 'Triggered test MQTT alert (Fallback Connection)')
            flash(f'Test alert sent (Local fallback socket).', 'success')
        except Exception as e: flash(f'MQTT Error: {str(e)}', 'danger')
    return redirect(url_for('index'))

@app.route('/add_switch', methods=['POST'])
@login_required
@admin_required
def add_switch():
    conn = get_db()
    name = request.form['name']
    try:
        conn.execute("INSERT INTO switches (name, ip) VALUES (?, ?)", (name, request.form['ip']))
        conn.commit()
        log_audit('User', current_user.username, f'Added new switch: {name}')
        force_disk_sync()
        trigger_monitor_check()
        flash('Switch added.', 'success')
    except sqlite3.IntegrityError: flash('Switch name already exists.', 'danger')
    finally: conn.close()
    return redirect(url_for('index'))

@app.route('/edit_switch/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_switch(id):
    conn = get_db()
    if request.method == 'POST':
        name = request.form['name']
        try:
            conn.execute("UPDATE switches SET name = ?, ip = ? WHERE id = ?", (name, request.form['ip'], id))
            conn.commit()
            log_audit('User', current_user.username, f'Edited switch config: {name}')
            force_disk_sync()
            trigger_monitor_check()
            flash('Switch updated.', 'success')
            conn.close()
            return redirect(url_for('index'))
        except sqlite3.IntegrityError: flash('Switch name already exists.', 'danger')
    switch = conn.execute("SELECT * FROM switches WHERE id = ?", (id,)).fetchone()
    conn.close()
    return render_template('edit_switch.html', switch=switch)

@app.route('/delete_switch/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_switch(id):
    conn = get_db()
    row = conn.execute("SELECT name FROM switches WHERE id = ?", (id,)).fetchone()
    name = row['name'] if row else "Unknown"
    conn.execute("DELETE FROM cameras WHERE switch_id = ?", (id,))
    conn.execute("DELETE FROM switches WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    log_audit('User', current_user.username, f'Deleted switch: {name}')
    force_disk_sync()
    trigger_monitor_check()
    flash('Switch deleted.', 'success')
    return redirect(url_for('index'))

@app.route('/add_camera', methods=['POST'])
@login_required
@admin_required
def add_camera():
    switch_id = request.form.get('switch_id') or None
    name = request.form['name']
    conn = get_db()
    try:
        conn.execute("""INSERT INTO cameras (switch_id, name, ip, stream_url, manufacturer, username, password) VALUES (?, ?, ?, ?, ?, ?, ?)""", 
                     (switch_id, name, request.form['ip'], request.form['stream_url'], request.form.get('manufacturer', 'Other'), request.form.get('username', ''), encrypt_pwd(request.form.get('password', ''))))
        conn.commit()
        eventlet.spawn_n(sync_mediamtx_cameras)
        log_audit('User', current_user.username, f'Added new camera: {name}')
        force_disk_sync()
        trigger_monitor_check()
        flash('Camera added.', 'success')
    except sqlite3.IntegrityError: flash('Camera name already exists.', 'danger')
    finally: conn.close()
    return redirect(url_for('index'))

@app.route('/edit_camera/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_camera(id):
    conn = get_db()
    if request.method == 'POST':
        switch_id = request.form.get('switch_id') or None 
        name = request.form['name']
        try:
            conn.execute("""UPDATE cameras SET switch_id = ?, name = ?, ip = ?, stream_url = ?, manufacturer = ?, username = ?, password = ? WHERE id = ?""", 
                         (switch_id, name, request.form['ip'], request.form['stream_url'], request.form.get('manufacturer', 'Other'), request.form.get('username', ''), encrypt_pwd(request.form.get('password', '')), id))
            conn.commit()
            eventlet.spawn_n(sync_mediamtx_cameras)
            log_audit('User', current_user.username, f'Edited camera config: {name}')
            force_disk_sync()
            trigger_monitor_check()
            flash('Camera updated.', 'success')
            conn.close()
            return redirect(url_for('index'))
        except sqlite3.IntegrityError: flash('Camera name already exists.', 'danger')
    
    camera = conn.execute("SELECT * FROM cameras WHERE id = ?", (id,)).fetchone()
    if camera:
        camera = dict(camera)
        camera['password'] = decrypt_pwd(camera['password']) 
    switches = conn.execute("SELECT * FROM switches").fetchall()
    conn.close()
    return render_template('edit_camera.html', camera=camera, switches=switches)

@app.route('/delete_camera/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_camera(id):
    conn = get_db()
    row = conn.execute("SELECT name FROM cameras WHERE id = ?", (id,)).fetchone()
    name = row['name'] if row else "Unknown"
    conn.execute("DELETE FROM cameras WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    eventlet.spawn_n(sync_mediamtx_cameras)
    log_audit('User', current_user.username, f'Deleted camera: {name}')
    force_disk_sync()
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
        log_audit('User', current_user.username, f'Provisioned new account for: {username}')
        force_disk_sync()
        flash('User added.', 'success')
    except sqlite3.IntegrityError: flash('Username already exists.', 'danger')
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete_user/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_user(id):
    if id == current_user.id:
        flash('You cannot delete yourself.', 'danger')
        return redirect(url_for('index'))
    conn = get_db()
    row = conn.execute("SELECT username FROM users WHERE id = ?", (id,)).fetchone()
    uname = row['username'] if row else "Unknown"
    conn.execute("DELETE FROM users WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    log_audit('User', current_user.username, f'Deleted account: {uname}')
    force_disk_sync()
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
@csrf.exempt
@app.route('/tunnel/<device_type>/<int:device_id>/', defaults={'req_path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/tunnel/<device_type>/<int:device_id>/<path:req_path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
@operator_required
def tunnel(device_type, device_id, req_path):
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
    
    clean_headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'origin', 'referer', 'accept-encoding']}
    # Force the strict host header resolution
    clean_headers['Host'] = resolved_ip 
    target_url = f"http://{resolved_ip}/{full_req_path.lstrip('/')}"
    
    try:
        resp = requests.request(method=request.method, url=target_url, headers=clean_headers, data=request.get_data(), cookies=request.cookies, allow_redirects=False, stream=True, timeout=10, verify=False)
        if resp.status_code in [301, 302, 307, 308]:
            loc = resp.headers.get('Location', '')
            if loc.startswith(f"https://{device['ip']}") or loc.startswith(f"https://{resolved_ip}"):
                target_url = f"https://{resolved_ip}/{full_req_path.lstrip('/')}"
                resp = requests.request(method=request.method, url=target_url, headers=clean_headers, data=request.get_data(), cookies=request.cookies, allow_redirects=False, stream=True, timeout=10, verify=False)
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        
        for i, (name, value) in enumerate(resp_headers):
            if name.lower() == 'location':
                parsed = urlparse(value)
                if parsed.hostname in [device['ip'], resolved_ip]:
                    new_loc = f"/tunnel/{device_type}/{device_id}{parsed.path}"
                    if parsed.query: new_loc += f"?{parsed.query}"
                    resp_headers[i] = (name, new_loc)
                elif not parsed.hostname and value.startswith('/'):
                    resp_headers[i] = (name, f"/tunnel/{device_type}/{device_id}{value}")

        content_type = resp.headers.get('Content-Type', '').lower()
        if 'text/html' in content_type or 'javascript' in content_type or 'json' in content_type:
            payload = resp.content.decode('utf-8', errors='ignore')
            payload = re.sub(rf"(https?|wss?)://{re.escape(device['ip'])}(:\d+)?", f"http://{request.host}/tunnel/{device_type}/{device_id}", payload)
            payload = payload.replace(device['ip'], f"{request.host}/tunnel/{device_type}/{device_id}")
            if 'text/html' in content_type:
                base_tag = f'<base href="/tunnel/{device_type}/{device_id}/">\n'
                payload = re.sub(r'(<head[^>]*>)', rf'\1\n{base_tag}', payload, flags=re.IGNORECASE)
            return Response(payload, resp.status_code, resp_headers)
        else:
            return Response(resp.iter_content(chunk_size=10*1024), resp.status_code, resp_headers)
            
    except requests.exceptions.RequestException as e:
        return f"Tunnel Error connecting to {device['ip']}: {str(e)}", 502

@csrf.exempt
@app.errorhandler(404)
def proxy_absolute_paths(e):
    if not current_user.is_authenticated: return "404 - Not Found", 404
    if current_user.role not in ['admin', 'operator']: return "403 - Forbidden", 403 
    referer = request.headers.get('Referer')
    if referer:
        parsed_referer = urlparse(referer)
        parts = parsed_referer.path.split('/')
        if len(parts) >= 4 and parts[1] == 'tunnel':
            return tunnel(parts[2], parts[3], request.path)
    return "404 - Not Found", 404

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
                    with open(filepath, 'wb') as f: f.write(resp.content)
                    return f"{serve_path}?t={int(time.time())}"
            except Exception: pass
            if os.path.exists(filepath): return f"{serve_path}?t={int(os.path.getmtime(filepath))}"
            return val
        return val

    LOCAL_COMPANY_LOGO = process_logo('COMPANY_LOGO_URL', 'company_logo.png')
    LOCAL_CUSTOMER_LOGO = process_logo('CUSTOMER_LOGO_URL', 'customer_logo.png')

# ==========================================
# STARTUP INITIALIZATION
# ==========================================
try:
    init_db()
    init_logos()
    os.makedirs('/app/data', exist_ok=True)
    
    # Start background polling tasks
    socketio.start_background_task(monitor_loop)
    socketio.start_background_task(automated_speedtest_loop)
    socketio.start_background_task(sync_db_loop)
    socketio.start_background_task(log_prune_loop)
    
    # Sync SQLite cameras to MediaMTX WebRTC Relay on boot
    eventlet.spawn_n(sync_mediamtx_cameras)
    
except Exception as e: 
    print(f"Startup initialization error: {e}")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
