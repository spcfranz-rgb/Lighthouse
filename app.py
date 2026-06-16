import os
import time
import sqlite3
import subprocess
import threading
import paho.mqtt.client as mqtt
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)
DB_PATH = '/app/data/cctv.db'

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
    
    cursor.execute("SELECT count(*) FROM settings")
    if cursor.fetchone()[0] == 0:
        settings = [
            ('mqtt_broker', '192.168.1.50'),
            ('mqtt_port', '1883'),
            ('mqtt_prefix', 'zabbix/cctv'),
            ('check_interval', '60')
        ]
        cursor.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", settings)
    
    conn.commit()
    conn.close()
    print("Database initialized.")

# ==========================================
# BACKGROUND MONITORING TASK
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
                print(f"MQTT Connect failed: {e}")
            
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
@app.route('/')
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
    conn.close()
    
    return render_template('index.html', switches=switches, cameras=cameras, settings=settings_dict)

@app.route('/update_settings', methods=['POST'])
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
def add_switch():
    conn = get_db()
    conn.execute("INSERT INTO switches (name, ip) VALUES (?, ?)", (request.form['name'], request.form['ip']))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/add_camera', methods=['POST'])
def add_camera():
    conn = get_db()
    conn.execute("INSERT INTO cameras (switch_id, name, ip, stream_url) VALUES (?, ?, ?, ?)", 
                 (request.form['switch_id'], request.form['name'], request.form['ip'], request.form['stream_url']))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete_camera/<int:id>')
def delete_camera(id):
    conn = get_db()
    conn.execute("DELETE FROM cameras WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete_switch/<int:id>')
def delete_switch(id):
    conn = get_db()
    conn.execute("DELETE FROM cameras WHERE switch_id = ?", (id,))
    conn.execute("DELETE FROM switches WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
    app.run(host='0.0.0.0', port=5000, debug=False)
