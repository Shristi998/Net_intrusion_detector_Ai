import sqlite3
import socketio
import time
import random
import os
from datetime import datetime, timezone

# Connect to SocketIO for real-time frontend updates
sio = socketio.Client(reconnection=True, reconnection_attempts=0, reconnection_delay=1, reconnection_delay_max=5)

db_path = "nids.db"

def connect_socket():
    try:
        sio.connect('http://localhost:5000')
        print("[+] Connected to NIDS API Server SocketIO")
    except Exception as e:
        print(f"[-] Could not connect to SocketIO: {e}")

def inject_packet(attack_class, confidence, severity):
    # Mock data
    src_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"
    dst_ip = "192.168.1.236"
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 53, 3306])
    protocol = random.choice([6, 17]) # 6 TCP, 17 UDP
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # 1. Save to SQLite
    try:
        # Ensure directory exists
        dirname = os.path.dirname(db_path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS TRAFFIC_LOG (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                destination_ip TEXT,
                port INTEGER,
                protocol TEXT,
                classification TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ALERT (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER,
                attack_type TEXT,
                severity_level TEXT,
                resolution_status TEXT,
                generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(log_id) REFERENCES TRAFFIC_LOG(log_id)
            )
        ''')
        
        cursor.execute('''
            INSERT INTO TRAFFIC_LOG (source_ip, destination_ip, port, protocol, classification, timestamp) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (src_ip, dst_ip, dst_port, str(protocol), attack_class, timestamp))
        log_id = cursor.lastrowid
        
        if attack_class != "Normal":
            cursor.execute('''
                INSERT INTO ALERT (log_id, attack_type, severity_level, resolution_status, generated_at) 
                VALUES (?, ?, ?, ?, ?)
            ''', (log_id, attack_class, severity, "Pending", timestamp))
            
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] Database Error: {e}")
        
    # 2. Emit via WebSocket
    if sio.connected:
        packet_data = {
            "timestamp": timestamp,
            "src": src_ip,
            "dst": dst_ip,
            "sport": src_port,
            "dport": dst_port,
            "proto": "TCP" if protocol == 6 else "UDP",
            "verdict": attack_class,
            "confidence": confidence,
            "length": random.randint(64, 4096),
            "latencyMs": round(random.uniform(0.1, 5.0), 2),
            "sev": severity,
            "type": attack_class
        }
        sio.emit('new_packet', packet_data)
        
    print(f"[*] Injected: {attack_class} (Conf: {confidence*100:.2f}%)")

def run_5x5_simulation():
    connect_socket()
    
    attacks = [
        ("Normal", 0.99, "Low"),
        ("PortScan", 0.98, "Medium"),
        ("Dos/DDos", 0.99, "Critical"),
        ("Brute Force", 0.97, "High"),
        ("Web Attack", 0.96, "High"),
        ("Botnet ARES", 0.99, "Critical"),
        ("Infiltration", 0.98, "Critical")
    ]
    
    print("\n==================================================")
    print("   STARTING DIRECT INJECTION SIMULATION (7 Classes)  ")
    print("==================================================")
    
    for attack_name, confidence, severity in attacks:
        print(f"\n[>>>] Commencing 5 loops of: {attack_name}")
        for i in range(5):
            print(f"      Loop {i+1}/5 ...")
            inject_packet(attack_name, confidence, severity)
            time.sleep(1) # Delay between packets
            
        print(f"[+] Finished 5 loops of {attack_name}.")
        time.sleep(3) # Delay between different attack types
        
    print("\n==================================================")
    print("   SIMULATION COMPLETE. Check NIDS Dashboard!       ")
    print("==================================================")
    
    if sio.connected:
        sio.disconnect()

if __name__ == "__main__":
    run_5x5_simulation()
