#!/usr/bin/env python3
"""
NIDS Live Network Packet Capture & Intrusion Detection
=======================================================
Captures live network packets via Scapy, reconstructs bidirectional flows,
extracts 79 CICFlowMeter features, runs through the trained XGBoost model,
and classifies each flow as BENIGN or a specific attack type.

Usage:
    python scripts/sniffer.py                          # capture on default interface
    python scripts/sniffer.py --interface eth0          # specify interface
    python scripts/sniffer.py --pcap captured.pcap      # analyze from PCAP file
    python scripts/sniffer.py --count 100               # stop after 100 flows
    python scripts/sniffer.py --alert-only              # show only intrusion alerts
    python scripts/sniffer.py --output alerts.csv        # save alerts to CSV
    python scripts/sniffer.py --no-save                 # don't save to alert DB
"""

import os
import sys
import time
import json
import argparse
import logging
import threading
import queue
import csv
import sqlite3
import socketio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from collections import deque

import numpy as np
import joblib

# ── Colored logging formatter ─────────────────────────────────────────
# Uses ANSI escape codes so intrusion alerts (WARNING) appear in RED
# and other levels get distinct colors.
_RESET = "\033[0m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_BOLD = "\033[1m"

_LEVEL_COLORS = {
    logging.CRITICAL: _BOLD + _RED,
    logging.ERROR:    _RED,
    logging.WARNING:  _RED,
    logging.INFO:     _GREEN,
    logging.DEBUG:    _YELLOW,
}


class ColoredFormatter(logging.Formatter):
    """Log formatter that colourises the level-name / message by severity."""

    def format(self, record: logging.LogRecord) -> str:
        color = _LEVEL_COLORS.get(record.levelno, _RESET)
        # Timestamp + coloured level badge + message
        asctime = self.formatTime(record, self.datefmt)
        levelname = f"{color}[{record.levelname}]{_RESET}"
        msg = record.getMessage()
        # Intrusion alerts (WARNING) get the whole message in red
        if record.levelno == logging.WARNING:
            msg = f"{color}{msg}{_RESET}"
        return f"{asctime} {levelname} {msg}"


_handler = logging.StreamHandler()
_handler.setFormatter(ColoredFormatter('%(asctime)s [%(levelname)s] %(message)s',
                                       datefmt='%Y-%m-%d %H:%M:%S'))
logging.basicConfig(level=logging.INFO, handlers=[_handler])
logger = logging.getLogger("NIDS-Sniffer")

# --- Constants ---
BENIGN_LABEL = "Normal"
ALERT_DB_PATH = "nids.db"
DEFAULT_INTERFACE = None  # None = auto-detect
DEFAULT_SNAPLEN = 65535
DEFAULT_TIMEOUT = 300  # seconds

# Project root for model loading
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
BACKEND_DIR = os.path.join(PROJECT_ROOT, 'backend')
sys.path.insert(0, BACKEND_DIR)

from utils import (
    PacketInfo, FlowFeatures, FlowCollector, decode_tcp_flags,
    MIN_FLOW_PACKETS, FLOW_TIMEOUT, MAX_FLOW_DURATION
)


# ============================================================
#  DATA CLEANING & FEATURE PREPROCESSING PIPELINE
# ============================================================
class FeaturePreprocessor:
    """Applies the exact same cleaning + preprocessing pipeline used during training."""

    def __init__(self, scaler_path: str, protocol_encoder_path: Optional[str] = None):
        """
        Load preprocessing artifacts from training.
        
        Args:
            scaler_path: Path to robust_scaler.pkl
            protocol_encoder_path: Path to protocol_encoder.pkl (if exists)
        """
        self.scaler = joblib.load(scaler_path)
        if protocol_encoder_path and os.path.exists(protocol_encoder_path):
            self.proto_encoder = joblib.load(protocol_encoder_path)
        else:
            self.proto_encoder = None

        # Store the feature names in exact order the model expects
        # (after dropping Source Port, Source IP, Dest IP, Timestamp)
        self.feature_names = [
            'Destination Port', 'Protocol', 'Flow Duration',
            'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Max', 'Fwd Packet Length Min',
            'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min',
            'Bwd Packet Length Mean', 'Bwd Packet Length Std',
            'Flow Bytess', 'Flow Packetss',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
            'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packetss', 'Bwd Packetss',
            'Min Packet Length', 'Max Packet Length',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'CWE Flag Count', 'ECE Flag Count',
            'Down Up Ratio', 'Average Packet Size',
            'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Fwd Avg Bytes Bulk', 'Fwd Avg Packets Bulk', 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes Bulk', 'Bwd Avg Packets Bulk', 'Bwd Avg Bulk Rate',
            'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
            'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
        ]

        # Skewed features that need log1p transformation
        self.skewed_features = {
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Flow Bytess', 'Flow Packetss', 'Fwd Packetss', 'Bwd Packetss',
            'Fwd Packet Length Max', 'Bwd Packet Length Max',
            'Fwd Packet Length Mean', 'Bwd Packet Length Mean'
        }

    def clean(self, feature_vector: List[float]) -> np.ndarray:
        """Handle Inf/NaN values and apply preprocessing."""
        arr = np.array(feature_vector, dtype=np.float64)

        # STEP 1: Replace infinite values with NaN
        arr = np.where(np.isinf(arr), np.nan, arr)

        # STEP 2: If any NaN present, replace with 0.0 (the training pipeline drops NaN rows,
        #         but for live classification we impute to avoid losing the flow)
        if np.any(np.isnan(arr)):
            logger.debug("Flow contained NaN/infinite values. Imputing with 0.0 for live classification.")
            arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)

        return arr

    def transform(self, features: FlowFeatures) -> np.ndarray:
        """
        Apply the full preprocessing pipeline:
        1. Extract feature list from FlowFeatures dataclass
        2. Clean Inf/NaN
        3. Apply port binning (replace Destination Port with 3 binary flags)
        4. Apply log1p transformation to skewed features
        5. Scale using the saved StandardScaler
        Returns a 2D array of shape (1, n_features) ready for model inference.
        """
        # Get raw feature list (matches CSV column order from training)
        raw_list = features.to_list()

        # Build a dict for easier manipulation
        feature_dict = dict(zip(self.feature_names, raw_list))

        # STEP 3: BEHAVIORAL PORT BINNING (Destination Port → 3 categories)
        dst_port = feature_dict.get('Destination Port', 0.0)
        feature_dict['PORT_WELL_KNOWN'] = 1.0 if dst_port < 1024 else 0.0
        feature_dict['PORT_REGISTERED'] = 1.0 if 1024 <= dst_port < 49152 else 0.0
        feature_dict['PORT_DYNAMIC'] = 1.0 if dst_port >= 49152 else 0.0

        # STEP 4: LOG TRANSFORM on skewed volumetric features
        for feat_name in self.skewed_features:
            if feat_name in feature_dict:
                val = feature_dict[feat_name]
                feature_dict[feat_name] = np.log1p(max(float(val), 0.0))

        # STEP 5: Protocol encoding (if protocol_encoder exists, apply it)
        # Protocol from Scapy is already numeric (6=TCP, 17=UDP, etc.)
        # The training LabelEncoder mapped text→int; since our capture is already numeric,
        # we keep it as-is (models handle numeric protocols directly)
        if 'Protocol' in feature_dict:
            feature_dict['Protocol'] = float(feature_dict['Protocol'])

        # Map internal sniffer names to new CSV format names
        name_map = {
            'Total Length of Fwd Packets': 'Fwd Packets Length Total',
            'Total Length of Bwd Packets': 'Bwd Packets Length Total',
            'Flow Bytess': 'Flow Bytes/s',
            'Flow Packetss': 'Flow Packets/s',
            'Fwd Packetss': 'Fwd Packets/s',
            'Bwd Packetss': 'Bwd Packets/s',
            'Down Up Ratio': 'Down/Up Ratio',
            'Average Packet Size': 'Avg Packet Size',
            'Fwd Avg Bytes Bulk': 'Fwd Avg Bytes/Bulk',
            'Fwd Avg Packets Bulk': 'Fwd Avg Packets/Bulk',
            'Fwd Avg Bulk Rate': 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes Bulk': 'Bwd Avg Bytes/Bulk',
            'Bwd Avg Packets Bulk': 'Bwd Avg Packets/Bulk',
            'Bwd Avg Bulk Rate': 'Bwd Avg Bulk Rate',
            'Init_Win_bytes_forward': 'Init Fwd Win Bytes',
            'Init_Win_bytes_backward': 'Init Bwd Win Bytes',
            'act_data_pkt_fwd': 'Fwd Act Data Packets',
            'min_seg_size_forward': 'Fwd Seg Size Min',
            'Min Packet Length': 'Packet Length Min',
            'Max Packet Length': 'Packet Length Max',
        }
        for old_name, new_name in name_map.items():
            if old_name in feature_dict:
                feature_dict[new_name] = feature_dict.pop(old_name)

        final_feature_names = ['Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packets Length Total', 'Bwd Packets Length Total', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Min', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Avg Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Fwd Act Data Packets', 'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

        final_values = [float(feature_dict.get(name, 0.0)) for name in final_feature_names]
        arr = self.clean(final_values)

        # Reshape to 2D and scale
        arr_2d = arr.reshape(1, -1)
        scaled = self.scaler.transform(arr_2d)

        return scaled

    def transform_batch(self, features_list: List[FlowFeatures]) -> np.ndarray:
        """
        Apply the full preprocessing pipeline for a batch of flows.
        Returns a 2D array of shape (n_samples, n_features).
        """
        if not features_list:
            return np.empty((0, len(self.feature_names) + 2)) # +2 for port binning replacing 1

        all_final_values = []
        for features in features_list:
            raw_list = features.to_list()
            feature_dict = dict(zip(self.feature_names, raw_list))

            dst_port = feature_dict.get('Destination Port', 0.0)
            feature_dict['PORT_WELL_KNOWN'] = 1.0 if dst_port < 1024 else 0.0
            feature_dict['PORT_REGISTERED'] = 1.0 if 1024 <= dst_port < 49152 else 0.0
            feature_dict['PORT_DYNAMIC'] = 1.0 if dst_port >= 49152 else 0.0

            for feat_name in self.skewed_features:
                if feat_name in feature_dict:
                    val = feature_dict[feat_name]
                    feature_dict[feat_name] = np.log1p(max(float(val), 0.0))

            if 'Protocol' in feature_dict:
                feature_dict['Protocol'] = float(feature_dict['Protocol'])

            # Map internal sniffer names to new CSV format names
            name_map = {
                'Total Length of Fwd Packets': 'Fwd Packets Length Total',
                'Total Length of Bwd Packets': 'Bwd Packets Length Total',
                'Flow Bytess': 'Flow Bytes/s',
                'Flow Packetss': 'Flow Packets/s',
                'Fwd Packetss': 'Fwd Packets/s',
                'Bwd Packetss': 'Bwd Packets/s',
                'Down Up Ratio': 'Down/Up Ratio',
                'Average Packet Size': 'Avg Packet Size',
                'Fwd Avg Bytes Bulk': 'Fwd Avg Bytes/Bulk',
                'Fwd Avg Packets Bulk': 'Fwd Avg Packets/Bulk',
                'Fwd Avg Bulk Rate': 'Fwd Avg Bulk Rate',
                'Bwd Avg Bytes Bulk': 'Bwd Avg Bytes/Bulk',
                'Bwd Avg Packets Bulk': 'Bwd Avg Packets/Bulk',
                'Bwd Avg Bulk Rate': 'Bwd Avg Bulk Rate',
                'Init_Win_bytes_forward': 'Init Fwd Win Bytes',
                'Init_Win_bytes_backward': 'Init Bwd Win Bytes',
                'act_data_pkt_fwd': 'Fwd Act Data Packets',
                'min_seg_size_forward': 'Fwd Seg Size Min',
                'Min Packet Length': 'Packet Length Min',
                'Max Packet Length': 'Packet Length Max',
            }
            for old_name, new_name in name_map.items():
                if old_name in feature_dict:
                    feature_dict[new_name] = feature_dict.pop(old_name)

            final_feature_names = ['Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packets Length Total', 'Bwd Packets Length Total', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Min', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Avg Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Fwd Act Data Packets', 'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']
            final_values = [float(feature_dict.get(name, 0.0)) for name in final_feature_names]
            all_final_values.append(final_values)

        arr_2d = np.array(all_final_values, dtype=np.float64)
        
        # Clean Inf/NaN
        arr_2d = np.where(np.isinf(arr_2d), np.nan, arr_2d)
        if np.any(np.isnan(arr_2d)):
            logger.debug("Batch contained NaN/infinite values. Imputing with 0.0.")
            arr_2d = np.nan_to_num(arr_2d, nan=0.0, posinf=0.0, neginf=0.0)

        scaled = self.scaler.transform(arr_2d)
        return scaled


# ============================================================
#  ALERT LOGGING & DATABASE
# ============================================================
class AlertLogger:
    """Logs intrusion alerts to SQLite and optional CSV, and emits to Socket.IO."""

    def __init__(self, db_path: Optional[str] = None, csv_path: Optional[str] = None,
                 save_to_db: bool = True):
        if db_path is None:
            self.db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'nids.db')
        else:
            self.db_path = db_path
        
        self.csv_path = csv_path
        self.save_to_db = save_to_db
        
        self.sio = socketio.Client(reconnection=True, reconnection_attempts=0, reconnection_delay=1, reconnection_delay_max=5)
        try:
            self.sio.connect('http://localhost:5000')
            logger.info("Connected to local Socket.IO API server.")
        except Exception as e:
            logger.warning(f"Could not connect to Socket.IO API server: {e}. Will retry in background.")

        self._init_db()
        self._init_csv()

        self.alert_queue = queue.Queue()
        self.running = True
        self.db_thread = threading.Thread(target=self._db_worker, daemon=True)
        self.db_thread.start()

    def _init_db(self):
        if not self.save_to_db:
            return
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute("PRAGMA foreign_keys = ON;")
            cursor = self.conn.cursor()
            # Removed ADMINISTRATOR since we use USER
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS DATASET (
                    dataset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dataset_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    source_url TEXT,
                    upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    FOREIGN KEY (user_id) REFERENCES USER (user_id)
                        ON DELETE SET NULL
                        ON UPDATE CASCADE
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS USER (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    email TEXT,
                    role TEXT
                )
            ''')
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
                    log_id INTEGER NOT NULL,
                    user_id INTEGER,
                    attack_type TEXT,
                    severity_level TEXT,
                    resolution_status TEXT DEFAULT 'Open',
                    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (log_id) REFERENCES TRAFFIC_LOG (log_id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES USER (user_id)
                        ON DELETE SET NULL
                        ON UPDATE CASCADE
                )
            ''')
            self.conn.commit()
            logger.info(f"Connected to SQLite at {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to connect to SQLite: {e}")
            self.save_to_db = False

    def _init_csv(self):
        if self.csv_path:
            file_exists = os.path.exists(self.csv_path)
            if not file_exists:
                with open(self.csv_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                        'protocol', 'prediction', 'confidence', 'num_packets',
                        'flow_duration_us', 'total_bytes'
                    ])

    def log_alert(self, prediction: str, confidence: float, flow_info: Dict,
                  features: FlowFeatures, num_packets: int):
        """Record an intrusion alert (and emit all packets to live UI)."""
        timestamp = datetime.now(timezone.utc).isoformat()
        src_ip = flow_info.get('src_ip', '')
        dst_ip = flow_info.get('dst_ip', '')
        src_port = flow_info.get('src_port', 0)
        dst_port = flow_info.get('dst_port', 0)
        protocol = flow_info.get('protocol', 0)
        flow_duration = features.Flow_Duration
        total_bytes = int(features.Flow_Bytess)
        
        is_intrusion = prediction != BENIGN_LABEL
        sev = "Low"
        if is_intrusion:
            pred_lower = prediction.lower()
            if 'dos' in pred_lower or 'infiltration' in pred_lower or 'botnet' in pred_lower:
                sev = 'Critical'
            elif 'web' in pred_lower or 'brute' in pred_lower or 'sql' in pred_lower:
                sev = 'High'
            elif 'scan' in pred_lower or 'recon' in pred_lower:
                sev = 'Medium'
            else:
                sev = 'High'
        
        flags_list = []
        if getattr(features, 'FIN_Flag_Count', 0) > 0: flags_list.append('FIN')
        if getattr(features, 'SYN_Flag_Count', 0) > 0: flags_list.append('SYN')
        if getattr(features, 'RST_Flag_Count', 0) > 0: flags_list.append('RST')
        if getattr(features, 'PSH_Flag_Count', 0) > 0: flags_list.append('PSH')
        if getattr(features, 'ACK_Flag_Count', 0) > 0: flags_list.append('ACK')
        if getattr(features, 'URG_Flag_Count', 0) > 0: flags_list.append('URG')
        flags_str = ", ".join(flags_list) if flags_list else "None"
        
        packet_data = {
            "timestamp": timestamp,
            "src": src_ip,
            "dst": dst_ip,
            "sport": src_port,
            "dport": dst_port,
            "proto": "TCP" if protocol == 6 else "UDP" if protocol == 17 else "ICMP" if protocol == 1 else str(protocol),
            "verdict": prediction,
            "confidence": confidence,
            "length": total_bytes,
            "latencyMs": (flow_duration / 1000.0), # approx inference/latency representation
            "sev": sev,
            "type": prediction,
            "flags": flags_str,
            "num_packets": num_packets
        }
        
        self.alert_queue.put({
            "prediction": prediction,
            "confidence": confidence,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "src_port": src_port,
            "protocol": protocol,
            "num_packets": num_packets,
            "flow_duration": flow_duration,
            "total_bytes": total_bytes,
            "packet_data": packet_data,
        })

    def _db_worker(self):
        batch = []
        last_commit = time.time()
        while self.running or not self.alert_queue.empty():
            try:
                item = self.alert_queue.get(timeout=0.5)
                if item is None:
                    continue
                batch.append(item)
            except queue.Empty:
                pass

            now = time.time()
            if len(batch) >= 100 or (batch and now - last_commit > 1.0) or (not self.running and batch):
                self._flush_batch(batch)
                batch = []
                last_commit = time.time()

    def _flush_batch(self, batch):
        if not batch: return
        
        if not self.sio.connected:
            try:
                self.sio.connect('http://localhost:5000')
            except Exception:
                pass

        if self.sio.connected:
            for item in batch:
                try:
                    self.sio.emit('new_packet', item['packet_data'])
                except Exception:
                    pass

        if self.csv_path:
            try:
                with open(self.csv_path, 'a', newline='') as f:
                    writer = csv.writer(f)
                    for item in batch:
                        writer.writerow([
                            item['timestamp'], item['src_ip'], item['dst_ip'], item['src_port'], item['dst_port'],
                            item['protocol'], item['prediction'], item['confidence'], item['num_packets'],
                            item['flow_duration'], item['total_bytes']
                        ])
            except Exception as e:
                import logging
                logging.error(f"Failed CSV write: {e}")

        if self.save_to_db:
            try:
                self.conn.execute("BEGIN TRANSACTION")
                cursor = self.conn.cursor()
                for item in batch:
                    cursor.execute('''
                        INSERT INTO TRAFFIC_LOG (
                            source_ip, destination_ip, port, protocol, classification, timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        item['src_ip'], item['dst_ip'], item['dst_port'], str(item['protocol']), item['prediction'], item['timestamp']
                    ))
                    log_id = cursor.lastrowid
                    if item['prediction'] != BENIGN_LABEL:
                        severity = "High" if item['confidence'] > 0.9 else "Medium"
                        cursor.execute('''
                            INSERT INTO ALERT (
                                log_id, attack_type, severity_level, resolution_status, generated_at
                            ) VALUES (?, ?, ?, ?, ?)
                        ''', (
                            log_id, item['prediction'], severity, "Open", item['timestamp']
                        ))
                self.conn.commit()
            except Exception as e:
                self.conn.rollback()
                import logging
                logging.error(f"Failed SQLite write: {e}")

    def stop(self):
        self.running = False
        self.alert_queue.put(None)
        if hasattr(self, 'db_thread') and self.db_thread.is_alive():
            self.db_thread.join(timeout=5.0)


# ============================================================
#  MODEL LOADER & CLASSIFIER
# ============================================================
class NIDSClassifier:
    """Loads the trained XGBoost model and performs inference."""

    def __init__(self, model_path: str, scaler_path: str,
                 label_encoder_path: str,
                 protocol_encoder_path: Optional[str] = None):
        """
        Args:
            model_path: Path to xgb_nids_engine.json or model.pkl
            scaler_path: Path to robust_scaler.pkl
            label_encoder_path: Path to attack_classes.pkl
            protocol_encoder_path: Path to protocol_encoder.pkl
        """
        logger.info(f"Loading XGBoost model from {model_path}...")
        import xgboost as xgb
        self.model = xgb.XGBClassifier()
        self.model.load_model(model_path)
        logger.info("Model loaded successfully.")

        self.label_encoder = joblib.load(label_encoder_path)
        self.preprocessor = FeaturePreprocessor(scaler_path, protocol_encoder_path)

        self.class_names = list(self.label_encoder.classes_)
        self.num_classes = len(self.class_names)
        logger.info(f"Detected {self.num_classes} traffic classes: {self.class_names}")

    def classify(self, features: FlowFeatures) -> Tuple[str, float, np.ndarray]:
        """
        Classify a single flow.
        
        Returns:
            Tuple of (predicted_label, confidence, probability_array)
        """
        X_scaled = self.preprocessor.transform(features)
        probas = self.model.predict_proba(X_scaled)[0]
        predicted_idx = int(np.argmax(probas))
        predicted_label = self.class_names[predicted_idx]
        if predicted_label == "Benign":
            predicted_label = "Normal"
        confidence = float(probas[predicted_idx])
        
        # Apply strict confidence threshold to prevent false positives on loopback/internet traffic
        if predicted_label == 'Dos/DDos' and confidence < 0.99:
            predicted_label = BENIGN_LABEL
        elif predicted_label != BENIGN_LABEL and confidence < 0.95:
            predicted_label = BENIGN_LABEL
            
        return predicted_label, confidence, probas

    def classify_batch(self, features_list: List[FlowFeatures]) -> Tuple[List[str], List[float], np.ndarray]:
        """
        Classify a batch of flows.
        
        Returns:
            Tuple of (predicted_labels, confidences, probability_array)
        """
        if not features_list:
            return [], [], np.array([])
            
        X_scaled = self.preprocessor.transform_batch(features_list)
        probas_batch = self.model.predict_proba(X_scaled)
        
        predicted_indices = np.argmax(probas_batch, axis=1)
        predicted_labels = []
        confidences = []
        
        for i, idx in enumerate(predicted_indices):
            label = self.class_names[idx]
            if label == "Benign":
                label = "Normal"
            conf = float(probas_batch[i][idx])
            
            # Apply strict confidence threshold to reduce false positives
            if label == 'Dos/DDos' and conf < 0.99:
                label = BENIGN_LABEL
            elif label != BENIGN_LABEL and conf < 0.95:
                label = BENIGN_LABEL
                
            predicted_labels.append(label)
            confidences.append(conf)
        
        return predicted_labels, confidences, probas_batch

    def is_intrusion(self, label: str) -> bool:
        """Check if a predicted label represents an intrusion."""
        return label != BENIGN_LABEL


# ============================================================
#  PACKET SNIFFER (Scapy-based)
# ============================================================
class LiveSniffer:
    """Captures packets, aggregates into flows, classifies, and alerts."""

    def __init__(self, classifier: NIDSClassifier, alert_logger: AlertLogger,
                 interface: Optional[str] = None, count: int = 0,
                 alert_only: bool = False, pcap_file: Optional[str] = None):
        self.classifier = classifier
        self.alert_logger = alert_logger
        self.interface = interface
        self.max_flows = count  # 0 = unlimited
        self.alert_only = alert_only
        self.pcap_file = pcap_file

        self.flow_collector = FlowCollector()
        self.flow_count = 0
        self.intrusion_count = 0
        self.running = False
        self.lock = threading.Lock()
        self.packet_count = 0
        self.start_time = None
        self.classified_flow_count = 0

        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'intrusion_flows': 0,
            'benign_flows': 0,
            'classification_time_ms': [],
            'recent_alerts': deque(maxlen=20),
        }
        
        self.blacklist = set()
        self.last_blacklist_refresh = 0
        self.threat_counts = {}

    def _check_and_auto_block(self, src_ip: str, label: str):
        """Check threat threshold and automatically block malicious IP if limit is exceeded."""
        if not src_ip or src_ip in self.blacklist or src_ip.startswith("127.") or src_ip == "0.0.0.0":
            return
        
        self.threat_counts[src_ip] = self.threat_counts.get(src_ip, 0) + 1
        count = self.threat_counts[src_ip]
        
        autoblock_enabled = True
        threshold = 1  # Default to immediate block on 1st threat detection
        try:
            conn = sqlite3.connect(ALERT_DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM CONTROL_FLAGS WHERE key IN ('autoblock_enabled', 'autoblock_threshold')")
            flags = dict(cursor.fetchall())
            conn.close()
            autoblock_enabled = flags.get('autoblock_enabled', '1') == '1'
            threshold = int(flags.get('autoblock_threshold', '1'))
        except Exception:
            pass
            
        if autoblock_enabled and (count >= threshold or label != BENIGN_LABEL):
            reason = f"IMMEDIATE AUTO-BLOCK: Threat detected ({label})"
            logger.warning(f"[!] INSTANT BLOCK TRIGGERED for {src_ip}: {reason}")
            self.blacklist.add(src_ip)
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            try:
                conn = sqlite3.connect(ALERT_DB_PATH)
                conn.execute('''
                    INSERT INTO BLOCKED_IP (ip, reason, blocked_at, auto_blocked)
                    VALUES (?, ?, ?, 1)
                    ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, blocked_at=excluded.blocked_at, auto_blocked=1
                ''', (src_ip, reason, now_str))
                conn.commit()
                conn.close()
                
                # Emit WebSocket update if connected
                if hasattr(self, 'alert_logger') and hasattr(self.alert_logger, 'sio') and self.alert_logger.sio.connected:
                    try:
                        self.alert_logger.sio.emit('blocked_ip_update', {
                            'action': 'block',
                            'ip': src_ip,
                            'reason': reason,
                            'blocked_at': now_str,
                            'auto_blocked': True
                        })
                    except Exception:
                        pass
                
                try:
                    subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name=NIDS_Block_{src_ip}', 'dir=in', 'action=block', f'remoteip={src_ip}'], capture_output=True)
                except Exception:
                    pass
            except Exception as e:
                logger.error(f"Error persisting auto-block rule for {src_ip}: {e}")

    def _scapy_callback(self, pkt):
        """Callback for each captured packet (runs in Scapy thread).
        Silently aggregates packets into flows. No raw packet output."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            from scapy.layers.inet import IP as IPLayer

            if not pkt.haslayer(IPLayer):
                return

            ip_layer = pkt[IPLayer]
            
            # Periodically refresh blacklist (every 5 seconds)
            current_time = time.time()
            if current_time - self.last_blacklist_refresh > 5:
                self.last_blacklist_refresh = current_time
                try:
                    conn = sqlite3.connect(ALERT_DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("SELECT ip FROM BLOCKED_IP")
                    self.blacklist = set(row[0] for row in cursor.fetchall())
                    conn.close()
                except Exception:
                    pass
            
            if ip_layer.src in self.blacklist or ip_layer.dst in self.blacklist:
                return
                
            timestamp = pkt.time if hasattr(pkt, 'time') else current_time

            # Determine protocol
            if pkt.haslayer(TCP):
                proto = 6
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = decode_tcp_flags(pkt[TCP].flags)
                header_len = (ip_layer.ihl * 4) + (pkt[TCP].dataofs * 4) if hasattr(pkt[TCP], 'dataofs') else 40
                tcp_window = pkt[TCP].window if hasattr(pkt[TCP], 'window') else 0
            elif pkt.haslayer(UDP):
                proto = 17
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                flags = 0
                header_len = ip_layer.ihl * 4 + 8  # UDP header is 8 bytes
                tcp_window = 0
            elif pkt.haslayer(ICMP):
                proto = 1
                sport = 0
                dport = 0
                flags = 0
                header_len = ip_layer.ihl * 4 + 8
                tcp_window = 0
            else:
                proto = ip_layer.proto
                sport = 0
                dport = 0
                flags = 0
                header_len = ip_layer.ihl * 4
                tcp_window = 0

            packet_info = PacketInfo(
                timestamp=timestamp,
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=sport,
                dst_port=dport,
                protocol=proto,
                length=ip_layer.len,
                flags=flags,
                header_len=header_len,
                tcp_window=tcp_window,
                urgent=bool(flags & 0x20),
                push=bool(flags & 0x08),
            )

            with self.lock:
                self.packet_count += 1
                self.stats['total_packets'] += 1
                self.flow_collector.add_packet(packet_info)

        except Exception as e:
            logger.debug(f"Error processing packet: {e}")

    def _process_ready_flows(self):
        """Process flows that are ready for classification."""
        ready_flows = self.flow_collector.get_ready_flows()
        if not ready_flows:
            return

        flow_keys = []
        features_list = []
        for flow_key, features in ready_flows.items():
            if self.max_flows > 0 and self.flow_count >= self.max_flows:
                break
            flow_keys.append(flow_key)
            features_list.append(features)

        if not features_list:
            return

        try:
            t0 = time.perf_counter()
            labels, confidences, probas_batch = self.classifier.classify_batch(features_list)
            elapsed = (time.perf_counter() - t0) * 1000
            self.stats['classification_time_ms'].append(elapsed)

            for i, flow_key in enumerate(flow_keys):
                label = labels[i]
                confidence = confidences[i]
                features = features_list[i]
                
                # Apply confidence threshold
                if confidence < 0.50:
                    label = BENIGN_LABEL
                    
                src_ip, src_port, dst_ip, dst_port, proto = flow_key
                
                # Heuristic to eliminate false positives for DoS
                if label == 'Dos/DDos':
                    total_pkts = features.Total_Fwd_Packets + features.Total_Backward_Packets
                    # Real DoS attacks have many packets. Background web browsing does not.
                    if total_pkts < 20:
                        label = BENIGN_LABEL
                    # Whitelist common Google/Cloud subnets that trigger false positives during normal browsing
                    elif dst_ip.startswith(('142.', '34.', '172.217', '104.', '166.', '23.')):
                        label = BENIGN_LABEL
                
                flow_info = {
                    'src_ip': src_ip, 'dst_ip': dst_ip,
                    'src_port': src_port, 'dst_port': dst_port,
                    'protocol': proto,
                }

                is_intrusion = self.classifier.is_intrusion(label)
                self.flow_count += 1
                self.stats['total_flows'] += 1

                # Socket emission was moved to alert_logger._flush_batch()

                # Always log the alert so it emits to the WebSocket UI
                self.alert_logger.log_alert(
                    prediction=label,
                    confidence=confidence,
                    flow_info=flow_info,
                    features=features,
                    num_packets=int(features.Flow_Packetss),
                )

                if is_intrusion:
                    self.intrusion_count += 1
                    self.stats['intrusion_flows'] += 1
                    self._check_and_auto_block(src_ip, label)
                    alert_msg = (
                        f"[!] INTRUSION DETECTED: {label} "
                        f"({confidence*100:.1f}% conf) | "
                        f"{src_ip}:{src_port} → {dst_ip}:{dst_port} "
                        f"proto={proto} | {int(features.Flow_Packetss)} pkts | "
                        f"duration={features.Flow_Duration:.0f}µs"
                    )
                    logger.warning(alert_msg)
                    self.stats['recent_alerts'].append(alert_msg)
                else:
                    self.stats['benign_flows'] += 1
                    if not self.alert_only:
                        logger.info(
                            f"    BENIGN flow classified | "
                            f"{src_ip}:{src_port} → {dst_ip}:{dst_port} "
                            f"| {label} ({confidence*100:.0f}%)"
                        )

        except Exception as e:
            logger.error(f"Error classifying batch of flows: {e}", exc_info=True)

    def _monitor_loop(self):
        """Background thread that periodically checks for ready flows."""
        while self.running:
            try:
                # Poll the database for control flags
                try:
                    conn = sqlite3.connect(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'nids.db'))
                    cursor = conn.cursor()
                    cursor.execute("SELECT value FROM CONTROL_FLAGS WHERE key = 'sniffer_state'")
                    row = cursor.fetchone()
                    conn.close()
                    
                    if row and row[0] in ['STOP', 'RESTART']:
                        logger.warning(f"Received {row[0]} signal from API. Stopping capture...")
                        self.running = False
                        break
                except Exception as db_e:
                    pass

                with self.lock:
                    self._process_ready_flows()
                    # Cleanup stale flows every 60 seconds
                    if self.flow_count % 50 == 0 and self.flow_count > 0:
                        self.flow_collector.cleanup_stale_flows()
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
            time.sleep(2.0)  # Check every two seconds

    def print_banner(self):
        """Display startup banner."""
        banner = """
    ╔══════════════════════════════════════════════════╗
    ║     NIDS - Network Intrusion Detection System    ║
    ║         Live Packet Capture & Classification     ║
    ╚══════════════════════════════════════════════════╝
    """
        logger.info(banner)

    def print_stats(self):
        """Print summary statistics."""
        logger.info("=" * 60)
        logger.info("  CAPTURE STATISTICS")
        logger.info("=" * 60)
        logger.info(f"  Total packets captured:  {self.stats['total_packets']}")
        logger.info(f"  Total flows classified:  {self.stats['total_flows']}")
        logger.info(f"  Benign flows:            {self.stats['benign_flows']}")
        logger.info(f"  Intrusion flows:         {self.stats['intrusion_flows']}")
        if self.stats['classification_time_ms']:
            avg_time = np.mean(self.stats['classification_time_ms'])
            logger.info(f"  Avg classification time: {avg_time:.2f} ms")
        if self.start_time:
            elapsed = time.time() - self.start_time
            logger.info(f"  Total runtime:           {elapsed:.1f}s")
        if self.stats['recent_alerts']:
            logger.info(f"\n  Recent Alerts ({len(self.stats['recent_alerts'])}):")
            for alert in list(self.stats['recent_alerts'])[-10:]:
                logger.info(f"    {alert}")
        logger.info("=" * 60)

    def start(self):
        """Start live capture or PCAP file analysis."""
        self.print_banner()

        if self.pcap_file:
            self._process_pcap(self.pcap_file)
            self.print_stats()
            return

        # Live capture mode
        try:
            import scapy.all as scapy
        except ImportError:
            logger.error(
                "Scapy is required for live packet capture.\n"
                "Install with: pip install scapy"
            )
            sys.exit(1)

        # Auto-detect interface
        if self.interface is None:
            try:
                self.interface = scapy.conf.iface
                logger.info(f"Using default interface: {self.interface}")
            except Exception:
                # Fallback: list available interfaces
                logger.info("No default interface. Available interfaces:")
                try:
                    for iface_name in scapy.get_if_list():
                        logger.info(f"  - {iface_name}")
                except Exception:
                    logger.warning("Could not list interfaces. Trying 'eth0'...")
                self.interface = 'eth0'

        logger.info(f"Starting packet capture on interface: {self.interface}")
        logger.info("Press Ctrl+C to stop capture and view statistics.\n")

        self.running = True
        self.start_time = time.time()

        # Start monitor thread
        monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()

        def stop_check(pkt):
            return not self.running

        try:
            # Start Scapy sniffing (blocking)
            scapy.sniff(
                iface=self.interface,
                prn=self._scapy_callback,
                store=False,  # Don't store packets in memory
                filter=None,  # Capture all traffic
                stop_filter=stop_check,
            )
        except PermissionError:
            logger.error(
                "Permission denied. Run with administrator/root privileges:\n"
                "  Windows: Run as Administrator\n"
                "  Linux:   sudo python scripts/sniffer.py"
            )
            self.running = False
            return
        except KeyboardInterrupt:
            logger.info("\nCapture interrupted by user.")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.running = False
            # Wait for remaining flows to complete
            logger.info("Processing remaining flows...")
            time.sleep(2)
            with self.lock:
                self._process_ready_flows()
            self.alert_logger.stop()
            self.print_stats()

    def _process_pcap(self, pcap_path: str):
        """Process a pre-recorded PCAP file."""
        try:
            import scapy.all as scapy
        except ImportError:
            logger.error("Scapy is required. Install with: pip install scapy")
            sys.exit(1)

        if not os.path.exists(pcap_path):
            logger.error(f"PCAP file not found: {pcap_path}")
            return

        logger.info(f"Processing PCAP file: {pcap_path}")
        self.running = True
        self.start_time = time.time()

        try:
            # Read all packets from PCAP
            packets = scapy.rdpcap(pcap_path)
            logger.info(f"Loaded {len(packets)} packets from PCAP.")

            for i, pkt in enumerate(packets):
                if self.max_flows > 0 and self.flow_count >= self.max_flows:
                    break
                self._scapy_callback(pkt)
                if i % 10000 == 0 and i > 0:
                    logger.info(f"Processed {i}/{len(packets)} packets...")

            logger.info("All packets processed. Finalizing flows...")

            # Force-classify all remaining flows
            with self.lock:
                remaining = dict(self.flow_collector.flows)
                self.flow_collector.flows.clear()

            for flow_key, flow_state in remaining.items():
                if flow_state.total_pkts >= MIN_FLOW_PACKETS:
                    if self.max_flows > 0 and self.flow_count >= self.max_flows:
                        break
                    try:
                        t0 = time.perf_counter()
                        features = self.flow_collector.extract_features(flow_state)
                        label, confidence, probas = self.classifier.classify(features)
                        
                        # Apply confidence threshold
                        if confidence < 0.50:
                            label = BENIGN_LABEL
                            
                        elapsed = (time.perf_counter() - t0) * 1000
                        self.stats['classification_time_ms'].append(elapsed)

                        src_ip, src_port, dst_ip, dst_port, proto = flow_key
                        flow_info = {
                            'src_ip': src_ip, 'dst_ip': dst_ip,
                            'src_port': src_port, 'dst_port': dst_port,
                            'protocol': proto,
                        }

                        is_intrusion = self.classifier.is_intrusion(label)
                        self.flow_count += 1
                        self.stats['total_flows'] += 1

                        if is_intrusion:
                            self.intrusion_count += 1
                            self.stats['intrusion_flows'] += 1
                            self.alert_logger.log_alert(
                                prediction=label,
                                confidence=confidence,
                                flow_info=flow_info,
                                features=features,
                                num_packets=flow_state.total_pkts,
                            )
                            logger.warning(
                                f"[!] INTRUSION: {label} ({confidence*100:.1f}%) | "
                                f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
                            )
                        else:
                            self.stats['benign_flows'] += 1
                    except Exception as e:
                        logger.error(f"Error classifying flow: {e}")

        except Exception as e:
            logger.error(f"PCAP processing error: {e}")
        finally:
            self.running = False


# ============================================================
#  MAIN ENTRY POINT
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="NIDS Live Packet Capture & Intrusion Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/sniffer.py                          # Live capture on default interface
  python scripts/sniffer.py --interface eth0          # Specific interface
  python scripts/sniffer.py --pcap captured.pcap      # Analyze PCAP file
  python scripts/sniffer.py --count 100               # Stop after 100 flows
  python scripts/sniffer.py --alert-only              # Show only alerts
  python scripts/sniffer.py --output alerts.csv        # Save alerts to CSV
  python scripts/sniffer.py --no-save                 # Don't save to DB
        """
    )
    parser.add_argument('--interface', '-i', type=str, default=None,
                        help='Network interface to capture on (default: auto-detect)')
    parser.add_argument('--pcap', '-p', type=str, default=None,
                        help='PCAP file to analyze instead of live capture')
    parser.add_argument('--count', '-c', type=int, default=0,
                        help='Stop after N flows classified (0=unlimited)')
    parser.add_argument('--alert-only', '-a', action='store_true',
                        help='Only show intrusion alerts (suppress benign flow output)')
    parser.add_argument('--output', '-o', type=str, default=None,
                        help='CSV file path to save intrusion alerts')
    parser.add_argument('--no-save', action='store_true',
                        help='Disable saving alerts to the SQLite database')
    parser.add_argument('--model', '-m', type=str, default=None,
                        help='Path to XGBoost model (default: models/xgb_nids_engine.json)')
    parser.add_argument('--scaler', '-s', type=str, default=None,
                        help='Path to scaler (default: models/robust_scaler.pkl)')
    parser.add_argument('--labels', '-l', type=str, default=None,
                        help='Path to label encoder (default: models/attack_classes.pkl)')

    args = parser.parse_args()

    # Resolve model paths
    model_path = args.model or os.path.join(MODELS_DIR, 'xgb_nids_engine.json')
    scaler_path = args.scaler or os.path.join(MODELS_DIR, 'robust_scaler.pkl')
    labels_path = args.labels or os.path.join(MODELS_DIR, 'attack_classes.pkl')
    proto_encoder_path = os.path.join(MODELS_DIR, 'protocol_encoder.pkl')

    # Verify model files exist
    for path, name in [(model_path, "Model"), (scaler_path, "Scaler"), (labels_path, "Labels")]:
        if not os.path.exists(path):
            logger.error(f"{name} file not found: {path}")
            logger.error("Run 'python run_training.py' first to train the model.")
            sys.exit(1)

    # Initialize components
    logger.info("Initializing NIDS live capture system...")
    classifier = NIDSClassifier(model_path, scaler_path, labels_path, proto_encoder_path)
    alert_logger = AlertLogger(
        db_path=None,
        csv_path=args.output,
        save_to_db=not args.no_save,
    )

    sniffer = LiveSniffer(
        classifier=classifier,
        alert_logger=alert_logger,
        interface=args.interface,
        count=args.count,
        alert_only=args.alert_only,
        pcap_file=args.pcap,
    )

    sniffer.start()


if __name__ == '__main__':
    main()