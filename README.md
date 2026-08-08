# Network Intrusion Detection System (NIDS) — AI-Powered

A comprehensive machine learning pipeline and real-time dashboard that detects network intrusions. It utilizes a trained XGBoost model operating on the IDS2025 network flow dataset. It includes data preparation, GAN-based data augmentation for class balancing, a Flask Socket.IO API server, and a high-performance React dashboard featuring Chart.js visual analytics, severity filtering, slide-in toast notifications, dynamic subnet topology monitoring, and CSV report exports.

---

## Project Structure

```
Nid/
├── backend/                          # Python source code & ML pipeline
│   ├── api_server.py                 # Flask/Socket.IO API server bridging sniffer & frontend
│   ├── run_detector.py               # Run live intrusion detection (uses trained model)
│   ├── sniffer.py                    # Real-time packet capture engine & classifier
│   ├── train_model.py                # Train the model ONCE (feature → GAN → XGBoost)
│   ├── gan_augmenter.py              # PyTorch GAN Implementation
│   ├── train_xgboost.py              # XGBoost training pipeline
│   ├── data_prep.py                  # Feature engineering module
│   └── utils.py                      # Flow feature extraction utilities
├── frontend/                         # React-based live dashboard (Vite)
│   └── src/                          # Real-time dashboard UI source code
├── models/                           # Trained model artifacts
│   ├── attack_classes.pkl            # Label encoder (class names → IDs)
│   ├── robust_scaler.pkl             # Fitted StandardScaler
│   ├── xgb_nids_engine.json          # Trained XGBoost model (JSON format)
│   └── model.pkl                     # Trained XGBoost model (pickle format)
├── others/                           # Documentation, data, and logs
│   ├── doc/                          # Project documentation & reports
│   ├── Data/                         # Original dataset and processed files
│   ├── logs/                         # Runtime logs
│   └── PROJECT_CONTEXT.md            # Extensive historical project context
├── start_all.bat                     # Quick-start script to launch the full system
├── requirements.txt                  # Python dependencies
├── package.json                      # Node dependencies (in frontend/)
├── .gitignore
└── Readme.md
```

---

## Dataset: IDS2025

| Property | Value |
|----------|-------|
| Total rows | 91,830 |
| Features | 80 (flow statistics, packet lengths, flags, IAT, etc.) |
| Target column | `newLabel` |
| Classes | 7 |

### Class Distribution (Training Set)

| Class | Samples |
|-------|---------|
| Normal | 20,932 |
| Dos/DDos | 20,794 |
| PortScan | 20,310 |
| Brute Force | 8,158 |
| Web Attack | 1,654 |
| Botnet ARES | 1,491 |
| Infiltration | 23 |

---

## Quick Start: Running the Live System

We have created a single batch script that will launch the entire ecosystem (Frontend, Backend API, and Packet Sniffer) simultaneously. 

### Step 1: Run the Startup Script
The Packet Sniffer requires raw socket access to capture live network traffic, which means it **must** be run with Administrator privileges on Windows.
1. Open a terminal (Command Prompt or PowerShell) **as Administrator**.
2. Navigate to the root `Nid` folder.
3. Run the startup script:
   ```cmd
   .\start_all.bat
   ```

### Step 2: Verify the Services
The script will open three separate terminal windows:
- **Window 1 (Frontend)**: Starts a Vite server on `http://localhost:5173`.
- **Window 2 (API Server)**: Starts a Flask-SocketIO server on `http://localhost:5000`.
- **Window 3 (Packet Sniffer)**: Loads the XGBoost model and begins capturing packets.

### Step 3: View the Dashboard
1. Open Google Chrome, Firefox, or Edge.
2. Navigate to: [http://localhost:5173](http://localhost:5173)

You will now see the live dashboard! As the Packet Sniffer analyzes traffic, it will send the data to the API Server via WebSockets, which beams it in real-time to your React Dashboard. 

---

## Re-Training the Model

If you ever want to re-train the AI model from scratch on the IDS2025 dataset:

```bash
python backend/train_model.py              # Full pipeline (feature → GAN → XGBoost)
python backend/train_model.py --skip-gan   # Skip GAN for faster training
python backend/train_model.py --phase xgboost   # Only train XGBoost (if data already processed)
```

This runs: **Feature Engineering → GAN Augmentation (optional) → XGBoost Training** and saves all artifacts to `models/`.

### Run live detection manually via CLI

```bash
python backend/run_detector.py                          # Capture on default interface
python backend/run_detector.py --interface eth0          # Specific interface
python backend/run_detector.py --pcap traffic.pcap       # Analyze PCAP file
python backend/run_detector.py --alert-only              # Show only intrusion alerts
python backend/run_detector.py --output alerts.csv       # Save alerts to CSV
```

The CLI detector loads the trained model and captures live network traffic, printing **red intrusion alerts** in real-time to your terminal.

---

## Pipeline Overview

### Phase 1: Feature Engineering (`backend/data_prep.py`)

- Loads IDS2025.csv (91,830 rows × 80 columns)
- Cleans infinite/NaN values (254 bad rows dropped)
- Drops leaky features: `Source IP`, `Dest IP`, `Timestamp`, `Source Port`
- Bins `Destination Port` into 3 behavioral categories (well-known / registered / dynamic)
- Applies log1p transformation to 10 skewed volumetric features (byte counts, packet counts)
- Encodes `Protocol` field (text → numeric via LabelEncoder)
- Encodes target labels (`newLabel`)
- Splits data 80/20 with stratified sampling (73,362 train / 18,341 test)
- Standardizes features with StandardScaler
- Saves: `.npy` arrays, `robust_scaler.pkl`, `attack_classes.pkl`

### Phase 2: GAN Data Augmentation (`backend/gan_augmenter.py`)

- PyTorch GAN with Generator (3-layer) + Discriminator (3-layer)
- Trains a separate GAN for each minority attack class
- Evaluates real-time Discriminator Accuracy (D-Accuracy)
- Generates synthetic samples to match the majority class size
- Fixes severe class imbalance (e.g., Infiltration: 23 → 20,932 samples)
- Outputs: `X_train_balanced.npy`, `y_train_balanced.npy`

> **Note:** Phase 2 is optional. The pipeline works without it (99% accuracy), but GAN augmentation improves minority-class recall.

### Phase 3: XGBoost Training (`backend/train_xgboost.py`)

- Loads training data (balanced if GAN was run, otherwise original processed data)
- XGBoost classifier: 300 trees, max_depth=7, learning_rate=0.08
- Trains with early stopping monitoring on validation set
- Exports model to `xgb_nids_engine.json` and `model.pkl`

---

## Results

### Model Performance (without GAN augmentation)

```
Overall Accuracy: 99.00%

              precision    recall  f1-score   support
 Botnet ARES       0.99      0.99      0.99       373
 Brute Force       1.00      1.00      1.00      2040
    Dos/DDos       0.98      0.99      0.98      5199
Infiltration       1.00      0.67      0.80         6
      Normal       0.99      0.97      0.98      5233
    PortScan       1.00      1.00      1.00      5077
  Web Attack       1.00      1.00      1.00       413
```

> Infiltration recall (67%) is low due to only 23 training samples. Running Phase 2 (GAN) resolves this.

---

## Tech Stack

- **Python 3.14**
- **pandas** — Data loading & manipulation
- **NumPy** — Numerical operations
- **scikit-learn** — Preprocessing, metrics, train/test split
- **XGBoost** — Gradient boosted tree classifier
- **PyTorch** — GAN implementation for data augmentation
- **joblib** — Model serialization
- **Scapy** — Live packet capturing
- **Flask-SocketIO** — Real-time WebSockets API
- **React + Vite** — High-performance interactive dashboard frontend
- **SQLite** — Storage for captured network flows and intrusion logs