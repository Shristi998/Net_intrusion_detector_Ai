import os
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

def run_phase_1(csv_path, output_dir):
    print("=" * 60)
    print("  PHASE 1: FEATURE ENGINEERING PIPELINE")
    print("=" * 60)

    print(f"[*] Launching IDS2025 Feature Engineering Pipeline.....")
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Target dataset '{csv_path}' not found.")
    print("[*] Ingesting CSV rows...")
    df = pd.read_csv(csv_path)
    print(f"[+] Data loaded. Dimensions: {df.shape[0]} rows, {df.shape[1]} columns.")

    # STEP 1: CLEAN MATHEMATICAL ANOMALIES (Inf / NaN)
    print("[*] Cleaning network flow math calc limits (Infinities/Nulls)...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    missing_count = df.isnull().sum().sum()
    if missing_count > 0:
        print(f"[!] Warning: Found {missing_count} total missing/infinite data blocks. Clearing records...")
        df.dropna(inplace=True)

    # STEP 2: ISOLATE TARGET LABELS & DROP SOURCE PORT/IPs
    target_col = 'Label' if 'Label' in df.columns else 'newLabel'
    if target_col not in df.columns:
        raise ValueError(f"Critical target columns missing from your dataset layout.")
    y_raw = df[target_col]

    features_to_drop = [target_col]
    for col in ['Source Port', 'Source IP', 'Dest IP', 'Timestamp']:
        if col in df.columns:
            features_to_drop.append(col)

    X = df.drop(columns=features_to_drop)

    print("[*] Engineering Destination Port network profiles...")
    port_col = 'Destination Port' if 'Destination Port' in X.columns else 'Dst Port'
    if port_col in X.columns:
        X['PORT_WELL_KNOWN'] = (X[port_col] < 1024).astype(int)
        X['PORT_REGISTERED'] = ((X[port_col] >= 1024) & (X[port_col] < 49152)).astype(int)
        X['PORT_DYNAMIC'] = (X[port_col] >= 49152).astype(int)
        X.drop(columns=[port_col], inplace=True)

    # STEP 4: LOG TRANSFORM DISTRIBUTIONS FOR VOLUMETRIC DATA
    print("[*] Applying log scale transformation on skewed volumetric parameters...")
    skewed_network_features = [
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
        'Fwd Packets Length Total', 'Bwd Packets Length Total',
        'Flow Bytes/s', 'Flow Packets/s', 'Flow Bytess', 'Flow Packetss',
        'Fwd Packets/s', 'Bwd Packets/s', 'Fwd Packetss', 'Bwd Packetss',
        'Fwd Packet Length Max', 'Bwd Packet Length Max',
        'Fwd Packet Length Mean', 'Bwd Packet Length Mean'
    ]
    for feature in skewed_network_features:
        if feature in X.columns:
            X[feature] = np.log1p(np.maximum(0, pd.to_numeric(X[feature], errors='coerce').fillna(0)))

    # Fill any remaining NaNs across all features if present
    X.fillna(0, inplace=True)

    # STEP 5: CATEGORICAL PROTOCOL ENCODING
    if 'Protocol' in X.columns:
        if X['Protocol'].dtype == 'object':
            print("[*] Encoding text-based Protocol fields...")
            proto_encoder = LabelEncoder()
            X['Protocol'] = proto_encoder.fit_transform(X['Protocol'].astype(str))
            joblib.dump(proto_encoder, os.path.join(output_dir, "protocol_encoder.pkl"))

    # STEP 6: TARGET ENCODING
    print("[*] Encapsulating threat output class matrices...")
    target_encoder = LabelEncoder()
    y_encoded = target_encoder.fit_transform(y_raw)
    print(f"[+] Map Configuration Classes Verified: {dict(zip(target_encoder.classes_, target_encoder.transform(target_encoder.classes_)))}")

    print("[*] Splitting dataset into training and validation environments...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, stratify=y_encoded, random_state=42
    )

    print("[*] Normalizing continuous features with StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("[*] Serializing engineered scaling artifacts...")
    joblib.dump(scaler, os.path.join(output_dir, "robust_scaler.pkl"))
    joblib.dump(target_encoder, os.path.join(output_dir, "attack_classes.pkl"))

    np.save(os.path.join(output_dir, 'X_train_processed.npy'), X_train_scaled)
    np.save(os.path.join(output_dir, 'X_test_processed.npy'), X_test_scaled)
    np.save(os.path.join(output_dir, 'y_train.npy'), y_train)
    np.save(os.path.join(output_dir, 'y_test.npy'), y_test)

    print("\n" + "=" * 40)
    print("[+] SUCCESS: Feature Engineering Pipeline Completed.")
    print(f"    Processed Features Shape: {X_train_scaled.shape}")
    print("    Saved Artifacts: robust_scaler.pkl, attack_classes.pkl")
    print("=" * 40)
