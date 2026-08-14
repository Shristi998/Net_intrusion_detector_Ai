import pandas as pd
import numpy as np

input_path = r"e:\Nid\others\Data\raw\DoS1-Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"
output_path = r"e:\Nid\cleaned_dos_dataset.csv"

print(f"[*] Loading {input_path}...")
df = pd.read_csv(input_path)

print(f"[*] Original shape: {df.shape}")

# 1. Rename columns to match IDS2025 exactly
column_mapping = {
    'Fwd Packets Length Total': 'Total Length of Fwd Packets',
    'Bwd Packets Length Total': 'Total Length of Bwd Packets',
    'Flow Bytes/s': 'Flow Bytess',
    'Flow Packets/s': 'Flow Packetss',
    'Fwd Packets/s': 'Fwd Packetss',
    'Bwd Packets/s': 'Bwd Packetss',
    'Packet Length Min': 'Min Packet Length',
    'Packet Length Max': 'Max Packet Length',
    'Down/Up Ratio': 'Down Up Ratio',
    'Avg Packet Size': 'Average Packet Size',
    'Fwd Avg Bytes/Bulk': 'Fwd Avg Bytes Bulk',
    'Fwd Avg Packets/Bulk': 'Fwd Avg Packets Bulk',
    'Fwd Avg Bulk Rate': 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk': 'Bwd Avg Bytes Bulk',
    'Bwd Avg Packets/Bulk': 'Bwd Avg Packets Bulk',
    'Bwd Avg Bulk Rate': 'Bwd Avg Bulk Rate',
    'Init Fwd Win Bytes': 'Init_Win_bytes_forward',
    'Init Bwd Win Bytes': 'Init_Win_bytes_backward',
    'Fwd Act Data Packets': 'act_data_pkt_fwd',
    'Fwd Seg Size Min': 'min_seg_size_forward',
    'Label': 'newLabel'
}

df.rename(columns=column_mapping, inplace=True)

# 2. Inject Dummy Destination Port (used for binning in data_prep.py)
df['Destination Port'] = 80

# 3. Simplify Labels
# Map all 'Benign' to 'Normal' and any DoS to 'Dos/DDos'
df['newLabel'] = df['newLabel'].apply(lambda x: 'Normal' if x == 'Benign' else 'Dos/DDos')

# 4. Define exact column order expected by sniffer.py
ordered_columns = [
    'Protocol', 'Flow Duration',
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
    'Destination Port', 'newLabel'
]

print("[*] Reordering and saving dataset...")
try:
    df_ordered = df[ordered_columns]
    
    # Optional: downsample slightly if it's too huge, but usually full dataset is fine.
    df_ordered.to_csv(output_path, index=False)
    print(f"[+] Successfully saved cleaned dataset to {output_path}")
    print(f"    Final shape: {df_ordered.shape}")
except KeyError as e:
    print(f"[-] Error missing columns: {e}")
    missing = [c for c in ordered_columns if c not in df.columns]
    print(f"Missing from dataframe: {missing}")
