import os
import sys
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
BACKEND_DIR = os.path.join(PROJECT_ROOT, 'backend')
sys.path.insert(0, BACKEND_DIR)

# ── ANSI color codes for terminal output ──────────────────────────────
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def print_banner():
    banner = f"""
    {_CYAN}╔══════════════════════════════════════════════════╗
    ║     NIDS - Network Intrusion Detection System    ║
    ║              Live Detection Mode                  ║
    ╚══════════════════════════════════════════════════╝{_RESET}
    """
    print(banner)


def check_artifacts():
    """Verify all required model artifacts exist before starting."""
    required = [
        (os.path.join(MODELS_DIR, 'xgb_nids_engine.json'), 'Model'),
        (os.path.join(MODELS_DIR, 'robust_scaler.pkl'),   'Scaler'),
        (os.path.join(MODELS_DIR, 'attack_classes.pkl'),  'Labels'),
    ]
    missing = [f"  - {name}: {path}" for path, name in required if not os.path.exists(path)]
    if missing:
        print(f"{_RED}[!] Required model artifacts not found:{_RESET}")
        print("\n".join(missing))
        print(f"\n{_YELLOW}[!] Train the model first: python train_model.py{_RESET}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="NIDS Live Intrusion Detector — uses the once-trained model",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python run_detector.py                          # Live capture on default interface
  python run_detector.py --interface eth0          # Specific interface
  python run_detector.py --pcap captured.pcap      # Analyze PCAP file
  python run_detector.py --count 100               # Stop after 100 flows
  python run_detector.py --alert-only              # Show only alerts
  python run_detector.py --output alerts.csv        # Save alerts to CSV
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

    print_banner()
    check_artifacts()

    # Resolve paths
    model_path = args.model or os.path.join(MODELS_DIR, 'xgb_nids_engine.json')
    scaler_path = args.scaler or os.path.join(MODELS_DIR, 'robust_scaler.pkl')
    labels_path = args.labels or os.path.join(MODELS_DIR, 'attack_classes.pkl')
    proto_encoder_path = os.path.join(MODELS_DIR, 'protocol_encoder.pkl')

    # Import sniffer components
    from sniffer import NIDSClassifier, AlertLogger, LiveSniffer

    # Set up alert logging
    db_path = os.path.join(PROJECT_ROOT, 'nids.db')
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    csv_output = args.output or os.path.join(PROJECT_ROOT, 'logs', 'alerts.csv')

    import time
    import sqlite3
    
    def get_sniffer_state():
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM CONTROL_FLAGS WHERE key = 'sniffer_state'")
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else 'RUNNING'
        except Exception:
            return 'RUNNING'

    while True:
        state = get_sniffer_state()
        if state == 'STOP':
            print(f"{_YELLOW}[*] Sniffer is stopped via API. Waiting for restart...{_RESET}", end='\r')
            time.sleep(3)
            continue
            
        print(f"\n{_CYAN}[*]{_RESET} Initializing NIDS live detection system...")
        print(f"{_CYAN}[*]{_RESET} Model:      {model_path}")
        print(f"{_CYAN}[*]{_RESET} Alert DB:   {db_path}")
        print(f"{_CYAN}[*]{_RESET} Alert CSV:  {csv_output}")
        print()
    
        # Load classifier (model + scaler + label encoder)
        classifier = NIDSClassifier(model_path, scaler_path, labels_path, proto_encoder_path)
    
        # Set up alert logger
        alert_logger = AlertLogger(
            db_path=db_path,
            csv_path=csv_output if args.output else None,
            save_to_db=not args.no_save,
        )
    
        # Create and start the sniffer
        sniffer = LiveSniffer(
            classifier=classifier,
            alert_logger=alert_logger,
            interface=args.interface,
            count=args.count,
            alert_only=args.alert_only,
            pcap_file=args.pcap,
        )
    
        try:
            sniffer.start()
        except KeyboardInterrupt:
            print(f"\n{_YELLOW}[!] Detector stopped by user.{_RESET}")
            break
        except Exception as e:
            print(f"\n{_RED}[!] Detector error: {e}{_RESET}")
            sys.exit(1)
            
        state = get_sniffer_state()
        if state == 'RESTART':
            try:
                conn = sqlite3.connect(db_path)
                conn.execute("UPDATE CONTROL_FLAGS SET value = 'RUNNING' WHERE key = 'sniffer_state'")
                conn.commit()
                conn.close()
            except Exception: pass
            print(f"\n{_YELLOW}[!] Restarting sniffer...{_RESET}")
            time.sleep(2)
            continue
        elif state == 'STOP':
            print(f"\n{_YELLOW}[!] Sniffer stopped via API.{_RESET}")
            continue
        else:
            break


if __name__ == '__main__':
    main()
