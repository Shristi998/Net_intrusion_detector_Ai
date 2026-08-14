"""
NIDS Training Pipeline Orchestrator
===================================
Orchestrates the model training process by running separate modules.
Runs: Feature Engineering → GAN Augmentation (optional) → XGBoost Training

Usage:
    python train_model.py                  # Full pipeline
    python train_model.py --phase feature  # Only feature engineering
    python train_model.py --phase gan      # Only GAN augmentation
    python train_model.py --phase xgboost  # Only XGBoost training
    python train_model.py --skip-gan       # Skip GAN for faster training
"""

import os
import sys
import argparse

import data_prep
import gan_augmenter
import train_xgboost

def main():
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
    
    # Ensure models directory exists
    if not os.path.exists(MODELS_DIR):
        os.makedirs(MODELS_DIR)

    # We need to change to the MODELS_DIR because Phase 2 & 3 expect to load/save .npy and .pkl files from the current working directory
    # Note: Phase 1 (data_prep) has been updated to use output_dir for saves.
    os.chdir(MODELS_DIR)
    
    parser = argparse.ArgumentParser(description="NIDS Training Pipeline")
    parser.add_argument('--phase', choices=['all', 'feature', 'gan', 'xgboost'], default='all',
                        help="Phase to run: 'feature', 'gan', 'xgboost', or 'all'")
    parser.add_argument('--skip-gan', action='store_true', help='Skip GAN augmentation')
    parser.add_argument('--csv', type=str, default=None, help='Path to custom dataset CSV')
    args = parser.parse_args()

    CSV_PATH = args.csv if args.csv else os.path.join(PROJECT_ROOT, "others", "Data", "raw", "IDS2025.csv")

    # ============================================================
    #  PHASE 1: FEATURE ENGINEERING
    # ============================================================
    if args.phase in ['all', 'feature']:
        data_prep.run_phase_1(CSV_PATH, MODELS_DIR)

    # ============================================================
    #  PHASE 2: GAN DATA AUGMENTATION
    # ============================================================
    run_gan = args.phase in ['all', 'gan'] and not (args.phase == 'all' and args.skip_gan)

    if not run_gan:
        if args.phase == 'all' and args.skip_gan:
            print("\n" + "=" * 60)
            print("  PHASE 2: GAN DATA AUGMENTATION - SKIPPED")
            print("=" * 60)
    else:
        gan_augmenter.run_phase_2(MODELS_DIR)

    # ============================================================
    #  PHASE 3: XGBOOST TRAINING
    # ============================================================
    if args.phase in ['all', 'xgboost']:
        train_xgboost.run_phase_3(MODELS_DIR)


if __name__ == "__main__":
    main()
