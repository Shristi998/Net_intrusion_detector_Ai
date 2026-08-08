import os
import sys
import numpy as np
import pandas as pd
import joblib
import pickle
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Ensure import paths
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
CSV_PATH = os.path.join(PROJECT_ROOT, "others", "Data", "raw", "IDS2025.csv")

if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import data_prep
import gan_augmenter

def print_section(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")

def print_confusion_matrix(cm, class_names):
    print("   CONFUSION MATRIX (rows = True Class, cols = Predicted Class):")
    print("   " + "-" * 65)
    header = "          " + " ".join([f"{str(c):>10s}" for c in class_names])
    print(header)
    for i, row in enumerate(cm):
        row_str = " ".join([f"{val:10d}" for val in row])
        print(f"   {class_names[i]:>10s} {row_str}")
    print("   " + "-" * 65)

def train_and_eval_xgb(X_train, y_train, X_test, y_test, class_names, model_name="XGBoost"):
    print(f"[*] Training {model_name}...")
    num_classes = len(class_names)
    
    xgb_device = 'cpu'
    model = xgb.XGBClassifier(
        n_estimators=50,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        objective='multi:softprob',
        num_class=num_classes,
        eval_metric='mlogloss',
        random_state=42,
        tree_method='hist',
        device=xgb_device
    )
    
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
    
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=class_names, output_dict=False)
    
    print(f"[+] {model_name} Overall Accuracy: {acc * 100:.2f}%\n")
    print(classification_report(y_test, y_pred, target_names=class_names))
    print_confusion_matrix(cm, class_names)
    
    return model, acc, cm, report

def main():
    if not os.path.exists(MODELS_DIR):
        os.makedirs(MODELS_DIR)

    # Change current directory to MODELS_DIR as expected by phases
    os.chdir(MODELS_DIR)

    print_section("STEP 1: FEATURE ENGINEERING PIPELINE (PHASE 1)")
    data_prep.run_phase_1(CSV_PATH, MODELS_DIR)

    # Load preprocessed matrices
    target_encoder = joblib.load(os.path.join(MODELS_DIR, 'attack_classes.pkl'))
    class_names = [str(cls) for cls in target_encoder.classes_]

    X_train_orig = np.load(os.path.join(MODELS_DIR, 'X_train_processed.npy'))
    y_train_orig = np.load(os.path.join(MODELS_DIR, 'y_train.npy'))
    X_test = np.load(os.path.join(MODELS_DIR, 'X_test_processed.npy'))
    y_test = np.load(os.path.join(MODELS_DIR, 'y_test.npy'))

    print_section("STEP 2: BASELINE XGBOOST MODEL (WITHOUT GAN)")
    xgb_base, acc_base, cm_base, _ = train_and_eval_xgb(
        X_train_orig, y_train_orig, X_test, y_test, class_names, "Baseline XGBoost Model (Original Imbalanced Data)"
    )

    print_section("STEP 3: GAN DATA AUGMENTATION (PHASE 2)")
    gan_augmenter.run_phase_2(MODELS_DIR)

    # Load GAN-balanced training set
    X_train_balanced = np.load(os.path.join(MODELS_DIR, 'X_train_balanced.npy'))
    y_train_balanced = np.load(os.path.join(MODELS_DIR, 'y_train_balanced.npy'))

    print_section("STEP 4: GAN-AUGMENTED XGBOOST MODEL (WITH GAN)")
    xgb_gan, acc_gan, cm_gan, _ = train_and_eval_xgb(
        X_train_balanced, y_train_balanced, X_test, y_test, class_names, "GAN-Augmented XGBoost Model (Balanced Data)"
    )

    # Evaluate pure synthetic data quality
    synthetic_mask = len(X_train_orig)
    if len(X_train_balanced) > synthetic_mask:
        print_section("STEP 5: PURE GAN SYNTHETIC MODEL EVALUATION")
        X_synth_only = X_train_balanced[synthetic_mask:]
        y_synth_only = y_train_balanced[synthetic_mask:]
        
        # Ensure all target classes are represented so XGBClassifier label inference succeeds
        present_classes = set(np.unique(y_synth_only))
        all_classes = set(range(len(class_names)))
        missing_classes = sorted(list(all_classes - present_classes))
        if missing_classes:
            extra_X, extra_y = [], []
            for mc in missing_classes:
                idx = np.where(y_train_orig == mc)[0]
                if len(idx) > 0:
                    extra_X.append(X_train_orig[idx[:1]])
                    extra_y.append(y_train_orig[idx[:1]])
            if extra_X:
                X_synth_only = np.vstack([X_synth_only] + extra_X)
                y_synth_only = np.concatenate([y_synth_only] + extra_y)

        try:
            _, acc_synth, cm_synth, _ = train_and_eval_xgb(
                X_synth_only, y_synth_only, X_test, y_test, class_names, "Pure GAN Synthetic-Trained Model"
            )
        except Exception as e:
            print(f"[!] Could not evaluate Pure GAN Synthetic model: {e}")

    # Save final operational model artifacts expected by the system
    output_model_path = os.path.join(MODELS_DIR, "xgb_nids_engine.json")
    xgb_gan.save_model(output_model_path)
    with open(os.path.join(MODELS_DIR, 'model.pkl'), 'wb') as f:
        pickle.dump(xgb_gan, f)

    print_section("MODEL TRAINING AND EVALUATION COMPLETE")
    print(f"Summary of Results:")
    print(f"1. Baseline XGBoost Accuracy: {acc_base * 100:.2f}%")
    print(f"2. GAN-Augmented XGBoost Accuracy: {acc_gan * 100:.2f}%")

if __name__ == "__main__":
    main()
