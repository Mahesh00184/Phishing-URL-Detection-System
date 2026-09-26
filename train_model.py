"""
Model Training Script for Phishing URL Detection System.
Trains a Random Forest Classifier on lexical & structural URL features.
Saves model artifact to models/phishing_model.pkl.
"""

import os
import csv
import json
import time
import numpy as np
import joblib

try:
    from sklearn.ensemble import RandomForestClassifier
except (ImportError, Exception):
    from sklearn.ensemble._forest import RandomForestClassifier

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from utils.url_features import extract_feature_vector, FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "phishing_urls.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")


def load_dataset(csv_path: str):
    """Loads URL dataset from CSV using standard library for zero-dependency reliability."""
    urls = []
    labels = []
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            u = row.get("url", "").strip()
            l = row.get("label", "").strip()
            if u and l in ["0", "1"]:
                urls.append(u)
                labels.append(int(l))
    return urls, labels


def train():
    print("=" * 65)
    print("  PHISHING URL DETECTION SYSTEM - MODEL TRAINING PIPELINE")
    print("=" * 65)

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}!")

    os.makedirs(MODEL_DIR, exist_ok=True)

    print(f"[*] Loading dataset from: {DATASET_PATH}")
    urls, raw_labels = load_dataset(DATASET_PATH)
    total_records = len(urls)
    print(f"[+] Loaded {total_records} total URL records.")
    
    legit_cnt = sum(1 for l in raw_labels if l == 0)
    phish_cnt = sum(1 for l in raw_labels if l == 1)
    print(f"    - Legitimate (0): {legit_cnt}")
    print(f"    - Phishing   (1): {phish_cnt}")

    print("\n[*] Extracting 18 lexical and structural cybersecurity features...")
    start_time = time.time()
    
    feature_matrix = []
    labels = []
    
    for u, l in zip(urls, raw_labels):
        try:
            vec = extract_feature_vector(u)
            feature_matrix.append(vec)
            labels.append(l)
        except Exception as e:
            print(f"[!] Warning: Skipped URL '{u}' due to error: {e}")

    X = np.array(feature_matrix)
    y = np.array(labels)
    extract_time = time.time() - start_time
    print(f"[+] Feature extraction completed in {extract_time:.2f}s. Matrix shape: {X.shape}")

    # Split dataset into 80% train, 20% test (stratified)
    print("\n[*] Splitting dataset (80% Train, 20% Test, Stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"    - Training samples: {X_train.shape[0]}")
    print(f"    - Testing samples:  {X_test.shape[0]}")

    print("\n[*] Training Random Forest Classifier (n_estimators=100, max_depth=14)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=14,
        min_samples_split=2,
        random_state=42,
        n_jobs=1
    )
    clf.fit(X_train, y_train)
    print("[+] Model fitting finished successfully.")

    # Evaluate model
    print("\n" + "=" * 65)
    print("  MODEL EVALUATION ON TEST SET (20%)")
    print("=" * 65)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Phishing (1)"], output_dict=True)
    report_text = classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Phishing (1)"])

    print(f"Accuracy Score: {acc * 100:.2f}%\n")
    print("Confusion Matrix:")
    print(f" [[True Negative: {cm[0][0]:3d}  | False Positive: {cm[0][1]:3d}]")
    print(f"  [False Negative: {cm[1][0]:3d} | True Positive:  {cm[1][1]:3d}]]\n")
    print("Classification Report:")
    print(report_text)

    # Calculate Feature Importances
    importances = clf.feature_importances_
    sorted_indices = np.argsort(importances)[::-1]
    print("Top Key Predictive URL Features:")
    top_features = {}
    for i in range(min(8, len(FEATURE_NAMES))):
        idx_f = sorted_indices[i]
        feat_name = FEATURE_NAMES[idx_f]
        score = float(importances[idx_f])
        top_features[feat_name] = round(score, 4)
        print(f"  {i+1}. {feat_name:<25} Importance: {score * 100:.2f}%")

    # Save model and metadata
    print(f"\n[*] Saving trained model artifact to: {MODEL_PATH}")
    joblib.dump(clf, MODEL_PATH)

    metadata = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "features": FEATURE_NAMES,
        "accuracy": round(float(acc), 4),
        "precision_phishing": round(float(report["Phishing (1)"]["precision"]), 4),
        "recall_phishing": round(float(report["Phishing (1)"]["recall"]), 4),
        "f1_phishing": round(float(report["Phishing (1)"]["f1-score"]), 4),
        "total_records": total_records,
        "top_features": top_features,
        "trained_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)

    print(f"[+] Metadata saved to: {METADATA_PATH}")
    print("=" * 65)
    print("  TRAINING PIPELINE COMPLETED SUCCESSFULLY!")
    print("=" * 65)
    return clf, metadata


if __name__ == "__main__":
    train()
