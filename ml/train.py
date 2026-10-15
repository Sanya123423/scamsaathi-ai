"""
ScamSaathi - Machine Learning Training Script
Pipeline: TfidfVectorizer + LogisticRegression
Trains a text classifier to distinguish legitimate communications from cyber scam patterns.

Fulfills requirements:
- Simple, reproducible training pipeline.
- Held-out evaluation metrics calculated on independent test split.
- Explicit documentation of small dataset limitations.
- Serializes model to ml/scam_classifier.joblib.
"""

import os
import json
from pathlib import Path
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
import joblib

from dataset import get_labeled_examples

# Paths
ML_DIR = Path(__file__).resolve().parent
MODEL_PATH = ML_DIR / "scam_classifier.joblib"
METADATA_PATH = ML_DIR / "model_meta.json"

def train_and_evaluate():
    print("=" * 65)
    print(" ScamSaathi ML: Training TF-IDF + Logistic Regression Pipeline")
    print("=" * 65)

    texts, raw_labels = get_labeled_examples()
    # Map to binary target: 1 = suspicious, 0 = legitimate
    y = [1 if label == "suspicious" else 0 for label in raw_labels]
    
    print(f"Loaded {len(texts)} labeled training examples.")
    print(f"Distribution: {y.count(1)} suspicious, {y.count(0)} legitimate.\n")

    # Train / Test split (75% train, 25% held-out test)
    X_train, X_test, y_train, y_test = train_test_split(
        texts, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"Training split: {len(X_train)} samples | Held-out test split: {len(X_test)} samples")

    # Define reproducible ML pipeline
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=1200,
            sublinear_tf=True,
            strip_accents='unicode'
        )),
        ('clf', LogisticRegression(
            C=1.0,
            max_iter=300,
            random_state=42,
            solver='lbfgs'
        ))
    ])

    # Train
    pipeline.fit(X_train, y_train)

    # Evaluate on held-out test split
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print("\n--- Held-Out Test Evaluation Results ---")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1-Score : {f1:.4f}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=['legitimate', 'suspicious']))

    # Save trained pipeline to disk
    joblib.dump(pipeline, MODEL_PATH)
    print(f"[SUCCESS] Model artifact saved to: {MODEL_PATH}")

    # Limitations & Documentation
    limitations = [
        "Small Sample Size: The seed dataset contains 60 curated examples. While sufficient for demonstration, real-world deployment requires tens of thousands of diverse SMS and email corpora.",
        "Distribution Shift: Novel zero-day phishing narratives or slang may differ substantially from the training distribution.",
        "Probabilistic Meaning: Model confidence scores indicate statistical feature similarity to training corpus distributions, NOT an objective mathematical probability of criminality.",
        "Hybrid Architecture: The system relies primarily on deterministic rule-based heuristics with ML functioning as an auxiliary scoring signal."
    ]

    metadata = {
        "model_architecture": "TfidfVectorizer(ngram_range=(1,2)) + LogisticRegression(C=1.0)",
        "total_samples": len(texts),
        "held_out_metrics": {
            "test_size": len(X_test),
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4)
        },
        "target_classes": {
            "0": "legitimate",
            "1": "suspicious"
        },
        "dataset_limitations": limitations
    }

    with open(METADATA_PATH, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    print(f"[SUCCESS] Model metadata saved to: {METADATA_PATH}")
    print("=" * 65)

if __name__ == '__main__':
    train_and_evaluate()
