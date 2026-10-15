"""
ScamSaathi - Machine Learning Inference Engine
Loads serialized TF-IDF + LogisticRegression model and performs text classification.

Guarantees:
- Predictions are kept separate from rule-based heuristic findings.
- Never crashes if model file or dependencies are absent (graceful fallback).
- Confidence is explicitly labeled as corpus statistical proximity, NOT probability of criminality.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional

# Global cached model pipeline
_CACHED_PIPELINE = None
_MODEL_LOAD_ATTEMPTED = False
_MODEL_LOAD_ERROR = None

ML_DIR = Path(__file__).resolve().parent
MODEL_FILE = ML_DIR / "scam_classifier.joblib"

def load_classifier():
    """
    Loads the trained TF-IDF + LogisticRegression pipeline from disk.
    Caches the model in memory for fast sub-millisecond inference.
    """
    global _CACHED_PIPELINE, _MODEL_LOAD_ATTEMPTED, _MODEL_LOAD_ERROR
    
    if _CACHED_PIPELINE is not None:
        return _CACHED_PIPELINE

    _MODEL_LOAD_ATTEMPTED = True

    if not MODEL_FILE.exists():
        _MODEL_LOAD_ERROR = f"Model artifact not found at {MODEL_FILE}. Run 'python ml/train.py' to generate."
        return None

    try:
        import joblib
        _CACHED_PIPELINE = joblib.load(MODEL_FILE)
        _MODEL_LOAD_ERROR = None
        return _CACHED_PIPELINE
    except Exception as exc:
        _MODEL_LOAD_ERROR = f"Failed to deserialize model: {str(exc)}"
        _CACHED_PIPELINE = None
        return None

def predict_message(text: str) -> Dict[str, Any]:
    """
    Performs machine learning classification on an input message string.
    
    Returns structured dictionary:
        {
            "status": "active" | "unavailable" | "empty_input",
            "is_experimental": True,
            "predicted_category": "Suspicious / Scam" | "Legitimate / Benign",
            "predicted_class_id": 1 | 0,
            "model_confidence": float (0.0 to 1.0),
            "model_architecture": str,
            "explanation": str,
            "disclaimer": str
        }
    """
    disclaimer = (
        "Statistical Disclaimer: Model confidence reflects relative cosine/feature similarity to "
        "training corpus distributions, NOT a verified real-world mathematical probability that a message is fraudulent."
    )

    if not text or not isinstance(text, str) or not text.strip():
        return {
            "status": "empty_input",
            "is_experimental": True,
            "predicted_category": "Insufficient Input",
            "predicted_class_id": 0,
            "model_confidence": 0.0,
            "model_architecture": "TF-IDF + LogisticRegression",
            "explanation": "No text content provided for statistical vectorization.",
            "disclaimer": disclaimer
        }

    pipeline = load_classifier()

    if pipeline is None:
        return {
            "status": "unavailable",
            "is_experimental": True,
            "predicted_category": "Model Unavailable",
            "predicted_class_id": 0,
            "model_confidence": 0.0,
            "model_architecture": "TF-IDF + LogisticRegression",
            "explanation": _MODEL_LOAD_ERROR or "ML model artifact is not loaded. System operating in deterministic rule-only mode.",
            "disclaimer": disclaimer
        }

    try:
        clean_text = text.strip()
        # Predict class
        pred = pipeline.predict([clean_text])[0]
        # Predict probabilities: [P(legitimate), P(suspicious)]
        proba = pipeline.predict_proba([clean_text])[0]
        
        confidence = float(proba[pred])
        category = "Suspicious / Scam" if pred == 1 else "Legitimate / Benign"
        
        explanation = (
            f"Logistic regression feature vector scored {confidence * 100:.1f}% alignment with {category.lower()} patterns in the training corpus."
        )

        return {
            "status": "active",
            "is_experimental": True,
            "predicted_category": category,
            "predicted_class_id": int(pred),
            "model_confidence": round(confidence, 4),
            "model_architecture": "TfidfVectorizer(1,2) + LogisticRegression(C=1.0)",
            "explanation": explanation,
            "disclaimer": disclaimer
        }

    except Exception as exc:
        return {
            "status": "error",
            "is_experimental": True,
            "predicted_category": "Inference Error",
            "predicted_class_id": 0,
            "model_confidence": 0.0,
            "model_architecture": "TF-IDF + LogisticRegression",
            "explanation": f"ML classification encountered an unexpected error: {str(exc)}",
            "disclaimer": disclaimer
        }
