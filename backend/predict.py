"""
CipherGuard Backend - Prediction Utilities

Standalone prediction module for batch processing network flows
through the trained AI model.
"""

import joblib
import pandas as pd
import os
from typing import List, Dict, Tuple


# Model path resolution
MODEL_PATHS = [
    "ids_classifier.pkl",
    "../ids_classifier.pkl",
    os.path.join(os.path.dirname(__file__), "..", "ids_classifier.pkl")
]

# Feature columns expected by the model
FEATURES = [
    "bidirectional_packets",
    "bidirectional_bytes",
    "bidirectional_duration_ms",
    "src2dst_packets",
    "dst2src_packets",
    "bidirectional_min_piat_ms",
    "bidirectional_max_piat_ms",
    "bidirectional_mean_piat_ms"
]


def load_model() -> object:
    """Load the trained Random Forest classifier model."""
    for path in MODEL_PATHS:
        if os.path.exists(path):
            return joblib.load(path)
    raise FileNotFoundError(
        "ids_classifier.pkl not found. Run train.py first."
    )


def predict_flows(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[int]]:
    """
    Run AI prediction on a DataFrame of network flows.

    Args:
        df: DataFrame containing network flow features

    Returns:
        Tuple of (DataFrame with predictions, list of prediction labels)
    """
    model = load_model()

    # Validate required features exist
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        raise ValueError(f"Missing required features: {missing}")

    X = df[FEATURES]
    predictions = model.predict(X)
    probabilities = model.predict_proba(X)

    df["Security Status"] = [
        "🚨 Malicious Attack" if p == 1 else "✅ Secure Connection"
        for p in predictions
    ]

    df["Confidence"] = [
        f"{max(prob) * 100:.2f}%"
        for prob in probabilities
    ]

    return df, predictions.tolist()


def predict_from_dict(flows: List[Dict]) -> Dict:
    """
    Predict from a list of flow dictionaries.

    Args:
        flows: List of dicts containing flow features

    Returns:
        Dict with prediction results summary
    """
    df = pd.DataFrame(flows)
    df, predictions = predict_flows(df)

    safe_count = predictions.count(0)
    threat_count = predictions.count(1)

    return {
        "total_flows": len(predictions),
        "safe": safe_count,
        "threats": threat_count,
        "predictions": predictions,
        "data": df.to_dict(orient="records")
    }