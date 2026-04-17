"""
Person B — ML Models (the Keras person)
Owner of: models/

Responsibilities:
  1. Isolation Forest (sklearn) — point anomalies
  2. LSTM Autoencoder (Keras) — temporal anomalies, trained in Colab on GPU
  3. XGBoost multi-class classifier — trained on CICIDS2018 + synthetic
  4. SHAP TreeExplainer integration
  5. Save all weights to models/weights/ so pipeline restarts are cheap

Contract with Person A: consumes np.ndarray from FeaturePipeline
Contract with Person C: emits Alert objects

WORKFLOW NOTE:
  - Do the LSTM training in a Colab notebook (free GPU)
  - Save weights to models/weights/lstm_ae.keras
  - Commit the .keras file to git (it's small enough) or use git-lfs
  - Local inference uses tf.keras.models.load_model() — no GPU needed
"""
from schema import Event, Alert
import numpy as np
from typing import List


# ---------- models/isolation_forest.py ----------
class IsoForestDetector:
    """contamination=0.01, n_estimators=100. Trains on benign only."""
    def fit(self, X: np.ndarray) -> None:
        raise NotImplementedError("Person B")

    def anomaly_score(self, x: np.ndarray) -> float:
        """Returns normalized score 0.0–1.0 (1.0 = most anomalous)."""
        raise NotImplementedError("Person B")

    def save(self, path: str) -> None: ...
    def load(self, path: str) -> "IsoForestDetector": ...


# ---------- models/lstm_autoencoder.py ----------
class LSTMAutoencoder:
    """
    Keras LSTM autoencoder. Input shape: (sequence_length=10, features=N).
    Anomaly = reconstruction MSE above threshold (set at 95th percentile of benign).
    Used for: process injection chains, beaconing interval patterns.

    Training: do this in Colab (GPU). Save with model.save('lstm_ae.keras').
    Inference: tf.keras.models.load_model('lstm_ae.keras') — CPU is fine.
    """
    def __init__(self, sequence_length: int = 10, n_features: int = 60):
        self.sequence_length = sequence_length
        self.n_features = n_features

    def build(self) -> None:
        """
        Suggested architecture (keep it small — 36h constraint):
          Encoder: LSTM(32, return_sequences=True) -> LSTM(16)
          Decoder: RepeatVector(seq_len) -> LSTM(16, return_sequences=True)
                   -> LSTM(32, return_sequences=True) -> TimeDistributed(Dense(n_features))
          Loss: mse, Optimizer: adam, Epochs: 20-30
        """
        raise NotImplementedError("Person B")

    def fit(self, X_sequences: np.ndarray, epochs: int = 20) -> None:
        raise NotImplementedError("Person B")

    def anomaly_score(self, sequence: np.ndarray) -> float:
        """Returns normalized reconstruction error 0.0–1.0."""
        raise NotImplementedError("Person B")

    def save(self, path: str) -> None: ...
    def load(self, path: str) -> "LSTMAutoencoder": ...


# ---------- models/xgboost_classifier.py ----------
class ThreatClassifier:
    """
    XGBoost multi:softprob over 5 classes:
      [benign, brute_force, lateral_movement, data_exfiltration, c2_beaconing]

    Training data: CICIDS2018 + synthetic lateral_movement + synthetic C2.
    """
    CLASSES = ["benign", "brute_force", "lateral_movement",
               "data_exfiltration", "c2_beaconing"]

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        raise NotImplementedError("Person B")

    def predict(self, x: np.ndarray) -> dict:
        """
        Returns:
          {
            "class": "c2_beaconing",
            "confidence": 0.87,
            "probabilities": {"benign": 0.02, "c2_beaconing": 0.87, ...}
          }
        """
        raise NotImplementedError("Person B")

    def save(self, path: str) -> None: ...
    def load(self, path: str) -> "ThreatClassifier": ...


# ---------- models/shap_explainer.py ----------
class ShapExplainer:
    """Wraps shap.TreeExplainer(xgboost_model)."""
    def __init__(self, classifier: ThreatClassifier, feature_names: List[str]):
        self.classifier = classifier
        self.feature_names = feature_names

    def explain(self, x: np.ndarray) -> dict:
        """
        Returns:
          {
            "top_features": {"beacon_interval_regularity": 0.82, ...},
            "shap_values": np.ndarray,
          }
        Top features: abs(shap) sorted desc, top 6.
        """
        raise NotImplementedError("Person B")


# ---------- models/severity.py ----------
def derive_severity(threat_class: str, confidence: float) -> str:
    """
    Decision matrix from your PPT slide 10:
      C2 Beaconing       ≥ 0.85  → CRITICAL
      Data Exfiltration  ≥ 0.75  → HIGH
      Lateral Movement   ≥ 0.60  → MEDIUM
      Brute Force        0.5–0.7 → MEDIUM
      anything else             → LOW
    """
    if threat_class == "c2_beaconing" and confidence >= 0.85:
        return "CRITICAL"
    if threat_class == "data_exfiltration" and confidence >= 0.75:
        return "HIGH"
    if threat_class == "lateral_movement" and confidence >= 0.60:
        return "MEDIUM"
    if threat_class == "brute_force" and 0.5 <= confidence <= 0.7:
        return "MEDIUM"
    if confidence >= 0.85:
        return "HIGH"
    if confidence >= 0.6:
        return "MEDIUM"
    return "LOW"
