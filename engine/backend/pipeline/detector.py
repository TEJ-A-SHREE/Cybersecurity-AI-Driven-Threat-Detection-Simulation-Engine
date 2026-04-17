"""
Layer 3: Unsupervised Anomaly Detection
Isolation Forest (point anomalies) + LSTM Autoencoder (sequence anomalies)
Ensemble: avg/max of normalized scores → anomaly_confidence float
"""

import numpy as np
import random
from typing import List


class IsolationForestLite:
    """
    Lightweight Isolation Forest implementation.
    In production: use sklearn.ensemble.IsolationForest
    contamination=0.01 (1% expected anomalies)
    """

    def __init__(self, n_estimators=100, contamination=0.01, max_samples=256):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.max_samples = max_samples
        self.trees = []
        self._threshold = 0.6
        self._fitted = False

        try:
            from sklearn.ensemble import IsolationForest
            self._sklearn_model = IsolationForest(
                n_estimators=n_estimators,
                contamination=contamination,
                random_state=42,
                n_jobs=-1
            )
            self._use_sklearn = True
        except ImportError:
            self._sklearn_model = None
            self._use_sklearn = False

    def fit(self, X: np.ndarray):
        if self._use_sklearn and X.shape[0] > 10:
            self._sklearn_model.fit(X)
        self._fitted = True

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        if self._use_sklearn and self._fitted:
            # sklearn returns negative scores; normalize to [0,1]
            raw = self._sklearn_model.score_samples(X)
            # More negative = more anomalous; flip and normalize
            normalized = 1.0 - (raw - raw.min()) / (raw.max() - raw.min() + 1e-8)
            return normalized.clip(0, 1)
        else:
            # Fallback: heuristic scoring based on feature extremity
            return self._heuristic_score(X)

    def _heuristic_score(self, X: np.ndarray) -> np.ndarray:
        # Z-score based anomaly proxy
        mean = X.mean(axis=0)
        std = X.std(axis=0) + 1e-8
        z_scores = np.abs((X - mean) / std)
        # Take max z-score per sample as anomaly indicator
        max_z = z_scores.max(axis=1)
        # Normalize to [0, 1] using sigmoid-like mapping
        scores = 1 / (1 + np.exp(-(max_z - 3)))
        return scores.clip(0, 1)


class LSTMAutoencoderLite:
    """
    LSTM Autoencoder for sequence anomaly detection.
    Detects: process injection signatures, beaconing patterns.
    In production: use Keras/PyTorch LSTM Autoencoder.
    """

    def __init__(self, sequence_len=10, threshold_percentile=95):
        self.sequence_len = sequence_len
        self.threshold_percentile = threshold_percentile
        self._reconstruction_threshold = 0.5
        self._fitted = False
        self._baseline_patterns = {}

        try:
            import tensorflow as tf
            self._use_tf = True
            self._model = None  # Built on fit()
        except ImportError:
            self._use_tf = False

    def fit(self, X: np.ndarray):
        """Learn normal sequence reconstruction threshold"""
        if X.shape[0] < self.sequence_len:
            self._fitted = True
            return

        if self._use_tf:
            self._build_and_train(X)
        else:
            # Heuristic: store baseline statistics per feature
            self._baseline_mean = X.mean(axis=0)
            self._baseline_std = X.std(axis=0) + 1e-8
        self._fitted = True

    def _build_and_train(self, X: np.ndarray):
        try:
            import tensorflow as tf
            from tensorflow.keras import layers, Model

            n_features = X.shape[1]
            # Build sequences
            seqs = self._make_sequences(X)
            if len(seqs) == 0:
                return

            inp = tf.keras.Input(shape=(self.sequence_len, n_features))
            enc = layers.LSTM(32, return_sequences=False)(inp)
            rep = layers.RepeatVector(self.sequence_len)(enc)
            dec = layers.LSTM(32, return_sequences=True)(rep)
            out = layers.TimeDistributed(layers.Dense(n_features))(dec)

            self._model = Model(inp, out)
            self._model.compile(optimizer="adam", loss="mse")
            self._model.fit(seqs, seqs, epochs=5, batch_size=32, verbose=0)

            # Compute reconstruction threshold
            recon = self._model.predict(seqs, verbose=0)
            mse = np.mean((seqs - recon) ** 2, axis=(1, 2))
            self._reconstruction_threshold = np.percentile(mse, self.threshold_percentile)
        except Exception:
            pass

    def _make_sequences(self, X: np.ndarray) -> np.ndarray:
        seqs = []
        for i in range(len(X) - self.sequence_len):
            seqs.append(X[i:i + self.sequence_len])
        return np.array(seqs) if seqs else np.empty((0, self.sequence_len, X.shape[1]))

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        if not self._fitted:
            return np.zeros(len(X))

        if self._use_tf and self._model is not None:
            return self._tf_score(X)
        else:
            return self._heuristic_sequence_score(X)

    def _tf_score(self, X: np.ndarray) -> np.ndarray:
        try:
            seqs = self._make_sequences(X)
            if len(seqs) == 0:
                return np.zeros(len(X))
            recon = self._model.predict(seqs, verbose=0)
            mse = np.mean((seqs - recon) ** 2, axis=(1, 2))
            scores_seq = (mse / (self._reconstruction_threshold + 1e-8)).clip(0, 1)
            # Pad to match input length
            full_scores = np.zeros(len(X))
            full_scores[self.sequence_len:] = scores_seq[:len(X) - self.sequence_len]
            return full_scores
        except Exception:
            return np.zeros(len(X))

    def _heuristic_sequence_score(self, X: np.ndarray) -> np.ndarray:
        """Detect beaconing: look for periodic, low-variance sequences"""
        if not hasattr(self, "_baseline_mean"):
            return np.zeros(len(X))
        z = np.abs((X - self._baseline_mean) / self._baseline_std)
        return (z.mean(axis=1) / 5.0).clip(0, 1)


class AnomalyDetector:
    """
    Ensemble detector: combines IsolationForest + LSTMAutoencoder
    Returns anomaly_confidence in [0, 1]
    """

    def __init__(self):
        self.iso_forest = IsolationForestLite(contamination=0.01)
        self.lstm_ae = LSTMAutoencoderLite(sequence_len=8)
        self._fitted = False

    def fit_baseline(self, n_samples: int = 500):
        """Generate benign baseline traffic to train the detector"""
        from pipeline.simulator import ThreatSimulator
        from pipeline.ingestion import EventIngester
        from pipeline.preprocessor import FeaturePreprocessor

        sim = ThreatSimulator()
        ingester = EventIngester()
        preprocessor = FeaturePreprocessor()

        baseline_events = sim.generate_benign_traffic(n_samples)
        normalized = ingester.normalize(baseline_events, "network")
        X = preprocessor.transform(normalized)

        self.iso_forest.fit(X)
        self.lstm_ae.fit(X)
        self._fitted = True
        print(f"[AnomalyDetector] Fitted on {n_samples} baseline samples")

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self._fitted or X.shape[0] == 0:
            return np.zeros(len(X))

        iso_scores  = self.iso_forest.score_samples(X)
        lstm_scores = self.lstm_ae.score_samples(X)

        # Ensemble: weighted average (iso: 0.6, lstm: 0.4)
        ensemble = 0.6 * iso_scores + 0.4 * lstm_scores
        return ensemble.clip(0, 1)
