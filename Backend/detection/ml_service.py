"""
ML Detection Service — Isolation Forest anomaly detection.
"""

import os
import logging
import numpy as np
import joblib
from typing import Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from django.conf import settings

logger = logging.getLogger(__name__)

ANOMALY_MODEL_FILE = "anomaly_model.joblib"
SCALER_FILE = "scaler.joblib"


class MLDetectionService:
    """
    AI-powered intrusion detection using Isolation Forest.
    Falls back to heuristic rules when model is not yet trained.
    """

    def __init__(self):
        self.model: IsolationForest | None = None
        self.scaler: StandardScaler | None = None
        self._load_or_init()

    def _model_path(self, filename: str) -> str:
        return os.path.join(settings.ML_MODEL_PATH, filename)

    def _load_or_init(self):
        model_file = self._model_path(ANOMALY_MODEL_FILE)
        scaler_file = self._model_path(SCALER_FILE)
        if os.path.exists(model_file) and os.path.exists(scaler_file):
            try:
                self.model = joblib.load(model_file)
                self.scaler = joblib.load(scaler_file)
                logger.info("ML models loaded from disk.")
                return
            except Exception as e:
                logger.warning(f"Failed to load models: {e}. Re-initializing.")
        self._init_fresh()

    def _init_fresh(self):
        self.model = IsolationForest(
            n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1
        )
        self.scaler = StandardScaler()
        logger.info("Fresh ML models initialized (untrained).")

    def extract_features(self, event: dict) -> np.ndarray:
        """Convert a network event dict to an 11-dimensional feature vector."""
        protocol = (event.get("protocol") or "").upper()
        flags = (event.get("flags") or "").lower()
        return np.array([[
            float(event.get("src_port") or 0),
            float(event.get("dst_port") or 0),
            float(event.get("packet_size") or 0),
            float(event.get("duration") or 0.0),
            1.0 if protocol == "TCP" else 0.0,
            1.0 if protocol == "UDP" else 0.0,
            1.0 if protocol == "ICMP" else 0.0,
            1.0 if "syn" in flags else 0.0,
            1.0 if "ack" in flags else 0.0,
            1.0 if "fin" in flags else 0.0,
            1.0 if "rst" in flags else 0.0,
        ]])

    def predict(self, event: dict) -> Tuple[float, bool]:
        """
        Returns (anomaly_score: float 0-1, is_anomalous: bool).
        Uses ML model if trained, otherwise falls back to heuristics.
        """
        if self.scaler and hasattr(self.scaler, "mean_"):
            try:
                features = self.extract_features(event)
                scaled = self.scaler.transform(features)
                raw_score = self.model.decision_function(scaled)[0]
                # Map to 0-1 where higher = more anomalous
                score = float(max(0.0, min(1.0, (0.5 - raw_score) + 0.5)))
                prediction = self.model.predict(scaled)[0]
                is_anomalous = prediction == -1 or score >= settings.ANOMALY_THRESHOLD
                return round(score, 4), is_anomalous
            except Exception as e:
                logger.error(f"ML prediction error: {e}")

        return self._heuristic(event)

    def _heuristic(self, event: dict) -> Tuple[float, bool]:
        """Rule-based fallback detection."""
        score = 0.0
        dst_port = event.get("dst_port") or 0
        packet_size = event.get("packet_size") or 0
        flags = (event.get("flags") or "").lower()

        SUSPICIOUS_PORTS = {22, 23, 445, 3389, 4444, 5900, 6666, 8080, 9999}
        if dst_port in SUSPICIOUS_PORTS:
            score += 0.30
        if packet_size > 65000:
            score += 0.20
        if "syn" in flags and "ack" not in flags:
            score += 0.15
        if "rst" in flags:
            score += 0.10

        score = min(1.0, score)
        return round(score, 4), score >= settings.ANOMALY_THRESHOLD

    def train(self, events: list) -> bool:
        """Train on a list of event dicts. Requires ≥50 samples."""
        if len(events) < 50:
            logger.warning(f"Not enough data: {len(events)} events (min 50).")
            return False
        try:
            features = np.vstack([self.extract_features(e) for e in events])
            self.scaler.fit(features)
            scaled = self.scaler.transform(features)
            self.model.fit(scaled)
            joblib.dump(self.model, self._model_path(ANOMALY_MODEL_FILE))
            joblib.dump(self.scaler, self._model_path(SCALER_FILE))
            logger.info(f"ML model trained on {len(events)} events and saved.")
            return True
        except Exception as e:
            logger.error(f"Training failed: {e}")
            return False

    @property
    def is_trained(self) -> bool:
        return self.scaler is not None and hasattr(self.scaler, "mean_")


# App-wide singleton
ml_service = MLDetectionService()
