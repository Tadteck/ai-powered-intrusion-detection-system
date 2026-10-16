"""
ML Detection Service - Core AI engine for intrusion detection.
Uses scikit-learn Isolation Forest + Random Forest classifier.
"""

import numpy as np
import joblib
import os
from typing import Dict, Any, Optional, Tuple
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from app.core.config import settings
from app.core.logger import logger


class MLDetectionService:
    """
    AI-powered intrusion detection service.
    Uses Isolation Forest for anomaly detection and
    Random Forest for attack classification.
    """

    ANOMALY_MODEL_FILE = "anomaly_model.joblib"
    CLASSIFIER_MODEL_FILE = "classifier_model.joblib"
    SCALER_FILE = "scaler.joblib"

    def __init__(self):
        self.anomaly_model: Optional[IsolationForest] = None
        self.classifier: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self._load_or_initialize_models()

    def _load_or_initialize_models(self):
        """Load existing models or initialize new ones."""
        anomaly_path = os.path.join(settings.MODEL_PATH, self.ANOMALY_MODEL_FILE)
        classifier_path = os.path.join(settings.MODEL_PATH, self.CLASSIFIER_MODEL_FILE)
        scaler_path = os.path.join(settings.MODEL_PATH, self.SCALER_FILE)

        if all(os.path.exists(p) for p in [anomaly_path, classifier_path, scaler_path]):
            try:
                self.anomaly_model = joblib.load(anomaly_path)
                self.classifier = joblib.load(classifier_path)
                self.scaler = joblib.load(scaler_path)
                logger.info("ML models loaded from disk")
            except Exception as e:
                logger.warning(f"Failed to load models: {e}. Initializing fresh models.")
                self._initialize_models()
        else:
            logger.info("No saved models found. Initializing fresh models.")
            self._initialize_models()

    def _initialize_models(self):
        """Initialize fresh (untrained) models."""
        self.anomaly_model = IsolationForest(
            n_estimators=100,
            contamination=0.05,  # Expect 5% anomalies
            random_state=42,
            n_jobs=-1,
        )
        self.classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            random_state=42,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        logger.info("Fresh ML models initialized")

    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """
        Extract numerical feature vector from a network event dict.
        Features: [src_port, dst_port, packet_size, duration,
                   protocol_tcp, protocol_udp, protocol_icmp,
                   flags_syn, flags_ack, flags_fin, flags_rst]
        """
        protocol = (event.get("protocol") or "").lower()
        flags = (event.get("flags") or "").lower()

        features = [
            float(event.get("src_port") or 0),
            float(event.get("dst_port") or 0),
            float(event.get("packet_size") or 0),
            float(event.get("duration") or 0.0),
            1.0 if protocol == "tcp" else 0.0,
            1.0 if protocol == "udp" else 0.0,
            1.0 if protocol == "icmp" else 0.0,
            1.0 if "syn" in flags else 0.0,
            1.0 if "ack" in flags else 0.0,
            1.0 if "fin" in flags else 0.0,
            1.0 if "rst" in flags else 0.0,
        ]
        return np.array(features).reshape(1, -1)

    def predict_anomaly(self, event: Dict[str, Any]) -> Tuple[float, bool]:
        """
        Predict whether a network event is anomalous.
        Returns: (anomaly_score: float, is_anomalous: bool)
        """
        if self.anomaly_model is None or self.scaler is None:
            return 0.0, False

        try:
            features = self.extract_features(event)
            # Check if scaler is fitted
            if not hasattr(self.scaler, "mean_"):
                # Model not trained yet - use a simple heuristic
                return self._heuristic_detection(event)

            features_scaled = self.scaler.transform(features)
            # Isolation Forest: -1 = anomaly, 1 = normal
            prediction = self.anomaly_model.predict(features_scaled)
            # Score: lower is more anomalous (convert to 0-1 scale)
            score = self.anomaly_model.decision_function(features_scaled)[0]
            # Normalize score to 0-1 (higher = more anomalous)
            normalized_score = max(0.0, min(1.0, (0.5 - score) + 0.5))
            is_anomalous = (
                prediction[0] == -1 or normalized_score >= settings.ANOMALY_THRESHOLD
            )
            return round(normalized_score, 4), is_anomalous
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return self._heuristic_detection(event)

    def _heuristic_detection(self, event: Dict[str, Any]) -> Tuple[float, bool]:
        """
        Simple rule-based heuristic when ML model is not trained.
        Used as a fallback until enough training data is collected.
        """
        score = 0.0
        dst_port = event.get("dst_port") or 0
        packet_size = event.get("packet_size") or 0
        flags = (event.get("flags") or "").lower()

        # Suspicious ports
        suspicious_ports = {22, 23, 3389, 4444, 5900, 6666, 8080, 8443, 9999}
        if dst_port in suspicious_ports:
            score += 0.3

        # Very large packets
        if packet_size > 65000:
            score += 0.2

        # SYN flood indicator
        if "syn" in flags and "ack" not in flags:
            score += 0.15

        # RST flood
        if flags.count("rst") > 0:
            score += 0.1

        score = min(1.0, score)
        return round(score, 4), score >= settings.ANOMALY_THRESHOLD

    def train(self, training_data: list) -> bool:
        """
        Train models on a list of network event dicts.
        Returns True if training was successful.
        """
        if len(training_data) < 50:
            logger.warning(f"Insufficient training data: {len(training_data)} samples (min 50)")
            return False

        try:
            features = np.vstack([self.extract_features(e) for e in training_data])
            features_scaled = self.scaler.fit_transform(features)
            self.anomaly_model.fit(features_scaled)
            logger.info(f"Anomaly model trained on {len(training_data)} samples")

            # Save models
            self._save_models()
            return True
        except Exception as e:
            logger.error(f"Training failed: {e}")
            return False

    def _save_models(self):
        """Persist models to disk."""
        try:
            joblib.dump(
                self.anomaly_model,
                os.path.join(settings.MODEL_PATH, self.ANOMALY_MODEL_FILE),
            )
            joblib.dump(
                self.scaler,
                os.path.join(settings.MODEL_PATH, self.SCALER_FILE),
            )
            logger.info("Models saved to disk")
        except Exception as e:
            logger.error(f"Failed to save models: {e}")


# Singleton instance
ml_service = MLDetectionService()
