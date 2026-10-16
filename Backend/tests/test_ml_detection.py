"""
Tests for ML detection service.
"""

import pytest
from app.services.ml_detection import MLDetectionService


def test_extract_features():
    svc = MLDetectionService()
    event = {
        "src_port": 443,
        "dst_port": 8080,
        "packet_size": 1024,
        "duration": 0.5,
        "protocol": "tcp",
        "flags": "syn ack",
    }
    features = svc.extract_features(event)
    assert features.shape == (1, 11)
    assert features[0][0] == 443.0   # src_port
    assert features[0][1] == 8080.0  # dst_port
    assert features[0][4] == 1.0     # protocol_tcp
    assert features[0][7] == 1.0     # flags_syn
    assert features[0][8] == 1.0     # flags_ack


def test_heuristic_detection_suspicious_port():
    svc = MLDetectionService()
    event = {
        "src_port": 12345,
        "dst_port": 4444,  # Suspicious port
        "packet_size": 500,
        "protocol": "tcp",
        "flags": "syn",
    }
    score, is_anomalous = svc._heuristic_detection(event)
    assert score >= 0.3
    assert isinstance(is_anomalous, bool)


def test_heuristic_detection_normal():
    svc = MLDetectionService()
    event = {
        "src_port": 54321,
        "dst_port": 80,
        "packet_size": 512,
        "protocol": "tcp",
        "flags": "ack",
    }
    score, _ = svc._heuristic_detection(event)
    assert score < 0.5


def test_predict_anomaly_returns_tuple():
    svc = MLDetectionService()
    event = {
        "src_port": 80,
        "dst_port": 443,
        "packet_size": 256,
        "protocol": "tcp",
        "flags": "ack",
    }
    score, is_anomalous = svc.predict_anomaly(event)
    assert 0.0 <= score <= 1.0
    assert isinstance(is_anomalous, bool)
