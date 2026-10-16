"""
Pydantic schemas for NetworkEvent and Alert.
"""

from pydantic import BaseModel, Field
from typing import Optional, Any, Dict
from datetime import datetime
from app.models.network import AlertSeverity, AlertStatus, AttackType


# ---- Network Event Schemas ----

class NetworkEventBase(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    packet_size: Optional[int] = None
    duration: Optional[float] = None
    flags: Optional[str] = None
    features: Optional[Dict[str, Any]] = None


class NetworkEventCreate(NetworkEventBase):
    pass


class NetworkEventResponse(NetworkEventBase):
    id: int
    timestamp: datetime
    anomaly_score: Optional[float] = None
    is_anomalous: bool

    model_config = {"from_attributes": True}


# ---- Alert Schemas ----

class AlertBase(BaseModel):
    title: str = Field(..., max_length=200)
    description: Optional[str] = None
    severity: AlertSeverity = AlertSeverity.MEDIUM
    attack_type: AttackType = AttackType.UNKNOWN
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None


class AlertCreate(AlertBase):
    anomaly_score: Optional[float] = None
    network_event_id: Optional[int] = None


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    severity: Optional[AlertSeverity] = None
    notes: Optional[str] = None


class AlertResponse(AlertBase):
    id: int
    timestamp: datetime
    status: AlertStatus
    anomaly_score: Optional[float] = None
    network_event_id: Optional[int] = None
    notes: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[int] = None

    model_config = {"from_attributes": True}


# ---- Dashboard Stats Schemas ----

class DashboardStats(BaseModel):
    total_events: int
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    anomalous_events: int
    detection_rate: float
    top_attack_types: Dict[str, int]
    events_last_24h: int
    alerts_last_24h: int
