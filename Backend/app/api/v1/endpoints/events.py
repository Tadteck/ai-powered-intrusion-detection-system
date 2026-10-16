"""
Network Events endpoints - ingest and query network traffic events.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List

from app.core.database import get_db
from app.core.security import get_current_user_id
from app.models.network import NetworkEvent, Alert, AttackType, AlertSeverity
from app.schemas.network import NetworkEventCreate, NetworkEventResponse, AlertCreate
from app.services.ml_detection import ml_service
from app.services.alert_service import alert_service
from app.core.logger import logger

router = APIRouter()


@router.get("/", response_model=List[NetworkEventResponse])
async def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    anomalous_only: bool = Query(False),
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """List network events, optionally filtering to anomalous only."""
    query = select(NetworkEvent).order_by(desc(NetworkEvent.timestamp))
    if anomalous_only:
        query = query.where(NetworkEvent.is_anomalous == True)
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post("/ingest", response_model=NetworkEventResponse, status_code=status.HTTP_201_CREATED)
async def ingest_event(
    data: NetworkEventCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest a network event for AI analysis.
    This endpoint does NOT require authentication to allow network agents to submit events.
    The ML model analyzes the event and auto-creates alerts for anomalies.
    """
    # Run ML detection
    event_dict = data.model_dump()
    anomaly_score, is_anomalous = ml_service.predict_anomaly(event_dict)

    # Create network event record
    event = NetworkEvent(
        **event_dict,
        anomaly_score=anomaly_score,
        is_anomalous=is_anomalous,
    )
    db.add(event)
    await db.flush()
    await db.refresh(event)

    # Auto-create alert if anomalous
    if is_anomalous:
        severity = AlertSeverity.CRITICAL if anomaly_score >= 0.9 else (
            AlertSeverity.HIGH if anomaly_score >= 0.75 else AlertSeverity.MEDIUM
        )
        alert_data = AlertCreate(
            title=f"Anomalous traffic detected from {data.src_ip}",
            description=(
                f"AI model detected suspicious network activity. "
                f"Anomaly score: {anomaly_score:.2%}. "
                f"Traffic: {data.src_ip}:{data.src_port} → {data.dst_ip}:{data.dst_port} "
                f"({data.protocol})"
            ),
            severity=severity,
            attack_type=AttackType.ANOMALY,
            src_ip=data.src_ip,
            dst_ip=data.dst_ip,
            src_port=data.src_port,
            dst_port=data.dst_port,
            anomaly_score=anomaly_score,
            network_event_id=event.id,
        )
        await alert_service.create_alert(db, alert_data)
        logger.warning(
            f"ANOMALY DETECTED: {data.src_ip} -> {data.dst_ip} score={anomaly_score}"
        )

    return event


@router.get("/{event_id}", response_model=NetworkEventResponse)
async def get_event(
    event_id: int,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific network event by ID."""
    result = await db.execute(select(NetworkEvent).where(NetworkEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
