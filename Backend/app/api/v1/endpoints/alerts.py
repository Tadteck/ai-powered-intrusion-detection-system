"""
Alert management endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional

from app.core.database import get_db
from app.core.security import get_current_user_id
from app.schemas.network import AlertCreate, AlertUpdate, AlertResponse
from app.models.network import AlertSeverity, AlertStatus, AttackType
from app.services.alert_service import alert_service

router = APIRouter()


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[AlertSeverity] = Query(None),
    status: Optional[AlertStatus] = Query(None),
    attack_type: Optional[AttackType] = Query(None),
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """List all alerts with optional filtering."""
    return await alert_service.list_alerts(
        db,
        skip=skip,
        limit=limit,
        severity=severity,
        status=status,
        attack_type=attack_type,
    )


@router.post("/", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(
    data: AlertCreate,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Manually create a new security alert."""
    return await alert_service.create_alert(db, data)


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific alert by ID."""
    alert = await alert_service.get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    data: AlertUpdate,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Update an alert's status, severity, or notes."""
    alert = await alert_service.update_alert(db, alert_id, data, resolver_id=int(user_id))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
