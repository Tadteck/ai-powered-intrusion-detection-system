"""
ML model management endpoints - training, status, and predictions.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Any, Dict, List

from app.core.database import get_db
from app.core.security import get_current_user_id
from app.models.network import NetworkEvent
from app.services.ml_detection import ml_service
from app.core.logger import logger

router = APIRouter()


@router.get("/status")
async def get_model_status(
    user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Get the current status of the ML detection model."""
    is_trained = (
        ml_service.scaler is not None
        and hasattr(ml_service.scaler, "mean_")
    )
    return {
        "model_type": "IsolationForest + Heuristic Fallback",
        "is_trained": is_trained,
        "anomaly_threshold": ml_service.anomaly_model.contamination if ml_service.anomaly_model else None,
        "detection_threshold": 0.75,
        "model_path": ml_service.ANOMALY_MODEL_FILE,
    }


@router.post("/train")
async def trigger_training(
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Trigger ML model retraining using all stored network events.
    Requires at least 50 events.
    """
    result = await db.execute(select(NetworkEvent))
    events = result.scalars().all()

    if len(events) < 50:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Insufficient data: {len(events)} events. Minimum 50 required.",
        )

    training_data = [
        {
            "src_port": e.src_port,
            "dst_port": e.dst_port,
            "packet_size": e.packet_size,
            "duration": e.duration,
            "protocol": e.protocol,
            "flags": e.flags,
        }
        for e in events
    ]

    success = ml_service.train(training_data)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Model training failed. Check logs for details.",
        )

    logger.info(f"ML model retrained with {len(events)} events by user {user_id}")
    return {
        "status": "success",
        "message": f"Model successfully trained on {len(events)} events",
        "events_used": len(events),
    }


@router.post("/predict")
async def predict_single(
    event: Dict[str, Any],
    user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Run anomaly detection on a single event payload (for testing)."""
    anomaly_score, is_anomalous = ml_service.predict_anomaly(event)
    return {
        "anomaly_score": anomaly_score,
        "is_anomalous": is_anomalous,
        "threshold": 0.75,
        "classification": "ANOMALOUS" if is_anomalous else "NORMAL",
    }
