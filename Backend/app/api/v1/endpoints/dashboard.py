"""
Dashboard statistics endpoint.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user_id
from app.schemas.network import DashboardStats
from app.services.alert_service import alert_service

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """
    Get aggregated dashboard statistics for the IDS overview page.
    Returns counts, rates, and top attack types.
    """
    return await alert_service.get_dashboard_stats(db)
