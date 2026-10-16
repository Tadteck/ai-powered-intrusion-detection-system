"""
API v1 Main Router - aggregates all endpoint routers.
"""

from fastapi import APIRouter
from app.api.v1.endpoints import auth, users, alerts, events, ml, dashboard

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
api_router.include_router(events.router, prefix="/events", tags=["Network Events"])
api_router.include_router(ml.router, prefix="/ml", tags=["ML Detection"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
