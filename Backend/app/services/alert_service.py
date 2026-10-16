"""
Alert Service - business logic for managing security alerts.
"""

from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from app.models.network import Alert, AlertStatus, AlertSeverity, AttackType, NetworkEvent
from app.schemas.network import AlertCreate, AlertUpdate, DashboardStats
from app.core.logger import logger


class AlertService:
    """Handles alert CRUD and dashboard statistics."""

    async def create_alert(self, db: AsyncSession, data: AlertCreate) -> Alert:
        """Create a new security alert."""
        alert = Alert(**data.model_dump())
        db.add(alert)
        await db.flush()
        await db.refresh(alert)
        logger.info(f"Alert created: id={alert.id} severity={alert.severity} type={alert.attack_type}")
        return alert

    async def get_alert(self, db: AsyncSession, alert_id: int) -> Optional[Alert]:
        """Get a single alert by ID."""
        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        return result.scalar_one_or_none()

    async def list_alerts(
        self,
        db: AsyncSession,
        skip: int = 0,
        limit: int = 50,
        severity: Optional[AlertSeverity] = None,
        status: Optional[AlertStatus] = None,
        attack_type: Optional[AttackType] = None,
    ) -> List[Alert]:
        """List alerts with optional filters."""
        query = select(Alert).order_by(desc(Alert.timestamp))
        if severity:
            query = query.where(Alert.severity == severity)
        if status:
            query = query.where(Alert.status == status)
        if attack_type:
            query = query.where(Alert.attack_type == attack_type)
        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        return list(result.scalars().all())

    async def update_alert(
        self, db: AsyncSession, alert_id: int, data: AlertUpdate, resolver_id: Optional[int] = None
    ) -> Optional[Alert]:
        """Update an alert's status or notes."""
        alert = await self.get_alert(db, alert_id)
        if not alert:
            return None

        update_data = data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(alert, field, value)

        if data.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
            alert.resolved_at = datetime.now(timezone.utc)
            alert.resolved_by = resolver_id

        await db.flush()
        await db.refresh(alert)
        return alert

    async def get_dashboard_stats(self, db: AsyncSession) -> DashboardStats:
        """Compute dashboard statistics."""
        # Total events
        total_events = (await db.execute(select(func.count(NetworkEvent.id)))).scalar_one()
        # Anomalous events
        anomalous_events = (
            await db.execute(
                select(func.count(NetworkEvent.id)).where(NetworkEvent.is_anomalous == True)
            )
        ).scalar_one()

        # Alert counts
        total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar_one()
        open_alerts = (
            await db.execute(
                select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
            )
        ).scalar_one()
        critical_alerts = (
            await db.execute(
                select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.CRITICAL)
            )
        ).scalar_one()
        high_alerts = (
            await db.execute(
                select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.HIGH)
            )
        ).scalar_one()
        medium_alerts = (
            await db.execute(
                select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.MEDIUM)
            )
        ).scalar_one()
        low_alerts = (
            await db.execute(
                select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.LOW)
            )
        ).scalar_one()

        # Detection rate
        detection_rate = (
            round(anomalous_events / total_events * 100, 2) if total_events > 0 else 0.0
        )

        # Top attack types
        attack_type_result = await db.execute(
            select(Alert.attack_type, func.count(Alert.id).label("count"))
            .group_by(Alert.attack_type)
            .order_by(desc("count"))
            .limit(5)
        )
        top_attack_types = {row.attack_type: row.count for row in attack_type_result}

        # Last 24h
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        events_last_24h = (
            await db.execute(
                select(func.count(NetworkEvent.id)).where(NetworkEvent.timestamp >= cutoff)
            )
        ).scalar_one()
        alerts_last_24h = (
            await db.execute(
                select(func.count(Alert.id)).where(Alert.timestamp >= cutoff)
            )
        ).scalar_one()

        return DashboardStats(
            total_events=total_events,
            total_alerts=total_alerts,
            open_alerts=open_alerts,
            critical_alerts=critical_alerts,
            high_alerts=high_alerts,
            medium_alerts=medium_alerts,
            low_alerts=low_alerts,
            anomalous_events=anomalous_events,
            detection_rate=detection_rate,
            top_attack_types=top_attack_types,
            events_last_24h=events_last_24h,
            alerts_last_24h=alerts_last_24h,
        )


alert_service = AlertService()
