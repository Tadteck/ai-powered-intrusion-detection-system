"""
Detection views — NetworkEvent ingestion, Alerts, ML, and Dashboard.
"""

import logging
from datetime import datetime, timedelta, timezone

from django.db.models import Count, Q
from rest_framework import generics, status, permissions, filters
from rest_framework.response import Response
from rest_framework.views import APIView
from django_filters.rest_framework import DjangoFilterBackend

from detection.models import NetworkEvent, Alert
from detection.serializers import (
    NetworkEventSerializer,
    NetworkEventIngestSerializer,
    AlertSerializer,
    AlertUpdateSerializer,
    DashboardStatsSerializer,
)
from detection.ml_service import ml_service

logger = logging.getLogger(__name__)


# ─── Network Events ────────────────────────────────────────────────────────────

class NetworkEventListView(generics.ListAPIView):
    """GET /api/v1/events/ — List network events."""
    queryset = NetworkEvent.objects.all()
    serializer_class = NetworkEventSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["is_anomalous", "protocol", "src_ip", "dst_ip"]
    ordering_fields = ["timestamp", "anomaly_score"]
    ordering = ["-timestamp"]


class NetworkEventIngestView(APIView):
    """
    POST /api/v1/events/ingest/ — Ingest a network event for AI analysis.
    No authentication required so network sensors can submit freely.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = NetworkEventIngestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Run ML detection
        event_dict = {
            "src_port": data.get("src_port"),
            "dst_port": data.get("dst_port"),
            "packet_size": data.get("packet_size"),
            "duration": data.get("duration"),
            "protocol": data.get("protocol", ""),
            "flags": data.get("flags", ""),
        }
        anomaly_score, is_anomalous = ml_service.predict(event_dict)

        # Save event
        event = NetworkEvent.objects.create(
            **data,
            anomaly_score=anomaly_score,
            is_anomalous=is_anomalous,
        )

        # Auto-create alert if anomalous
        if is_anomalous:
            if anomaly_score >= 0.9:
                severity = Alert.Severity.CRITICAL
            elif anomaly_score >= 0.75:
                severity = Alert.Severity.HIGH
            else:
                severity = Alert.Severity.MEDIUM

            Alert.objects.create(
                title=f"Anomalous traffic detected from {data.get('src_ip')}",
                description=(
                    f"AI model detected suspicious network activity. "
                    f"Anomaly score: {anomaly_score:.1%}. "
                    f"Traffic: {data.get('src_ip')}:{data.get('src_port')} → "
                    f"{data.get('dst_ip')}:{data.get('dst_port')} ({data.get('protocol')})"
                ),
                severity=severity,
                attack_type=Alert.AttackType.ANOMALY,
                src_ip=data.get("src_ip"),
                dst_ip=data.get("dst_ip"),
                src_port=data.get("src_port"),
                dst_port=data.get("dst_port"),
                anomaly_score=anomaly_score,
                network_event=event,
            )
            logger.warning(
                f"ANOMALY DETECTED | {data.get('src_ip')} → {data.get('dst_ip')} | score={anomaly_score}"
            )

        return Response(NetworkEventSerializer(event).data, status=status.HTTP_201_CREATED)


class NetworkEventDetailView(generics.RetrieveAPIView):
    """GET /api/v1/events/<id>/ — Get a single network event."""
    queryset = NetworkEvent.objects.all()
    serializer_class = NetworkEventSerializer
    permission_classes = [permissions.IsAuthenticated]


# ─── Alerts ────────────────────────────────────────────────────────────────────

class AlertListCreateView(generics.ListCreateAPIView):
    """GET/POST /api/v1/alerts/ — List or create alerts."""
    queryset = Alert.objects.select_related("network_event", "resolved_by").all()
    serializer_class = AlertSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["severity", "status", "attack_type", "src_ip"]
    search_fields = ["title", "description", "src_ip", "dst_ip"]
    ordering_fields = ["timestamp", "severity", "anomaly_score"]
    ordering = ["-timestamp"]


class AlertDetailView(generics.RetrieveAPIView):
    """GET /api/v1/alerts/<id>/ — Retrieve a single alert."""
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [permissions.IsAuthenticated]


class AlertUpdateView(generics.UpdateAPIView):
    """PATCH /api/v1/alerts/<id>/update/ — Update alert status/severity/notes."""
    queryset = Alert.objects.all()
    serializer_class = AlertUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]
    http_method_names = ["patch"]

    def perform_update(self, serializer):
        instance = serializer.save()
        if instance.status in (Alert.Status.RESOLVED, Alert.Status.FALSE_POSITIVE):
            from django.utils import timezone as dj_timezone
            instance.resolved_at = dj_timezone.now()
            instance.resolved_by = self.request.user
            instance.save(update_fields=["resolved_at", "resolved_by"])


# ─── ML Model ──────────────────────────────────────────────────────────────────

class MLStatusView(APIView):
    """GET /api/v1/ml/status/ — Get ML model status."""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({
            "model_type": "Isolation Forest",
            "is_trained": ml_service.is_trained,
            "anomaly_threshold": 0.75,
            "fallback": "Heuristic rule-based detection",
        })


class MLTrainView(APIView):
    """POST /api/v1/ml/train/ — Trigger model retraining."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        events = NetworkEvent.objects.values(
            "src_port", "dst_port", "packet_size", "duration", "protocol", "flags"
        )
        event_list = list(events)
        if len(event_list) < 50:
            return Response(
                {"error": f"Not enough data: {len(event_list)} events (min 50 required)."},
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        success = ml_service.train(event_list)
        if not success:
            return Response(
                {"error": "Training failed. Check server logs."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return Response({
            "status": "success",
            "message": f"Model retrained on {len(event_list)} events.",
            "events_used": len(event_list),
        })


class MLPredictView(APIView):
    """POST /api/v1/ml/predict/ — Run prediction on a single event payload."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        score, is_anomalous = ml_service.predict(request.data)
        return Response({
            "anomaly_score": score,
            "is_anomalous": is_anomalous,
            "classification": "ANOMALOUS" if is_anomalous else "NORMAL",
            "threshold": 0.75,
        })


# ─── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardStatsView(APIView):
    """GET /api/v1/dashboard/stats/ — Aggregated dashboard statistics."""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        total_events = NetworkEvent.objects.count()
        anomalous_events = NetworkEvent.objects.filter(is_anomalous=True).count()
        total_alerts = Alert.objects.count()
        open_alerts = Alert.objects.filter(status=Alert.Status.OPEN).count()

        severity_counts = {
            s: Alert.objects.filter(severity=s).count()
            for s in [Alert.Severity.CRITICAL, Alert.Severity.HIGH,
                      Alert.Severity.MEDIUM, Alert.Severity.LOW]
        }

        top_attack_types = dict(
            Alert.objects.values("attack_type")
            .annotate(count=Count("id"))
            .order_by("-count")
            .values_list("attack_type", "count")[:5]
        )

        detection_rate = (
            round(anomalous_events / total_events * 100, 2) if total_events > 0 else 0.0
        )

        stats = {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "critical_alerts": severity_counts[Alert.Severity.CRITICAL],
            "high_alerts": severity_counts[Alert.Severity.HIGH],
            "medium_alerts": severity_counts[Alert.Severity.MEDIUM],
            "low_alerts": severity_counts[Alert.Severity.LOW],
            "anomalous_events": anomalous_events,
            "detection_rate": detection_rate,
            "top_attack_types": top_attack_types,
            "events_last_24h": NetworkEvent.objects.filter(timestamp__gte=cutoff).count(),
            "alerts_last_24h": Alert.objects.filter(timestamp__gte=cutoff).count(),
        }

        serializer = DashboardStatsSerializer(stats)
        return Response(serializer.data)
