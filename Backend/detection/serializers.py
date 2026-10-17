"""
DRF Serializers for NetworkEvent, Alert, and Dashboard.
"""

from rest_framework import serializers
from detection.models import NetworkEvent, Alert


class NetworkEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkEvent
        fields = "__all__"
        read_only_fields = ("id", "timestamp", "anomaly_score", "is_anomalous")


class NetworkEventIngestSerializer(serializers.ModelSerializer):
    """Serializer used for ingesting new events (writable fields only)."""

    class Meta:
        model = NetworkEvent
        fields = (
            "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "packet_size", "duration", "flags", "features",
        )


class AlertSerializer(serializers.ModelSerializer):
    network_event_id = serializers.PrimaryKeyRelatedField(
        source="network_event",
        queryset=NetworkEvent.objects.all(),
        required=False,
        allow_null=True,
    )
    resolved_by_username = serializers.CharField(
        source="resolved_by.username", read_only=True, default=None
    )

    class Meta:
        model = Alert
        fields = "__all__"
        read_only_fields = ("id", "timestamp", "resolved_at", "resolved_by", "resolved_by_username")


class AlertUpdateSerializer(serializers.ModelSerializer):
    """Partial update: only allow status, severity, notes."""

    class Meta:
        model = Alert
        fields = ("status", "severity", "notes")


class DashboardStatsSerializer(serializers.Serializer):
    total_events = serializers.IntegerField()
    total_alerts = serializers.IntegerField()
    open_alerts = serializers.IntegerField()
    critical_alerts = serializers.IntegerField()
    high_alerts = serializers.IntegerField()
    medium_alerts = serializers.IntegerField()
    low_alerts = serializers.IntegerField()
    anomalous_events = serializers.IntegerField()
    detection_rate = serializers.FloatField()
    top_attack_types = serializers.DictField(child=serializers.IntegerField())
    events_last_24h = serializers.IntegerField()
    alerts_last_24h = serializers.IntegerField()
