"""Django admin registration for detection models."""

from django.contrib import admin
from detection.models import NetworkEvent, Alert


@admin.register(NetworkEvent)
class NetworkEventAdmin(admin.ModelAdmin):
    list_display = ("id", "timestamp", "src_ip", "dst_ip", "protocol", "anomaly_score", "is_anomalous")
    list_filter = ("is_anomalous", "protocol")
    search_fields = ("src_ip", "dst_ip")
    readonly_fields = ("timestamp", "anomaly_score", "is_anomalous")
    ordering = ("-timestamp",)


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("id", "timestamp", "title", "severity", "status", "attack_type", "src_ip")
    list_filter = ("severity", "status", "attack_type")
    search_fields = ("title", "description", "src_ip", "dst_ip")
    readonly_fields = ("timestamp", "resolved_at", "resolved_by")
    ordering = ("-timestamp",)
