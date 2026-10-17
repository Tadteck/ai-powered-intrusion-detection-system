"""URL patterns for the detection app."""

from django.urls import path
from detection.views import (
    NetworkEventListView,
    NetworkEventIngestView,
    NetworkEventDetailView,
    AlertListCreateView,
    AlertDetailView,
    AlertUpdateView,
    MLStatusView,
    MLTrainView,
    MLPredictView,
    DashboardStatsView,
)

urlpatterns = [
    # Network Events
    path("events/", NetworkEventListView.as_view(), name="event-list"),
    path("events/ingest/", NetworkEventIngestView.as_view(), name="event-ingest"),
    path("events/<int:pk>/", NetworkEventDetailView.as_view(), name="event-detail"),

    # Alerts
    path("alerts/", AlertListCreateView.as_view(), name="alert-list"),
    path("alerts/<int:pk>/", AlertDetailView.as_view(), name="alert-detail"),
    path("alerts/<int:pk>/update/", AlertUpdateView.as_view(), name="alert-update"),

    # ML
    path("ml/status/", MLStatusView.as_view(), name="ml-status"),
    path("ml/train/", MLTrainView.as_view(), name="ml-train"),
    path("ml/predict/", MLPredictView.as_view(), name="ml-predict"),

    # Dashboard
    path("dashboard/stats/", DashboardStatsView.as_view(), name="dashboard-stats"),
]
