"""URL patterns for the accounts app."""

from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from accounts.views import (
    RegisterView,
    CustomTokenObtainPairView,
    MeView,
    UserListView,
)

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", CustomTokenObtainPairView.as_view(), name="login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("me/", MeView.as_view(), name="me"),
    path("users/", UserListView.as_view(), name="user-list"),
]
