"""Serializers for User accounts."""

from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from accounts.models import User


class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for new user registration."""

    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True, label="Confirm Password")

    class Meta:
        model = User
        fields = ("username", "email", "password", "password2", "full_name", "role")
        extra_kwargs = {"email": {"required": True}}

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserSerializer(serializers.ModelSerializer):
    """Read-only user profile serializer."""

    class Meta:
        model = User
        fields = (
            "id", "username", "email", "full_name", "role",
            "is_active", "is_staff", "date_joined", "last_login",
        )
        read_only_fields = ("id", "date_joined", "last_login", "is_staff")


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """JWT token serializer that includes user info in the response."""

    def validate(self, attrs):
        data = super().validate(attrs)
        data["user"] = UserSerializer(self.user).data
        return data
