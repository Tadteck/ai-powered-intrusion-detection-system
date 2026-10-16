"""
User Service - business logic for user management.
"""

from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate
from app.core.security import get_password_hash, verify_password
from app.core.logger import logger


class UserService:
    """Handles user CRUD operations."""

    async def create_user(self, db: AsyncSession, data: UserCreate) -> User:
        """Create a new user with hashed password."""
        hashed_password = get_password_hash(data.password)
        user = User(
            username=data.username,
            email=data.email,
            full_name=data.full_name,
            role=data.role,
            hashed_password=hashed_password,
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)
        logger.info(f"User created: id={user.id} username={user.username}")
        return user

    async def get_by_id(self, db: AsyncSession, user_id: int) -> Optional[User]:
        """Get user by ID."""
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_username(self, db: AsyncSession, username: str) -> Optional[User]:
        """Get user by username."""
        result = await db.execute(select(User).where(User.username == username))
        return result.scalar_one_or_none()

    async def get_by_email(self, db: AsyncSession, email: str) -> Optional[User]:
        """Get user by email."""
        result = await db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def list_users(
        self, db: AsyncSession, skip: int = 0, limit: int = 100
    ) -> List[User]:
        """List all users."""
        result = await db.execute(select(User).offset(skip).limit(limit))
        return list(result.scalars().all())

    async def update_user(
        self, db: AsyncSession, user_id: int, data: UserUpdate
    ) -> Optional[User]:
        """Update user fields."""
        user = await self.get_by_id(db, user_id)
        if not user:
            return None
        for field, value in data.model_dump(exclude_unset=True).items():
            setattr(user, field, value)
        await db.flush()
        await db.refresh(user)
        return user

    async def authenticate(
        self, db: AsyncSession, username: str, password: str
    ) -> Optional[User]:
        """Authenticate a user by username/password."""
        user = await self.get_by_username(db, username)
        if not user or not verify_password(password, user.hashed_password):
            return None
        if not user.is_active:
            return None
        # Update last login
        user.last_login = datetime.now(timezone.utc)
        await db.flush()
        return user


user_service = UserService()
