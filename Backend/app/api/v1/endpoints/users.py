"""
User management endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from app.core.database import get_db
from app.core.security import get_current_user_id
from app.schemas.user import UserResponse, UserUpdate
from app.services.user_service import user_service

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Get the currently authenticated user's profile."""
    user = await user_service.get_by_id(db, int(user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("/", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """List all users (admin only in production)."""
    return await user_service.list_users(db, skip=skip, limit=limit)


@router.get("/{target_user_id}", response_model=UserResponse)
async def get_user(
    target_user_id: int,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific user by ID."""
    user = await user_service.get_by_id(db, target_user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch("/{target_user_id}", response_model=UserResponse)
async def update_user(
    target_user_id: int,
    data: UserUpdate,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Update user information."""
    user = await user_service.update_user(db, target_user_id, data)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
