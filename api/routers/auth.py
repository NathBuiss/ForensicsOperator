"""Authentication router — login + token + current user + admin management."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

from auth.service import (
    authenticate,
    create_token,
    create_user,
    delete_user,
    get_user,
    list_users,
    update_user,
    verify_password,
    VALID_ROLES,
)
from auth.dependencies import get_current_user, require_admin

router = APIRouter(prefix="/auth", tags=["auth"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    role: str


class UserInfo(BaseModel):
    username: str
    role: str


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=8)
    role: str = Field("analyst", description="User role: admin or analyst")


class UpdateUserRequest(BaseModel):
    role: Optional[str] = Field(None, description="New role: admin or analyst")
    password: Optional[str] = Field(None, min_length=8, description="New password (min 8 chars)")


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse, summary="Login (JSON)")
async def login(body: LoginRequest):
    """Primary login endpoint used by the frontend."""
    user = authenticate(body.username, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token = create_token(user["username"], user["role"])
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        username=user["username"],
        role=user["role"],
    )


@router.post("/token", response_model=TokenResponse, summary="Login (OAuth2 form)")
async def token(form: OAuth2PasswordRequestForm = Depends()):
    """OAuth2-compatible endpoint for tooling (Swagger UI, curl, etc.)."""
    user = authenticate(form.username, form.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    tok = create_token(user["username"], user["role"])
    return TokenResponse(
        access_token=tok,
        token_type="bearer",
        username=user["username"],
        role=user["role"],
    )


@router.get("/me", response_model=UserInfo, summary="Current user info")
async def me(current_user: dict = Depends(get_current_user)):
    return UserInfo(username=current_user["username"], role=current_user["role"])


# ── Self-service: change own password ────────────────────────────────────────

@router.put("/me/password", summary="Change own password")
async def change_own_password(
    body: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
):
    """Any authenticated user can change their own password."""
    user = get_user(current_user["username"])
    if not user or not verify_password(body.old_password, user.get("hashed_password", "")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    update_user(current_user["username"], password=body.new_password)
    return {"detail": "Password updated successfully"}


# ── Admin: user management ───────────────────────────────────────────────────

@router.get("/users", summary="List all users (admin only)")
async def admin_list_users(admin: dict = Depends(require_admin)):
    """Return all users with their roles."""
    return list_users()


@router.post(
    "/users",
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user (admin only)",
)
async def admin_create_user(
    body: CreateUserRequest,
    admin: dict = Depends(require_admin),
):
    """Create a user with the given username, password and role."""
    try:
        user = create_user(body.username, body.password, body.role)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    return user


@router.put("/users/{username}", summary="Update a user (admin only)")
async def admin_update_user(
    username: str,
    body: UpdateUserRequest,
    admin: dict = Depends(require_admin),
):
    """Update a user's role and/or reset their password."""
    if body.role is None and body.password is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nothing to update — provide 'role' and/or 'password'",
        )
    try:
        user = update_user(username, role=body.role, password=body.password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    return user


@router.delete("/users/{username}", summary="Delete a user (admin only)")
async def admin_delete_user(
    username: str,
    admin: dict = Depends(require_admin),
):
    """Delete a user. Admins cannot delete themselves."""
    if username == admin["username"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )
    if not delete_user(username):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found",
        )
    return {"detail": f"User '{username}' deleted"}
