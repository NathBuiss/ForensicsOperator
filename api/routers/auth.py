"""Authentication router — login + token + current user."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from auth.service import authenticate, create_token, get_user
from auth.dependencies import get_current_user

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
