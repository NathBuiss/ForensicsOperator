"""FastAPI auth dependencies — inject into routers via Depends()."""
from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

from auth.service import decode_token, get_user
from config import settings

_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)


async def get_current_user(token: str | None = Depends(_oauth2)) -> dict:
    """
    Validate the JWT and return the user dict.

    If AUTH_ENABLED=false the dependency is a no-op and returns a synthetic
    admin user so all existing code keeps working in dev/trusted-LAN mode.
    """
    if not settings.AUTH_ENABLED:
        return {"username": "local", "role": "admin"}

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(token)
        username: str | None = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = get_user(username)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user
