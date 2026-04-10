"""FastAPI auth dependencies — inject into routers via Depends()."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

from auth.service import decode_token, get_user
from config import settings

_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)


async def get_current_user(
    request: Request,
    token: str | None = Depends(_oauth2),
) -> dict:
    """
    Validate the JWT and return the user dict.

    Accepts the token from:
      1. Authorization: Bearer <token>  header  (normal API calls)
      2. ?_token=<token>                query param  (browser downloads — CSV export,
                                                      collector script — where headers
                                                      cannot be set by the browser)

    If AUTH_ENABLED=false the dependency is a no-op and returns a synthetic
    admin user so all existing code keeps working in dev/trusted-LAN mode.
    """
    if not settings.AUTH_ENABLED:
        return {"username": "local", "role": "admin"}

    # Fall back to ?_token query param for browser-initiated downloads
    effective_token = token or request.query_params.get("_token")

    if not effective_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(effective_token)
        username: str | None = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = get_user(username)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        # Defensive: backfill role for pre-RBAC accounts still in Redis.
        # The startup migration normally handles this; this guard covers edge cases.
        if not user.get("role"):
            from auth.service import _USER_KEY, user_count
            try:
                from config import get_redis as _get_redis
                r = _get_redis()
                r.hset(_USER_KEY.format(username=username), "role", "admin")
                user["role"] = "admin"
            except Exception:
                user["role"] = "admin"  # best-effort in memory
        return user
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Only allow users with the 'admin' role."""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


async def require_analyst_or_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Allow users with either the 'analyst' or 'admin' role."""
    if current_user.get("role") not in ("admin", "analyst"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or admin access required",
        )
    return current_user
