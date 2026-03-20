"""Authentication service — JWT + bcrypt, users stored in Redis."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

import redis as redis_lib
from jose import JWTError, jwt
from passlib.context import CryptContext

from config import settings

logger = logging.getLogger(__name__)

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

_USERS_SET  = "fo:users"
_USER_KEY   = "fo:user:{username}"


def _redis() -> redis_lib.Redis:
    return redis_lib.Redis.from_url(settings.REDIS_URL, decode_responses=True)


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return _pwd_ctx.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


# ── JWT helpers ───────────────────────────────────────────────────────────────

def create_token(username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRE_HOURS)
    payload = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and verify JWT. Raises JWTError on failure."""
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])


# ── User CRUD (Redis-backed) ──────────────────────────────────────────────────

def get_user(username: str) -> Optional[dict]:
    r = _redis()
    data = r.hgetall(_USER_KEY.format(username=username))
    return data or None


def authenticate(username: str, password: str) -> Optional[dict]:
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user.get("hashed_password", "")):
        return None
    return user


def create_user(username: str, password: str, role: str = "analyst") -> dict:
    r = _redis()
    key = _USER_KEY.format(username=username)
    if r.exists(key):
        raise ValueError(f"User '{username}' already exists")
    user = {
        "username":        username,
        "hashed_password": hash_password(password),
        "role":            role,
        "created_at":      datetime.now(timezone.utc).isoformat(),
    }
    r.hset(key, mapping=user)
    r.sadd(_USERS_SET, username)
    return _public(user)


def delete_user(username: str) -> bool:
    r = _redis()
    key = _USER_KEY.format(username=username)
    if not r.exists(key):
        return False
    r.delete(key)
    r.srem(_USERS_SET, username)
    return True


def list_users() -> list[dict]:
    r = _redis()
    usernames = r.smembers(_USERS_SET)
    users = []
    for u in sorted(usernames):
        user = r.hgetall(_USER_KEY.format(username=u))
        if user:
            users.append(_public(user))
    return users


def update_password(username: str, new_password: str) -> bool:
    r = _redis()
    key = _USER_KEY.format(username=username)
    if not r.exists(key):
        return False
    r.hset(key, "hashed_password", hash_password(new_password))
    return True


def change_role(username: str, new_role: str) -> bool:
    r = _redis()
    key = _USER_KEY.format(username=username)
    if not r.exists(key):
        return False
    r.hset(key, "role", new_role)
    return True


def user_count() -> int:
    return _redis().scard(_USERS_SET)


def _public(user: dict) -> dict:
    """Strip hashed_password before returning to callers."""
    return {k: v for k, v in user.items() if k != "hashed_password"}
