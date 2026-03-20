"""Application configuration via environment variables."""
import os


class Settings:
    # ── Infrastructure ─────────────────────────────────────────────────────
    ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch-service:9200")
    REDIS_URL: str         = os.getenv("REDIS_URL",         "redis://redis-service:6379/0")
    MINIO_ENDPOINT: str    = os.getenv("MINIO_ENDPOINT",    "minio-service:9000")
    MINIO_ACCESS_KEY: str  = os.getenv("MINIO_ACCESS_KEY",  "minioadmin")
    MINIO_SECRET_KEY: str  = os.getenv("MINIO_SECRET_KEY",  "minioadmin")
    MINIO_BUCKET: str      = os.getenv("MINIO_BUCKET",      "forensics-cases")
    PLUGINS_DIR: str       = os.getenv("PLUGINS_DIR",       "/app/plugins")

    # ── Pagination ─────────────────────────────────────────────────────────
    DEFAULT_PAGE_SIZE: int = int(os.getenv("DEFAULT_PAGE_SIZE", "100"))
    MAX_PAGE_SIZE: int     = int(os.getenv("MAX_PAGE_SIZE",     "1000"))

    # ── Authentication ─────────────────────────────────────────────────────
    # Set AUTH_ENABLED=false to disable auth (dev/trusted-LAN only).
    AUTH_ENABLED: bool     = os.getenv("AUTH_ENABLED", "true").lower() not in ("false", "0", "no")
    # JWT_SECRET MUST be a strong random string in production.
    # Generate one: python -c "import secrets; print(secrets.token_hex(32))"
    JWT_SECRET: str        = os.getenv("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")
    JWT_ALGORITHM: str     = "HS256"
    JWT_EXPIRE_HOURS: int  = int(os.getenv("JWT_EXPIRE_HOURS", "8"))


settings = Settings()
