"""Application configuration via environment variables."""
import os


class Settings:
    ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch-service:9200")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis-service:6379/0")
    MINIO_ENDPOINT: str = os.getenv("MINIO_ENDPOINT", "minio-service:9000")
    MINIO_ACCESS_KEY: str = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
    MINIO_SECRET_KEY: str = os.getenv("MINIO_SECRET_KEY", "minioadmin")
    MINIO_BUCKET: str = os.getenv("MINIO_BUCKET", "forensics-cases")
    PLUGINS_DIR: str = os.getenv("PLUGINS_DIR", "/app/plugins")
    DEFAULT_PAGE_SIZE: int = int(os.getenv("DEFAULT_PAGE_SIZE", "100"))
    MAX_PAGE_SIZE: int = int(os.getenv("MAX_PAGE_SIZE", "1000"))


settings = Settings()
