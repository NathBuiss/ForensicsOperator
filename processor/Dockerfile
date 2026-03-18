FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# Install system deps
# Note: plaso-tools (psort) is NOT installed here because the GIFT PPA requires
# a gpg-agent that is unavailable in Docker build contexts. The plaso plugin
# falls back to reading .plaso SQLite storage files directly instead.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    libmagic1 libmagic-dev \
    wget curl \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .
RUN touch tasks/__init__.py utils/__init__.py

# Mount point for the shared plugins volume
RUN mkdir -p /app/plugins

CMD ["celery", "-A", "celery_app", "worker", "--loglevel=info", "--concurrency=2"]
