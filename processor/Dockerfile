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
COPY processor/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Processor source code
COPY processor/ .
RUN touch tasks/__init__.py utils/__init__.py

# Built-in plugins baked into the image at a separate path.
# The seed-plugins init container copies these into the shared PVC (/app/plugins)
# at pod startup, so they are available at runtime without being overwritten by
# the volume mount.
COPY plugins/ /app/plugins_builtin/

# Mount point for the shared plugins volume (populated at runtime by init container)
RUN mkdir -p /app/plugins

CMD ["celery", "-A", "celery_app", "worker", "--loglevel=info", "--concurrency=2"]
