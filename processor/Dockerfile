FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# Install system deps + Plaso from GIFT PPA
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    software-properties-common \
    libmagic1 libmagic-dev \
    wget curl \
    && add-apt-repository ppa:gift/stable -y \
    && apt-get update \
    && apt-get install -y --no-install-recommends plaso-tools \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .
RUN touch tasks/__init__.py utils/__init__.py

# Mount point for the shared plugins volume
RUN mkdir -p /app/plugins

CMD ["celery", "-A", "celery_app", "worker", "--loglevel=info", "--concurrency=2"]
