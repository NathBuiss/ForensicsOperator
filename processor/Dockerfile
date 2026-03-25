FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# ── System deps ───────────────────────────────────────────────────────────────
# binutils               → 'strings' command for Strings module
# perl                   → RegRipper (Perl-based)
# unzip                  → Hayabusa + RegRipper zip extraction
# libimage-exiftool-perl → ExifTool metadata extractor
# libjpeg-dev / zlib1g-dev → optional image libraries for ExifTool
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    libmagic1 libmagic-dev \
    wget curl \
    binutils \
    perl \
    unzip \
    libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

# ── Hayabusa DFIR binary + rules (Sigma-based EVTX threat hunting) ───────────
# Extract to a temp location, then normalize: copy the *contents* of the
# directory that contains the binary (which also contains rules/ and config/)
# into /opt/hayabusa/ — regardless of whether the zip has a top-level folder.
ARG HAYABUSA_VERSION=3.2.0
RUN wget -q -O /tmp/hayabusa.zip \
         "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl.zip" \
    && unzip -q /tmp/hayabusa.zip -d /tmp/hayabusa_extracted \
    && BIN=$(find /tmp/hayabusa_extracted -name "hayabusa-*-lin-x64-musl" -not -name "*.zip" -type f | head -1) \
    && cp -r "$(dirname "$BIN")/." /opt/hayabusa/ \
    && chmod +x "/opt/hayabusa/$(basename "$BIN")" \
    && ln -sf "/opt/hayabusa/$(basename "$BIN")" /usr/local/bin/hayabusa \
    && rm -rf /tmp/hayabusa.zip /tmp/hayabusa_extracted

# ── RegRipper (deep Windows registry analysis, Perl) ─────────────────────────
RUN wget -q -O /tmp/regripper.zip \
         "https://github.com/keydet89/RegRipper3.0/archive/refs/heads/master.zip" \
    && unzip -q /tmp/regripper.zip -d /opt/ \
    && mv /opt/RegRipper3.0-master /opt/regripper \
    && chmod +x /opt/regripper/rip.pl \
    && rm /tmp/regripper.zip

# ── Python deps (includes pyhindsight for the Hindsight module) ───────────────
COPY processor/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# ── Processor source code ─────────────────────────────────────────────────────
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
