FROM ubuntu:24.04

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
    build-essential \
    libmagic1 libmagic-dev \
    wget curl git \
    binutils \
    perl \
    unzip \
    libimage-exiftool-perl \
    libtsk-dev \
    testdisk \
    mono-runtime \
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

# ── de4dot (.NET assembly deobfuscator, runs under Mono) ─────────────────────
# Uses kant2002/de4dot v3.2.0 net48 build (Mono-compatible Linux binary).
RUN wget -q -O /tmp/de4dot.zip \
         "https://github.com/kant2002/de4dot/releases/download/v3.2.0/de4dot-net48.zip" \
    && unzip -q /tmp/de4dot.zip -d /tmp/de4dot_extracted \
    && mkdir -p /usr/local/lib/de4dot \
    && EXE=$(find /tmp/de4dot_extracted -name "de4dot.exe" -type f | head -1) \
    && cp "$EXE" /usr/local/lib/de4dot/de4dot.exe \
    && printf '#!/bin/sh\nexec mono /usr/local/lib/de4dot/de4dot.exe "$@"\n' \
         > /usr/local/bin/de4dot \
    && chmod +x /usr/local/bin/de4dot \
    && rm -rf /tmp/de4dot.zip /tmp/de4dot_extracted

# ── Plaso (log2timeline/psort) — required for .plaso file parsing ────────────
# Try latest plaso versions from PyPI until one installs successfully
RUN pip3 install --no-cache-dir --upgrade pip setuptools wheel && \
    (pip3 install --no-cache-dir plaso==20260119 || \
     pip3 install --no-cache-dir plaso==20250918 || \
     pip3 install --no-cache-dir plaso==20240826 || \
     pip3 install --no-cache-dir plaso==20240308)

# ── Python deps (includes pyhindsight for the Hindsight module) ───────────────
# Upgrade build tools first so pyproject.toml-based packages build on Ubuntu 22.04's old pip.
RUN pip3 install --no-cache-dir --upgrade pip setuptools wheel
COPY processor/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# ccl_chromium_reader is required by pyhindsight but is not on PyPI.
# Install from GitHub (has pyproject.toml so pip handles it, including its ccl_simplesnappy dep).
RUN pip3 install --no-cache-dir \
    "git+https://github.com/cclgroupltd/ccl_chromium_reader.git" \
    && python3 -c "import ccl_chromium_reader; print('ccl_chromium_reader installed OK')"

# Patch pyhindsight for Python < 3.11 compatibility.
# datetime.UTC was introduced in Python 3.11; replace with datetime.timezone.utc.
RUN python3 -c "import datetime; datetime.UTC" 2>/dev/null || \
    find /usr/local/lib /usr/lib -name "*.py" -path "*/pyhindsight/*" -exec \
    sed -i 's/datetime\.UTC/datetime.timezone.utc/g' {} \;

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

# CELERY_CONCURRENCY — number of parallel worker processes per pod replica.
# Default 4 is a good baseline for mixed I/O + CPU workloads.
# For CPU-heavy modules (Hayabusa, Volatility3) set to number of vCPUs assigned.
# For I/O-heavy ingest-only workers set to 8–16.
CMD ["sh", "-c", "celery -A celery_app worker --loglevel=info --concurrency=${CELERY_CONCURRENCY:-4} -Q ingest,modules,default"]
