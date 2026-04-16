FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Build context is the repo root — copy api/ sources first
COPY api/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ .

# Bake the artifact collector script into the image so the download
# endpoint always works — regardless of whether the volume mount is present.
RUN mkdir -p /app/collector
COPY collector/collect.py /app/collector/collect.py

# Bake the ForensicHarvester source tree so the package download endpoint works.
COPY forensic_harvester/ /app/forensic_harvester/

RUN mkdir -p /app/static

# Ensure all internal packages have __init__.py stubs
RUN touch routers/__init__.py services/__init__.py auth/__init__.py

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
