FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Embed the artifact collector script so the download endpoint can serve it
RUN mkdir -p /app/static
# collector/collect.py is copied via docker-compose build context (../collector/collect.py)
# If running from the api/ sub-directory, the file is placed here at build time.

# Create routers and services __init__.py stubs
RUN touch routers/__init__.py services/__init__.py

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
