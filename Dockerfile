# Dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir requests

# Copy app
COPY main.py /app/main.py
COPY healthcheck.py /app/healthcheck.py

# Run as non-root (optional)
RUN useradd -r -u 1000 ddns
USER ddns

# Docker healthcheck uses our /healthz endpoint
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
  CMD ["python", "/app/healthcheck.py"]

CMD ["python", "-u", "main.py"]
