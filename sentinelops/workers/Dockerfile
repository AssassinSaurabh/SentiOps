# ─────────────────────────────────────────────────────────────
# workers/Dockerfile
# ONE Dockerfile shared by all 3 workers.
# The docker-compose.yml command: field selects which worker runs.
# ─────────────────────────────────────────────────────────────

FROM python:3.11-slim

# Security: run as non-root user
RUN groupadd -r worker && useradd -r -g worker worker

WORKDIR /app

# Install system dependencies
# librdkafka-dev = C library required by confluent-kafka
# libpq-dev      = PostgreSQL C library required by psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    librdkafka-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (cached layer if requirements.txt unchanged)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy all worker code
COPY . .

# Set correct ownership
RUN chown -R worker:worker /app

# Run as non-root user
USER worker

# Default command (overridden per service in docker-compose.yml)
CMD ["python", "-u", "normalizer/main.py"]
