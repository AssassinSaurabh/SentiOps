# ─────────────────────────────────────────────────
# Stage 1: Base image
# ─────────────────────────────────────────────────

# FROM: start with this base image
# python:3.11-slim = Python 3.11 on Debian Slim (smaller than full Debian)
# Why 3.11? Latest stable Python with best performance
# Why slim? Removes unnecessary packages, smaller image, fewer vulnerabilities
FROM python:3.11-slim

# ─────────────────────────────────────────────────
# Security: Don't run as root
# ─────────────────────────────────────────────────

# Create a non-root user for running our app
# Why? If the container is compromised, attacker only has 'appuser' privileges
# Root = can do anything. appuser = limited permissions.
RUN groupadd -r appuser && useradd -r -g appuser appuser
# groupadd -r = create a system group (no login shell, no home dir)
# useradd -r  = create a system user
# -g appuser  = add to appuser group

# ─────────────────────────────────────────────────
# Set the working directory inside the container
# ─────────────────────────────────────────────────
WORKDIR /app
# All subsequent commands run from /app
# This is where our code lives inside the container

# ─────────────────────────────────────────────────
# System dependencies
# ─────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libpq-dev \
    librdkafka-dev \
    && rm -rf /var/lib/apt/lists/*
# apt-get update        = refresh package list
# apt-get install -y    = install without asking yes/no
# --no-install-recommends = don't install suggested packages (smaller image)
# curl     = for healthcheck scripts
# gcc      = compiler (some Python packages need it)
# libpq-dev = PostgreSQL C library (required for psycopg2/asyncpg)
# rm -rf /var/lib/apt/lists/* = delete package cache (reduces image size)

# ─────────────────────────────────────────────────
# Install Python dependencies
# ─────────────────────────────────────────────────

# Copy requirements FIRST (before copying code)
# Why? Docker caches layers. If requirements don't change,
# Docker skips re-installing packages on every code change.
# This makes rebuilds much faster.
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt
# --no-cache-dir = don't save downloaded packages (smaller image)
# --upgrade pip  = ensure pip itself is latest version

# ─────────────────────────────────────────────────
# Copy application code
# ─────────────────────────────────────────────────
COPY . .
# Copy everything from ./backend (your Mac) to /app (container)

# Set correct ownership (our non-root user owns the files)
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# ─────────────────────────────────────────────────
# Document which port this container uses
# ─────────────────────────────────────────────────
EXPOSE 8000
# This is documentation only. Actual port mapping in docker-compose.yml.

# ─────────────────────────────────────────────────
# Default command to start FastAPI
# ─────────────────────────────────────────────────
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
# This is overridden by docker-compose.yml's 'command' in development
# Used when running the container directly: docker run sentinelops-fastapi
