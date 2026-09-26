# ─────────────────────────────────────────────────────────────
# app/main.py
# Purpose: FastAPI application entry point
# ─────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager
# asynccontextmanager = decorator for creating async context managers
# Used for startup/shutdown lifecycle management

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
# CORS = Cross-Origin Resource Sharing
# Browser security: by default, a page at http://localhost:3000
# CANNOT call an API at http://localhost:8000 (different port = different origin)
# CORS middleware tells the browser: "It's okay, I allow this."

from app.config import settings
from app.database import check_database_connection
from app.cache import init_redis, close_redis
from app.api.health import router as health_router
from app.api.events import router as events_router

# ─────────────────────────────────────────────────────────────
# Configure structured logging
# ─────────────────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.dev.ConsoleRenderer() if True else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(20),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)
# Why structured (JSON) logging?
# Traditional: "2026-07-07 21:55:05 ERROR Database connection failed"
# Structured:  {"timestamp": "...", "level": "error", "event": "database_connection_failed"}
# OpenSearch can query structured logs: "show me all errors in the last hour"

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# Application Lifecycle (startup + shutdown)
# ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # This function runs:
    # - BEFORE the first request (startup code)
    # - AFTER the last request (shutdown code)
    
    # ── STARTUP ──
    logger.info("sentinelops_starting", version=settings.app_version)
    
    # Initialize Redis connection
    await init_redis()
    logger.info("redis_initialized")
    
    # Check database is reachable
    db_ok = await check_database_connection()
    if not db_ok:
        logger.error("database_not_reachable_on_startup")
        # In production: you might want to raise an exception here
        # For development: we continue and let health check report it
    
    logger.info("sentinelops_ready", 
                service=settings.app_name,
                environment=settings.environment)
    
    yield
    # ↑ Everything BEFORE yield = startup
    # ↓ Everything AFTER yield = shutdown
    
    # ── SHUTDOWN ──
    logger.info("sentinelops_shutting_down")
    await close_redis()
    logger.info("sentinelops_stopped")


# ─────────────────────────────────────────────────────────────
# Create the FastAPI application
# ─────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.app_name,
    # Shows in the /docs page title
    
    version=settings.app_version,
    
    description="""
    SentinelOps Platform API
    
    AI-Augmented Security Operations Platform for on-premises infrastructure.
    """,
    
    docs_url="/docs" if settings.debug else None,
    # /docs = Swagger UI (interactive documentation)
    # In production (debug=False): disable public docs (security risk)
    
    redoc_url="/redoc" if settings.debug else None,
    # /redoc = alternative documentation UI
    
    lifespan=lifespan,
    # Tell FastAPI to use our startup/shutdown function
)


# ─────────────────────────────────────────────────────────────
# Middleware: CORS (Cross-Origin Resource Sharing)
# ─────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # React dev server
        "http://localhost:80",    # Nginx
        "http://localhost",
    ],
    # In production: replace with your actual domain
    # allow_origins=["https://sentinelops.yourcompany.com"]
    
    allow_credentials=True,
    # Allow cookies/auth headers in cross-origin requests
    
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    # Which HTTP methods are allowed
    
    allow_headers=["*"],
    # Which headers are allowed (Authorization, Content-Type, etc.)
)


# ─────────────────────────────────────────────────────────────
# Include Routers
# ─────────────────────────────────────────────────────────────
app.include_router(health_router)
# This adds all routes from health.py to our app
# /health, /health/ready, /health/live are now active

app.include_router(events_router)
# Phase 3: event simulation and pipeline status endpoints
# POST /api/v1/events/simulate  — inject test event into Kafka
# GET  /api/v1/events/pipeline-status — check Kafka connectivity


# ─────────────────────────────────────────────────────────────
# Root endpoint
# ─────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "docs": "/docs" if settings.debug else "disabled",
        "health": "/health",
        "events": "/api/v1/events/simulate",
        "pipeline_status": "/api/v1/events/pipeline-status",
        "message": "SentinelOps Platform is running — Phase 3 active"
    }
