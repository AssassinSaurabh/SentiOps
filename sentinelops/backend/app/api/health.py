# ─────────────────────────────────────────────────────────────
# app/api/health.py
# Purpose: Health check endpoint (/health)
# ─────────────────────────────────────────────────────────────

from datetime import datetime

from fastapi import APIRouter, Depends
# APIRouter = way to group related endpoints (we include this in main.py)
# Depends = FastAPI's dependency injection system

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.database import get_db
from app.cache import check_redis_connection
from app.config import settings
import structlog

logger = structlog.get_logger(__name__)

# Create a router for health-related endpoints
# prefix="/health" means: all routes in this router start with /health
router = APIRouter(prefix="/health", tags=["Health"])
# tags=["Health"] = groups this endpoint in the /docs page under "Health"


@router.get("")
# @router.get("") = handle GET requests to /health (empty string = no extra path)
async def health_check(db: AsyncSession = Depends(get_db)):
    # async def = this function is asynchronous (non-blocking)
    # db: AsyncSession = Depends(get_db):
    #   FastAPI calls get_db() and passes the session as 'db'
    #   This is "Dependency Injection" - FastAPI handles the lifecycle
    
    health_status = {
        "status": "healthy",
        # We'll change this to "degraded" or "unhealthy" if something fails
        
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "timestamp": datetime.utcnow().isoformat(),
        # utcnow() = current time in UTC (always use UTC in APIs)
        
        "checks": {}
        # We'll populate this with individual component checks
    }
    
    # ── Check 1: Database (PostgreSQL) ──
    try:
        await db.execute(text("SELECT 1"))
        # Run the simplest possible query
        health_status["checks"]["database"] = {
            "status": "healthy",
            "type": "postgresql"
        }
    except Exception as e:
        health_status["checks"]["database"] = {
            "status": "unhealthy",
            "error": str(e),
            "type": "postgresql"
        }
        health_status["status"] = "degraded"
        # degraded = app is running but some dependencies are unhealthy
        logger.error("health_check_database_failed", error=str(e))
    
    # ── Check 2: Cache (Redis) ──
    redis_healthy = await check_redis_connection()
    health_status["checks"]["cache"] = {
        "status": "healthy" if redis_healthy else "unhealthy",
        "type": "redis"
    }
    if not redis_healthy:
        health_status["status"] = "degraded"
        logger.warning("health_check_redis_failed")
    
    # ── Determine HTTP status code ──
    # HTTP 200 = everything OK
    # HTTP 503 = service unavailable (something critical is down)
    
    from fastapi.responses import JSONResponse
    status_code = 200 if health_status["status"] == "healthy" else 503
    
    return JSONResponse(
        content=health_status,
        status_code=status_code
    )
    # JSONResponse = FastAPI returns JSON with the specified HTTP status code


@router.get("/ready")
async def readiness_check():
    # Readiness check: "Is this app ready to receive traffic?"
    # Used by Kubernetes to decide if this pod should get requests
    # Different from health check: readiness = can serve, health = is alive
    return {"ready": True, "timestamp": datetime.utcnow().isoformat()}


@router.get("/live")
async def liveness_check():
    # Liveness check: "Is this app still running?"
    # If this fails, Kubernetes restarts the pod
    # Should be very simple - just return 200 if the process is alive
    return {"alive": True, "timestamp": datetime.utcnow().isoformat()}
