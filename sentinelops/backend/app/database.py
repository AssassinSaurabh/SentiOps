# ─────────────────────────────────────────────────────────────
# app/database.py
# Purpose: PostgreSQL database connection and session management
# ─────────────────────────────────────────────────────────────

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
# SQLAlchemy's async components:
# create_async_engine  → creates the connection pool to PostgreSQL
# async_sessionmaker   → factory that creates database sessions
# AsyncSession         → the actual session object (one per request)

from sqlalchemy.orm import DeclarativeBase
# DeclarativeBase → base class for our database models (table definitions)

import structlog
from app.config import settings

# Get a logger for this module
logger = structlog.get_logger(__name__)
# __name__ = current module name: "app.database"
# Structured logs will include: {"module": "app.database", ...}


# ─────────────────────────────────────────────────────────────
# Create the database engine (connection pool)
# ─────────────────────────────────────────────────────────────
engine = create_async_engine(
    settings.database_url,
    # database_url from config.py: postgresql+asyncpg://user:pass@host/db
    
    echo=settings.debug,
    # echo=True → print every SQL query to terminal (useful for debugging)
    # echo=False in production (don't log passwords in queries!)
    
    pool_size=10,
    # Connection pool: keep 10 connections open and ready
    # Why a pool? Opening a new DB connection takes ~50ms
    # With pool: reuse existing connections (nearly 0ms)
    
    max_overflow=20,
    # Allow up to 20 EXTRA connections beyond pool_size when busy
    # Total max: 30 connections at once
    
    pool_pre_ping=True,
    # Before using a connection, test if it's still alive
    # Prevents "SSL connection has been closed unexpectedly" errors
    
    pool_recycle=3600,
    # Recycle (close and reopen) connections every 3600 seconds (1 hour)
    # Prevents stale connections from failing silently
)


# ─────────────────────────────────────────────────────────────
# Session factory (creates one session per API request)
# ─────────────────────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    # expire_on_commit=False → after committing, keep objects accessible
    # Default (True): objects expire after commit, requiring another DB query
    # False is better for APIs where we return data after committing
)


# ─────────────────────────────────────────────────────────────
# Base class for all database models (tables)
# ─────────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass
# All our models (Finding, AuditLog, etc.) will inherit from Base
# This lets SQLAlchemy know about all our tables


# ─────────────────────────────────────────────────────────────
# Dependency: get database session per request
# ─────────────────────────────────────────────────────────────
async def get_db() -> AsyncSession:
    # This function is a FastAPI "dependency"
    # FastAPI calls this for each request that needs database access
    # It provides a session and ensures it's closed after the request
    
    async with AsyncSessionLocal() as session:
        # async with → open the session
        try:
            yield session
            # yield = "here's the session, use it"
            # The request handler runs here with the session
            await session.commit()
            # commit = save all changes to database
        except Exception:
            await session.rollback()
            # rollback = undo all changes if anything went wrong
            raise
            # re-raise the exception so FastAPI handles it
        # When the 'with' block exits: session is automatically closed


# ─────────────────────────────────────────────────────────────
# Test database connection on startup
# ─────────────────────────────────────────────────────────────
async def check_database_connection() -> bool:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            # "SELECT 1" is the simplest possible query
            # If it works, database is reachable and responding
            logger.info("database_connection_successful")
            return True
    except Exception as e:
        logger.error("database_connection_failed", error=str(e))
        return False
