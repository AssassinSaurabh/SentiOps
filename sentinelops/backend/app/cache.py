# ─────────────────────────────────────────────────────────────
# app/cache.py
# Purpose: Redis connection and cache helper functions
# ─────────────────────────────────────────────────────────────

import json
from typing import Any, Optional

import redis.asyncio as aioredis
# redis.asyncio = async version of Redis client
# Works with FastAPI's async (non-blocking)

import structlog
from app.config import settings

logger = structlog.get_logger(__name__)

# ─────────────────────────────────────────────────────────────
# Redis connection pool
# ─────────────────────────────────────────────────────────────
redis_client: Optional[aioredis.Redis] = None
# Start as None. Will be created when app starts.


async def init_redis() -> None:
    # Called once when FastAPI app starts
    global redis_client
    # global = we're modifying the module-level variable (not a local copy)
    
    try:
        redis_client = await aioredis.from_url(
            settings.redis_url,
            # redis://redis:6379/0
            
            encoding="utf-8",
            # Store/retrieve strings as UTF-8 (not bytes)
            
            decode_responses=True,
            # Automatically decode bytes to strings
            # Without this: GET returns b"hello" instead of "hello"
            
            max_connections=20,
            # Maximum Redis connections in pool
        )
        
        # Test the connection
        await redis_client.ping()
        # Redis responds with "PONG" if working
        
        logger.info("redis_connection_successful")
        
    except Exception as e:
        logger.error("redis_connection_failed", error=str(e))
        # Do not re-raise: Redis failure is non-fatal at startup.
        # The app will start, /health will report cache as unhealthy,
        # and cache functions degrade gracefully (return None on get, skip on set).


async def close_redis() -> None:
    # Called when FastAPI app shuts down. Close connection gracefully.
    global redis_client
    if redis_client:
        await redis_client.close()


# ─────────────────────────────────────────────────────────────
# Cache helper functions
# ─────────────────────────────────────────────────────────────

async def cache_get(key: str) -> Optional[Any]:
    # Get a value from cache
    # Returns None if key doesn't exist or is expired
    
    if not redis_client:
        return None
        # If Redis is down, gracefully return None (don't crash)
    
    try:
        value = await redis_client.get(key)
        # GET key → returns the stored string, or None
        
        if value is None:
            return None
            # Cache miss: key not found
        
        return json.loads(value)
        # We stored JSON string, parse back to Python dict/list
        
    except Exception as e:
        logger.warning("cache_get_failed", key=key, error=str(e))
        return None  # Cache failure is not fatal, continue without cache


async def cache_set(key: str, value: Any, ttl: int = 300) -> None:
    # Store a value in cache
    # key: the cache key (e.g., "findings:list:24h")
    # value: any Python object (dict, list, string)
    # ttl: time-to-live in seconds (default: 300 = 5 minutes)
    
    if not redis_client:
        return
    
    try:
        json_value = json.dumps(value, default=str)
        # json.dumps = convert Python object to JSON string
        # default=str = if object can't be serialized (e.g., datetime), use str()
        
        await redis_client.setex(
            key,      # The cache key
            ttl,      # Expire after this many seconds
            json_value  # The value to store
        )
        # SETEX = SET with EXpiry. Atomically sets value + expiry.
        
    except Exception as e:
        logger.warning("cache_set_failed", key=key, error=str(e))


async def cache_delete(key: str) -> None:
    # Delete a specific cache key (e.g., when data is updated)
    if not redis_client:
        return
    try:
        await redis_client.delete(key)
    except Exception as e:
        logger.warning("cache_delete_failed", key=key, error=str(e))


async def check_redis_connection() -> bool:
    # Health check: is Redis working?
    try:
        if redis_client:
            await redis_client.ping()
            return True
        return False
    except Exception:
        return False
