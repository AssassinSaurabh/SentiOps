# ─────────────────────────────────────────────────────────────
# app/config.py
# Purpose: Load and validate all configuration from environment variables
# ─────────────────────────────────────────────────────────────

from pydantic_settings import BaseSettings
# pydantic_settings → library that reads .env and validates values
# BaseSettings → base class we inherit from

from functools import lru_cache
# lru_cache → "Least Recently Used Cache"
# Ensures get_settings() is called ONCE, not on every request
# Without this: reads .env file on every API call (slow)


class Settings(BaseSettings):
    # ── App ──
    app_name: str = "SentinelOps"
    # str = this must be a string. "SentinelOps" = default if not in .env
    
    app_version: str = "0.1.0"
    
    debug: bool = False
    # bool = True or False. If .env has DEBUG=true, Pydantic converts "true" → True
    
    environment: str = "development"

    # ── Database ──
    database_url: str
    # No default = REQUIRED. App refuses to start if not set.
    # Pydantic reads DATABASE_URL from .env automatically.
    # Why? pydantic_settings maps env var DATABASE_URL → database_url
    
    postgres_user: str = "sentinelops"
    postgres_password: str
    postgres_db: str = "sentinelops"
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    # int = must be a number. "5432" in .env → 5432 integer automatically

    # ── Redis ──
    redis_url: str = "redis://redis:6379/0"
    redis_host: str = "redis"
    redis_port: int = 6379

    # ── Security ──
    secret_key: str
    # REQUIRED. Used for JWT token signing.

    # ── API ──
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    class Config:
        # Config = Pydantic's inner configuration class
        env_file = ".env"
        # Tell Pydantic: read variables from this file
        env_file_encoding = "utf-8"
        # Character encoding of the file
        case_sensitive = False
        # DATABASE_URL and database_url are treated the same


@lru_cache()
def get_settings() -> Settings:
    # Returns the Settings object.
    # @lru_cache means: call this function once, cache the result forever.
    # Every subsequent call returns the SAME cached object.
    return Settings()


# settings = the single settings object used everywhere in the app
settings = get_settings()
