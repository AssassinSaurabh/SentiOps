# workers/storage/main.py
# Purpose: Read enriched events, deduplicate via Redis, store in PostgreSQL
#
# Pipeline step:
#   security.events.enriched → [THIS WORKER] → PostgreSQL findings table
#
# Key features:
#   1. Redis deduplication: same event in 10 min window = SKIP (reduces noise)
#   2. PostgreSQL write: stores finding for dashboard/API access
#   3. Auto-reconnect: if DB connection drops, reconnect and continue

import json
import os
import signal
import sys
import hashlib
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import structlog
import redis
import psycopg2
import psycopg2.extras
from common.kafka_client import create_consumer
from common.models import EnrichedEvent

# ── Logging ──
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.dev.ConsoleRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)
logger = structlog.get_logger("storage")

# ── Graceful Shutdown ──
running = True

def handle_shutdown(sig, frame):
    global running
    running = False
    logger.info("storage_shutdown_requested")

signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)


# ── How long to suppress duplicate events (10 minutes) ──
DEDUP_TTL_SECONDS = 600


def get_redis_client():
    """Connect to Redis for deduplication."""
    return redis.Redis(
        host     = os.getenv("REDIS_HOST", "redis"),
        port     = int(os.getenv("REDIS_PORT", 6379)),
        password = os.getenv("REDIS_PASSWORD", "SentinelRedis2024"),
        db       = 0,
        decode_responses = True,
        socket_connect_timeout = 5,
    )


def get_postgres_conn():
    """Connect to PostgreSQL to store findings."""
    return psycopg2.connect(
        host     = os.getenv("POSTGRES_HOST", "postgres"),
        port     = int(os.getenv("POSTGRES_PORT", 5432)),
        dbname   = os.getenv("POSTGRES_DB", "sentinelops"),
        user     = os.getenv("POSTGRES_USER", "sentinelops"),
        password = os.getenv("POSTGRES_PASSWORD", "SentinelOps2024Secure"),
        connect_timeout = 10,
    )


def is_duplicate(redis_client, event: EnrichedEvent) -> bool:
    """
    Check if we've seen this exact event recently.

    Deduplication key = hash of (source_ip + event_type + target_host)
    This means:
      - Same IP doing same attack on same host = DUPLICATE → SKIP
      - Same IP, different attack type = NEW → STORE
      - Different IP = NEW → STORE

    Redis SET with NX (only set if Not eXists) + EX (expire after TTL):
      - First time: key doesn't exist → SET succeeds → return False (not duplicate)
      - Second time (within TTL): key exists → SET fails → return True (duplicate)
    """
    # Create fingerprint from key event fields
    fingerprint_raw = f"{event.source_ip}:{event.event_type}:{event.target_host}"
    fingerprint = hashlib.sha256(fingerprint_raw.encode()).hexdigest()[:16]
    # sha256 → 16-char hex string (compact but collision-resistant enough)

    redis_key = f"dedup:{fingerprint}"

    # NX = set only if key does Not eXist
    # EX = expire after DEDUP_TTL_SECONDS seconds
    result = redis_client.set(redis_key, "1", nx=True, ex=DEDUP_TTL_SECONDS)

    # result = True  → key was SET (first time) → NOT a duplicate
    # result = None  → key ALREADY existed → IS a duplicate
    return result is None


# SQL to insert a finding into PostgreSQL
INSERT_SQL = """
    INSERT INTO findings (
        id,
        title,
        description,
        severity,
        source,
        event_type,
        source_ip,
        target_host,
        raw_event,
        enrichment_data,
        remediated
    )
    VALUES (
        %s, %s, %s, %s, %s, %s,
        %s::inet,
        %s, %s, %s,
        false
    )
    RETURNING id;
"""
# %s::inet = cast to PostgreSQL inet type (validates IP format)
# RETURNING id = give us back the auto-generated ID
# remediated = false (new findings are always un-remediated)


def store_finding(pg_conn, event: EnrichedEvent) -> str:
    """
    Write an enriched event to PostgreSQL as a Finding.
    Returns the new finding's UUID.
    """
    finding_id = str(uuid.uuid4())

    # Build a JSON blob of all enrichment data for storage
    enrichment_data = json.dumps({
        "ip_country":        event.ip_country,
        "ip_city":           event.ip_city,
        "ip_reputation":     event.ip_reputation,
        "ip_abuse_score":    event.ip_abuse_score,
        "asset_criticality": event.asset_criticality,
        "asset_description": event.asset_description,
        "confidence":        event.confidence,
        "enriched_at":       event.enriched_at,
    })

    raw_event_data = json.dumps({
        "event_id":     event.event_id,
        "raw_event_id": event.raw_event_id,
        "source":       event.source,
        "protocol":     event.protocol,
        "username":     event.username,
    })

    # Human-readable title for the finding
    title = (
        f"{event.event_type.replace('_', ' ').title()}: {event.target_host or 'Unknown'}"
    )

    with pg_conn.cursor() as cursor:
        cursor.execute(INSERT_SQL, (
            finding_id,
            title,
            event.description,
            event.severity,
            event.source,
            event.event_type,
            event.source_ip,
            event.target_host,
            raw_event_data,
            enrichment_data,
        ))
        pg_conn.commit()

    return finding_id


def main():
    logger.info(
        "storage_starting",
        kafka    = os.getenv("KAFKA_BOOTSTRAP_SERVERS"),
        postgres = os.getenv("POSTGRES_HOST", "postgres"),
        redis    = os.getenv("REDIS_HOST", "redis"),
    )

    consumer     = create_consumer("storage-group", ["security.events.enriched"])
    redis_client = get_redis_client()
    pg_conn      = get_postgres_conn()

    processed = stored = skipped = 0

    try:
        while running:
            msg = consumer.poll(timeout=1.0)

            if msg is None:
                continue

            if msg.error():
                logger.error("consumer_error", error=str(msg.error()))
                continue

            try:
                event = EnrichedEvent(**json.loads(msg.value().decode("utf-8")))
                processed += 1

                # ── Step 1: Deduplication check ──
                if is_duplicate(redis_client, event):
                    skipped += 1
                    logger.info(
                        "duplicate_suppressed",
                        event_id   = event.event_id,
                        event_type = event.event_type,
                        source_ip  = event.source_ip,
                        total_skipped = skipped,
                    )
                    consumer.commit(msg)
                    continue

                # ── Step 2: Write to PostgreSQL ──
                finding_id = store_finding(pg_conn, event)
                stored += 1

                logger.info(
                    "finding_stored",
                    finding_id        = finding_id,
                    severity          = event.severity,
                    event_type        = event.event_type,
                    source_ip         = event.source_ip,
                    target_host       = event.target_host,
                    confidence        = event.confidence,
                    asset_criticality = event.asset_criticality,
                    total_stored      = stored,
                )

                consumer.commit(msg)

            except psycopg2.OperationalError as e:
                # Database connection dropped — try to reconnect
                logger.error("postgres_connection_lost", error=str(e))
                try:
                    pg_conn = get_postgres_conn()
                    logger.info("postgres_reconnected")
                except Exception as re:
                    logger.error("postgres_reconnect_failed", error=str(re))

            except redis.RedisError as e:
                # Redis connection issue — skip dedup and store anyway
                logger.warning("redis_error_skipping_dedup", error=str(e))
                try:
                    finding_id = store_finding(pg_conn, event)
                    stored += 1
                    logger.info("finding_stored_without_dedup", finding_id=finding_id)
                    consumer.commit(msg)
                except Exception as se:
                    logger.error("storage_failed_after_redis_error", error=str(se))

            except Exception as e:
                logger.error("storage_failed", error=str(e))
                consumer.commit(msg)  # Skip bad message, don't block the pipeline

    finally:
        consumer.close()
        try:
            pg_conn.close()
        except Exception:
            pass
        logger.info(
            "storage_stopped",
            total_processed = processed,
            total_stored    = stored,
            total_skipped   = skipped,
        )


if __name__ == "__main__":
    main()
