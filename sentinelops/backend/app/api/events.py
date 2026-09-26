# backend/app/api/events.py
# Purpose: API endpoint to simulate security events
#
# In Phase 4: real events come from Wazuh/Suricata agents.
# In Phase 3: we simulate events here for testing the pipeline end-to-end.
#
# POST /api/v1/events/simulate
#   → Creates a RawEvent
#   → Sends it to Kafka topic: security.events.raw
#   → Pipeline picks it up and processes it automatically

import json
import os
import uuid
from datetime import datetime
from typing import Optional

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

router = APIRouter(
    prefix="/api/v1/events",
    tags=["Events"],
)


class SimulateEventRequest(BaseModel):
    """
    Request body for the event simulation endpoint.
    Caller provides the event details, we send them to Kafka.
    """
    event_type: str = "brute_force"
    # Type of attack to simulate
    # Options: brute_force, authentication_failure, port_scan,
    #          privilege_escalation, malware_detected, data_exfiltration, test

    source: str = "manual_simulation"
    # Who is reporting this event
    # In production: "wazuh", "suricata", "openvas"

    source_ip: Optional[str] = "185.220.101.45"
    # Attacker's IP address (185.220.x.x = known Tor exit node range)

    target_host: Optional[str] = "prod-db-01"
    # Which server is being attacked

    username: Optional[str] = "root"
    # Username being targeted

    failure_count: Optional[int] = 15
    # Number of failed attempts (used for brute force classification)

    severity: Optional[str] = "HIGH"
    # Override severity (normalizer will also determine this based on event_type)

    message: Optional[str] = None
    # Optional human-readable message to include in the event


def _get_kafka_producer():
    """
    Create a Kafka producer. We create a new one per request
    (stateless approach — simpler for low-volume simulation endpoint).
    In Phase 5: we'll use a connection pool for high volume.
    """
    try:
        from confluent_kafka import Producer
        bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
        producer = Producer({
            "bootstrap.servers": bootstrap,
            "client.id": f"sentinelops-fastapi-{os.getpid()}",
            "message.timeout.ms": 5000,
            # Fail fast if Kafka is unreachable (don't hang forever)
        })
        return producer
    except Exception as e:
        logger.error("kafka_producer_creation_failed", error=str(e))
        raise HTTPException(
            status_code=503,
            detail=f"Kafka unavailable: {str(e)}. Is Kafka running?"
        )


@router.post("/simulate")
async def simulate_event(request: SimulateEventRequest):
    """
    Simulate a security event and inject it into the SentinelOps pipeline.

    This endpoint:
    1. Creates a RawEvent in our standard format
    2. Sends it to Kafka topic 'security.events.raw'
    3. Returns immediately (async processing begins in workers)

    Track the event's journey:
    - Kafka UI:    http://localhost:8090
    - Worker logs: docker compose logs -f normalizer enrichment storage
    - Findings DB: docker compose exec postgres psql -U sentinelops -d sentinelops -c "SELECT title, severity, created_at FROM findings ORDER BY created_at DESC LIMIT 5;"
    """
    event_id = str(uuid.uuid4())

    # Build the RawEvent payload
    raw_event = {
        "event_id":    event_id,
        "source":      request.source,
        "received_at": datetime.utcnow().isoformat(),
        "raw_data": {
            "event_type":    request.event_type,
            "source_ip":     request.source_ip,
            "target_host":   request.target_host,
            "username":      request.username,
            "failure_count": request.failure_count,
            "severity":      request.severity,
            "message":       request.message or f"Simulated {request.event_type} event",
            "port":          22,
            "protocol":      "SSH",
            "timestamp":     datetime.utcnow().isoformat(),
        }
    }

    # Send to Kafka
    try:
        producer = _get_kafka_producer()
        producer.produce(
            topic  = "security.events.raw",
            value  = json.dumps(raw_event).encode("utf-8"),
            key    = event_id.encode("utf-8"),
        )
        # flush() waits for the message to be delivered to Kafka
        # (or fails within message.timeout.ms)
        producer.flush(timeout=5)
    except Exception as e:
        logger.error("event_simulation_failed", event_id=event_id, error=str(e))
        raise HTTPException(status_code=503, detail=f"Failed to send to Kafka: {str(e)}")

    logger.info(
        "event_simulated",
        event_id   = event_id,
        event_type = request.event_type,
        source_ip  = request.source_ip,
        target_host = request.target_host,
    )

    return {
        "status":     "sent_to_pipeline",
        "event_id":   event_id,
        "topic":      "security.events.raw",
        "pipeline":   "raw → normalizer → normalized → enrichment → enriched → storage → postgresql",
        "monitoring": {
            "kafka_ui":    "http://localhost:8090",
            "worker_logs": "docker compose logs -f normalizer enrichment storage",
            "swagger":     "http://localhost:8000/docs",
        },
        "note": "Event is being processed asynchronously. Check worker logs or Kafka UI."
    }


@router.get("/pipeline-status")
async def pipeline_status():
    """
    Check if Kafka is reachable from FastAPI.
    Useful for debugging Phase 3 connectivity.
    """
    try:
        from confluent_kafka.admin import AdminClient
        bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
        admin = AdminClient({"bootstrap.servers": bootstrap})
        metadata = admin.list_topics(timeout=3)
        topics = list(metadata.topics.keys())
        return {
            "kafka_reachable":  True,
            "kafka_bootstrap":  bootstrap,
            "topics_available": topics,
            "pipeline_ready":   "security.events.raw" in topics,
        }
    except Exception as e:
        return {
            "kafka_reachable": False,
            "error":           str(e),
            "pipeline_ready":  False,
        }
