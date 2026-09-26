# workers/normalizer/main.py
# Purpose: Read raw security events from Kafka and normalize them
#
# Pipeline step:
#   security.events.raw → [THIS WORKER] → security.events.normalized
#
# What "normalize" means:
#   Raw:        {"srcip": "1.2.3.4", "dstuser": "root", "Failed": 15, ...}
#   Normalized: {"event_type": "brute_force", "severity": "HIGH",
#                "source_ip": "1.2.3.4", "username": "root", ...}

import json
import os
import signal
import sys

# Add parent directory to Python path so we can import from common/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import structlog
from common.kafka_client import create_consumer, create_producer, produce_message
from common.models import RawEvent, NormalizedEvent

# ── Logging Setup ──
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.dev.ConsoleRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)
logger = structlog.get_logger("normalizer")

# ── Graceful Shutdown Handler ──
# When Docker stops the container (SIGTERM), finish current message then exit
running = True

def handle_shutdown(sig, frame):
    global running
    running = False
    logger.info("normalizer_shutdown_requested")

signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)


# ── Core Logic: Raw → Normalized ──
def normalize_event(raw_event: RawEvent) -> NormalizedEvent:
    """
    Convert a raw event dict into a clean, structured NormalizedEvent.
    This is where we map different source formats to our standard format.
    """
    raw = raw_event.raw_data

    # Extract common fields (handles different field names from different sources)
    source_ip   = raw.get("source_ip") or raw.get("srcip") or raw.get("src_ip")
    target_host = raw.get("target_host") or raw.get("hostname") or raw.get("dsthost", "unknown")
    target_port = raw.get("port") or raw.get("dst_port")
    username    = raw.get("username") or raw.get("dstuser") or raw.get("user")
    protocol    = raw.get("protocol", "UNKNOWN").upper()
    etype       = raw.get("event_type", "").lower()
    failure_count = raw.get("failure_count", 0)

    # ── Event Classification Logic ──
    # Each block maps raw event characteristics to our standard event_type + severity

    if etype == "brute_force" or (isinstance(failure_count, int) and failure_count >= 10):
        event_type  = "brute_force"
        severity    = "HIGH"
        description = f"Brute force attack detected: {failure_count} failed login attempts from {source_ip}"
        protocol    = "SSH"
        target_port = target_port or 22

    elif etype == "authentication_failure" or "failed password" in str(raw.get("message", "")).lower():
        event_type  = "authentication_failure"
        severity    = "MEDIUM"
        description = f"SSH authentication failure for user '{username}' from {source_ip}"
        protocol    = "SSH"
        target_port = target_port or 22

    elif etype == "port_scan":
        event_type  = "port_scan"
        severity    = "MEDIUM"
        description = f"Port scan detected from {source_ip} targeting {target_host}"

    elif etype == "privilege_escalation" or etype == "sudo_abuse":
        event_type  = "privilege_escalation"
        severity    = "CRITICAL"
        description = f"Privilege escalation attempt by '{username}' on {target_host}"

    elif etype == "malware_detected":
        event_type  = "malware_detected"
        severity    = "CRITICAL"
        description = f"Malware detected on {target_host}: {raw.get('malware_name', 'unknown')}"

    elif etype == "data_exfiltration":
        event_type  = "data_exfiltration"
        severity    = "CRITICAL"
        description = f"Data exfiltration attempt from {target_host} to {source_ip}"

    elif etype in ("test", "test_event"):
        event_type  = "test_event"
        severity    = raw.get("severity", "INFO").upper()
        description = raw.get("message", "Test security event received by SentinelOps")

    elif etype == "web_attack" or etype == "sql_injection":
        event_type  = "web_attack"
        severity    = "HIGH"
        description = f"Web attack from {source_ip}: {etype}"
        protocol    = "HTTP"
        target_port = target_port or 80

    else:
        # Unknown event type: normalize what we can, mark as LOW severity
        event_type  = etype if etype else "unknown"
        severity    = raw.get("severity", "LOW").upper()
        description = raw.get("message", f"Security event from {raw_event.source}: {etype}")

    # Validate severity is one of our allowed values
    allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    if severity not in allowed:
        severity = "MEDIUM"

    return NormalizedEvent(
        event_id    = raw_event.event_id,
        source      = raw_event.source,
        event_type  = event_type,
        severity    = severity,
        source_ip   = source_ip,
        target_host = target_host,
        target_port = int(target_port) if target_port else None,
        username    = username,
        protocol    = protocol,
        description = description,
        raw_event_id = raw_event.event_id,
    )


def main():
    logger.info("normalizer_starting", kafka=os.getenv("KAFKA_BOOTSTRAP_SERVERS"))

    consumer = create_consumer(
        group_id = "normalizer-group",
        topics   = ["security.events.raw"],
    )
    producer = create_producer()

    processed = 0

    try:
        while running:
            # poll() waits up to 1.0 second for a message
            # Returns None if no message in that time (loop continues)
            msg = consumer.poll(timeout=1.0)

            if msg is None:
                continue  # No message yet, try again

            if msg.error():
                logger.error("consumer_error", error=str(msg.error()))
                continue

            try:
                # Decode bytes → string → dict → RawEvent model
                raw_event = RawEvent(**json.loads(msg.value().decode("utf-8")))

                # Do the actual normalization
                normalized = normalize_event(raw_event)

                # Send to the next topic in the pipeline
                produce_message(
                    producer = producer,
                    topic    = "security.events.normalized",
                    message  = normalized.model_dump(),
                    key      = normalized.source_ip or normalized.event_id,
                    # Key = source_ip: all events from same IP → same partition
                    # This preserves ORDER of events per attacker IP
                )

                # MANUALLY commit the offset AFTER successful processing
                # This ensures: if we crash BEFORE commit, message is re-delivered
                consumer.commit(msg)
                processed += 1

                logger.info(
                    "event_normalized",
                    event_id   = normalized.event_id,
                    event_type = normalized.event_type,
                    severity   = normalized.severity,
                    source_ip  = normalized.source_ip,
                    total      = processed,
                )

            except Exception as e:
                logger.error("normalization_failed", error=str(e), msg=str(msg.value()))
                consumer.commit(msg)  # Commit even on failure (skip bad messages)

    finally:
        consumer.close()
        logger.info("normalizer_stopped", total_processed=processed)


if __name__ == "__main__":
    main()
