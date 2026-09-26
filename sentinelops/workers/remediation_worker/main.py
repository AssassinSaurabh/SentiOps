# workers/remediation_worker/main.py
"""
SentinelOps — Auto-Remediation Worker (Phase 5)
================================================
Consumes: ai.analysis.results  (Kafka)
Actions:  BLOCK_IP, AUTO_REMEDIATE, ESCALATE, INVESTIGATE, IGNORE
Updates:  PostgreSQL findings (remediated=true, remediation_details)
Produces: notifications.outbound (Kafka → Phase 6)
          remediation.tasks      (Kafka — audit log)

How it works:
  1. Read AI decision from Kafka
  2. Execute the appropriate playbook based on action
  3. Record what was done in PostgreSQL
  4. Notify via Kafka (Phase 6 will send Slack/email)
"""

import json
import os
import signal
import sys
import time
import subprocess
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import structlog
import psycopg2
import psycopg2.extras
from common.kafka_client import create_consumer, create_producer, produce_message

# ─── Logging ──────────────────────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.dev.ConsoleRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)
logger = structlog.get_logger("remediation_worker")

# ─── Graceful Shutdown ────────────────────────────────────────────────────────
running = True
def handle_shutdown(sig, frame):
    global running
    running = False
    logger.info("shutdown_signal")
signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)

# ─── Configuration ────────────────────────────────────────────────────────────
# Risk score threshold — only auto-remediate if risk >= this value
AUTO_REMEDIATE_THRESHOLD = int(os.getenv("AUTO_REMEDIATE_THRESHOLD", "70"))
# Only block IPs if risk >= this value
BLOCK_IP_THRESHOLD = int(os.getenv("BLOCK_IP_THRESHOLD", "60"))


# ─── PostgreSQL ───────────────────────────────────────────────────────────────
def get_db():
    return psycopg2.connect(
        host     = os.getenv("POSTGRES_HOST", "postgres"),
        port     = int(os.getenv("POSTGRES_PORT", 5432)),
        dbname   = os.getenv("POSTGRES_DB", "sentinelops"),
        user     = os.getenv("POSTGRES_USER", "sentinelops"),
        password = os.getenv("POSTGRES_PASSWORD", "SentinelOps2024Secure"),
        connect_timeout=10,
    )


def mark_remediated(conn, event_id: str, details: dict) -> bool:
    """Update findings row to mark it as remediated with details."""
    sql = """
        UPDATE findings
        SET
            remediated          = true,
            remediation_details = %s,
            updated_at          = NOW()
        WHERE raw_event->>'event_id' = %s
           OR (source_ip::text = %s AND event_type = %s
               AND remediated = false AND created_at > NOW() - INTERVAL '10 minutes')
        RETURNING id
    """
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (
                json.dumps(details),
                event_id,
                details.get("source_ip", ""),
                details.get("event_type", ""),
            ))
            conn.commit()
            rows = cur.fetchall()
            return len(rows) > 0
    except Exception as e:
        logger.error("db_update_failed", error=str(e))
        conn.rollback()
        return False


# ─── Remediation Playbooks ────────────────────────────────────────────────────

def playbook_block_ip(event: dict) -> dict:
    """
    BLOCK_IP Playbook
    -----------------
    In production: runs iptables/firewalld/cloud WAF API call.
    In our setup: simulates the block and logs it.
    Returns a result dict describing what was done.
    """
    source_ip = event.get("source_ip", "unknown")

    # Simulation — in real SOC this would be:
    # subprocess.run(["iptables", "-A", "INPUT", "-s", source_ip, "-j", "DROP"])
    # or an API call to a cloud firewall (AWS Security Group, GCP VPC Firewall)
    logger.info("executing_block_ip", source_ip=source_ip)

    # Verify the IP looks valid before "blocking"
    if not source_ip or source_ip == "unknown":
        return {
            "status": "skipped",
            "reason": "No source IP available",
            "playbook": "block_ip",
        }

    # Record the block (simulated)
    return {
        "status":     "success",
        "playbook":   "block_ip",
        "action":     f"Simulated: iptables -A INPUT -s {source_ip} -j DROP",
        "source_ip":  source_ip,
        "blocked_at": datetime.datetime.utcnow().isoformat(),
        "note":       "Simulated block — in production connects to firewall API",
    }


def playbook_escalate(event: dict) -> dict:
    """
    ESCALATE Playbook
    -----------------
    Creates a high-priority incident ticket.
    In production: calls PagerDuty/Jira/ServiceNow API.
    """
    ticket_id = f"INC-{int(time.time())}"
    logger.info("escalating", event_id=event.get("event_id"), ticket=ticket_id)
    return {
        "status":     "success",
        "playbook":   "escalate",
        "ticket_id":  ticket_id,
        "priority":   "P1-CRITICAL",
        "assigned_to": "security-oncall@company.com",
        "created_at": datetime.datetime.utcnow().isoformat(),
        "note":       f"Simulated ticket {ticket_id} — in production calls PagerDuty/Jira",
    }


def playbook_auto_remediate(event: dict) -> dict:
    """
    AUTO_REMEDIATE Playbook
    -----------------------
    Runs a full remediation: block IP + rotate credentials + notify.
    Used for the highest-confidence threats.
    """
    source_ip = event.get("source_ip", "unknown")
    block_result = playbook_block_ip(event)
    ticket_id = f"AUTO-{int(time.time())}"

    logger.info("auto_remediating",
                event_id=event.get("event_id"),
                source_ip=source_ip,
                ticket=ticket_id)

    return {
        "status":        "success",
        "playbook":      "auto_remediate",
        "steps_taken":   [
            f"Blocked IP {source_ip} at firewall",
            "Triggered credential rotation (simulated)",
            f"Created incident ticket {ticket_id}",
            "Notified security team via Slack (Phase 6)",
        ],
        "block_details": block_result,
        "ticket_id":     ticket_id,
        "remediated_at": datetime.datetime.utcnow().isoformat(),
    }


def playbook_investigate(event: dict) -> dict:
    """INVESTIGATE — log for manual analyst review."""
    return {
        "status":    "queued",
        "playbook":  "investigate",
        "queue":     "analyst-review",
        "priority":  "MEDIUM",
        "note":      "Queued for manual analyst review",
        "queued_at": datetime.datetime.utcnow().isoformat(),
    }


def playbook_ignore(event: dict) -> dict:
    """IGNORE — confirmed false positive, dismiss safely."""
    return {
        "status":     "dismissed",
        "playbook":   "ignore",
        "reason":     "AI classified as false positive",
        "dismissed_at": datetime.datetime.utcnow().isoformat(),
    }


# ─── Playbook Router ─────────────────────────────────────────────────────────

PLAYBOOKS = {
    "BLOCK_IP":        playbook_block_ip,
    "ESCALATE":        playbook_escalate,
    "AUTO_REMEDIATE":  playbook_auto_remediate,
    "INVESTIGATE":     playbook_investigate,
    "IGNORE":          playbook_ignore,
}


def execute_remediation(event: dict) -> dict:
    """
    Route the event to the right playbook based on AI action.
    Applies risk score thresholds as a safety gate.
    """
    action     = event.get("action", "INVESTIGATE")
    risk_score = int(event.get("risk_score", 0))
    verdict    = event.get("verdict", "NEEDS_INVESTIGATION")

    # Safety gate — don't auto-block/remediate low-confidence events
    if action == "BLOCK_IP" and risk_score < BLOCK_IP_THRESHOLD:
        logger.warning("block_ip_downgraded",
                       reason=f"risk_score {risk_score} < threshold {BLOCK_IP_THRESHOLD}",
                       downgraded_to="INVESTIGATE")
        action = "INVESTIGATE"

    if action == "AUTO_REMEDIATE" and risk_score < AUTO_REMEDIATE_THRESHOLD:
        logger.warning("auto_remediate_downgraded",
                       reason=f"risk_score {risk_score} < threshold {AUTO_REMEDIATE_THRESHOLD}",
                       downgraded_to="BLOCK_IP")
        action = "BLOCK_IP"

    playbook_fn = PLAYBOOKS.get(action, playbook_investigate)
    result = playbook_fn(event)

    result["event_id"]   = event.get("event_id")
    result["ai_verdict"] = verdict
    result["risk_score"] = risk_score
    result["source_ip"]  = event.get("source_ip")
    result["event_type"] = event.get("event_type")

    return result


# ─── Main Loop ────────────────────────────────────────────────────────────────

def main():
    logger.info("remediation_worker_starting",
                block_threshold=BLOCK_IP_THRESHOLD,
                auto_threshold=AUTO_REMEDIATE_THRESHOLD)

    conn     = get_db()
    consumer = create_consumer("remediation-group", ["ai.analysis.results"])
    producer = create_producer()

    total = remediated = skipped = 0

    try:
        while running:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                logger.error("consumer_error", error=str(msg.error()))
                continue

            try:
                event = json.loads(msg.value().decode("utf-8"))
                action    = event.get("action", "INVESTIGATE")
                verdict   = event.get("verdict", "NEEDS_INVESTIGATION")
                risk      = event.get("risk_score", 0)
                source_ip = event.get("source_ip", "?")
                event_id  = event.get("event_id", "?")

                total += 1
                logger.info("processing_event",
                            event_id=event_id,
                            verdict=verdict,
                            action=action,
                            risk_score=risk,
                            source_ip=source_ip)

                # Skip FALSE_POSITIVE events — no remediation needed
                if verdict == "FALSE_POSITIVE":
                    skipped += 1
                    logger.info("skipped_false_positive", event_id=event_id)
                    consumer.commit(msg)
                    continue

                # Execute the appropriate playbook
                result = execute_remediation(event)

                # Update PostgreSQL
                db_updated = mark_remediated(conn, event_id, result)

                # Publish to remediation.tasks (audit trail)
                produce_message(producer, "remediation.tasks", result)

                # Publish to notifications.outbound (Phase 6 — Slack/email)
                if result.get("status") in ("success", "queued"):
                    notification = {
                        "channel":   "slack",
                        "severity":  event.get("severity", "HIGH"),
                        "event_id":  event_id,
                        "verdict":   verdict,
                        "risk_score": risk,
                        "action_taken": result.get("playbook"),
                        "status":    result.get("status"),
                        "source_ip": source_ip,
                        "summary":   event.get("summary", "Security event detected"),
                        "ticket_id": result.get("ticket_id"),
                        "timestamp": datetime.datetime.utcnow().isoformat(),
                    }
                    produce_message(producer, "notifications.outbound", notification)

                consumer.commit(msg)
                remediated += 1

                logger.info("remediation_complete",
                            event_id=event_id,
                            playbook=result.get("playbook"),
                            status=result.get("status"),
                            db_updated=db_updated,
                            total=total,
                            remediated=remediated)

            except psycopg2.OperationalError as e:
                logger.error("db_connection_lost", error=str(e))
                try:
                    conn = get_db()
                    logger.info("db_reconnected")
                except Exception as re:
                    logger.error("db_reconnect_failed", error=str(re))
            except Exception as e:
                logger.error("processing_error", error=str(e))
                consumer.commit(msg)

    finally:
        consumer.close()
        try:
            conn.close()
        except Exception:
            pass
        logger.info("remediation_worker_stopped",
                    total=total, remediated=remediated, skipped=skipped)


if __name__ == "__main__":
    main()
