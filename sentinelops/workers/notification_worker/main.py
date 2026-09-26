# workers/notification_worker/main.py
"""
SentinelOps — Notification Worker (Phase 6)
============================================
Consumes: notifications.outbound  (Kafka — from Remediation Worker)
Outputs:
  1. Structured console alert (always — no config needed)
  2. Slack webhook    (if SLACK_WEBHOOK_URL is set)
  3. PostgreSQL notifications table (always — for history/dashboard)

Severity routing:
  CRITICAL / HIGH  → immediate alert
  MEDIUM           → batched digest
  LOW              → log only
"""

import json
import os
import signal
import sys
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import structlog
import requests
import psycopg2
import psycopg2.extras
from common.kafka_client import create_consumer

# ─── Logging ──────────────────────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.dev.ConsoleRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)
logger = structlog.get_logger("notification_worker")

# ─── Config ───────────────────────────────────────────────────────────────────
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")  # Optional
NOTIFICATION_TTL_DAYS = int(os.getenv("NOTIFICATION_TTL_DAYS", "30"))

# ─── Graceful Shutdown ────────────────────────────────────────────────────────
running = True
def handle_shutdown(sig, frame):
    global running
    running = False
    logger.info("shutdown_signal")
signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)


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


def ensure_notifications_table(conn):
    """Create notifications table if it doesn't exist."""
    sql = """
    CREATE TABLE IF NOT EXISTS notifications (
        id           UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
        event_id     TEXT,
        channel      VARCHAR(50)  DEFAULT 'console',
        severity     VARCHAR(20),
        verdict      VARCHAR(30),
        risk_score   INTEGER,
        action_taken VARCHAR(50),
        status       VARCHAR(30),
        source_ip    TEXT,
        summary      TEXT,
        ticket_id    TEXT,
        payload      JSONB,
        sent_at      TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_notifications_severity ON notifications(severity);
    CREATE INDEX IF NOT EXISTS idx_notifications_sent_at  ON notifications(sent_at DESC);
    """
    with conn.cursor() as cur:
        cur.execute(sql)
        conn.commit()


def store_notification(conn, notification: dict) -> bool:
    """Persist notification record to PostgreSQL."""
    sql = """
        INSERT INTO notifications
          (event_id, channel, severity, verdict, risk_score,
           action_taken, status, source_ip, summary, ticket_id, payload)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (
                notification.get("event_id"),
                notification.get("channel", "console"),
                notification.get("severity"),
                notification.get("verdict"),
                notification.get("risk_score"),
                notification.get("action_taken"),
                notification.get("status"),
                notification.get("source_ip"),
                notification.get("summary", "")[:500],
                notification.get("ticket_id"),
                json.dumps(notification),
            ))
            conn.commit()
            return True
    except Exception as e:
        logger.error("db_store_failed", error=str(e))
        conn.rollback()
        return False


# ─── Console Alert ────────────────────────────────────────────────────────────

SEVERITY_ICONS = {
    "CRITICAL": "🚨",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

ACTION_ICONS = {
    "block_ip":       "🛡️  BLOCKED IP",
    "escalate":       "📟 ESCALATED",
    "auto_remediate": "⚡ AUTO-REMEDIATED",
    "investigate":    "🔍 QUEUED FOR REVIEW",
    "ignore":         "✅ DISMISSED",
}

def print_alert(notification: dict):
    """Print a nicely formatted security alert to console."""
    severity     = notification.get("severity", "UNKNOWN")
    verdict      = notification.get("verdict", "UNKNOWN")
    risk_score   = notification.get("risk_score", 0)
    source_ip    = notification.get("source_ip", "unknown")
    summary      = notification.get("summary", "Security event detected")
    action_taken = notification.get("action_taken", "unknown")
    ticket_id    = notification.get("ticket_id", "")

    icon     = SEVERITY_ICONS.get(severity, "⚪")
    act_text = ACTION_ICONS.get(action_taken, f"➡️  {action_taken.upper()}")

    print(f"\n{'='*60}")
    print(f"{icon} SENTINELOPS SECURITY ALERT [{severity}]")
    print(f"{'='*60}")
    print(f"  Verdict:     {verdict}")
    print(f"  Risk Score:  {risk_score}/100")
    print(f"  Source IP:   {source_ip}")
    print(f"  Summary:     {summary}")
    print(f"  Action:      {act_text}")
    if ticket_id:
        print(f"  Ticket:      {ticket_id}")
    print(f"  Time:        {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*60}\n")


# ─── Slack Notification ───────────────────────────────────────────────────────

def send_slack(notification: dict) -> bool:
    """
    Send a Slack notification via incoming webhook.
    Set SLACK_WEBHOOK_URL env var to enable.
    Free way to get one: https://api.slack.com/apps → Incoming Webhooks
    """
    if not SLACK_WEBHOOK_URL:
        return False

    severity   = notification.get("severity", "UNKNOWN")
    risk_score = notification.get("risk_score", 0)
    verdict    = notification.get("verdict", "UNKNOWN")
    source_ip  = notification.get("source_ip", "unknown")
    summary    = notification.get("summary", "Security event")
    action     = notification.get("action_taken", "unknown")
    ticket     = notification.get("ticket_id", "N/A")

    color = {"CRITICAL": "#FF0000", "HIGH": "#FF6600", "MEDIUM": "#FFAA00"}.get(severity, "#36A64F")
    icon  = SEVERITY_ICONS.get(severity, "⚪")

    payload = {
        "text": f"{icon} *SentinelOps Alert — {severity}*",
        "attachments": [{
            "color": color,
            "fields": [
                {"title": "Verdict",    "value": verdict,    "short": True},
                {"title": "Risk Score", "value": f"{risk_score}/100", "short": True},
                {"title": "Source IP",  "value": source_ip,  "short": True},
                {"title": "Action",     "value": action,     "short": True},
                {"title": "Summary",    "value": summary,    "short": False},
                {"title": "Ticket",     "value": ticket,     "short": True},
            ],
            "footer": "SentinelOps AI Security Platform",
            "ts": int(datetime.datetime.utcnow().timestamp()),
        }]
    }

    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        if resp.status_code == 200:
            logger.info("slack_sent", severity=severity)
            return True
        else:
            logger.warning("slack_failed", status=resp.status_code, body=resp.text[:100])
            return False
    except Exception as e:
        logger.error("slack_error", error=str(e))
        return False


# ─── Main Loop ────────────────────────────────────────────────────────────────

def main():
    slack_enabled = bool(SLACK_WEBHOOK_URL)
    logger.info("notification_worker_starting",
                slack_enabled=slack_enabled,
                ttl_days=NOTIFICATION_TTL_DAYS)

    conn     = get_db()
    ensure_notifications_table(conn)
    consumer = create_consumer("notification-group", ["notifications.outbound"])

    total = 0

    try:
        while running:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                logger.error("consumer_error", error=str(msg.error()))
                continue

            try:
                notification = json.loads(msg.value().decode("utf-8"))
                severity     = notification.get("severity", "MEDIUM")
                verdict      = notification.get("verdict", "UNKNOWN")
                action_taken = notification.get("action_taken", "unknown")

                total += 1

                # 1. Console alert (always)
                print_alert(notification)

                # 2. Slack (if configured)
                slack_sent = False
                if slack_enabled and severity in ("CRITICAL", "HIGH"):
                    slack_sent = send_slack(notification)

                # 3. Store in PostgreSQL notifications table
                db_stored = store_notification(conn, notification)

                consumer.commit(msg)

                logger.info("notification_sent",
                            severity=severity,
                            verdict=verdict,
                            action=action_taken,
                            slack=slack_sent,
                            db_stored=db_stored,
                            total=total)

            except psycopg2.OperationalError as e:
                logger.error("db_lost", error=str(e))
                try:
                    conn = get_db()
                    ensure_notifications_table(conn)
                except Exception:
                    pass
            except Exception as e:
                logger.error("processing_error", error=str(e))
                consumer.commit(msg)

    finally:
        consumer.close()
        try:
            conn.close()
        except Exception:
            pass
        logger.info("notification_worker_stopped", total=total)


if __name__ == "__main__":
    main()
