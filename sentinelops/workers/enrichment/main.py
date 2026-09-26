# workers/enrichment/main.py
# Purpose: Read normalized events and enrich them with context data
#
# Pipeline step:
#   security.events.normalized → [THIS WORKER] → security.events.enriched
#
# What "enrich" means:
#   Add IP geo info, reputation scores, asset criticality, confidence score
#
# Real-world: these lookups would hit APIs like:
#   - AbuseIPDB (IP reputation)
#   - MaxMind GeoIP (IP geolocation)
#   - Internal CMDB (asset database)
# For Phase 3 we simulate these with built-in data (no API keys needed)

import json
import os
import signal
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import structlog
from common.kafka_client import create_consumer, create_producer, produce_message
from common.models import NormalizedEvent, EnrichedEvent

# ── Logging ──
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.dev.ConsoleRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)
logger = structlog.get_logger("enrichment")

# ── Graceful Shutdown ──
running = True

def handle_shutdown(sig, frame):
    global running
    running = False
    logger.info("enrichment_shutdown_requested")

signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)


# ── Simulated Asset Database (In Phase 5: this comes from CMDB/API) ──
# Maps hostname → asset metadata
ASSET_DB = {
    "prod-db-01":      {"criticality": "CRITICAL", "description": "Production PostgreSQL — payment data"},
    "prod-web-01":     {"criticality": "HIGH",     "description": "Production web server — customer facing"},
    "prod-api-01":     {"criticality": "HIGH",     "description": "Production API gateway"},
    "staging-app-01":  {"criticality": "MEDIUM",   "description": "Staging application server"},
    "dev-server-01":   {"criticality": "LOW",       "description": "Developer workstation"},
    "test-server":     {"criticality": "LOW",       "description": "Test/QA server"},
    "bastion-01":      {"criticality": "CRITICAL",  "description": "Bastion/jump host — SSH gateway"},
    "jenkins-01":      {"criticality": "HIGH",      "description": "CI/CD server — build pipeline"},
}

# ── Known Malicious IP Ranges (In Phase 5: this comes from threat intel feed) ──
# These are real Tor exit node and scanner IP ranges
KNOWN_BAD_RANGES = [
    "185.220.",   # Tor exit nodes
    "45.33.",     # Known scanner (Shodan)
    "23.129.",    # Tor exit nodes
    "198.98.",    # Tor exit nodes
    "171.25.",    # Tor exit nodes
    "199.87.",    # Known attacker range
    "141.98.",    # Mass scanner
]

# ── IP Geolocation (Simulated — In Phase 5: MaxMind GeoIP API) ──
def get_ip_info(ip: str) -> dict:
    """
    Look up IP geolocation and reputation.
    Phase 3: simulated with simple rules.
    Phase 5: real AbuseIPDB + MaxMind API calls.
    """
    if not ip:
        return {"country": "Unknown", "city": "Unknown", "reputation": "Unknown", "abuse_score": 0}

    # Check known bad ranges first
    for bad_range in KNOWN_BAD_RANGES:
        if ip.startswith(bad_range):
            return {
                "country": "Multiple",
                "city":    "Tor Network",
                "reputation": "Known Tor exit node / malicious range",
                "abuse_score": 95,
            }

    # Simulate geolocation based on first octet
    first = int(ip.split(".")[0]) if "." in ip else 0

    if first < 50:
        return {"country": "United States", "city": "New York",   "reputation": "Clean",      "abuse_score": 0}
    elif first < 80:
        return {"country": "Germany",       "city": "Frankfurt",  "reputation": "Clean",      "abuse_score": 2}
    elif first < 110:
        return {"country": "Japan",         "city": "Tokyo",      "reputation": "Clean",      "abuse_score": 3}
    elif first < 140:
        return {"country": "China",         "city": "Beijing",    "reputation": "Suspicious", "abuse_score": 55}
    elif first < 175:
        return {"country": "Russia",        "city": "Moscow",     "reputation": "Suspicious", "abuse_score": 65}
    elif first < 200:
        return {"country": "Brazil",        "city": "Sao Paulo",  "reputation": "Moderate",   "abuse_score": 20}
    else:
        return {"country": "Unknown",       "city": "Unknown",    "reputation": "Unknown",    "abuse_score": 10}


# ── Confidence Score Calculator ──
def calculate_confidence(
    event: NormalizedEvent,
    ip_info: dict,
    asset_info: dict
) -> int:
    """
    Calculate 0-100 confidence score for this finding.
    Higher score = more likely to be a real threat (not a false positive).

    Factors:
    - IP abuse score (from threat intel)
    - Asset criticality (how important is the target?)
    - Event type risk level
    - Severity level
    """
    score = 40  # Base score

    # IP reputation contribution (up to +30 points)
    abuse = ip_info.get("abuse_score", 0)
    score += int(abuse * 0.3)

    # Asset criticality contribution (up to +20 points)
    criticality_scores = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 8, "LOW": 2}
    score += criticality_scores.get(asset_info.get("criticality", "LOW"), 2)

    # High-risk event types get a boost (+10 points)
    high_risk_events = {
        "brute_force", "privilege_escalation",
        "malware_detected", "data_exfiltration"
    }
    if event.event_type in high_risk_events:
        score += 10

    # Severity boost
    severity_scores = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0, "INFO": 0}
    score += severity_scores.get(event.severity, 0)

    # Keep score within 0-100
    return min(max(score, 0), 100)


def enrich_event(normalized: NormalizedEvent) -> EnrichedEvent:
    """
    Add context to a normalized event.
    Returns an EnrichedEvent with all original fields plus enrichment data.
    """
    ip_info    = get_ip_info(normalized.source_ip)
    asset_info = ASSET_DB.get(normalized.target_host, {})

    return EnrichedEvent(
        # Pass through all original normalized fields
        event_id    = normalized.event_id,
        source      = normalized.source,
        event_type  = normalized.event_type,
        severity    = normalized.severity,
        source_ip   = normalized.source_ip,
        target_host = normalized.target_host,
        target_port = normalized.target_port,
        username    = normalized.username,
        protocol    = normalized.protocol,
        description = normalized.description,
        raw_event_id = normalized.raw_event_id,

        # Add enrichment fields
        ip_country        = ip_info.get("country"),
        ip_city           = ip_info.get("city"),
        ip_reputation     = ip_info.get("reputation"),
        ip_abuse_score    = ip_info.get("abuse_score"),
        asset_criticality = asset_info.get("criticality"),
        asset_description = asset_info.get("description"),
        confidence        = calculate_confidence(normalized, ip_info, asset_info),
    )


def main():
    logger.info("enrichment_starting", kafka=os.getenv("KAFKA_BOOTSTRAP_SERVERS"))

    consumer = create_consumer(
        group_id = "enrichment-group",
        topics   = ["security.events.normalized"],
    )
    producer = create_producer()
    processed = 0

    try:
        while running:
            msg = consumer.poll(timeout=1.0)

            if msg is None:
                continue

            if msg.error():
                logger.error("consumer_error", error=str(msg.error()))
                continue

            try:
                normalized = NormalizedEvent(**json.loads(msg.value().decode("utf-8")))
                enriched   = enrich_event(normalized)

                produce_message(
                    producer = producer,
                    topic    = "security.events.enriched",
                    message  = enriched.model_dump(),
                    key      = enriched.source_ip or enriched.event_id,
                )

                consumer.commit(msg)
                processed += 1

                logger.info(
                    "event_enriched",
                    event_id          = enriched.event_id,
                    confidence        = enriched.confidence,
                    ip_country        = enriched.ip_country,
                    ip_abuse_score    = enriched.ip_abuse_score,
                    asset_criticality = enriched.asset_criticality,
                    total             = processed,
                )

            except Exception as e:
                logger.error("enrichment_failed", error=str(e))
                consumer.commit(msg)

    finally:
        consumer.close()
        logger.info("enrichment_stopped", total_processed=processed)


if __name__ == "__main__":
    main()
