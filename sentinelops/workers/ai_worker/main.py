# workers/ai_worker/main.py
"""
SentinelOps — AI Analysis Worker (Phase 4)
==========================================
Consumes: security.events.enriched  (Kafka)
Calls:    NVIDIA NIM — moonshotai/kimi-k3
Produces: ai.analysis.results       (Kafka)
Updates:  PostgreSQL findings table (ai_* columns)
"""

import json
import sys
import os
import signal
import time
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import structlog
import requests
import sqlalchemy
from sqlalchemy import create_engine, text
from common.kafka_client import create_consumer, create_producer, produce_message
from common.models import EnrichedEvent

# ─── Logging ──────────────────────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.dev.ConsoleRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)
logger = structlog.get_logger("ai_worker")

# ─── Configuration ────────────────────────────────────────────────────────────
NVIDIA_API_KEY  = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
NVIDIA_MODEL    = os.getenv("NVIDIA_MODEL", "moonshotai/kimi-k3")
AI_TIMEOUT      = int(os.getenv("AI_TIMEOUT_SECONDS", "120"))   # kimi-k3 reasoning takes ~60-90s
AI_TEMPERATURE  = float(os.getenv("AI_TEMPERATURE", "1"))   # kimi-k3 default
AI_MAX_TOKENS   = int(os.getenv("AI_MAX_TOKENS", "1000"))

# Sync DATABASE_URL (strip +asyncpg for psycopg2)
DATABASE_URL = os.getenv("DATABASE_URL", "").replace("+asyncpg", "")

INVOKE_URL = f"{NVIDIA_BASE_URL}/chat/completions"

# ─── Graceful Shutdown ────────────────────────────────────────────────────────
running = True
def handle_shutdown(sig, frame):
    global running
    running = False
    logger.info("shutdown_signal")
signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)

# ─── System Prompt ────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert cybersecurity analyst with 15+ years experience in SOC, incident response, and threat hunting.

Analyze the provided security finding. Respond with ONLY a valid JSON object — no markdown, no code blocks, no text outside the JSON.

Required JSON:
{
  "verdict": "TRUE_POSITIVE",
  "risk_score": 87,
  "confidence": 0.91,
  "summary": "Single sentence max 150 chars",
  "reasoning": "2-4 sentences technical analysis",
  "action": "BLOCK_IP",
  "mitre_techniques": ["T1110.001"]
}

verdict options: TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_INVESTIGATION
action options: BLOCK_IP | INVESTIGATE | IGNORE | ESCALATE | AUTO_REMEDIATE
mitre_techniques: list of MITRE ATT&CK IDs or empty list []"""


def build_prompt(event: EnrichedEvent) -> str:
    return f"""Analyze this security finding and return JSON only:

EVENT: {event.event_type} | Severity: {event.severity} | Source: {event.source}
Description: {event.description}

Network: src={event.source_ip or 'unknown'} -> {event.target_host or 'unknown'}:{event.target_port or '?'} ({event.protocol or '?'})
Target user: {event.username or 'none'}

Threat Intel: reputation={event.ip_reputation or 'unknown'} abuse_score={event.ip_abuse_score or 'N/A'}/100 location={event.ip_city or '?'},{event.ip_country or '?'}

Asset: criticality={event.asset_criticality or 'unknown'} desc={event.asset_description or 'N/A'}

Return JSON verdict:"""


def call_kimi_k3(prompt_text: str) -> str:
    """
    Call NVIDIA NIM moonshotai/kimi-k3 using the exact same format
    as the official sample code — content as a list of typed objects.
    """
    headers = {
        "Authorization": f"Bearer {NVIDIA_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    payload = {
        "model": NVIDIA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": [{"type": "text", "text": SYSTEM_PROMPT}]
            },
            {
                "role": "user",
                "content": [{"type": "text", "text": prompt_text}]
            }
        ],
        "max_tokens": AI_MAX_TOKENS,
        "temperature": AI_TEMPERATURE,
        "stream": False,
        "reasoning_effort": "low",
    }

    response = requests.post(INVOKE_URL, headers=headers, json=payload, timeout=AI_TIMEOUT)
    response.raise_for_status()
    data = response.json()

    msg = data["choices"][0]["message"]
    content          = msg.get("content") or ""
    reasoning_content = msg.get("reasoning_content") or ""

    logger.info("llm_raw_response",
                content_len=len(content),
                reasoning_len=len(reasoning_content))

    # Try content first; if it has no JSON object, fall back to reasoning_content
    # kimi-k3 sometimes puts the full structured answer inside reasoning_content
    # and just says "Clear" or similar in content
    if "{" not in content and "{" in reasoning_content:
        logger.info("using_reasoning_content_for_json")
        return reasoning_content

    return content if content else reasoning_content


def parse_response(raw: str, event_id: str) -> dict:
    """Parse JSON from LLM response with multiple fallback strategies."""
    text = raw.strip()

    # Strip markdown code fences if present
    if "```" in text:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if match:
            text = match.group(1).strip()

    # Find JSON object boundaries
    if not text.startswith("{"):
        start = text.find("{")
        end = text.rfind("}") + 1
        if start != -1 and end > start:
            text = text[start:end]

    try:
        result = json.loads(text)
        # Validate required fields, fill defaults if missing
        result.setdefault("verdict", "NEEDS_INVESTIGATION")
        result.setdefault("risk_score", 50)
        result.setdefault("confidence", 0.5)
        result.setdefault("summary", "AI analysis complete")
        result.setdefault("reasoning", "See raw response")
        result.setdefault("action", "INVESTIGATE")
        result.setdefault("mitre_techniques", [])
        return result
    except json.JSONDecodeError:
        logger.error("json_parse_failed", event_id=event_id, snippet=raw[:200])
        return {
            "verdict": "NEEDS_INVESTIGATION",
            "risk_score": 50,
            "confidence": 0.0,
            "summary": "AI parse error — manual review needed",
            "reasoning": f"Could not parse LLM response. Raw: {raw[:150]}",
            "action": "INVESTIGATE",
            "mitre_techniques": [],
        }


def analyze_event(event: EnrichedEvent) -> dict:
    """Full AI analysis for one security event."""
    prompt = build_prompt(event)
    try:
        raw = call_kimi_k3(prompt)
        result = parse_response(raw, event.event_id)
        result["provider"] = "nvidia"
        result["model"] = NVIDIA_MODEL
        logger.info("llm_response_received",
                    event_id=event.event_id,
                    verdict=result.get("verdict"),
                    risk_score=result.get("risk_score"))
        return result
    except requests.exceptions.HTTPError as e:
        logger.error("nvidia_api_http_error", event_id=event.event_id,
                     status=e.response.status_code, body=e.response.text[:300])
        return {
            "verdict": "NEEDS_INVESTIGATION", "risk_score": 50, "confidence": 0.0,
            "summary": f"API error {e.response.status_code}",
            "reasoning": f"NVIDIA API returned error: {e.response.text[:200]}",
            "action": "INVESTIGATE", "mitre_techniques": [],
            "provider": "error", "model": NVIDIA_MODEL,
        }
    except Exception as e:
        logger.error("analyze_failed", event_id=event.event_id, error=str(e))
        return {
            "verdict": "NEEDS_INVESTIGATION", "risk_score": 50, "confidence": 0.0,
            "summary": f"Analysis error: {str(e)[:80]}",
            "reasoning": "Unexpected error during AI analysis.",
            "action": "INVESTIGATE", "mitre_techniques": [],
            "provider": "error", "model": NVIDIA_MODEL,
        }


def update_db(engine, event_id: str, analysis: dict) -> bool:
    """Write AI verdict back to PostgreSQL findings row."""
    sql = text("""
        UPDATE findings
        SET
            ai_verdict          = :verdict,
            ai_risk_score       = :risk_score,
            ai_confidence       = :confidence,
            ai_summary          = :summary,
            ai_reasoning        = :reasoning,
            ai_action           = :action,
            ai_mitre_techniques = :mitre,
            ai_analyzed_at      = NOW(),
            ai_provider         = :provider,
            ai_model            = :model,
            updated_at          = NOW()
        WHERE raw_event->>'event_id' = :event_id
           OR (source_ip::text = :source_ip AND event_type = :event_type
               AND ai_verdict IS NULL AND created_at > NOW() - INTERVAL '5 minutes')
        RETURNING id
    """)
    try:
        with engine.connect() as conn:
            result = conn.execute(sql, {
                "verdict":    str(analysis.get("verdict", "NEEDS_INVESTIGATION")),
                "risk_score": int(analysis.get("risk_score", 50)),
                "confidence": float(analysis.get("confidence", 0.5)),
                "summary":    str(analysis.get("summary", ""))[:500],
                "reasoning":  str(analysis.get("reasoning", "")),
                "action":     str(analysis.get("action", "INVESTIGATE")),
                "mitre":      analysis.get("mitre_techniques", []),
                "provider":   str(analysis.get("provider", "nvidia")),
                "model":      str(analysis.get("model", NVIDIA_MODEL)),
                "event_id":   event_id,
                "source_ip":  analysis.get("_source_ip", ""),
                "event_type": analysis.get("_event_type", ""),
            })
            conn.commit()
            rows = result.fetchall()
            return len(rows) > 0
    except Exception as e:
        logger.error("db_update_failed", event_id=event_id, error=str(e))
        return False


def main():
    logger.info("ai_worker_starting", model=NVIDIA_MODEL, url=INVOKE_URL)

    if not NVIDIA_API_KEY:
        logger.error("NVIDIA_API_KEY missing — exiting")
        return

    engine   = create_engine(DATABASE_URL, pool_size=2, pool_recycle=3600)
    consumer = create_consumer("ai-worker-group", ["security.events.enriched"])
    producer = create_producer()

    total = 0
    errors = 0

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
                logger.info("analyzing", event_id=event.event_id,
                            type=event.event_type, severity=event.severity)

                t0 = time.time()
                analysis = analyze_event(event)
                elapsed = round(time.time() - t0, 2)

                # Attach event metadata for DB fallback matching
                analysis["_source_ip"]  = event.source_ip or ""
                analysis["_event_type"] = event.event_type or ""

                # Save to PostgreSQL
                updated = update_db(engine, event.event_id, analysis)

                # Publish to Kafka for Phase 5 (remediation)
                produce_message(producer, "ai.analysis.results", {
                    "event_id":         event.event_id,
                    "source_ip":        event.source_ip,
                    "target_host":      event.target_host,
                    "event_type":       event.event_type,
                    "severity":         event.severity,
                    "verdict":          analysis.get("verdict"),
                    "risk_score":       analysis.get("risk_score"),
                    "action":           analysis.get("action"),
                    "summary":          analysis.get("summary"),
                    "mitre_techniques": analysis.get("mitre_techniques", []),
                })

                consumer.commit(msg)
                total += 1

                logger.info("analysis_done",
                            event_id=event.event_id,
                            verdict=analysis.get("verdict"),
                            risk_score=analysis.get("risk_score"),
                            action=analysis.get("action"),
                            db_updated=updated,
                            elapsed_s=elapsed,
                            total=total)

            except Exception as e:
                errors += 1
                logger.error("processing_error", error=str(e), errors=errors)
                consumer.commit(msg)

    finally:
        consumer.close()
        engine.dispose()
        logger.info("ai_worker_stopped", total=total, errors=errors)


if __name__ == "__main__":
    main()
