# workers/common/models.py
# Purpose: Shared data models used by ALL workers
# Using Pydantic for validation — if a field is wrong type, it fails loudly

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime
import uuid


class RawEvent(BaseModel):
    """
    What comes INTO the pipeline first.
    Produced by: FastAPI /api/v1/events/simulate endpoint
    Consumed by: Normalizer Worker
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str                          # "wazuh", "suricata", "manual"
    raw_data: Dict[str, Any]             # The original unprocessed event
    received_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )


class NormalizedEvent(BaseModel):
    """
    After normalization: raw log → clean structured fields.
    Produced by: Normalizer Worker
    Consumed by: Enrichment Worker
    """
    event_id: str
    source: str
    event_type: str                      # "brute_force", "port_scan", etc.
    severity: str                        # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    source_ip: Optional[str] = None      # Attacker's IP
    target_host: Optional[str] = None    # Victim host
    target_port: Optional[int] = None
    username: Optional[str] = None
    protocol: Optional[str] = None
    description: str
    raw_event_id: str
    normalized_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )


class EnrichedEvent(BaseModel):
    """
    After enrichment: normalized fields + geo/threat/asset context.
    Produced by: Enrichment Worker
    Consumed by: Storage Worker
    """
    event_id: str
    source: str
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    target_host: Optional[str] = None
    target_port: Optional[int] = None
    username: Optional[str] = None
    protocol: Optional[str] = None
    description: str
    raw_event_id: str
    # ── Enrichment fields ──
    ip_country: Optional[str] = None
    ip_city: Optional[str] = None
    ip_reputation: Optional[str] = None
    ip_abuse_score: Optional[int] = None
    asset_criticality: Optional[str] = None
    asset_description: Optional[str] = None
    confidence: int = 50                 # 0-100 score
    enriched_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )


class AIAnalysis(BaseModel):
    """
    Structured output from LLM security analysis.
    Produced by: AI Worker
    Stored in:   PostgreSQL findings table (ai_* columns)
    Published to: ai.analysis.results Kafka topic (for Phase 5 remediation)
    """
    event_id: str
    verdict: str        # TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_INVESTIGATION
    risk_score: int     # 0-100
    confidence: float   # 0.0-1.0
    summary: str
    reasoning: str
    action: str         # BLOCK_IP | INVESTIGATE | IGNORE | ESCALATE | AUTO_REMEDIATE
    mitre_techniques: list = []
    provider: str = "nvidia"
    model: str = "meta/llama-3.1-8b-instruct"
    analyzed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
