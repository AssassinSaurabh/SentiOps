#!/usr/bin/env bash
# scripts/test_phase4_ai.sh
# SentinelOps Phase 4 — AI Engine Test Suite
# Tests: AI worker startup, NVIDIA NIM API, full pipeline, DB persistence
set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'
PASS=0; FAIL=0

pass() { echo -e "${GREEN}✅ PASS${NC} — $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}❌ FAIL${NC} — $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${YELLOW}ℹ️  $1${NC}"; }

echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   SentinelOps Phase 4 — AI Engine Test Suite         ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ── TEST 1: AI worker container running ───────────────────────────────────────
echo "TEST 1: AI worker container is running"
if docker ps --format '{{.Names}}' | grep -q "sentinelops-ai-worker"; then
  pass "sentinelops-ai-worker is running"
else
  fail "sentinelops-ai-worker is NOT running"
fi

# ── TEST 2: AI worker started with correct model ──────────────────────────────
echo "TEST 2: AI worker configured with kimi-k3 model"
MODEL=$(docker exec sentinelops-ai-worker env 2>/dev/null | grep NVIDIA_MODEL | cut -d= -f2)
if echo "$MODEL" | grep -q "kimi-k3"; then
  pass "AI worker env NVIDIA_MODEL=$MODEL"
else
  fail "NVIDIA_MODEL not set to kimi-k3 (got: $MODEL)"
fi

# ── TEST 3: AI columns exist in PostgreSQL findings table ─────────────────────
echo "TEST 3: AI columns exist in PostgreSQL findings table"
COLS=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
  "SELECT count(*) FROM information_schema.columns WHERE table_name='findings' AND column_name LIKE 'ai_%';" 2>&1 | tr -d ' ')
if [ "$COLS" -ge 10 ]; then
  pass "All 10 AI columns present in findings table"
else
  fail "Only $COLS AI columns found (expected 10)"
fi

# ── TEST 4: Kafka topic ai.analysis.results exists ───────────────────────────
echo "TEST 4: Kafka topic ai.analysis.results exists"
if docker exec sentinelops-kafka kafka-topics --list --bootstrap-server localhost:9092 2>/dev/null | grep -q "ai.analysis.results"; then
  pass "Kafka topic ai.analysis.results exists"
else
  fail "Kafka topic ai.analysis.results NOT found"
fi

# ── TEST 5: NVIDIA NIM API reachable ─────────────────────────────────────────
echo "TEST 5: NVIDIA NIM API reachable"
API_KEY=$(grep NVIDIA_API_KEY /Users/saurabhpandey/Documents/SentiOps/sentinelops/.env | cut -d= -f2)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
  https://integrate.api.nvidia.com/v1/models \
  -H "Authorization: Bearer $API_KEY" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  pass "NVIDIA NIM API reachable (HTTP 200)"
else
  fail "NVIDIA NIM API returned HTTP $HTTP_CODE"
fi

# ── TEST 6: Full pipeline — inject event and wait for AI analysis ─────────────
echo "TEST 6: Full pipeline — event → normalizer → enrichment → storage → AI"
info "Flushing Redis dedup cache..."
docker exec sentinelops-redis redis-cli -a SentinelRedis2024 --no-auth-warning FLUSHDB > /dev/null 2>&1

info "Injecting test event..."
RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/events/simulate \
  -H "Content-Type: application/json" \
  -d '{"source":"wazuh","event_type":"port_scan","raw_payload":{"source_ip":"198.51.100.42","target_host":"prod-fw-01","port_count":1500,"protocol":"TCP"}}' 2>/dev/null)
EVENT_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_id',''))" 2>/dev/null)

if [ -z "$EVENT_ID" ]; then
  fail "Failed to inject test event"
else
  pass "Event injected: $EVENT_ID"
fi

# ── TEST 7: Storage worker stores the finding ─────────────────────────────────
echo "TEST 7: Storage worker stores finding in PostgreSQL (within 15s)"
STORED=false
for i in $(seq 1 15); do
  sleep 1
  COUNT=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
    "SELECT count(*) FROM findings WHERE raw_event->>'event_id'='$EVENT_ID';" 2>/dev/null | tr -d ' ')
  if [ "$COUNT" -ge 1 ] 2>/dev/null; then
    STORED=true
    break
  fi
done
if $STORED; then
  pass "Finding stored in PostgreSQL for event $EVENT_ID"
else
  fail "Finding NOT stored in PostgreSQL after 15s"
fi

# ── TEST 8: AI worker processes and updates with real verdict ─────────────────
echo "TEST 8: AI worker updates finding with real verdict (wait up to 120s)"
info "Waiting for kimi-k3 reasoning model (~60-90s)..."
AI_DONE=false
for i in $(seq 1 24); do
  sleep 5
  VERDICT=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
    "SELECT ai_verdict FROM findings WHERE raw_event->>'event_id'='$EVENT_ID';" 2>/dev/null | tr -d ' \n')
  if [ -n "$VERDICT" ] && [ "$VERDICT" != "" ]; then
    AI_DONE=true
    break
  fi
done

if $AI_DONE; then
  RISK=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
    "SELECT ai_risk_score FROM findings WHERE raw_event->>'event_id'='$EVENT_ID';" 2>/dev/null | tr -d ' ')
  ACTION=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
    "SELECT ai_action FROM findings WHERE raw_event->>'event_id'='$EVENT_ID';" 2>/dev/null | tr -d ' ')
  pass "AI verdict stored: verdict=$VERDICT risk=$RISK action=$ACTION"
else
  fail "AI verdict NOT stored after 120s"
fi

# ── TEST 9: ai.analysis.results Kafka topic has messages ──────────────────────
echo "TEST 9: ai.analysis.results Kafka topic has messages"
OFFSET=$(docker exec sentinelops-kafka kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 \
  --topic ai.analysis.results 2>/dev/null | cut -d: -f3 | tr -d ' ')
if [ -n "$OFFSET" ] && [ "$OFFSET" -gt 0 ] 2>/dev/null; then
  pass "ai.analysis.results has $OFFSET message(s) at offset $OFFSET"
else
  fail "ai.analysis.results topic appears empty (offset=$OFFSET)"
fi

# ── TEST 10: All 10 services still healthy ───────────────────────────────────
echo "TEST 10: All 10 services still running"
RUNNING=$(docker ps --format '{{.Names}}' | grep sentinelops | wc -l | tr -d ' ')
if [ "$RUNNING" -ge 10 ]; then
  pass "All $RUNNING sentinelops services running"
else
  fail "Only $RUNNING/10 services running"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════${NC}"
TOTAL=$((PASS + FAIL))
echo -e "${BOLD}Phase 4 Results: ${GREEN}$PASS passed${NC} / ${RED}$FAIL failed${NC} / $TOTAL total${NC}"
echo -e "${BOLD}═══════════════════════════════════════${NC}"

if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}🎉 PHASE 4 COMPLETE — AI Engine fully operational!${NC}"
  echo -e "Model: moonshotai/kimi-k3 via NVIDIA NIM"
  exit 0
else
  echo -e "${RED}${BOLD}⚠️  $FAIL test(s) failed — check logs above${NC}"
  exit 1
fi
