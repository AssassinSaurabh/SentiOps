#!/usr/bin/env bash
# scripts/test_phase5_remediation.sh
# SentinelOps Phase 5 — Auto-Remediation Test Suite
set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'
PASS=0; FAIL=0

pass() { echo -e "${GREEN}✅ PASS${NC} — $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}❌ FAIL${NC} — $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${YELLOW}ℹ️  $1${NC}"; }

echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  SentinelOps Phase 5 — Auto-Remediation Test Suite   ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# TEST 1: Remediation worker container running
echo "TEST 1: Remediation worker container running"
if docker ps --format '{{.Names}}' | grep -q "sentinelops-remediation-worker"; then
  pass "sentinelops-remediation-worker is running"
else
  fail "sentinelops-remediation-worker is NOT running"
fi

# TEST 2: All 11 services running
echo "TEST 2: All 11 services running"
COUNT=$(docker ps --format '{{.Names}}' | grep sentinelops | wc -l | tr -d ' ')
if [ "$COUNT" -ge 11 ]; then
  pass "All $COUNT sentinelops services running"
else
  fail "Only $COUNT/11 services running"
fi

# TEST 3: Kafka remediation.tasks topic has messages (audit log)
echo "TEST 3: remediation.tasks Kafka topic has audit messages"
OFFSET=$(docker exec sentinelops-kafka kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 --topic remediation.tasks 2>/dev/null | cut -d: -f3 | tr -d ' ')
if [ -n "$OFFSET" ] && [ "$OFFSET" -gt 0 ] 2>/dev/null; then
  pass "remediation.tasks has $OFFSET audit message(s)"
else
  fail "remediation.tasks topic appears empty (offset=$OFFSET)"
fi

# TEST 4: Kafka notifications.outbound topic has messages (for Phase 6)
echo "TEST 4: notifications.outbound topic has notification messages"
OFFSET2=$(docker exec sentinelops-kafka kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 --topic notifications.outbound 2>/dev/null | cut -d: -f3 | tr -d ' ')
if [ -n "$OFFSET2" ] && [ "$OFFSET2" -gt 0 ] 2>/dev/null; then
  pass "notifications.outbound has $OFFSET2 message(s)"
else
  fail "notifications.outbound topic appears empty (offset=$OFFSET2)"
fi

# TEST 5: PostgreSQL has remediated=true rows
echo "TEST 5: PostgreSQL findings marked as remediated"
REMEDIATED=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
  "SELECT count(*) FROM findings WHERE remediated=true;" 2>/dev/null | tr -d ' ')
if [ -n "$REMEDIATED" ] && [ "$REMEDIATED" -gt 0 ] 2>/dev/null; then
  pass "$REMEDIATED findings marked remediated=true in PostgreSQL"
else
  fail "No remediated findings found in PostgreSQL"
fi

# TEST 6: Full end-to-end — inject → AI → remediation within one test
echo "TEST 6: Full pipeline with remediation (inject → storage → AI → remediation)"
info "Flushing Redis dedup cache..."
docker exec sentinelops-redis redis-cli -a SentinelRedis2024 --no-auth-warning FLUSHDB >/dev/null 2>&1

info "Injecting high-severity test event..."
EVENT_ID=$(curl -s -X POST http://localhost:8080/api/v1/events/simulate \
  -H "Content-Type: application/json" \
  -d '{"source":"suricata","event_type":"sql_injection","raw_payload":{"source_ip":"192.0.2.100","target_host":"prod-db-02","query":"SELECT * FROM users--","protocol":"HTTP"}}' \
  2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_id',''))" 2>/dev/null)

if [ -z "$EVENT_ID" ]; then
  fail "Failed to inject test event"
else
  pass "Event injected: $EVENT_ID"
fi

# Wait for storage to persist
info "Waiting for storage worker (15s)..."
STORED=false
for i in $(seq 1 15); do
  sleep 1
  COUNT_DB=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
    "SELECT count(*) FROM findings WHERE raw_event->>'event_id'='$EVENT_ID';" 2>/dev/null | tr -d ' ')
  if [ "${COUNT_DB:-0}" -ge 1 ] 2>/dev/null; then STORED=true; break; fi
done

if $STORED; then
  pass "Finding stored in PostgreSQL"
else
  fail "Finding NOT stored after 15s"
fi

# Wait for AI analysis
info "Waiting for AI analysis — kimi-k3 takes ~60-90s..."
AI_DONE=false
for i in $(seq 1 24); do
  sleep 5
  VERDICT=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
    "SELECT ai_verdict FROM findings WHERE raw_event->>'event_id'='$EVENT_ID';" 2>/dev/null | tr -d ' \n')
  if [ -n "$VERDICT" ]; then AI_DONE=true; break; fi
done

if $AI_DONE; then
  pass "AI verdict received: $VERDICT"
else
  fail "AI verdict not received after 120s"
fi

# Wait for remediation (should be near-instant after AI)
info "Waiting for remediation (10s)..."
sleep 10
REM=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
  "SELECT remediated FROM findings WHERE raw_event->>'event_id'='$EVENT_ID';" 2>/dev/null | tr -d ' \n')
PLAYBOOK=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
  "SELECT remediation_details->>'playbook' FROM findings WHERE raw_event->>'event_id'='$EVENT_ID';" 2>/dev/null | tr -d ' \n')

if [ "$REM" = "t" ]; then
  pass "Finding remediated=true | playbook=$PLAYBOOK"
else
  fail "Finding NOT remediated (remediated=$REM)"
fi

# TEST 7: Verify remediation_details JSONB content
echo "TEST 7: remediation_details JSONB populated correctly"
STATUS=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
  "SELECT remediation_details->>'status' FROM findings WHERE raw_event->>'event_id'='$EVENT_ID';" 2>/dev/null | tr -d ' \n')
if [ "$STATUS" = "success" ] || [ "$STATUS" = "queued" ]; then
  pass "remediation_details.status=$STATUS"
else
  fail "remediation_details.status='$STATUS' (expected success or queued)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════${NC}"
TOTAL=$((PASS + FAIL))
echo -e "${BOLD}Phase 5 Results: ${GREEN}$PASS passed${NC} / ${RED}$FAIL failed${NC} / $TOTAL total${NC}"
echo -e "${BOLD}═══════════════════════════════════════${NC}"

if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}🎉 PHASE 5 COMPLETE — Auto-Remediation fully operational!${NC}"
  exit 0
else
  echo -e "${RED}${BOLD}⚠️  $FAIL test(s) failed${NC}"
  exit 1
fi
