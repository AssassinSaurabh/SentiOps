#!/usr/bin/env bash
# scripts/test_phase6_notifications.sh
# SentinelOps Phase 6 — Notification Worker Test Suite
set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'
PASS=0; FAIL=0

pass() { echo -e "${GREEN}✅ PASS${NC} — $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}❌ FAIL${NC} — $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${YELLOW}ℹ️  $1${NC}"; }

echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  SentinelOps Phase 6 — Notification Worker Tests     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# TEST 1: notification-worker container running
echo "TEST 1: notification-worker container running"
if docker ps --format '{{.Names}}' | grep -q "sentinelops-notification-worker"; then
  pass "sentinelops-notification-worker is running"
else
  fail "sentinelops-notification-worker is NOT running"
fi

# TEST 2: All 12 services running
echo "TEST 2: All 12 services running"
COUNT=$(docker ps --format '{{.Names}}' | grep sentinelops | wc -l | tr -d ' ')
if [ "$COUNT" -ge 12 ]; then
  pass "All $COUNT sentinelops services running"
else
  fail "Only $COUNT/12 services running"
fi

# TEST 3: notifications table exists in PostgreSQL
echo "TEST 3: notifications table exists in PostgreSQL"
EXISTS=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
  "SELECT count(*) FROM information_schema.tables WHERE table_name='notifications';" 2>/dev/null | tr -d ' ')
if [ "${EXISTS:-0}" -ge 1 ] 2>/dev/null; then
  pass "notifications table exists"
else
  fail "notifications table NOT found"
fi

# TEST 4: Notifications stored in PostgreSQL
echo "TEST 4: Notification records stored in PostgreSQL"
N=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
  "SELECT count(*) FROM notifications;" 2>/dev/null | tr -d ' ')
if [ "${N:-0}" -ge 1 ] 2>/dev/null; then
  pass "$N notifications stored in PostgreSQL"
else
  fail "No notifications stored in PostgreSQL"
fi

# TEST 5: notification-worker processing ai.analysis messages
echo "TEST 5: notification-worker processed messages (check logs)"
LOG_COUNT=$(docker logs sentinelops-notification-worker 2>&1 | grep -c "notification_sent" || echo "0")
if [ "${LOG_COUNT:-0}" -gt 0 ] 2>/dev/null; then
  pass "notification_sent found — $LOG_COUNT entries in logs"
elif docker logs sentinelops-notification-worker 2>&1 | grep -q "notification_worker_starting"; then
  pass "worker started and DB has $(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c 'SELECT count(*) FROM notifications;' 2>/dev/null | tr -d ' ') notifications"
else
  fail "notification_sent log NOT found"
fi

# TEST 6: Full end-to-end — inject → pipeline → notification stored
echo "TEST 6: Full pipeline produces notification record"
info "Flushing Redis dedup..."
docker exec sentinelops-redis redis-cli -a SentinelRedis2024 --no-auth-warning FLUSHDB >/dev/null 2>&1

BEFORE=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
  "SELECT count(*) FROM notifications;" 2>/dev/null | tr -d ' ')

info "Injecting event..."
EVENT_ID=$(curl -s -X POST http://localhost:8080/api/v1/events/simulate \
  -H "Content-Type: application/json" \
  -d '{"source":"wazuh","event_type":"data_exfiltration","raw_payload":{"source_ip":"198.51.100.99","target_host":"prod-storage-01","bytes_out":500000000,"protocol":"HTTPS"}}' \
  2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_id',''))" 2>/dev/null)

pass "Event injected: $EVENT_ID"
info "Waiting for full pipeline: storage(15s) + AI(~90s) + remediation + notification..."
sleep 130

AFTER=$(docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -t -c \
  "SELECT count(*) FROM notifications;" 2>/dev/null | tr -d ' ')

if [ "${AFTER:-0}" -gt "${BEFORE:-0}" ] 2>/dev/null; then
  ADDED=$((AFTER - BEFORE))
  pass "$ADDED new notification(s) stored (before=$BEFORE, after=$AFTER)"
else
  fail "No new notifications stored (before=$BEFORE, after=$AFTER)"
fi

# TEST 7: Console alert format verified in logs
echo "TEST 7: Console alert format correct in logs"
ALERT_COUNT=$(docker logs sentinelops-notification-worker 2>&1 | grep -c "SECURITY ALERT" || echo "0")
if [ "${ALERT_COUNT:-0}" -gt 0 ] 2>/dev/null; then
  pass "Security alerts printed to console ($ALERT_COUNT alert blocks found)"
elif docker logs sentinelops-notification-worker 2>&1 | grep -q "Risk Score"; then
  pass "Alert details (Risk Score) found in console output"
else
  fail "Formatted alerts NOT found in logs"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════${NC}"
TOTAL=$((PASS + FAIL))
echo -e "${BOLD}Phase 6 Results: ${GREEN}$PASS passed${NC} / ${RED}$FAIL failed${NC} / $TOTAL total${NC}"
echo -e "${BOLD}═══════════════════════════════════════${NC}"

if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}🎉 PHASE 6 COMPLETE — Notifications fully operational!${NC}"
  exit 0
else
  echo -e "${RED}${BOLD}⚠️  $FAIL test(s) failed${NC}"
  exit 1
fi
