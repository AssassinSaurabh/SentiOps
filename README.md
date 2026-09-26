# SentinelOps

SentinelOps is an AI-powered Security Operations platform built to detect, analyze, and respond to threats in real time. It ingests raw security events from tools such as CrowdStrike, Wazuh, and Suricata, moves them through a Kafka streaming pipeline, runs deep AI reasoning on each threat using the kimi-k3 model via NVIDIA NIM, and then automatically executes remediation playbooks — all without human intervention.

The project is organized into six phases, each building on the last. Every phase ships with an automated test suite that must pass completely before the next phase begins.

---

## Architecture

```
External Security Tools (CrowdStrike, Wazuh, Suricata)
              |
              v
      [Nginx :8080]  →  [FastAPI :8000]
              |
              v
     security.events.raw   (Kafka)
              |
              v
     [Normalizer Worker]
       parse + fingerprint + Redis dedup
              |
              v
     security.events.normalized   (Kafka)
              |
              v
     [Enrichment Worker]
       IP reputation + geolocation + asset criticality
              |
              v
     security.events.enriched   (Kafka)
              |
              v
     [Storage Worker]  →  PostgreSQL (pgvector)
              |
              v
     security.findings.stored   (Kafka)
              |
              v
     [AI Worker]
       moonshotai/kimi-k3 via NVIDIA NIM
       ~70 seconds deep reasoning
       verdict · risk_score · action · mitre_techniques
              |
              v
     ai.analysis.results   (Kafka)
              |
              v
     [Remediation Worker]
       BLOCK_IP · ESCALATE · AUTO_REMEDIATE · INVESTIGATE · IGNORE
       findings.remediated = true  →  PostgreSQL
              |
              v
     notifications.outbound   (Kafka)
              |
              v
     [Notification Worker]
       Console alert · Slack webhook · notifications table
```

---

## Getting Started

### Prerequisites

Before you begin, make sure you have Docker Desktop running with at least 4 GB of memory allocated. You will also need a free NVIDIA NIM API key from [build.nvidia.com](https://build.nvidia.com) to power the AI analysis engine.

### Installation

Clone the repository and enter the project directory.

```bash
git clone git@github.com:AssassinSaurabh/SentiOps.git
cd SentiOps/sentinelops
```

Open the `.env` file and add your NVIDIA NIM API key.

```
NVIDIA_API_KEY=nvapi-your-key-here
NVIDIA_MODEL=moonshotai/kimi-k3
AI_TIMEOUT_SECONDS=120
```

Start all twelve services with a single command.

```bash
docker compose up -d
```

Give Kafka about thirty seconds to finish its initialization, then verify that all containers are healthy.

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

### Sending Your First Event

Once the platform is running, inject a simulated brute force attack and watch the pipeline respond.

```bash
curl -X POST http://localhost:8080/api/v1/events/simulate \
  -H "Content-Type: application/json" \
  -d '{
    "source": "crowdstrike",
    "event_type": "brute_force",
    "raw_payload": {
      "source_ip": "185.220.101.45",
      "target_host": "prod-db-01",
      "failure_count": 847,
      "port": 5432,
      "protocol": "SSH"
    }
  }'
```

After approximately ninety seconds, the notification worker will print a formatted security alert to its console log.

```bash
docker logs sentinelops-notification-worker --tail 20
```

You should see output similar to the following.

```
============================================================
SENTINELOPS SECURITY ALERT [HIGH]
============================================================
  Verdict:     TRUE_POSITIVE
  Risk Score:  95/100
  Source IP:   185.220.101.45
  Summary:     SSH brute force from known Tor exit node targeting
               root account on critical production database.
  Action:      BLOCKED IP
  Time:        2026-09-26 05:18:53 UTC
============================================================
```

---

## Services

The platform runs twelve containers. Each one has a single responsibility.

| Container | Port | Responsibility |
|---|---|---|
| sentinelops-postgres | 5433 | Persistent storage with pgvector extension |
| sentinelops-redis | 6380 | Event deduplication with ten-minute TTL |
| sentinelops-kafka | 9092 | Event streaming backbone in KRaft mode |
| sentinelops-kafka-ui | 8090 | Visual browser for Kafka topics |
| sentinelops-backend | 8000 | FastAPI REST application |
| sentinelops-nginx | 8080 | Reverse proxy and API gateway |
| sentinelops-normalizer | — | Parses and deduplicates raw events |
| sentinelops-enrichment | — | Adds IP reputation and asset intelligence |
| sentinelops-storage | — | Writes enriched findings to PostgreSQL |
| sentinelops-ai-worker | — | Calls kimi-k3 to classify each threat |
| sentinelops-remediation-worker | — | Executes remediation playbooks |
| sentinelops-notification-worker | — | Sends alerts and stores notification history |

---

## Project Phases

### Phase 1: Architecture and Planning

The initial phase establishes the full system design, data models, Kafka topic layout, and service boundaries before a single line of implementation code is written.

### Phase 2: Foundation

This phase brings up the core infrastructure: FastAPI with async PostgreSQL access via asyncpg, pgvector for semantic similarity search on findings, Redis for deduplication, and Nginx as the front door.

### Phase 3: Kafka Event Streaming

Phase 3 introduces the full streaming pipeline across nine Kafka topics. The normalizer worker parses events from multiple source formats, computes a SHA-256 fingerprint for each one, and checks Redis before allowing it downstream. The enrichment worker adds IP reputation, geolocation, and asset criticality scores. The storage worker persists the finished finding to PostgreSQL.

### Phase 4: AI Analysis Engine

The AI worker reads from the `security.findings.stored` topic and calls NVIDIA NIM to run each event through the kimi-k3 reasoning model. The model takes roughly seventy seconds to reason through the threat context and returns a structured verdict including `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `NEEDS_INVESTIGATION`, a risk score from 0 to 100, a confidence value, recommended MITRE ATT&CK techniques, and a plain-language summary. All fields are written back to the PostgreSQL `findings` table.

### Phase 5: Auto-Remediation

The remediation worker reads from `ai.analysis.results` and routes each event to one of five playbooks based on the AI decision and a configurable risk score threshold.

| Action | Minimum Risk Score | What Happens |
|---|---|---|
| BLOCK_IP | 60 | IP is blocked at the firewall |
| ESCALATE | any | P1 ticket created in the ticketing system |
| AUTO_REMEDIATE | 70 | IP blocked, credentials rotated, ticket opened |
| INVESTIGATE | any | Event queued for analyst review |
| IGNORE | any | Event dismissed as a confirmed false positive |

### Phase 6: Notifications

The notification worker consumes from `notifications.outbound` and delivers alerts through three channels simultaneously. It always prints a formatted alert block to its container logs. It stores a complete record in the PostgreSQL `notifications` table for dashboard queries and audit purposes. If the `SLACK_WEBHOOK_URL` environment variable is set, it also posts a rich Slack message for every HIGH or CRITICAL severity event.

---

## Running the Tests

Each phase ships with a standalone test script. Run them in order after bringing the platform up.

```bash
bash scripts/test_phase3_pipeline.sh
bash scripts/test_phase4_ai.sh
bash scripts/test_phase5_remediation.sh
bash scripts/test_phase6_notifications.sh
```

Total coverage: 51 automated tests, all passing.

---

## Configuration Reference

The `.env` file in the `sentinelops/` directory controls all runtime behaviour. The most important variables are listed below.

```
POSTGRES_PASSWORD         Password for the PostgreSQL instance
REDIS_PASSWORD            Password for the Redis instance

NVIDIA_API_KEY            Your NVIDIA NIM API key
NVIDIA_MODEL              Model name (moonshotai/kimi-k3)
AI_TIMEOUT_SECONDS        Seconds to wait for AI response (default 120)
AI_MAX_TOKENS             Maximum tokens in AI response (default 1000)

BLOCK_IP_THRESHOLD        Minimum risk score required to block an IP (default 60)
AUTO_REMEDIATE_THRESHOLD  Minimum risk score for full auto-remediation (default 70)

SLACK_WEBHOOK_URL         Slack incoming webhook URL — leave empty to disable
NOTIFICATION_TTL_DAYS     How long to retain notification records (default 30)
```

### Enabling Slack Notifications

To enable Slack alerts, open `docker-compose.yml`, locate the `notification-worker` service, and set the `SLACK_WEBHOOK_URL` value. Then restart that single container.

```bash
docker compose up -d notification-worker
```

You can generate a free incoming webhook at [api.slack.com/apps](https://api.slack.com/apps) by creating a new app, enabling Incoming Webhooks, and copying the generated URL.

---

## Repository Layout

```
SentiOps/
  README.md
  sentinelops/
    docker-compose.yml
    nginx/
      nginx.conf
    backend/
      app/
        main.py
        models/
        api/
    workers/
      Dockerfile
      requirements.txt
      common/
        kafka_client.py
        models.py
      normalizer/
      enrichment/
      storage/
      ai_worker/
      remediation_worker/
      notification_worker/
    scripts/
      test_phase3_pipeline.sh
      test_phase4_ai.sh
      test_phase5_remediation.sh
      test_phase6_notifications.sh
```

---

## Technology

| Component | Technology |
|---|---|
| API Gateway | Nginx |
| Backend | FastAPI + Python 3.11 |
| Database | PostgreSQL 15 + pgvector |
| Cache | Redis 7 |
| Streaming | Apache Kafka 7.6 in KRaft mode |
| AI | moonshotai/kimi-k3 via NVIDIA NIM |
| Containers | Docker and Docker Compose v2 |

---

## License

MIT
