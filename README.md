# 🛡️ SentinelOps — AI-Powered Security Operations Platform

<div align="center">

![SentinelOps](https://img.shields.io/badge/SentinelOps-v1.0-blue?style=for-the-badge&logo=shield)
![Python](https://img.shields.io/badge/Python-3.11-green?style=for-the-badge&logo=python)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker)
![Kafka](https://img.shields.io/badge/Apache-Kafka-231F20?style=for-the-badge&logo=apachekafka)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-pgvector-4169E1?style=for-the-badge&logo=postgresql)
![AI](https://img.shields.io/badge/AI-kimi--k3%20%7C%20NVIDIA%20NIM-76B900?style=for-the-badge&logo=nvidia)

**A production-grade Security Operations Center (SOC) platform powered by AI threat analysis, real-time event streaming, and automated remediation.**

[Architecture](#-architecture) • [Quick Start](#-quick-start) • [Features](#-features) • [Phases](#-project-phases) • [API](#-api-reference) • [Tests](#-running-tests)

</div>

---

## 🌟 What is SentinelOps?

SentinelOps is a full-stack **AI Security Operations Platform** that ingests security events from tools like CrowdStrike, Wazuh, and Suricata, processes them through a real-time Kafka streaming pipeline, uses a **deep reasoning AI model (kimi-k3)** to classify threats, and automatically remediates confirmed attacks — all within seconds.

### Key Capabilities

| Capability | Details |
|---|---|
| 🔄 **Real-time streaming** | Apache Kafka with 9 topics, KRaft mode (no Zookeeper) |
| 🧠 **AI threat analysis** | `moonshotai/kimi-k3` via NVIDIA NIM — deep reasoning |
| 🛡️ **Auto-remediation** | 5 playbooks: BLOCK_IP, ESCALATE, AUTO_REMEDIATE, INVESTIGATE, IGNORE |
| 📊 **Vector search** | PostgreSQL + pgvector for semantic similarity on findings |
| 🔔 **Notifications** | Console alerts + Slack webhook + PostgreSQL history |
| 🐳 **Fully containerized** | 12 Docker services, one `docker compose up -d` |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SentinelOps Platform                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [CrowdStrike] [Wazuh] [Suricata]                               │
│         │                                                       │
│         ▼                                                       │
│   [Nginx :8080] ──► [FastAPI :8000]                             │
│                           │                                     │
│                ┌──────────▼──────────┐                          │
│                │   Apache Kafka      │  9 Topics, KRaft Mode    │
│                │   security.events.* │                          │
│                └──┬──────┬──────┬───┘                          │
│                   │      │      │                               │
│            ┌──────▼─┐ ┌──▼───┐ ┌▼────────┐                    │
│            │Normaliz│ │Enrich│ │ Storage │                     │
│            │  er    │ │  er  │ │ Worker  │──► PostgreSQL       │
│            └────────┘ └──────┘ └─────────┘    (pgvector)      │
│                                    │                            │
│                          ┌─────────▼──────────┐                │
│                          │    AI Worker        │                │
│                          │  moonshotai/kimi-k3 │◄── NVIDIA NIM  │
│                          │  ~70s deep reasoning│                │
│                          └─────────┬──────────┘                │
│                                    │                            │
│                       ai.analysis.results (Kafka)               │
│                                    │                            │
│                     ┌──────────────▼──────────────┐            │
│                     │    Remediation Worker        │            │
│                     │  BLOCK_IP / ESCALATE /       │            │
│                     │  AUTO_REMEDIATE / INVESTIGATE│            │
│                     └──────────────┬──────────────┘            │
│                                    │                            │
│                       notifications.outbound (Kafka)            │
│                                    │                            │
│                     ┌──────────────▼──────────────┐            │
│                     │   Notification Worker        │            │
│                     │  Console + Slack + DB        │            │
│                     └─────────────────────────────┘            │
│                                                                 │
│  [Redis :6380]  — Event deduplication                           │
│  [Kafka UI :8090] — Browse topics & messages                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

### Phase 2 — Foundation
- **FastAPI** REST backend with async PostgreSQL via `asyncpg`
- **PostgreSQL 15 + pgvector** for findings storage and semantic similarity search
- **Redis** for sub-millisecond event deduplication (10-min TTL)
- **Nginx** reverse proxy with rate limiting

### Phase 3 — Kafka Event Streaming
- **Apache Kafka** (KRaft mode, no Zookeeper) running on ARM64/Apple Silicon
- 9 Kafka topics: `security.events.raw`, `security.events.normalized`, `security.events.enriched`, `security.findings.stored`, `ai.analysis.results`, `ai.high.priority`, `remediation.tasks`, `notifications.outbound`, `dlq.failed.events`
- **Normalizer Worker** — parses multi-source events (CrowdStrike, Wazuh, Suricata, SentinelOne), computes SHA-256 fingerprint, deduplicates via Redis
- **Enrichment Worker** — IP reputation lookup, geolocation, asset criticality scoring
- **Storage Worker** — persists enriched findings to PostgreSQL with vector embeddings

### Phase 4 — AI Analysis Engine
- **AI Worker** powered by `moonshotai/kimi-k3` via NVIDIA NIM
- Deep reasoning model — ~70s per analysis, extremely high accuracy
- Outputs: `verdict`, `risk_score` (0-100), `confidence`, `action`, `mitre_techniques`, `summary`, `reasoning`
- Handles `reasoning_content` fallback for reasoning model response format
- Safe retry logic + JSON extraction from mixed reasoning/content responses

### Phase 5 — Auto-Remediation
| Playbook | Trigger | Action |
|---|---|---|
| `BLOCK_IP` | risk ≥ 60, TRUE_POSITIVE | Firewall block (iptables / cloud WAF) |
| `ESCALATE` | HIGH severity | Create P1 ticket (PagerDuty/Jira) |
| `AUTO_REMEDIATE` | risk ≥ 70 | Block + rotate credentials + ticket |
| `INVESTIGATE` | NEEDS_INVESTIGATION | Queue for analyst review |
| `IGNORE` | FALSE_POSITIVE | Safely dismiss |

### Phase 6 — Notifications
- **Console alerts** — beautifully formatted, always on
- **Slack webhook** — HIGH/CRITICAL events (set `SLACK_WEBHOOK_URL`)
- **PostgreSQL history** — full `notifications` table with audit trail

---

## 🚀 Quick Start

### Prerequisites
- Docker Desktop (4GB+ RAM)
- Docker Compose v2
- NVIDIA NIM API key ([get free at build.nvidia.com](https://build.nvidia.com))

### 1. Clone & Configure

```bash
git clone git@github.com:AssassinSaurabh/SentiOps.git
cd SentiOps/sentinelops
```

Edit `.env` and add your NVIDIA NIM API key:
```env
NVIDIA_API_KEY=nvapi-your-key-here
NVIDIA_MODEL=moonshotai/kimi-k3
AI_TIMEOUT_SECONDS=120
```

### 2. Start All 12 Services

```bash
docker compose up -d
```

Wait ~30s for Kafka to initialize, then verify:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

### 3. Inject Your First Security Event

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

### 4. Watch the Pipeline in Real Time

```bash
# Watch AI analysis
docker logs -f sentinelops-ai-worker

# Watch remediation
docker logs -f sentinelops-remediation-worker

# Watch notifications
docker logs -f sentinelops-notification-worker
```

After ~90 seconds you'll see:
```
🔴 SENTINELOPS SECURITY ALERT [HIGH]
============================================================
  Verdict:     TRUE_POSITIVE
  Risk Score:  95/100
  Source IP:   185.220.101.45
  Summary:     SSH brute force from known Tor exit node...
  Action:      🛡️  BLOCKED IP
============================================================
```

### 5. Query Results

```bash
# AI verdicts in PostgreSQL
docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -c \
  "SELECT title, ai_verdict, ai_risk_score, ai_action, remediated
   FROM findings ORDER BY created_at DESC LIMIT 5;"

# Notification history
docker exec sentinelops-postgres psql -U sentinelops -d sentinelops -c \
  "SELECT severity, verdict, action_taken, source_ip
   FROM notifications ORDER BY sent_at DESC LIMIT 5;"
```

---

## 🗂️ Project Structure

```
sentinelops/
├── docker-compose.yml          # 12 services
├── .env                        # Configuration
├── nginx/
│   └── nginx.conf              # Reverse proxy config
├── backend/
│   ├── main.py                 # FastAPI application
│   ├── models.py               # SQLAlchemy models
│   └── requirements.txt
├── workers/
│   ├── Dockerfile              # Shared Dockerfile for all workers
│   ├── requirements.txt        # Shared Python dependencies
│   ├── common/
│   │   ├── kafka_client.py     # Kafka producer/consumer factory
│   │   └── models.py           # Shared Pydantic models
│   ├── normalizer/
│   │   └── main.py             # Event parsing + deduplication
│   ├── enrichment/
│   │   └── main.py             # IP reputation + asset lookup
│   ├── storage/
│   │   └── main.py             # PostgreSQL persistence
│   ├── ai_worker/
│   │   └── main.py             # kimi-k3 AI threat analysis
│   ├── remediation_worker/
│   │   └── main.py             # Playbook execution
│   └── notification_worker/
│       └── main.py             # Alerts + Slack + DB
└── scripts/
    ├── test_phase3_pipeline.sh # 23 pipeline tests
    ├── test_phase4_ai.sh       # 10 AI engine tests
    ├── test_phase5_remediation.sh # 10 remediation tests
    └── test_phase6_notifications.sh # 8 notification tests
```

---

## 🧪 Running Tests

```bash
# Phase 3 — Kafka Pipeline (23 tests)
bash scripts/test_phase3_pipeline.sh

# Phase 4 — AI Engine (10 tests)
bash scripts/test_phase4_ai.sh

# Phase 5 — Auto-Remediation (10 tests)
bash scripts/test_phase5_remediation.sh

# Phase 6 — Notifications (8 tests)
bash scripts/test_phase6_notifications.sh
```

**Total: 51 automated tests — all passing ✅**

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health check |
| `GET` | `/api/v1/findings` | List all security findings |
| `GET` | `/api/v1/findings/{id}` | Get specific finding |
| `POST` | `/api/v1/events/simulate` | Inject a test security event |
| `GET` | `/api/v1/stats` | Platform statistics |

Base URL: `http://localhost:8080`

---

## ⚙️ Configuration

Key environment variables in `.env`:

```env
# Database
POSTGRES_PASSWORD=SentinelOps2024Secure
REDIS_PASSWORD=SentinelRedis2024

# AI Engine (NVIDIA NIM)
NVIDIA_API_KEY=nvapi-your-key-here
NVIDIA_MODEL=moonshotai/kimi-k3
AI_TIMEOUT_SECONDS=120
AI_MAX_TOKENS=1000

# Remediation thresholds
BLOCK_IP_THRESHOLD=60       # Min risk score to block an IP
AUTO_REMEDIATE_THRESHOLD=70 # Min risk score to auto-remediate

# Notifications (optional)
SLACK_WEBHOOK_URL=          # Set to enable Slack alerts
```

---

## 🔔 Enable Slack Notifications

1. Go to [api.slack.com/apps](https://api.slack.com/apps)
2. Create App → Incoming Webhooks → Activate
3. Copy the webhook URL
4. Set in `docker-compose.yml`:
   ```yaml
   notification-worker:
     environment:
       SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/YOUR/URL"
   ```
5. Restart: `docker compose up -d notification-worker`

---

## 🖥️ Port Reference

| Service | Host Port | Purpose |
|---|---|---|
| Nginx | `8080` | API gateway (use this) |
| FastAPI | `8000` | Direct backend access |
| PostgreSQL | `5433` | Database |
| Redis | `6380` | Cache |
| Kafka | `9092` | Event streaming |
| Kafka UI | `8090` | Visual topic browser |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| API Gateway | Nginx |
| Backend | FastAPI + Python 3.11 |
| Database | PostgreSQL 15 + pgvector |
| Cache | Redis 7 |
| Streaming | Apache Kafka 7.6 (KRaft) |
| AI | moonshotai/kimi-k3 via NVIDIA NIM |
| Containers | Docker + Docker Compose v2 |
| Workers | Python (structlog, psycopg2, confluent-kafka) |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built with ❤️ — AI-powered security for the modern SOC
</div>
