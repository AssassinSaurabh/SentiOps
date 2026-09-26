-- This file runs automatically when PostgreSQL starts for the first time

-- ─────────────────────────────────────────────────
-- Create the pgvector extension for AI/RAG features
-- (We install it now, use it in Phase 5)
-- ─────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS vector;
-- IF NOT EXISTS = don't error if it already exists
-- vector = pgvector extension for storing AI embeddings

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- uuid-ossp = lets us generate UUID (unique IDs) with uuid_generate_v4()

-- ─────────────────────────────────────────────────
-- Create the severity enum type
-- Enum = a fixed list of allowed values
-- ─────────────────────────────────────────────────
CREATE TYPE severity_level AS ENUM (
    'CRITICAL',
    'HIGH',
    'MEDIUM',
    'LOW',
    'INFO'
);
-- Why enum? Prevents storing "CRITCAL" (typo) or "critical" (wrong case)
-- Database enforces the allowed values

-- ─────────────────────────────────────────────────
-- Create the findings table
-- ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    -- id: unique identifier for every finding
    -- UUID is better than integer because:
    -- → No sequential guessing (attacker can't try id=1,2,3)
    -- → Safe to use in public URLs
    -- → Works across distributed systems
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- title: short human-readable name
    title VARCHAR(500) NOT NULL,
    -- VARCHAR(500) = text, max 500 characters
    -- NOT NULL = this field is required (can never be empty)

    -- description: detailed LLM-generated explanation
    description TEXT,
    -- TEXT = unlimited length text (for long LLM outputs)
    -- No NOT NULL = it's okay to be empty initially

    -- severity: must be one of our enum values
    severity severity_level NOT NULL DEFAULT 'MEDIUM',
    -- DEFAULT 'MEDIUM' = if not specified, use MEDIUM

    -- source: which tool detected this
    source VARCHAR(100) NOT NULL,
    -- Examples: 'wazuh', 'suricata', 'openvas', 'zeek'

    -- event_type: category of the security event
    event_type VARCHAR(200),
    -- Examples: 'brute_force_ssh', 'privilege_escalation', 'malware_detected'

    -- source_ip: attacker's IP address
    source_ip INET,
    -- INET = PostgreSQL's special type for IP addresses (validates format)

    -- target_host: which server was attacked
    target_host VARCHAR(255),

    -- raw_event: the original unmodified data (JSON)
    raw_event JSONB,
    -- JSONB = binary JSON. Stored compressed. Can be queried.
    -- Example: WHERE raw_event->>'protocol' = 'SSH'

    -- enrichment_data: what our enrichment worker added
    enrichment_data JSONB,
    -- IP geolocation, threat intel, asset info

    -- remediated: has this been fixed?
    remediated BOOLEAN DEFAULT FALSE,

    -- remediation_details: what we did to fix it
    remediation_details JSONB,

    -- embedding: vector for AI similarity search (Phase 5)
    -- vector(1536) = 1536-dimensional vector (OpenAI/nomic-embed size)
    embedding vector(768),
    -- 768 dimensions = nomic-embed-text model output size

    -- Timestamps: when was this created and last updated
    created_at TIMESTAMPTZ DEFAULT NOW(),
    -- TIMESTAMPTZ = timestamp WITH timezone (always store UTC)
    -- DEFAULT NOW() = automatically set to current time

    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────
-- Create indexes for fast querying
-- ─────────────────────────────────────────────────

-- Index on severity: we often filter by severity
CREATE INDEX idx_findings_severity ON findings(severity);
-- Without index: "SELECT * WHERE severity='CRITICAL'" scans ALL rows
-- With index: instantly jumps to CRITICAL rows

-- Index on created_at: we often sort by time
CREATE INDEX idx_findings_created_at ON findings(created_at DESC);

-- Index on source_ip: security queries often filter by IP
CREATE INDEX idx_findings_source_ip ON findings(source_ip);

-- Index on remediated: common filter "show me unfixed findings"
CREATE INDEX idx_findings_remediated ON findings(remediated);

-- Vector index for AI similarity search (Phase 5)
-- ivfflat = Inverted File Flat index for vectors
-- lists=100 = number of clusters (tune based on data size)
CREATE INDEX idx_findings_embedding ON findings
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- ─────────────────────────────────────────────────
-- Create audit_logs table (every action is logged)
-- This is non-negotiable for compliance (SOC2, ISO27001)
-- ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action VARCHAR(100) NOT NULL,
    -- Examples: 'finding_created', 'finding_remediated', 'user_login'

    actor VARCHAR(255),
    -- Who did this? 'system', 'user:john@company.com', 'ansible-worker'

    resource_type VARCHAR(100),
    -- What type of thing was acted on? 'finding', 'user', 'playbook'

    resource_id UUID,
    -- Which specific thing? The finding's UUID

    details JSONB,
    -- Any extra context

    ip_address INET,
    -- Where did this action come from?

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor);

-- ─────────────────────────────────────────────────
-- Auto-update updated_at timestamp
-- ─────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    -- NEW refers to the row being updated
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';
-- This is a PostgreSQL function (like a stored procedure)
-- It runs automatically whenever a row is updated

CREATE TRIGGER update_findings_updated_at
    BEFORE UPDATE ON findings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
-- TRIGGER = runs the function automatically BEFORE every UPDATE
-- FOR EACH ROW = runs once per updated row

-- ─────────────────────────────────────────────────
-- Insert a test finding to verify setup works
-- ─────────────────────────────────────────────────
INSERT INTO findings (title, description, severity, source, event_type, source_ip, target_host)
VALUES (
    'SSH Brute Force Test',
    'Test finding created during database initialization',
    'HIGH',
    'system',
    'brute_force_ssh',
    '192.168.1.100',
    'test-server-01'
);
