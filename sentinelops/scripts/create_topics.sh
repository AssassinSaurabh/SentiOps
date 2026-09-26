#!/bin/bash
# scripts/create_topics.sh
# Purpose: Create all Kafka topics for SentinelOps
# Run this ONCE after Kafka starts for the first time.
# Safe to run multiple times (--if-not-exists flag)

set -e

BOOTSTRAP="localhost:9092"
# Bitnami kafka: scripts are on PATH directly (no full path needed)

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  SentinelOps — Creating Kafka Topics         ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

KAFKA_TOPICS_CMD="kafka-topics"
if ! command -v kafka-topics &> /dev/null; then
    if command -v kafka-topics.sh &> /dev/null; then
        KAFKA_TOPICS_CMD="kafka-topics.sh"
    elif [ -f /opt/kafka/bin/kafka-topics.sh ]; then
        KAFKA_TOPICS_CMD="/opt/kafka/bin/kafka-topics.sh"
    elif [ -f /usr/bin/kafka-topics ]; then
        KAFKA_TOPICS_CMD="/usr/bin/kafka-topics"
    fi
fi

# Helper function: creates a topic if it doesn't exist
# Arguments: topic_name  partitions  retention_ms
create_topic() {
    local name=$1
    local partitions=$2
    local retention_ms=$3

    echo "  → Creating: $name"
    $KAFKA_TOPICS_CMD \
        --create \
        --if-not-exists \
        --bootstrap-server $BOOTSTRAP \
        --topic "$name" \
        --partitions $partitions \
        --replication-factor 1 \
        --config retention.ms=$retention_ms \
        > /dev/null 2>&1 && echo "    ✓ Done" || echo "    ✓ Already exists"
}

# 604800000  ms = 7 days
# 259200000  ms = 3 days
# 2592000000 ms = 30 days
# 86400000   ms = 1 day

echo "Creating pipeline topics..."
create_topic "security.events.raw"        3  604800000
create_topic "security.events.normalized" 3  259200000
create_topic "security.events.enriched"   3  259200000
create_topic "security.findings"          3  2592000000

echo ""
echo "Creating operational topics..."
create_topic "remediation.tasks"          1  604800000
create_topic "notifications.outbound"     1  86400000

echo ""
echo "══════════════════════════════════════════════"
echo "All topics:"
$KAFKA_TOPICS_CMD \
    --list \
    --bootstrap-server $BOOTSTRAP
echo ""
echo "✅ Topics created successfully!"
echo ""
