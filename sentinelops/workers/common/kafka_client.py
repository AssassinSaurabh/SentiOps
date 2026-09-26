# workers/common/kafka_client.py
# Purpose: Reusable Kafka producer and consumer factory functions
# All workers import from here — consistent configuration across the platform

import json
import os
from typing import Any, Dict, List

from confluent_kafka import Producer, Consumer, KafkaException
import structlog

logger = structlog.get_logger(__name__)

# Read Kafka address from environment variable
# Default: "kafka:9092" (works inside Docker network)
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")


def create_producer() -> Producer:
    """
    Create a Kafka producer.
    A producer WRITES messages to Kafka topics.
    """
    return Producer({
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        # bootstrap.servers = the Kafka broker address(es) to connect to

        "client.id": f"sentinelops-producer-{os.getpid()}",
        # client.id = a name for this producer (appears in Kafka logs)
        # os.getpid() = current process ID (makes it unique per process)

        "acks": "all",
        # acks = acknowledgement mode
        # "all" = wait until ALL replicas confirm message is written
        # Slowest but safest (no data loss)
        # In dev with 1 broker, "all" == "1" == same thing

        "retries": 3,
        # If a send fails, retry up to 3 times

        "retry.backoff.ms": 1000,
        # Wait 1000ms (1 second) between retries

        "compression.type": "snappy",
        # Compress messages with Snappy algorithm
        # Reduces network traffic by ~50-70%
        # Snappy = fast compression (good for high-throughput systems)

        "linger.ms": 5,
        # Wait up to 5ms for more messages before sending a batch
        # Allows batching of multiple messages into one network request
        # Tradeoff: slight latency increase for much better throughput
    })


def create_consumer(
    group_id: str,
    topics: List[str],
    auto_offset_reset: str = "earliest"
) -> Consumer:
    """
    Create a Kafka consumer.
    A consumer READS messages from Kafka topics.

    group_id: Consumer group name. Workers in the same group share the work.
    topics:   List of topic names to subscribe to.
    auto_offset_reset: Where to start reading.
        "earliest" = read from the very beginning (good for workers)
        "latest"   = only read new messages (good for dashboards)
    """
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,

        "group.id": group_id,
        # group.id = the consumer group name
        # All workers with the same group.id share partitions
        # Each partition goes to exactly ONE consumer in the group

        "auto.offset.reset": auto_offset_reset,
        # Where to start if this consumer has no committed offset yet

        "enable.auto.commit": False,
        # CRITICAL: We commit offsets MANUALLY after successful processing
        # auto.commit = True would mark messages as "done" BEFORE processing
        # If the worker crashes, those messages would be LOST
        # Manual commit = at-least-once delivery guarantee

        "max.poll.interval.ms": 300000,
        # Max time (5 min) between poll() calls before Kafka assumes consumer is dead
        # Important for slow processing tasks

        "session.timeout.ms": 30000,
        # If no heartbeat in 30s, consumer is considered dead
        # Kafka will reassign its partitions to other consumers

        "heartbeat.interval.ms": 3000,
        # Send heartbeat to Kafka every 3 seconds
        # Must be less than session.timeout.ms / 3
    })

    consumer.subscribe(topics)
    # subscribe() = register interest in these topics
    # Kafka will assign specific partitions to this consumer

    return consumer


def produce_message(
    producer: Producer,
    topic: str,
    message: Dict[str, Any],
    key: str = None
) -> None:
    """
    Send one message to a Kafka topic.

    topic:   Which topic to send to
    message: Python dict (will be JSON-serialized)
    key:     Optional message key (determines which partition it goes to)
             Same key = same partition = ordering preserved for that key
             Using source_ip as key: all events from same IP go to same partition
    """
    def delivery_callback(err, msg):
        # This function is called AFTER Kafka confirms the message was stored
        if err:
            logger.error(
                "kafka_produce_failed",
                topic=topic,
                error=str(err)
            )
        # Success case: we don't log here to avoid noise (high volume)

    json_message = json.dumps(message, default=str)
    # json.dumps = convert Python dict to JSON string
    # default=str = if any value can't be serialized (like datetime), use str()

    producer.produce(
        topic=topic,
        value=json_message.encode("utf-8"),
        key=key.encode("utf-8") if key else None,
        callback=delivery_callback,
    )

    producer.poll(0)
    # poll(0) = check for delivery callbacks (non-blocking)
    # Without this, callbacks may never fire
