# ─────────────────────────────────────────────────────────────
# app/models/finding.py
# Purpose: SQLAlchemy model for the findings table
# ─────────────────────────────────────────────────────────────

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Enum as SQLEnum,
    String, Text, func
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
# postgresql-specific types:
# UUID  → PostgreSQL native UUID type
# INET  → PostgreSQL IP address type (validates format)
# JSONB → Binary JSON (compressed, queryable)

from pgvector.sqlalchemy import Vector
# Vector → pgvector's SQLAlchemy column type for vector embeddings

from app.database import Base
# Base → our DeclarativeBase from database.py


class Finding(Base):
    # Finding class maps to the 'findings' table
    # Every attribute = a column in the table
    
    __tablename__ = "findings"
    # __tablename__ = the actual SQL table name
    
    id = Column(
        UUID(as_uuid=True),
        # UUID type. as_uuid=True = Python gets uuid.UUID object (not string)
        primary_key=True,
        # PRIMARY KEY = unique identifier for each row
        default=uuid.uuid4,
        # default = call uuid.uuid4() to generate new UUID for each row
    )
    
    title = Column(String(500), nullable=False)
    # String(500) = VARCHAR(500)
    # nullable=False = this column cannot be NULL (required)
    
    description = Column(Text, nullable=True)
    # Text = unlimited length
    # nullable=True = this column CAN be NULL (optional)
    
    severity = Column(
        SQLEnum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
                name="severity_level"),
        # SQLEnum = maps to our PostgreSQL enum type
        # name="severity_level" = must match the enum name in init.sql
        nullable=False,
        default="MEDIUM",
    )
    
    source = Column(String(100), nullable=False)
    # Examples: 'wazuh', 'suricata', 'openvas'
    
    event_type = Column(String(200), nullable=True)
    
    source_ip = Column(INET, nullable=True)
    # PostgreSQL validates this is a real IP address format
    
    target_host = Column(String(255), nullable=True)
    
    raw_event = Column(JSONB, nullable=True)
    # Store the original event as JSON
    
    enrichment_data = Column(JSONB, nullable=True)
    # IP geo, threat intel, asset info added by enrichment worker
    
    remediated = Column(Boolean, default=False, nullable=False)
    
    remediation_details = Column(JSONB, nullable=True)
    
    embedding = Column(Vector(768), nullable=True)
    # 768-dimensional vector for AI similarity search
    # Will be populated in Phase 5 (AI layer)
    
    created_at = Column(
        DateTime(timezone=True),
        # timezone=True = store with timezone info (UTC)
        server_default=func.now(),
        # server_default = database generates the default (not Python)
        # func.now() = call PostgreSQL's NOW() function
        nullable=False,
    )
    
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        # onupdate = when row is updated, automatically set to now()
        nullable=False,
    )
    
    def to_dict(self) -> dict:
        # Helper method: convert this object to a Python dict
        # Useful for returning in API responses and storing in Redis cache
        return {
            "id": str(self.id),
            # Convert UUID object to string for JSON serialization
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "event_type": self.event_type,
            "source_ip": str(self.source_ip) if self.source_ip else None,
            "target_host": self.target_host,
            "raw_event": self.raw_event,
            "enrichment_data": self.enrichment_data,
            "remediated": self.remediated,
            "remediation_details": self.remediation_details,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            # isoformat() = "2026-07-07T21:55:05+00:00" (standard date format)
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
    
    def __repr__(self) -> str:
        # __repr__ = how Python displays this object in terminal/logs
        return f"<Finding id={self.id} severity={self.severity} title={self.title!r}>"
