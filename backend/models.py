"""
SQLAlchemy ORM Models for Cyber Triage Tool Database.
SIH1744 • SIH 2024
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from backend.database import Base


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_number = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), default="ACTIVE_INVESTIGATION")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    evidence = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="case", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="case", cascade="all, delete-orphan")
    entities = relationship("Entity", back_populates="case", cascade="all, delete-orphan")
    relationships = relationship("Relationship", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="case", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(50), primary_key=True, index=True)  # E.g. "EVD-1001"
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False)
    filename = Column(String(255), nullable=False)
    original_path = Column(Text, nullable=True)
    evidence_type = Column(String(50), nullable=False)  # File, Process, Network, Browser, System, User
    size = Column(String(50), nullable=True)
    sha256 = Column(String(64), index=True, nullable=True)
    md5 = Column(String(32), nullable=True)
    mime_type = Column(String(100), nullable=True)
    source = Column(Text, nullable=True)
    collected_at = Column(DateTime, nullable=True)
    status = Column(String(50), default="Flagged")
    risk_score = Column(Integer, default=0)
    risk_tier = Column(String(20), default="LOW")
    risk_reasons = Column(Text, nullable=True)  # Stored as JSON string
    description = Column(Text, nullable=True)
    mitre_attack = Column(String(100), nullable=True)
    parent_process = Column(String(100), nullable=True)
    user = Column(String(100), nullable=True)
    command_line = Column(Text, nullable=True)
    destination_ip = Column(String(50), nullable=True)
    is_malicious_hash = Column(Boolean, default=False)
    recently_downloaded = Column(Boolean, default=False)
    related_evidence_ids = Column(Text, nullable=True)  # Stored as JSON string list
    related_iocs = Column(Text, nullable=True)  # Stored as JSON string list
    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("Case", back_populates="evidence")

    __table_args__ = (
        Index("ix_evidence_case_risk", "case_id", "risk_score"),
        Index("ix_evidence_type", "evidence_type"),
    )


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False)
    evidence_id = Column(String(50), nullable=True)
    ioc_type = Column(String(50), nullable=False)  # IP, Domain, URL, File Hash (SHA-256), Process, etc.
    value = Column(String(255), index=True, nullable=False)
    confidence = Column(Integer, default=80)
    source = Column(String(255), nullable=True)
    first_seen = Column(String(50), nullable=True)
    last_seen = Column(String(50), nullable=True)
    status = Column(String(50), nullable=True)
    risk = Column(String(20), default="MEDIUM")
    asn = Column(String(50), nullable=True)
    country = Column(String(10), nullable=True)
    occurrences = Column(Integer, default=1)
    related_evidence_ids = Column(Text, nullable=True)  # Stored as JSON string list

    case = relationship("Case", back_populates="iocs")

    __table_args__ = (
        Index("ix_iocs_case_type", "case_id", "ioc_type"),
    )


class Event(Base):
    __tablename__ = "events"

    id = Column(String(50), primary_key=True, index=True)  # E.g. "TL-01"
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False)
    evidence_id = Column(String(50), nullable=True)
    timestamp = Column(String(50), index=True, nullable=False)
    time = Column(String(20), nullable=True)
    date = Column(String(20), nullable=True)
    event_type = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source = Column(String(255), nullable=True)
    process = Column(String(255), nullable=True)
    user = Column(String(100), nullable=True)
    risk_score = Column(Integer, default=0)
    severity = Column(String(20), default="LOW")
    mitre = Column(String(50), nullable=True)

    case = relationship("Case", back_populates="events")

    __table_args__ = (
        Index("ix_events_case_timestamp", "case_id", "timestamp"),
        Index("ix_events_severity", "severity"),
    )


class Entity(Base):
    __tablename__ = "entities"

    id = Column(String(50), primary_key=True, index=True)  # E.g. "user_jdoe"
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False)
    entity_type = Column(String(50), nullable=True)
    value = Column(String(255), nullable=True)
    label = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False)  # User, Process, File, Network, Domain, System
    risk = Column(String(20), default="LOW")
    details = Column(Text, nullable=True)

    case = relationship("Case", back_populates="entities")


class Relationship(Base):
    __tablename__ = "relationships"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False)
    source_entity_id = Column(String(50), ForeignKey("entities.id", ondelete="CASCADE"), index=True, nullable=False)
    target_entity_id = Column(String(50), ForeignKey("entities.id", ondelete="CASCADE"), index=True, nullable=False)
    relationship_type = Column(String(50), nullable=True)
    label = Column(String(50), nullable=False)
    confidence = Column(Integer, default=100)

    case = relationship("Case", back_populates="relationships")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=True)
    generated_at = Column(DateTime, default=datetime.utcnow)
    content = Column(Text, nullable=True)  # Stored as JSON string

    case = relationship("Case", back_populates="reports")
