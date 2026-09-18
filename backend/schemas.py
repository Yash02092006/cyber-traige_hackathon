"""
Pydantic Validation and Serialization Schemas.
SIH1744 • SIH 2024
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict


# ==============================================================================
# Case Schemas
# ==============================================================================
class CaseBase(BaseModel):
    case_number: str = Field(..., example="INC-2024-0918")
    name: str = Field(..., example="Project Blackout - Financial Workstation Triage")
    description: Optional[str] = Field(None, example="SIMULATION DATA • Comprehensive digital forensics investigation.")
    status: Optional[str] = Field("ACTIVE_INVESTIGATION", example="ACTIVE_INVESTIGATION")


class CaseCreate(CaseBase):
    pass


class CaseUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None


class CaseResponse(CaseBase):
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# Evidence Schemas
# ==============================================================================
class EvidenceBase(BaseModel):
    filename: str
    original_path: Optional[str] = None
    evidence_type: str = "File"
    size: Optional[str] = "0 B"
    sha256: Optional[str] = None
    md5: Optional[str] = None
    mime_type: Optional[str] = "application/octet-stream"
    source: Optional[str] = None
    collected_at: Optional[datetime] = None
    status: Optional[str] = "Flagged"
    risk_score: Optional[int] = 0
    risk_tier: Optional[str] = "LOW"
    description: Optional[str] = None
    mitre_attack: Optional[str] = None
    parent_process: Optional[str] = None
    user: Optional[str] = None
    command_line: Optional[str] = None
    destination_ip: Optional[str] = None
    is_malicious_hash: Optional[bool] = False
    recently_downloaded: Optional[bool] = False


class EvidenceCreate(EvidenceBase):
    id: Optional[str] = None
    case_id: int = 1
    risk_reasons: Optional[Union[str, List[Dict[str, Any]]]] = None
    related_evidence_ids: Optional[Union[str, List[str]]] = None
    related_iocs: Optional[Union[str, List[str]]] = None


class EvidenceResponse(BaseModel):
    id: str
    case_id: int
    filename: str
    name: Optional[str] = None  # Frontend convenience alias
    original_path: Optional[str] = None
    evidence_type: str
    type: Optional[str] = None  # Frontend convenience alias
    size: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    mime_type: Optional[str] = None
    source: Optional[str] = None
    collected_at: Optional[datetime] = None
    timestamp: Optional[str] = None  # Frontend convenience alias
    status: Optional[str] = None
    risk_score: int = 0
    risk_tier: str = "LOW"
    risk_reasons: Optional[List[Dict[str, Any]]] = None
    description: Optional[str] = None
    mitre_attack: Optional[str] = None
    parent_process: Optional[str] = None
    user: Optional[str] = None
    command_line: Optional[str] = None
    destination_ip: Optional[str] = None
    is_malicious_hash: bool = False
    recently_downloaded: bool = False
    related_evidence_ids: Optional[List[str]] = None
    related_iocs: Optional[List[str]] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# IOC Schemas
# ==============================================================================
class IOCBase(BaseModel):
    ioc_type: str
    value: str
    confidence: Optional[int] = 80
    source: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    status: Optional[str] = None
    risk: Optional[str] = "MEDIUM"
    asn: Optional[str] = "N/A"
    country: Optional[str] = "N/A"
    occurrences: Optional[int] = 1


class IOCResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: Optional[str] = None
    ioc_type: str
    type: Optional[str] = None  # Frontend convenience alias
    value: str
    ioc: Optional[str] = None  # Frontend convenience alias
    confidence: int = 80
    source: Optional[str] = None
    first_seen: Optional[str] = None
    firstSeen: Optional[str] = None  # Frontend convenience alias
    last_seen: Optional[str] = None
    lastSeen: Optional[str] = None  # Frontend convenience alias
    status: Optional[str] = None
    risk: Optional[str] = "MEDIUM"
    asn: Optional[str] = "N/A"
    country: Optional[str] = "N/A"
    occurrences: int = 1
    related_evidence_ids: Optional[List[str]] = None

    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# Event / Timeline Schemas
# ==============================================================================
class EventResponse(BaseModel):
    id: str
    case_id: int
    evidence_id: Optional[str] = None
    relatedEvidenceId: Optional[str] = None  # Frontend convenience alias
    timestamp: str
    time: Optional[str] = None
    date: Optional[str] = None
    event_type: str
    eventType: Optional[str] = None  # Frontend convenience alias
    title: str
    description: Optional[str] = None
    source: Optional[str] = None
    process: Optional[str] = None
    user: Optional[str] = None
    risk_score: int = 0
    severity: str = "LOW"
    mitre: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# Graph Schemas
# ==============================================================================
class GraphNode(BaseModel):
    id: str
    label: str
    category: str
    risk: Optional[str] = "LOW"
    details: Optional[str] = ""


class GraphLink(BaseModel):
    source: str
    target: str
    label: str
    type: Optional[str] = "associated"


class GraphResponse(BaseModel):
    nodes: List[GraphNode]
    links: List[GraphLink]
    edges: List[GraphLink]  # Backward compatibility alias


# ==============================================================================
# Dashboard Telemetry Schemas
# ==============================================================================
class DashboardStatisticsResponse(BaseModel):
    case_id: int
    case_number: str
    case_name: str
    total_evidence: int
    critical_findings: int
    high_risk_evidence: int
    suspicious_evidence: int
    total_iocs: int
    total_events: int
    risk_distribution: Dict[str, int]
    type_distribution: Dict[str, int]
    mitre_coverage: List[str]
    recent_events: List[EventResponse]
    priority_watchlist: List[EvidenceResponse]


# ==============================================================================
# Report Schemas
# ==============================================================================
class ReportCreate(BaseModel):
    title: str
    summary: Optional[str] = None
    content: Optional[Dict[str, Any]] = None


class ReportResponse(BaseModel):
    id: int
    case_id: int
    title: str
    summary: Optional[str] = None
    generated_at: Optional[datetime] = None
    content: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)
