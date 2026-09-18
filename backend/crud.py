"""
Database Access Layer (CRUD) for Cyber Triage Tool.
SIH1744 • SIH 2024
"""

import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc, asc

from backend import models, schemas
from backend.services.timeline_engine import sort_events_chronologically


# ==============================================================================
# Helper Serialization Functions
# ==============================================================================
def serialize_evidence(e: models.Evidence) -> Dict[str, Any]:
    reasons = json.loads(e.risk_reasons) if e.risk_reasons else []
    related_ev = json.loads(e.related_evidence_ids) if e.related_evidence_ids else []
    related_ioc = json.loads(e.related_iocs) if e.related_iocs else []

    ts_str = e.collected_at.strftime("%Y-%m-%d %H:%M:%S") if e.collected_at else (e.created_at.strftime("%Y-%m-%d %H:%M:%S") if e.created_at else "")

    return {
        "id": e.id,
        "case_id": e.case_id,
        "filename": e.filename,
        "name": e.filename,  # UI compatibility
        "original_path": e.original_path,
        "evidence_type": e.evidence_type,
        "type": e.evidence_type,  # UI compatibility
        "size": e.size or "0 B",
        "sha256": e.sha256,
        "md5": e.md5,
        "mime_type": e.mime_type,
        "source": e.source or e.original_path or "N/A",
        "collected_at": e.collected_at,
        "timestamp": ts_str,  # UI compatibility
        "status": e.status,
        "risk_score": e.risk_score,
        "risk_tier": e.risk_tier,
        "riskScore": e.risk_score,  # UI compatibility
        "riskTier": e.risk_tier,  # UI compatibility
        "risk_reasons": reasons,
        "riskReasons": reasons,  # UI compatibility
        "description": e.description or "",
        "mitre_attack": e.mitre_attack,
        "mitreAttack": e.mitre_attack,  # UI compatibility
        "parent_process": e.parent_process,
        "parentProcess": e.parent_process,  # UI compatibility
        "user": e.user or "N/A",
        "command_line": e.command_line,
        "commandLine": e.command_line,  # UI compatibility
        "destination_ip": e.destination_ip,
        "destinationIp": e.destination_ip,  # UI compatibility
        "is_malicious_hash": e.is_malicious_hash,
        "recently_downloaded": e.recently_downloaded,
        "related_evidence_ids": related_ev,
        "relatedEvidenceIds": related_ev,  # UI compatibility
        "related_iocs": related_ioc,
        "relatedIocs": related_ioc,  # UI compatibility
        "created_at": e.created_at
    }


def serialize_ioc(i: models.IOC) -> Dict[str, Any]:
    rel = json.loads(i.related_evidence_ids) if i.related_evidence_ids else []
    return {
        "id": i.id,
        "case_id": i.case_id,
        "evidence_id": i.evidence_id,
        "ioc_type": i.ioc_type,
        "type": i.ioc_type,  # UI compatibility
        "value": i.value,
        "ioc": i.value,  # UI compatibility
        "confidence": i.confidence,
        "source": i.source or "N/A",
        "first_seen": i.first_seen,
        "firstSeen": i.first_seen,  # UI compatibility
        "last_seen": i.last_seen,
        "lastSeen": i.last_seen,  # UI compatibility
        "status": i.status or "Identified",
        "risk": i.risk,
        "asn": i.asn or "N/A",
        "country": i.country or "N/A",
        "occurrences": i.occurrences,
        "related_evidence_ids": rel,
        "relatedEvidenceIds": rel  # UI compatibility
    }


def serialize_event(ev: models.Event) -> Dict[str, Any]:
    return {
        "id": ev.id,
        "case_id": ev.case_id,
        "evidence_id": ev.evidence_id,
        "relatedEvidenceId": ev.evidence_id,  # UI compatibility
        "timestamp": ev.timestamp,
        "time": ev.time or (ev.timestamp.split(" ")[1] if " " in ev.timestamp else ev.timestamp),
        "date": ev.date or (ev.timestamp.split(" ")[0] if " " in ev.timestamp else ""),
        "event_type": ev.event_type,
        "eventType": ev.event_type,  # UI compatibility
        "title": ev.title,
        "description": ev.description,
        "source": ev.source,
        "process": ev.process,
        "user": ev.user,
        "risk_score": ev.risk_score,
        "severity": ev.severity,
        "mitre": ev.mitre
    }


# ==============================================================================
# Cases CRUD
# ==============================================================================
def get_cases(db: Session, skip: int = 0, limit: int = 50) -> List[models.Case]:
    return db.query(models.Case).offset(skip).limit(limit).all()


def get_case(db: Session, case_id: int) -> Optional[models.Case]:
    return db.query(models.Case).filter(models.Case.id == case_id).first()


def get_case_by_number(db: Session, case_number: str) -> Optional[models.Case]:
    return db.query(models.Case).filter(models.Case.case_number == case_number).first()


def create_case(db: Session, case_in: schemas.CaseCreate) -> models.Case:
    db_case = models.Case(
        case_number=case_in.case_number,
        name=case_in.name,
        description=case_in.description,
        status=case_in.status or "ACTIVE_INVESTIGATION"
    )
    db.add(db_case)
    db.commit()
    db.refresh(db_case)
    return db_case


def update_case(db: Session, case_id: int, case_in: schemas.CaseUpdate) -> Optional[models.Case]:
    db_case = get_case(db, case_id)
    if not db_case:
        return None
    if case_in.name is not None:
        db_case.name = case_in.name
    if case_in.description is not None:
        db_case.description = case_in.description
    if case_in.status is not None:
        db_case.status = case_in.status
    db_case.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_case)
    return db_case


# ==============================================================================
# Evidence CRUD
# ==============================================================================
def get_evidence_list(
    db: Session,
    case_id: Optional[int] = None,
    evidence_type: Optional[str] = None,
    risk: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: Optional[str] = "risk-desc",
    skip: int = 0,
    limit: int = 200
) -> List[Dict[str, Any]]:
    query = db.query(models.Evidence)

    if case_id:
        query = query.filter(models.Evidence.case_id == case_id)

    if evidence_type and evidence_type.upper() != "ALL":
        query = query.filter(models.Evidence.evidence_type == evidence_type)

    if risk and risk.upper() != "ALL":
        query = query.filter(models.Evidence.risk_tier == risk.upper())

    if status and status.upper() != "ALL":
        query = query.filter(models.Evidence.status == status)

    if search:
        s = f"%{search.lower()}%"
        query = query.filter(
            or_(
                models.Evidence.id.ilike(s),
                models.Evidence.filename.ilike(s),
                models.Evidence.source.ilike(s),
                models.Evidence.description.ilike(s),
                models.Evidence.sha256.ilike(s),
                models.Evidence.user.ilike(s),
                models.Evidence.mitre_attack.ilike(s)
            )
        )

    # Sorting
    if sort_by == "risk-desc":
        query = query.order_by(desc(models.Evidence.risk_score))
    elif sort_by == "risk-asc":
        query = query.order_by(asc(models.Evidence.risk_score))
    elif sort_by == "time-desc":
        query = query.order_by(desc(models.Evidence.collected_at), desc(models.Evidence.created_at))
    elif sort_by == "time-asc":
        query = query.order_by(asc(models.Evidence.collected_at), asc(models.Evidence.created_at))
    elif sort_by == "id-asc":
        query = query.order_by(asc(models.Evidence.id))
    elif sort_by == "name-asc":
        query = query.order_by(asc(models.Evidence.filename))
    else:
        query = query.order_by(desc(models.Evidence.risk_score))

    items = query.offset(skip).limit(limit).all()
    return [serialize_evidence(item) for item in items]


def get_evidence_by_id(db: Session, evidence_id: str) -> Optional[Dict[str, Any]]:
    item = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    return serialize_evidence(item) if item else None


def create_evidence(db: Session, ev_dict: Dict[str, Any]) -> Dict[str, Any]:
    # Check if custom ID passed or generate one
    ev_id = ev_dict.get("id")
    if not ev_id:
        total = db.query(models.Evidence).count()
        ev_id = f"EVD-{1000 + total + 1}"

    reasons_json = json.dumps(ev_dict.get("risk_reasons") or ev_dict.get("riskReasons") or [])
    related_ev_json = json.dumps(ev_dict.get("related_evidence_ids") or ev_dict.get("relatedEvidenceIds") or [])
    related_ioc_json = json.dumps(ev_dict.get("related_iocs") or ev_dict.get("relatedIocs") or [])

    db_ev = models.Evidence(
        id=ev_id,
        case_id=ev_dict.get("case_id", 1),
        filename=ev_dict.get("filename") or ev_dict.get("name") or "untitled_evidence",
        original_path=ev_dict.get("original_path") or ev_dict.get("source"),
        evidence_type=ev_dict.get("evidence_type") or ev_dict.get("type") or "File",
        size=ev_dict.get("size") or "0 B",
        sha256=ev_dict.get("sha256"),
        md5=ev_dict.get("md5"),
        mime_type=ev_dict.get("mime_type") or "application/octet-stream",
        source=ev_dict.get("source") or ev_dict.get("original_path") or "Local Ingestion",
        collected_at=ev_dict.get("collected_at") or datetime.utcnow(),
        status=ev_dict.get("status") or "Flagged",
        risk_score=ev_dict.get("risk_score") or ev_dict.get("riskScore") or 0,
        risk_tier=ev_dict.get("risk_tier") or ev_dict.get("riskTier") or "LOW",
        risk_reasons=reasons_json,
        description=ev_dict.get("description") or "",
        mitre_attack=ev_dict.get("mitre_attack") or ev_dict.get("mitreAttack"),
        parent_process=ev_dict.get("parent_process") or ev_dict.get("parentProcess"),
        user=ev_dict.get("user") or "N/A",
        command_line=ev_dict.get("command_line") or ev_dict.get("commandLine"),
        destination_ip=ev_dict.get("destination_ip") or ev_dict.get("destinationIp"),
        is_malicious_hash=bool(ev_dict.get("is_malicious_hash") or ev_dict.get("isMaliciousHash")),
        recently_downloaded=bool(ev_dict.get("recently_downloaded") or ev_dict.get("recentlyDownloaded")),
        related_evidence_ids=related_ev_json,
        related_iocs=related_ioc_json
    )

    db.add(db_ev)
    db.commit()
    db.refresh(db_ev)
    return serialize_evidence(db_ev)


def delete_evidence(db: Session, evidence_id: str) -> bool:
    item = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not item:
        return False
    db.delete(item)
    db.commit()
    return True


# ==============================================================================
# IOC CRUD
# ==============================================================================
def get_iocs(
    db: Session,
    case_id: Optional[int] = None,
    ioc_type: Optional[str] = None,
    risk: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
) -> List[Dict[str, Any]]:
    query = db.query(models.IOC)
    if case_id:
        query = query.filter(models.IOC.case_id == case_id)
    if ioc_type and ioc_type.upper() != "ALL":
        query = query.filter(models.IOC.ioc_type.ilike(f"%{ioc_type}%"))
    if risk and risk.upper() != "ALL":
        query = query.filter(models.IOC.risk == risk.upper())
    if search:
        s = f"%{search.lower()}%"
        query = query.filter(
            or_(
                models.IOC.value.ilike(s),
                models.IOC.source.ilike(s),
                models.IOC.status.ilike(s)
            )
        )
    query = query.order_by(desc(models.IOC.occurrences), desc(models.IOC.confidence))
    items = query.offset(skip).limit(limit).all()
    return [serialize_ioc(item) for item in items]


def get_ioc_by_id(db: Session, ioc_id: int) -> Optional[Dict[str, Any]]:
    item = db.query(models.IOC).filter(models.IOC.id == ioc_id).first()
    return serialize_ioc(item) if item else None


def create_ioc(db: Session, ioc_dict: Dict[str, Any]) -> Dict[str, Any]:
    rel_json = json.dumps(ioc_dict.get("related_evidence_ids") or ioc_dict.get("relatedEvidenceIds") or [])
    val = ioc_dict.get("value") or ioc_dict.get("ioc") or ""

    # Check for duplicate
    existing = db.query(models.IOC).filter(
        models.IOC.case_id == ioc_dict.get("case_id", 1),
        models.IOC.value == val
    ).first()

    if existing:
        existing.occurrences += 1
        db.commit()
        db.refresh(existing)
        return serialize_ioc(existing)

    db_ioc = models.IOC(
        case_id=ioc_dict.get("case_id", 1),
        evidence_id=ioc_dict.get("evidence_id"),
        ioc_type=ioc_dict.get("ioc_type") or ioc_dict.get("type") or "Unknown",
        value=val,
        confidence=ioc_dict.get("confidence", 80),
        source=ioc_dict.get("source"),
        first_seen=ioc_dict.get("first_seen") or ioc_dict.get("firstSeen"),
        last_seen=ioc_dict.get("last_seen") or ioc_dict.get("lastSeen"),
        status=ioc_dict.get("status") or "Identified",
        risk=ioc_dict.get("risk") or "MEDIUM",
        asn=ioc_dict.get("asn") or "N/A",
        country=ioc_dict.get("country") or "N/A",
        occurrences=ioc_dict.get("occurrences", 1),
        related_evidence_ids=rel_json
    )
    db.add(db_ioc)
    db.commit()
    db.refresh(db_ioc)
    return serialize_ioc(db_ioc)


# ==============================================================================
# Events / Timeline CRUD
# ==============================================================================
def get_events(
    db: Session,
    case_id: Optional[int] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
) -> List[Dict[str, Any]]:
    query = db.query(models.Event)
    if case_id:
        query = query.filter(models.Event.case_id == case_id)
    if severity and severity.upper() != "ALL":
        query = query.filter(models.Event.severity == severity.upper())
    if event_type and event_type.upper() != "ALL":
        query = query.filter(models.Event.event_type.ilike(f"%{event_type}%"))
    if search:
        s = f"%{search.lower()}%"
        query = query.filter(
            or_(
                models.Event.title.ilike(s),
                models.Event.description.ilike(s),
                models.Event.mitre.ilike(s),
                models.Event.evidence_id.ilike(s)
            )
        )

    items = query.all()
    serialized = [serialize_event(item) for item in items]
    sorted_items = sort_events_chronologically(serialized)
    return sorted_items[skip : skip + limit]


def create_event(db: Session, ev_dict: Dict[str, Any]) -> Dict[str, Any]:
    ev_id = ev_dict.get("id")
    if not ev_id:
        total = db.query(models.Event).count()
        ev_id = f"TL-{total + 1:02d}"

    db_event = models.Event(
        id=ev_id,
        case_id=ev_dict.get("case_id", 1),
        evidence_id=ev_dict.get("evidence_id") or ev_dict.get("relatedEvidenceId"),
        timestamp=ev_dict.get("timestamp") or f"{ev_dict.get('date', '')} {ev_dict.get('time', '')}".strip(),
        time=ev_dict.get("time"),
        date=ev_dict.get("date"),
        event_type=ev_dict.get("event_type") or ev_dict.get("eventType") or "System",
        title=ev_dict.get("title") or "Forensic Event",
        description=ev_dict.get("description"),
        source=ev_dict.get("source"),
        process=ev_dict.get("process"),
        user=ev_dict.get("user"),
        risk_score=ev_dict.get("risk_score") or 0,
        severity=ev_dict.get("severity") or "LOW",
        mitre=ev_dict.get("mitre")
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return serialize_event(db_event)


# ==============================================================================
# Graph Topology CRUD
# ==============================================================================
def get_graph_data(db: Session, case_id: int = 1) -> Dict[str, Any]:
    entities = db.query(models.Entity).filter(models.Entity.case_id == case_id).all()
    relationships = db.query(models.Relationship).filter(models.Relationship.case_id == case_id).all()

    nodes = [
        {
            "id": ent.id,
            "label": ent.label,
            "category": ent.category,
            "risk": ent.risk,
            "details": ent.details or ""
        }
        for ent in entities
    ]

    links = [
        {
            "source": rel.source_entity_id,
            "target": rel.target_entity_id,
            "label": rel.label,
            "type": rel.relationship_type or "associated"
        }
        for rel in relationships
    ]

    return {
        "nodes": nodes,
        "links": links,
        "edges": links
    }


# ==============================================================================
# Dashboard Statistics
# ==============================================================================
def get_case_statistics(db: Session, case_id: int = 1) -> Dict[str, Any]:
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    evidence_items = db.query(models.Evidence).filter(models.Evidence.case_id == case_id).all()
    ioc_count = db.query(models.IOC).filter(models.IOC.case_id == case_id).count()
    event_items = db.query(models.Event).filter(models.Event.case_id == case_id).all()

    total_evidence = len(evidence_items)

    risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    type_dist: Dict[str, int] = {}
    mitre_set = set()

    for ev in evidence_items:
        tier = ev.risk_tier.upper() if ev.risk_tier else "LOW"
        risk_dist[tier] = risk_dist.get(tier, 0) + 1

        ev_type = ev.evidence_type or "File"
        type_dist[ev_type] = type_dist.get(ev_type, 0) + 1

        if ev.mitre_attack:
            mitre_set.add(ev.mitre_attack.split(" - ")[0].strip())

    critical_count = risk_dist["CRITICAL"]
    high_count = risk_dist["HIGH"]
    suspicious_count = critical_count + high_count

    # Recent 5 events
    serialized_events = [serialize_event(e) for e in event_items]
    recent_events = sort_events_chronologically(serialized_events)[:5]

    # Priority watchlist (score >= 60)
    priority_items = sorted(
        [serialize_evidence(e) for e in evidence_items if e.risk_score >= 60],
        key=lambda x: x["risk_score"],
        reverse=True
    )[:8]

    return {
        "case_id": case.id if case else case_id,
        "case_number": case.case_number if case else "INC-2024-0918",
        "case_name": case.name if case else "Financial Workstation Triage",
        "total_evidence": total_evidence,
        "totalEvidence": total_evidence,  # UI compatibility
        "critical_findings": critical_count,
        "criticalFindings": critical_count,  # UI compatibility
        "high_risk_evidence": high_count,
        "suspicious_evidence": suspicious_count,
        "suspiciousEvidence": suspicious_count,  # UI compatibility
        "total_iocs": ioc_count,
        "totalIocs": ioc_count,  # UI compatibility
        "total_events": len(event_items),
        "totalEvents": len(event_items),  # UI compatibility
        "risk_distribution": risk_dist,
        "riskDistribution": risk_dist,  # UI compatibility
        "type_distribution": type_dist,
        "typeDistribution": type_dist,  # UI compatibility
        "mitre_coverage": sorted(list(mitre_set)),
        "mitreCoverage": sorted(list(mitre_set)),  # UI compatibility
        "recent_events": recent_events,
        "recentEvents": recent_events,  # UI compatibility
        "priority_watchlist": priority_items,
        "priorityWatchlist": priority_items  # UI compatibility
    }


# ==============================================================================
# Reports CRUD
# ==============================================================================
def get_reports(db: Session, case_id: int = 1) -> List[models.Report]:
    return db.query(models.Report).filter(models.Report.case_id == case_id).order_by(desc(models.Report.generated_at)).all()


def create_report(db: Session, case_id: int, title: str, summary: str, content: Dict[str, Any]) -> models.Report:
    content_json = json.dumps(content)
    db_report = models.Report(
        case_id=case_id,
        title=title,
        summary=summary,
        content=content_json
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return db_report
