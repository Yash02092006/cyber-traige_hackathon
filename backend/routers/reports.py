"""
Forensic Reporting and Case Dossier Router.
SIH1744 • SIH 2024
"""

import json
from datetime import datetime
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend import crud, schemas

router = APIRouter(prefix="/api/cases/{case_id}", tags=["Forensic Reports"])


@router.get("/reports", response_model=List[schemas.ReportResponse], summary="List generated case reports")
def get_reports(case_id: int, db: Session = Depends(get_db)):
    """Retrieves all formal report snapshots saved for the case."""
    reports = crud.get_reports(db, case_id=case_id)
    out = []
    for r in reports:
        parsed_content = json.loads(r.content) if r.content else {}
        out.append(
            schemas.ReportResponse(
                id=r.id,
                case_id=r.case_id,
                title=r.title,
                summary=r.summary,
                generated_at=r.generated_at,
                content=parsed_content
            )
        )
    return out


@router.post("/reports", response_model=schemas.ReportResponse, status_code=status.HTTP_201_CREATED, summary="Create a new report snapshot")
def create_report(case_id: int, report_in: schemas.ReportCreate, db: Session = Depends(get_db)):
    """Saves a formal report snapshot into the database."""
    case = crud.get_case(db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found."
        )
    created = crud.create_report(
        db=db,
        case_id=case_id,
        title=report_in.title,
        summary=report_in.summary or "Digital Forensics Incident Triage Report",
        content=report_in.content or {}
    )
    return schemas.ReportResponse(
        id=created.id,
        case_id=created.case_id,
        title=created.title,
        summary=created.summary,
        generated_at=created.generated_at,
        content=report_in.content or {}
    )


@router.get("/dossier", summary="Generate dynamic live case dossier with simulation disclaimer")
def get_live_case_dossier(case_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Assembles a comprehensive case dossier combining statistics, critical findings,
    verified IOCs, timeline events, and investigative methodology.
    Explicitly distinguishes SIMULATION DATA from live findings.
    """
    case = crud.get_case(db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found."
        )

    stats = crud.get_case_statistics(db, case_id=case_id)
    evidence_items = crud.get_evidence_list(db, case_id=case_id, limit=100)
    iocs = crud.get_iocs(db, case_id=case_id, limit=50)
    timeline = crud.get_events(db, case_id=case_id, limit=50)

    # Filter critical findings (Score >= 75)
    critical_findings = [e for e in evidence_items if e.get("risk_score", 0) >= 75]

    return {
        "disclaimer": "SIMULATION DATA • This investigation report was generated from a synthetic cyber triage hackathon dataset (SIH1744). Not from real forensic evidence.",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "case": {
            "id": case.id,
            "case_number": case.case_number,
            "name": case.name,
            "description": case.description,
            "status": case.status,
            "lead_investigator": "Forensic Triage Specialist (CERT-IN / SIH Team)",
            "classification": "CONFIDENTIAL // TLP:AMBER (SIMULATION)"
        },
        "statistics": stats,
        "critical_findings": critical_findings,
        "iocs": iocs,
        "timeline": timeline,
        "methodology": {
            "evidence_acquisition": "File ingestion prototype with streaming SHA-256/MD5 hashing.",
            "risk_scoring": "Transparent 8-factor heuristic engine (0-100 score).",
            "correlation": "Graph topological entity mapping across processes, IPs, and user sessions."
        },
        "chain_of_custody": [
            {"time": "09:42:00", "action": "Incident triage case initiated", "actor": "Forensic Intake"},
            {"time": "09:43:02", "action": "Malicious dropper captured & hashed", "actor": "Automated Agent"},
            {"time": "09:45:10", "action": "LSASS memory dump detected & flagged", "actor": "Heuristic Engine"},
            {"time": "09:48:10", "action": "C2 exfiltration blocked & host isolated", "actor": "Incident Response"}
        ]
    }
