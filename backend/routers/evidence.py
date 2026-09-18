"""
Evidence Ingestion, Filtering, and Acquisition Router.
SIH1744 • SIH 2024
"""

import os
import uuid
import mimetypes
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, status
from sqlalchemy.orm import Session

from backend.database import get_db, BASE_DIR
from backend import crud, schemas
from backend.services.hashing import calculate_hashes_for_file
from backend.services.risk_engine import evaluate_risk
from backend.services.ioc_extractor import extract_iocs_from_text

router = APIRouter(prefix="/api/evidence", tags=["Evidence Management"])

UPLOADS_DIR = os.path.join(BASE_DIR, "data", "uploads")
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB safety cap


def format_bytes(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


@router.get("", response_model=List[schemas.EvidenceResponse], summary="Query and filter evidence records")
def get_evidence(
    case_id: Optional[int] = Query(None, description="Filter by investigation case ID"),
    evidence_type: Optional[str] = Query(None, description="Filter by category: File, Process, Network, Browser, System, User"),
    risk: Optional[str] = Query(None, description="Filter by risk tier: CRITICAL, HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="Filter by status: Flagged, Analyzed, Baseline"),
    search: Optional[str] = Query(None, description="Keyword search across ID, filename, source, description, SHA-256, user"),
    sort: Optional[str] = Query("risk-desc", description="Sort order: risk-desc, risk-asc, time-desc, time-asc, id-asc, name-asc"),
    skip: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """
    Retrieves evidence records matching multi-vector filtering, search, and sorting criteria.
    """
    return crud.get_evidence_list(
        db=db,
        case_id=case_id,
        evidence_type=evidence_type,
        risk=risk,
        status=status,
        search=search,
        sort_by=sort,
        skip=skip,
        limit=limit
    )


@router.get("/{evidence_id}", response_model=schemas.EvidenceResponse, summary="Get evidence dossier by ID")
def get_evidence_by_id(evidence_id: str, db: Session = Depends(get_db)):
    """
    Retrieves full technical metadata and explainable risk breakdown for an evidence item.
    """
    item = crud.get_evidence_by_id(db, evidence_id=evidence_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found."
        )
    return item


@router.post("/upload", response_model=schemas.EvidenceResponse, status_code=status.HTTP_201_CREATED, summary="Evidence file ingestion and triage prototype")
async def upload_evidence(
    file: UploadFile = File(..., description="Binary or log artifact for triage ingestion"),
    case_id: int = Form(1, description="Associated case ID"),
    evidence_type: Optional[str] = Form(None, description="Optional explicit evidence type"),
    db: Session = Depends(get_db)
):
    """
    Evidence file ingestion and triage prototype.
    Safely stores file under data/uploads/, streams SHA-256 and MD5 hash calculations,
    infers MIME type, runs transparent heuristic risk scoring, and extracts rule-based IOCs.
    """
    # 1. Sanitize filename and prevent path traversal
    raw_filename = os.path.basename(file.filename or "unknown_artifact")
    safe_name = "".join(c for c in raw_filename if c.isalnum() or c in "._- ").strip()
    if not safe_name:
        safe_name = f"evidence_{uuid.uuid4().hex[:8]}.bin"

    # Unique storage name
    unique_prefix = uuid.uuid4().hex[:12]
    saved_filename = f"{unique_prefix}_{safe_name}"
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    destination_path = os.path.join(UPLOADS_DIR, saved_filename)

    # 2. Stream write to disk while enforcing max file size
    total_written = 0
    try:
        with open(destination_path, "wb") as buffer:
            while chunk := await file.read(64 * 1024):
                total_written += len(chunk)
                if total_written > MAX_FILE_SIZE_BYTES:
                    buffer.close()
                    if os.path.exists(destination_path):
                        os.remove(destination_path)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Uploaded file exceeds maximum allowed size of {format_bytes(MAX_FILE_SIZE_BYTES)}."
                    )
                buffer.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        if os.path.exists(destination_path):
            os.remove(destination_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error saving uploaded artifact: {str(e)}"
        )

    # 3. Calculate streaming SHA-256 and MD5 hashes
    hash_result = calculate_hashes_for_file(destination_path)
    sha256_val = hash_result["sha256"]
    md5_val = hash_result["md5"]
    file_size_formatted = format_bytes(total_written)

    # 4. Infer MIME and evidence category
    mime_type, _ = mimetypes.guess_type(safe_name)
    if not mime_type:
        mime_type = file.content_type or "application/octet-stream"

    inferred_type = evidence_type or "File"
    lower_name = safe_name.lower()
    if lower_name.endswith((".pcap", ".pcapng")):
        inferred_type = "Network"
    elif lower_name.endswith((".evtx", ".reg")):
        inferred_type = "System"
    elif any(kw in lower_name for kw in ("history", "cookie", "cache")):
        inferred_type = "Browser"

    # 5. Evaluate explainable risk score
    evidence_eval_data = {
        "filename": safe_name,
        "name": safe_name,
        "source": destination_path,
        "sha256": sha256_val,
        "recentlyDownloaded": True,
        "parentProcess": "web_triage_ingestion",
        "description": f"Ingested evidence artifact. SHA-256: {sha256_val}"
    }
    risk_result = evaluate_risk(evidence_eval_data)

    # 6. Extract IOCs from filename and textual snippet (if text)
    discovered_iocs = extract_iocs_from_text(safe_name, source_label=f"Ingested: {safe_name}")

    # Generate sequential evidence ID
    total_ev = db.query(crud.models.Evidence).count()
    new_ev_id = f"EVD-{1000 + total_ev + 1}"

    # 7. Persist Evidence to SQLite
    evidence_dict = {
        "id": new_ev_id,
        "case_id": case_id,
        "filename": safe_name,
        "original_path": destination_path,
        "evidence_type": inferred_type,
        "size": file_size_formatted,
        "sha256": sha256_val,
        "md5": md5_val,
        "mime_type": mime_type,
        "source": f"Local Upload / {saved_filename}",
        "collected_at": datetime.utcnow(),
        "status": "Analyzed",
        "risk_score": risk_result["score"],
        "risk_tier": risk_result["tier"],
        "risk_reasons": risk_result["reasons"],
        "description": f"Evidence file ingestion and triage prototype. Size: {file_size_formatted}. Verified SHA-256: {sha256_val}.",
        "mitre_attack": "T1005 - Data from Local System",
        "parent_process": "web_triage_ingestion",
        "user": "local\\investigator",
        "command_line": None,
        "destination_ip": None,
        "is_malicious_hash": False,
        "recently_downloaded": True,
        "related_evidence_ids": [],
        "related_iocs": [sha256_val] + [ioc["value"] for ioc in discovered_iocs]
    }

    saved_ev = crud.create_evidence(db, evidence_dict)

    # Persist discovered IOCs
    for ioc in discovered_iocs:
        ioc_record = {
            "case_id": case_id,
            "evidence_id": new_ev_id,
            "ioc_type": ioc["ioc_type"],
            "value": ioc["value"],
            "confidence": ioc["confidence"],
            "source": f"Ingestion ({safe_name})",
            "first_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "status": ioc["status"],
            "risk": ioc["risk"],
            "occurrences": 1,
            "related_evidence_ids": [new_ev_id]
        }
        crud.create_ioc(db, ioc_record)

    return saved_ev


@router.delete("/{evidence_id}", status_code=status.HTTP_200_OK, summary="Remove evidence record")
def delete_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """Deletes an evidence record from the investigation case."""
    success = crud.delete_evidence(db, evidence_id=evidence_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found."
        )
    return {"status": "success", "message": f"Evidence artifact '{evidence_id}' deleted."}
