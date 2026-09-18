"""
Correlated Chronological Attack Timeline Router.
SIH1744 • SIH 2024
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend import crud, schemas

router = APIRouter(prefix="/api/cases/{case_id}/timeline", tags=["Attack Timeline"])


@router.get("", response_model=List[schemas.EventResponse], summary="Retrieve chronological attack progression")
def get_case_timeline(
    case_id: int,
    severity: Optional[str] = Query(None, description="Filter by event severity: CRITICAL, HIGH, MEDIUM, LOW"),
    event_type: Optional[str] = Query(None, description="Filter by event category: Authentication, Execution, Network, File, System, Web"),
    search: Optional[str] = Query(None, description="Search term in title, description, or MITRE technique"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """
    Retrieves normalized, chronologically sorted forensic events demonstrating
    the end-to-end incident kill-chain sequence.
    """
    return crud.get_events(
        db=db,
        case_id=case_id,
        severity=severity,
        event_type=event_type,
        search=search,
        skip=skip,
        limit=limit
    )
