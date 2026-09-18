"""
Indicators of Compromise (IOC) Router.
SIH1744 • SIH 2024
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend import crud, schemas

router = APIRouter(tags=["Indicators of Compromise (IOCs)"])


@router.get("/api/iocs", response_model=List[schemas.IOCResponse], summary="List all Indicators of Compromise")
def get_all_iocs(
    ioc_type: Optional[str] = Query(None, description="Filter by type: IP, Domain, URL, File Hash (SHA-256), Process"),
    risk: Optional[str] = Query(None, description="Filter by risk tier: CRITICAL, HIGH, MEDIUM, LOW"),
    search: Optional[str] = Query(None, description="Search term in IOC value or source"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Retrieves all global Indicators of Compromise across cases."""
    return crud.get_iocs(
        db=db,
        ioc_type=ioc_type,
        risk=risk,
        search=search,
        skip=skip,
        limit=limit
    )


@router.get("/api/iocs/{ioc_id}", response_model=schemas.IOCResponse, summary="Get IOC by ID")
def get_ioc_by_id(ioc_id: int, db: Session = Depends(get_db)):
    """Retrieves details and correlation telemetry for a specific indicator."""
    ioc = crud.get_ioc_by_id(db, ioc_id=ioc_id)
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC with ID {ioc_id} not found."
        )
    return ioc


@router.get("/api/cases/{case_id}/iocs", response_model=List[schemas.IOCResponse], summary="Get IOCs scoped to a case")
def get_case_iocs(
    case_id: int,
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type"),
    risk: Optional[str] = Query(None, description="Filter by risk"),
    search: Optional[str] = Query(None, description="Search filter"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Retrieves all correlated IOCs belonging to a specific investigation case."""
    return crud.get_iocs(
        db=db,
        case_id=case_id,
        ioc_type=ioc_type,
        risk=risk,
        search=search,
        skip=skip,
        limit=limit
    )
