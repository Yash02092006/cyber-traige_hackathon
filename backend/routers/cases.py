"""
Cases and Dashboard Telemetry Router.
SIH1744 • SIH 2024
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend import crud, schemas

router = APIRouter(prefix="/api/cases", tags=["Cases & Telemetry"])


@router.get("", response_model=List[schemas.CaseResponse], summary="List all investigation cases")
def list_cases(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """Retrieve all triage cases registered in the system."""
    return crud.get_cases(db, skip=skip, limit=limit)


@router.get("/{case_id}", response_model=schemas.CaseResponse, summary="Get case details by ID")
def get_case(case_id: int, db: Session = Depends(get_db)):
    """Retrieve metadata for a specific forensic case."""
    case = crud.get_case(db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found."
        )
    return case


@router.post("", response_model=schemas.CaseResponse, status_code=status.HTTP_201_CREATED, summary="Create a new case")
def create_case(case_in: schemas.CaseCreate, db: Session = Depends(get_db)):
    """Register a new digital forensics investigation case."""
    existing = crud.get_case_by_number(db, case_number=case_in.case_number)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Case number '{case_in.case_number}' already exists."
        )
    return crud.create_case(db, case_in=case_in)


@router.put("/{case_id}", response_model=schemas.CaseResponse, summary="Update case details")
def update_case(case_id: int, case_in: schemas.CaseUpdate, db: Session = Depends(get_db)):
    """Update case metadata or operational status."""
    updated = crud.update_case(db, case_id=case_id, case_in=case_in)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found."
        )
    return updated


@router.get("/{case_id}/statistics", response_model=schemas.DashboardStatisticsResponse, summary="Get dashboard telemetry and risk distribution")
def get_case_statistics(case_id: int, db: Session = Depends(get_db)):
    """
    Computes real-time investigation metrics, explainable risk tier distribution,
    priority watchlist (Risk >= 60), and recent timeline telemetry for the dashboard.
    """
    case = crud.get_case(db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found."
        )
    return crud.get_case_statistics(db, case_id=case_id)
