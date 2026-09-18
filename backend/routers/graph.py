"""
Entity-Relationship Topology Graph Router.
SIH1744 • SIH 2024
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database import get_db
from backend import crud, schemas

router = APIRouter(prefix="/api/cases/{case_id}/graph", tags=["Investigation Graph"])


@router.get("", response_model=schemas.GraphResponse, summary="Get investigation entity relationship graph")
def get_investigation_graph(case_id: int, db: Session = Depends(get_db)):
    """
    Returns entity nodes and relationship edges representing cross-artifact correlations
    between users, processes, files, network connections, domains, and scheduled tasks.
    """
    return crud.get_graph_data(db, case_id=case_id)
