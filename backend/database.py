"""
Database Configuration & Session Management using SQLite & SQLAlchemy.
SIH1744 • SIH 2024
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Locate database folder relative to project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE_DIR, "database")
os.makedirs(DB_DIR, exist_ok=True)

DATABASE_PATH = os.path.join(DB_DIR, "cyber_triage.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DATABASE_PATH.replace(os.sep, '/')}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    FastAPI dependency that yields an isolated database session and ensures closure.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
