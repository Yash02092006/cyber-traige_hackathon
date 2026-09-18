"""
Database Initialization Utility.
Creates SQLite tables and required directory structure.
SIH1744 • SIH 2024
"""

import os
import sys

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.database import engine, Base, DB_DIR
from backend import models

UPLOADS_DIR = os.path.join(BASE_DIR, "data", "uploads")


def init_db():
    """
    Creates SQLite database directories and schema tables.
    """
    os.makedirs(DB_DIR, exist_ok=True)
    os.makedirs(UPLOADS_DIR, exist_ok=True)

    print(f"[*] Initializing SQLite database schema at: {DB_DIR}")
    Base.metadata.create_all(bind=engine)
    print("[+] Database tables successfully initialized.")


if __name__ == "__main__":
    init_db()
