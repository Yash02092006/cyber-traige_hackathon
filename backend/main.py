"""
Cyber Triage Tool - FastAPI Main Application Server.
Smart India Hackathon • SIH1744 • SIH 2024
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.database import engine, Base, DB_DIR
from backend.init_db import init_db
from backend.seed import seed_database
from backend.routers import cases, evidence, iocs, timeline, graph, reports

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifecycle event.
    Automatically initializes SQLite schema and seeds simulation data if empty.
    """
    print("[*] Starting Cyber Triage Tool Backend...")
    init_db()
    try:
        seed_database()
    except Exception as e:
        print(f"[!] Warning: Seed check encountered an issue: {e}")
    print("[+] Cyber Triage Tool Backend is operational.")
    yield
    print("[*] Shutting down Cyber Triage Tool Backend...")


app = FastAPI(
    title="Cyber Triage Tool API",
    description=(
        "Production-grade REST API for digital forensics triage investigation (SIH1744 • SIH 2024).\n\n"
        "Provides streaming file hashing (SHA-256 / MD5), explainable heuristic risk scoring, "
        "rule-based IOC extraction, chronological timeline reconstruction, entity graph topology, "
        "and formal reporting.\n\n"
        "**NOTE: All preloaded evidence records are SIMULATION DATA for hackathon demonstration.**"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# 1. Enable CORS for local cross-origin development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Include REST API Routers
app.include_router(cases.router)
app.include_router(evidence.router)
app.include_router(iocs.router)
app.include_router(timeline.router)
app.include_router(graph.router)
app.include_router(reports.router)


# 3. Health Check Endpoint
@app.get("/api/health", tags=["System"], summary="API Health Probe")
def health_check():
    """Returns runtime health, version, and database connectivity."""
    db_exists = os.path.isfile(os.path.join(DB_DIR, "cyber_triage.db"))
    return {
        "status": "healthy",
        "service": "Cyber Triage Tool Backend",
        "hackathon_id": "SIH1744",
        "version": "1.0.0",
        "database_connected": db_exists,
        "mode": "SIMULATION_PROTOTYPE"
    }


# 4. Static Asset Mounts (CSS, JS)
css_dir = os.path.join(BASE_DIR, "css")
js_dir = os.path.join(BASE_DIR, "js")

if os.path.isdir(css_dir):
    app.mount("/css", StaticFiles(directory=css_dir), name="css")

if os.path.isdir(js_dir):
    app.mount("/js", StaticFiles(directory=js_dir), name="js")


# 5. Frontend HTML Routes (Serve the complete vanilla UI seamlessly)
def serve_html_file(filename: str):
    file_path = os.path.join(BASE_DIR, filename)
    if os.path.isfile(file_path):
        return FileResponse(file_path, media_type="text/html")
    raise HTTPException(status_code=404, detail=f"Page {filename} not found.")


@app.get("/", tags=["Frontend"], summary="Landing / Problem Statement Page")
@app.get("/index.html", tags=["Frontend"], include_in_schema=False)
def index_page():
    return serve_html_file("index.html")


@app.get("/dashboard", tags=["Frontend"], summary="Investigation Dashboard")
@app.get("/dashboard.html", tags=["Frontend"], include_in_schema=False)
def dashboard_page():
    return serve_html_file("dashboard.html")


@app.get("/evidence", tags=["Frontend"], summary="Evidence Explorer")
@app.get("/evidence.html", tags=["Frontend"], include_in_schema=False)
def evidence_page():
    return serve_html_file("evidence.html")


@app.get("/ioc", tags=["Frontend"], summary="IOC Correlation Repository")
@app.get("/ioc.html", tags=["Frontend"], include_in_schema=False)
def ioc_page():
    return serve_html_file("ioc.html")


@app.get("/timeline", tags=["Frontend"], summary="Attack Super-Timeline")
@app.get("/timeline.html", tags=["Frontend"], include_in_schema=False)
def timeline_page():
    return serve_html_file("timeline.html")


@app.get("/graph", tags=["Frontend"], summary="Interactive Relationship Graph")
@app.get("/graph.html", tags=["Frontend"], include_in_schema=False)
def graph_page():
    return serve_html_file("graph.html")


@app.get("/reports", tags=["Frontend"], summary="Forensic Case Dossier & Reporting")
@app.get("/reports.html", tags=["Frontend"], include_in_schema=False)
def reports_page():
    return serve_html_file("reports.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
