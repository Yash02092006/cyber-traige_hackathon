# Cyber Triage Tool

**SIH1744 — Cybersecurity / Digital Forensics**  
*Smart India Hackathon 2024*

---

## 1. Problem Statement

Modern cybersecurity incident responders face an overwhelming volume of volatile endpoint data, network logs, memory artifacts, and system events during an intrusion. Manually sifting through multi-gigabyte disk dumps and unindexed logs delays critical containment decisions. Investigators need a high-velocity **Cyber Triage Tool** that rapidly ingests, indexes, scores, and correlates digital evidence across endpoints, users, processes, and network communication channels.

---

## 2. Solution

The **Cyber Triage Tool** provides an end-to-end digital forensics triage platform. It combines:
- A high-contrast, technical cybersecurity user interface designed for speed and clarity.
- An asynchronous **Python FastAPI** backend backed by a structured **SQLite** database and **SQLAlchemy ORM**.
- Safe evidence file ingestion with streaming **SHA-256** and **MD5** dual-hash calculation.
- A **transparent, explainable heuristic risk scoring engine** (0–100 score with rule breakdown).
- Automated **rule-based regex IOC extraction** (IPs, domains, URLs, hashes).
- Chronological **super-timeline correlation** reconstructing the adversary's kill chain.
- An interactive **topological entity relationship graph** mapping lateral movement, credentials, and C2 beacons.
- Dynamic **forensic reporting** with exportable HTML, Plain Text, and print-ready formats.

---

## 3. Features

- **Investigation Dashboard**: Real-time triage telemetry, threat meter, MITRE ATT&CK coverage, and priority watchlist (\(\text{Risk} \ge 60\)).
- **Evidence Explorer**: Interactive data grid indexing 42+ forensic artifacts across 6 categories (`File`, `Process`, `Network`, `Browser`, `System`, `User`) with multi-facet filtering, search, sorting, and CSV export.
- **Evidence File Ingestion Prototype**: Safe upload modal calculating streaming cryptographic hashes, inferring MIME types, and computing explainable risk scores without disk execution.
- **Indicators of Compromise (IOC) Hub**: Centralized repository of IPs, domains, URLs, and hashes with occurrence frequencies and correlated evidence drill-down.
- **Attack Super-Timeline**: Chronologically ordered progression of events reconstructing the breach from initial phishing access (09:42:11) to lateral movement (09:48:10).
- **Interactive Relationship Graph**: Pure-SVG network graph supporting node dragging, pan, zoom, edge highlighting, and sidebar inspection.
- **Formal Case Dossier & Reporting**: Generates downloadable standalone HTML reports, plain text forensic log summaries, and clean print/PDF layouts.

---

## 4. System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│              FRONTEND (Vanilla HTML5 / CSS3 / ES6 JavaScript)          │
│  index.html │ dashboard.html │ evidence.html │ ioc.html │ timeline     │
│  graph.html │ reports.html   │ js/api.js (REST Client with Fallback)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / JSON / Multipart
┌───────────────────────────────────▼────────────────────────────────────┐
│                       FASTAPI APPLICATION SERVER                       │
│  backend/main.py  (CORS, Static Mounting, Lifespan Init, Routes)      │
├────────────────────────────────────────────────────────────────────────┤
│  ROUTERS:                                                              │
│  - /api/cases        (Case metadata & telemetry)                       │
│  - /api/evidence     (Evidence querying, streaming uploads, deletion)  │
│  - /api/iocs         (Indicators of Compromise & linked artifacts)     │
│  - /api/timeline     (Normalized chronological events)                 │
│  - /api/graph        (Topological nodes & relationships)               │
│  - /api/reports      (Dossier snapshots & exports)                     │
├────────────────────────────────────────────────────────────────────────┤
│  SERVICES:                                                             │
│  - hashing.py        (Streaming SHA-256 & MD5 chunk processor)         │
│  - risk_engine.py    (Transparent 8-factor heuristic scoring)          │
│  - ioc_extractor.py  (Regex IP, Domain, URL, Hash extraction)          │
│  - timeline_engine.py(ISO-8601 normalization & ordering)               │
│  - correlation.py    (Cross-artifact entity graph correlation)         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ SQLAlchemy ORM
┌───────────────────────────────────▼────────────────────────────────────┐
│                    PERSISTENT STORAGE (SQLite)                         │
│  database/cyber_triage.db                                              │
│  Tables: cases, evidence, iocs, events, entities, relationships, report│
│  data/uploads/ (Safely isolated uploaded binary/log files)             │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Tech Stack

- **Backend Framework**: Python 3.12, FastAPI
- **ASGI Web Server**: Uvicorn
- **Database**: SQLite 3
- **ORM & Data Modeling**: SQLAlchemy 2.0, Pydantic v2
- **File Ingestion**: `python-multipart`, streaming `hashlib`
- **Frontend Architecture**: Vanilla HTML5, CSS3, ES6 JavaScript (Zero heavy external frameworks)
- **Vector Graphics**: Native browser SVG (Interactive force-directed layout)
- **Documentation**: OpenAPI 3.0 / Swagger UI (`/docs`), ReDoc (`/redoc`)

---

## 6. Database Architecture

SQLite database located at `database/cyber_triage.db`.

### Core Tables & Schema
1. **`cases`**:
   - `id` (INTEGER, PK, Autoincrement)
   - `case_number` (VARCHAR(50), Unique, Indexed) — e.g. `INC-2024-0918`
   - `name` (VARCHAR(255))
   - `description` (TEXT)
   - `status` (VARCHAR(50))
   - `created_at`, `updated_at` (DATETIME)

2. **`evidence`**:
   - `id` (VARCHAR(50), PK, Indexed) — e.g. `EVD-1001`
   - `case_id` (INTEGER, FK `cases.id`, Indexed)
   - `filename` (VARCHAR(255))
   - `original_path` (TEXT)
   - `evidence_type` (VARCHAR(50)) — File, Process, Network, Browser, System, User
   - `size` (VARCHAR(50))
   - `sha256` (VARCHAR(64), Indexed)
   - `md5` (VARCHAR(32))
   - `mime_type` (VARCHAR(100))
   - `source` (TEXT)
   - `collected_at` (DATETIME)
   - `status` (VARCHAR(50))
   - `risk_score` (INTEGER)
   - `risk_tier` (VARCHAR(20)) — LOW, MEDIUM, HIGH, CRITICAL
   - `risk_reasons` (TEXT / JSON)
   - `description` (TEXT)
   - `mitre_attack` (VARCHAR(100))
   - `parent_process`, `user`, `command_line`, `destination_ip`
   - `related_evidence_ids`, `related_iocs` (JSON)
   - `created_at` (DATETIME)

3. **`iocs`**:
   - `id` (INTEGER, PK, Autoincrement)
   - `case_id` (INTEGER, FK `cases.id`, Indexed)
   - `evidence_id` (VARCHAR(50), Nullable)
   - `ioc_type` (VARCHAR(50)) — IP, Domain, URL, SHA-256, Process
   - `value` (VARCHAR(255), Indexed)
   - `confidence` (INTEGER)
   - `source`, `first_seen`, `last_seen`, `status`, `risk`, `asn`, `country`
   - `occurrences` (INTEGER)
   - `related_evidence_ids` (JSON)

4. **`events`**:
   - `id` (VARCHAR(50), PK) — e.g. `TL-01`
   - `case_id` (INTEGER, FK `cases.id`, Indexed)
   - `evidence_id` (VARCHAR(50))
   - `timestamp` (VARCHAR(50), Indexed)
   - `time`, `date`, `event_type`, `title`, `description`, `source`, `process`, `user`
   - `risk_score` (INTEGER), `severity` (VARCHAR(20)), `mitre` (VARCHAR(50))

5. **`entities`**:
   - `id` (VARCHAR(50), PK) — e.g. `user_jdoe`
   - `case_id` (INTEGER, FK `cases.id`, Indexed)
   - `entity_type`, `value`, `label`, `category`, `risk`, `details`

6. **`relationships`**:
   - `id` (INTEGER, PK, Autoincrement)
   - `case_id` (INTEGER, FK `cases.id`, Indexed)
   - `source_entity_id` (FK `entities.id`, Indexed)
   - `target_entity_id` (FK `entities.id`, Indexed)
   - `relationship_type`, `label`, `confidence`

7. **`reports`**:
   - `id` (INTEGER, PK, Autoincrement)
   - `case_id` (INTEGER, FK `cases.id`, Indexed)
   - `title`, `summary`, `generated_at`, `content` (JSON)

---

## 7. API Architecture

All endpoints return clean, typed JSON responses:

### Cases & Dashboard
- `GET /api/cases` — List all registered cases.
- `GET /api/cases/{case_id}` — Retrieve case details.
- `POST /api/cases` — Register a new case.
- `PUT /api/cases/{case_id}` — Update case status or description.
- `GET /api/cases/{case_id}/statistics` — Telemetry for dashboard cards, risk meter, MITRE matrix, and priority watchlist.

### Evidence Management
- `GET /api/evidence` — Query evidence with query parameters: `case_id`, `evidence_type`, `risk`, `status`, `search`, `sort`, `limit`, `skip`.
- `GET /api/evidence/{evidence_id}` — Detailed evidence record with raw metadata and rule scoring breakdown.
- `POST /api/evidence/upload` — Multipart file ingestion with streaming SHA-256/MD5 hashing, risk evaluation, and IOC extraction.
- `DELETE /api/evidence/{evidence_id}` — Delete evidence record.

### Indicators of Compromise (IOCs)
- `GET /api/iocs` — List all indicators with optional `ioc_type`, `risk`, `search` filtering.
- `GET /api/iocs/{ioc_id}` — Indicator detail view.
- `GET /api/cases/{case_id}/iocs` — Case-scoped indicators with occurrence counts and correlated evidence IDs.

### Timeline
- `GET /api/cases/{case_id}/timeline` — Chronologically sorted incident sequence with `severity`, `event_type`, `search` filters.

### Investigation Graph
- `GET /api/cases/{case_id}/graph` — Topological entity graph returning `{ "nodes": [...], "links": [...] }`.

### Reports & Dossier
- `GET /api/cases/{case_id}/reports` — List saved report snapshots.
- `POST /api/cases/{case_id}/reports` — Save new report snapshot.
- `GET /api/cases/{case_id}/dossier` — Comprehensive live case dossier with simulation metadata.

### System Health
- `GET /api/health` — Probe backend health, version, and database connectivity.

---

## 8. Evidence Workflow

```
File Upload (evidence.html)
         │
         ▼
POST /api/evidence/upload
         │
         ├── 1. Filename sanitization & path traversal check
         ├── 2. Safe storage into data/uploads/{uuid}_{filename}
         ├── 3. Streaming 64 KB chunk calculation: SHA-256 + MD5
         ├── 4. MIME type and evidence category inference
         ├── 5. Explainable Heuristic Risk Engine evaluation
         ├── 6. Rule-based regex IOC extraction
         ├── 7. SQLite database persistence
         │
         ▼
JSON Evidence Record Returned & UI View Dynamically Refreshed
```

---

## 9. Risk Scoring

The triage tool rejects opaque black-box AI scores in favor of a transparent, additive heuristic engine (`backend/services/risk_engine.py`):

$$\text{Risk Score} = \min\left(100, \sum \text{Applied Rules}\right)$$

### Heuristic Rule Weighting:
| Rule Code | Rule Name | Points | Trigger Criteria |
| :--- | :--- | :--- | :--- |
| `RULE_HASH_THREAT` | Known Malicious Hash Match | **+30** | Hash matches known malicious database or signature prefix |
| `RULE_C2_IP` | Suspicious IP / External C2 | **+20** | Destination IP in malicious/bulletproof subnet (e.g. `185.220.`, `91.240.`) |
| `RULE_LOLBIN_EXEC` | Unusual Execution / LOLBin | **+15** | Living-off-the-Land binary invocation (`powershell`, `certutil`, `rundll32`, `vssadmin`) |
| `RULE_PARENT_ANOMALY`| Anomalous Parent Process | **+15** | Office application, web browser, or explorer spawning shells or droppers |
| `RULE_TEMP_PATH` | Temp / AppData Directory | **+10** | Execution originating from `%TEMP%`, `%APPDATA%`, or `/tmp/` |
| `RULE_WEB_DOWNLOAD` | Recently Downloaded | **+10** | Zone Identifier Mark-of-the-Web (MOTW) or browser download path |
| `RULE_OBFUSCATED_CMD`| Obfuscated Command Line | **+15** | Base64 encoded payload (`-enc`), hidden window, or bypass switches |
| `RULE_CRED_DUMP` | LSASS Handle / Credential Dump | **+25** | Process handle opened to LSASS memory or minidump artifact |

### Severity Tiers:
- **CRITICAL** (\(80 - 100\)): Confirmed threat requiring immediate host isolation.
- **HIGH** (\(60 - 79\)): High-confidence intrusion indicator.
- **MEDIUM** (\(30 - 59\)): Suspicious anomaly requiring correlation.
- **LOW** (\(0 - 29\)): Normal system baseline activity.

---

## 10. IOC Extraction

`backend/services/ioc_extractor.py` scans uploaded files, logs, and command lines for:
- **IPv4 Addresses**: Standard dotted-quad notation, excluding loopback/broadcast, flagging known C2 ranges.
- **Domains**: RFC-compliant hostnames, excluding standard legitimate OS domains (`microsoft.com`, etc.).
- **URLs**: Active web endpoints (`http://`, `https://`, `hxxp://`).
- **Email Addresses**: RFC 5322 formatted sender/recipient addresses.
- **SHA-256 Hashes**: 64-character hexadecimal digests.
- **MD5 Hashes**: 32-character hexadecimal digests.

Discovered indicators are automatically cataloged in the SQLite `iocs` table and linked to the source evidence.

---

## 11. Timeline Correlation

`backend/services/timeline_engine.py` aggregates logs from disparate sources (Sysmon, Windows Event Logs, network flows, Chrome history) into a unified chronological attack sequence. Events are normalized to ISO-8601 UTC timestamps, establishing cause-and-effect progression from initial access to data exfiltration.

---

## 12. Investigation Graph

`backend/services/correlation.py` analyzes evidence items, IOCs, processes, network connections, and user accounts to generate a connected topological graph. Served via `GET /api/cases/{case_id}/graph`, the frontend renders this into an interactive SVG visualization where investigators can drag entities, explore relationships, and inspect properties in the sidebar.

---

## 13. Installation

### Prerequisites
- **Python 3.10+** (Python 3.12 recommended)
- **pip** package installer

### Setup Steps

1. **Clone or Navigate to the Project Root**:
   ```bash
   cd "e:\SMESTER 1\HACKATHON"
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv .venv
   ```

3. **Activate the Virtual Environment**:
   - On Windows (PowerShell):
     ```powershell
     .venv\Scripts\Activate.ps1
     ```
   - On Windows (Command Prompt):
     ```cmd
     .venv\Scripts\activate.bat
     ```
   - On Linux / macOS:
     ```bash
     source .venv/bin/activate
     ```

4. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 14. Running Locally

### Start the Application Server
Run Uvicorn from the project root:

```bash
uvicorn backend.main:app --reload
```

The application will start at:
- **Application Web UI**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Investigation Dashboard**: [http://127.0.0.1:8000/dashboard.html](http://127.0.0.1:8000/dashboard.html)
- **Interactive Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Alternative ReDoc Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

> [!TIP]
> The database schema is automatically created and seeded on first startup. You can also re-seed the simulation dataset at any time using:
> ```bash
> python -m backend.seed
> ```

---

## 15. API Documentation

FastAPI provides an interactive OpenAPI / Swagger UI:
- Navigate to **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)** to test all endpoints interactively directly from your browser.
- Schemas for all models (`CaseResponse`, `EvidenceResponse`, `IOCResponse`, `EventResponse`, `GraphResponse`) are documented with request/response payloads.

---

## 16. Project Structure

```
e:\SMESTER 1\HACKATHON\
├── index.html                  # Landing page & Problem Statement presentation
├── dashboard.html              # Investigation command dashboard
├── evidence.html               # Evidence explorer with search, filter, and upload
├── ioc.html                    # Correlated indicators of compromise repository
├── timeline.html               # Chronological attack kill chain stream
├── graph.html                  # Interactive pure-SVG entity topology graph
├── reports.html                # Forensic case dossier, exports, and print view
│
├── css/
│   ├── style.css               # Core typography, dark theme tokens, landing layout
│   └── app.css                 # Application components, tables, modals, graph & print
│
├── js/
│   ├── api.js                  # Centralized asynchronous REST API client
│   ├── data.js                 # Forensic mock data store & client-side fallback
│   ├── app.js                  # Global navbar, toasts, evidence modal & upload handler
│   ├── script.js               # Landing page pipeline inspector & presentation mode
│   ├── dashboard.js            # Telemetry cards, risk meters, and priority watchlist
│   ├── evidence.js             # Evidence table query, filtering, and CSV export
│   ├── ioc.js                  # IOC catalog, occurrence counters, and linked modal
│   ├── timeline.js             # Timeline card stream, category filters, and JSON export
│   ├── graph.js                # SVG graph physics, pan/zoom, drag, and inspector
│   └── reports.js              # Dossier compiler, HTML/TXT downloads, and print layout
│
├── backend/
│   ├── __init__.py
│   ├── main.py                 # FastAPI app, CORS, static mounts, frontend routes
│   ├── database.py             # SQLite engine, sessionmaker, declarative base
│   ├── models.py               # SQLAlchemy ORM models (Cases, Evidence, IOCs, etc.)
│   ├── schemas.py              # Pydantic validation and response schemas
│   ├── crud.py                 # Reusable database query access layer
│   ├── init_db.py              # Database schema initialization utility
│   ├── seed.py                 # Idempotent simulation dataset seeder
│   ├── seed_data.json          # Extracted 42 evidence, 12 IOC, 17 timeline records
│   ├── routers/
│   │   ├── cases.py            # Case endpoints & dashboard statistics
│   │   ├── evidence.py         # Evidence list, filters, upload & delete
│   │   ├── iocs.py             # IOC repository & correlation
│   │   ├── timeline.py         # Chronological timeline query
│   │   ├── graph.py            # Entity topology graph query
│   │   └── reports.py          # Report snapshots & live dossier
│   └── services/
│       ├── hashing.py          # Streaming SHA-256 and MD5 file calculation
│       ├── risk_engine.py      # Explainable heuristic risk scoring engine
│       ├── ioc_extractor.py    # Rule-based regex IOC extraction
│       ├── timeline_engine.py  # Timestamp normalization and chronological sorting
│       └── correlation.py      # Cross-artifact entity relationship correlation
│
├── data/
│   └── uploads/                # Safe storage for uploaded evidence files
│
├── database/
│   └── cyber_triage.db         # Persistent SQLite database file
│
├── requirements.txt            # Python dependencies
├── README.md                   # Comprehensive documentation
└── .gitignore                  # Git ignore rules for database and uploads
```

---

## 17. Simulation Data Disclaimer

> [!IMPORTANT]
> **SIMULATION DATA DISCLAIMER**:
> All preloaded evidence records, IP addresses, domains, process names, and user accounts in this tool are **synthetic simulation data** created exclusively for hackathon evaluation and digital forensics demonstration under **Smart India Hackathon 2024 (SIH1744)**.
> They do not represent real-world compromised individuals or organizations.

---

## 18. Current Limitations

- **File Ingestion Scope**: The upload functionality is an evidence file ingestion and triage prototype. It does not perform physical raw disk imaging (`.E01` / raw bitstream imaging), live RAM acquisition, kernel memory introspection, or NTFS master file table (MFT) raw parsing.
- **Rule-Based IOC Extraction**: Indicator extraction uses regular expression pattern matching and does not query external commercial threat-intelligence feeds (e.g. VirusTotal, AlienVault OTX) unless API keys are configured.
- **Single-Node Prototype**: Built on SQLite for zero-configuration local evaluation. Production deployment would benefit from PostgreSQL for high-concurrency multi-investigator teams.

---

## 19. Future Scope

1. **YARA & Sigma Integration**: Ingest custom YARA rules and Sigma detection logic directly into the risk evaluation pipeline.
2. **Volatile Memory Parser**: Integrate `volatility3` bindings for automated memory dump parsing (process lists, network sockets, injected code).
3. **Live Forensic Agent**: A lightweight Go/Rust client agent to collect triage packages from remote endpoints over mTLS.
4. **MITRE ATT&CK Navigator Export**: Single-click export of discovered techniques directly into standard ATT&CK Navigator JSON layer formats.
5. **Multi-Tenancy & RBAC**: Role-based access control for lead investigators, analysts, and legal auditors.
