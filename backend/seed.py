"""
Database Seeding Script for Cyber Triage Tool.
Imports the 42 synthetic evidence records, 12 IOCs, 17 timeline events,
and 15 graph topology entities into SQLite.
Explicitly labels all imported records as 'SIMULATION DATA'.
Idempotent: safe to run multiple times without creating duplicate records.
SIH1744 • SIH 2024
"""

import os
import sys
import json
from datetime import datetime

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.database import SessionLocal, engine, Base
from backend import models
from backend.services.risk_engine import evaluate_risk
from backend.init_db import init_db

SEED_DATA_PATH = os.path.join(BASE_DIR, "backend", "seed_data.json")


def seed_database():
    print("[*] Ensuring database tables exist...")
    init_db()

    db = SessionLocal()
    try:
        # 1. Create or retrieve primary case
        case_number = "INC-2024-0918"
        case = db.query(models.Case).filter(models.Case.case_number == case_number).first()

        if not case:
            case = models.Case(
                case_number=case_number,
                name="Project Blackout - Financial Workstation Triage",
                description="SIMULATION DATA • Digital forensics triage investigation into suspected spearphishing, LOLBin staging, LSASS credential access, C2 beaconing, and lateral movement.",
                status="ACTIVE_INVESTIGATION"
            )
            db.add(case)
            db.commit()
            db.refresh(case)
            print(f"[+] Created Case {case.case_number} (ID: {case.id})")
        else:
            print(f"[i] Existing Case {case.case_number} found (ID: {case.id})")

        case_id = case.id

        # Check if already seeded
        existing_evidence_count = db.query(models.Evidence).filter(models.Evidence.case_id == case_id).count()
        if existing_evidence_count > 0:
            print(f"[i] Case already contains {existing_evidence_count} evidence records. Skipping duplicate seeding.")
            print("[+] Database is already up to date.")
            return

        if not os.path.isfile(SEED_DATA_PATH):
            raise FileNotFoundError(f"Seed data file not found at: {SEED_DATA_PATH}")

        with open(SEED_DATA_PATH, "r", encoding="utf-8") as f:
            dataset = json.load(f)

        evidence_items = dataset.get("evidence", [])
        iocs = dataset.get("iocs", [])
        timeline_events = dataset.get("timeline", [])
        graph = dataset.get("graph", {})

        print(f"[*] Importing {len(evidence_items)} synthetic evidence records (SIMULATION DATA)...")
        for item in evidence_items:
            # Evaluate transparent risk score
            eval_res = evaluate_risk(item)

            # Parse timestamp if available
            ts = None
            if item.get("timestamp"):
                try:
                    ts = datetime.strptime(item["timestamp"].strip(), "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass

            db_ev = models.Evidence(
                id=item["id"],
                case_id=case_id,
                filename=item.get("name", "untitled_evidence"),
                original_path=item.get("source"),
                evidence_type=item.get("type", "File"),
                size=item.get("size", "0 B"),
                sha256=item.get("sha256"),
                md5=item.get("md5"),
                mime_type="application/octet-stream",
                source=item.get("source", "SIMULATION DATA"),
                collected_at=ts or datetime.utcnow(),
                status=item.get("status", "Flagged"),
                risk_score=eval_res["score"],
                risk_tier=eval_res["tier"],
                risk_reasons=json.dumps(eval_res["reasons"]),
                description=f"SIMULATION DATA • {item.get('description', '')}".strip(),
                mitre_attack=item.get("mitreAttack"),
                parent_process=item.get("parentProcess"),
                user=item.get("user", "N/A"),
                command_line=item.get("commandLine"),
                destination_ip=item.get("destinationIp"),
                is_malicious_hash=bool(item.get("isMaliciousHash")),
                recently_downloaded=bool(item.get("recentlyDownloaded")),
                related_evidence_ids=json.dumps(item.get("relatedEvidenceIds", [])),
                related_iocs=json.dumps(item.get("relatedIocs", []))
            )
            db.add(db_ev)

        print(f"[*] Importing {len(iocs)} Indicators of Compromise (IOCs)...")
        for ioc in iocs:
            db_ioc = models.IOC(
                case_id=case_id,
                evidence_id=ioc.get("relatedEvidenceIds", [None])[0] if ioc.get("relatedEvidenceIds") else None,
                ioc_type=ioc.get("type", "Unknown"),
                value=ioc.get("ioc", ""),
                confidence=85 if ioc.get("risk") == "CRITICAL" else 75,
                source=f"SIMULATION DATA ({ioc.get('status', 'Analyzed')})",
                first_seen=ioc.get("firstSeen"),
                last_seen=ioc.get("lastSeen"),
                status=ioc.get("status"),
                risk=ioc.get("risk", "MEDIUM"),
                asn=ioc.get("asn", "N/A"),
                country=ioc.get("country", "N/A"),
                occurrences=ioc.get("occurrences", 1),
                related_evidence_ids=json.dumps(ioc.get("relatedEvidenceIds", []))
            )
            db.add(db_ioc)

        print(f"[*] Importing {len(timeline_events)} Correlated Timeline Events...")
        for ev in timeline_events:
            ts_str = f"{ev.get('date', '2024-10-14')} {ev.get('time', '09:42:00')}"
            db_event = models.Event(
                id=ev.get("id"),
                case_id=case_id,
                evidence_id=ev.get("relatedEvidenceId"),
                timestamp=ts_str,
                time=ev.get("time"),
                date=ev.get("date"),
                event_type=ev.get("eventType", "System"),
                title=ev.get("title", "Forensic Event"),
                description=f"SIMULATION DATA • {ev.get('description', '')}".strip(),
                source="Endpoint & Network Telemetry",
                process="N/A",
                user="corp\\j.doe",
                risk_score=90 if ev.get("severity") == "CRITICAL" else 65 if ev.get("severity") == "HIGH" else 30,
                severity=ev.get("severity", "LOW"),
                mitre=ev.get("mitre")
            )
            db.add(db_event)

        print(f"[*] Importing {len(graph.get('nodes', []))} Graph Entities and {len(graph.get('links', []))} Relationships...")
        for node in graph.get("nodes", []):
            db_entity = models.Entity(
                id=node["id"],
                case_id=case_id,
                entity_type=node.get("category"),
                value=node.get("label"),
                label=node.get("label"),
                category=node.get("category", "Entity"),
                risk=node.get("risk", "LOW"),
                details=f"SIMULATION DATA • {node.get('details', '')}".strip()
            )
            db.add(db_entity)

        db.flush()  # Ensure entities are flushed before relationships

        for link in graph.get("links", []):
            db_rel = models.Relationship(
                case_id=case_id,
                source_entity_id=link["source"],
                target_entity_id=link["target"],
                relationship_type=link.get("type", "associated"),
                label=link.get("label", "RELATED_TO"),
                confidence=95
            )
            db.add(db_rel)

        db.commit()
        print("\n==================================================")
        print("SIMULATION DATASET SUCCESSFULLY IMPORTED INTO SQLITE")
        print("==================================================")
        print(f"Case Number:   {case_number}")
        print(f"Evidence:      {len(evidence_items)} records")
        print(f"IOCs:          {len(iocs)} indicators")
        print(f"Timeline:      {len(timeline_events)} events")
        print(f"Graph Nodes:   {len(graph.get('nodes', []))} entities")
        print(f"Graph Edges:   {len(graph.get('links', []))} relationships")
        print("All records tagged as: SIMULATION DATA\n")

    except Exception as e:
        db.rollback()
        print(f"[!] Error seeding database: {e}")
        raise e
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
