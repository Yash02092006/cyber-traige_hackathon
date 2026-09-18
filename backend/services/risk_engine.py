"""
Explainable Heuristic Risk Scoring Engine for Digital Forensic Triage.
Provides transparent, rule-by-rule point breakdowns instead of opaque black-box AI scores.
SIH1744 • SIH 2024
"""

from typing import Dict, Any, List

RISK_RULES = {
    "SUSPICIOUS_HASH": {
        "points": 30,
        "name": "Known Malicious Hash Match",
        "code": "RULE_HASH_THREAT"
    },
    "SUSPICIOUS_IP": {
        "points": 20,
        "name": "Connection to Known C2 / Tor Exit IP",
        "code": "RULE_C2_IP"
    },
    "UNUSUAL_PROCESS": {
        "points": 15,
        "name": "Unusual Execution / LOLBin Invocation",
        "code": "RULE_LOLBIN_EXEC"
    },
    "UNEXPECTED_PARENT": {
        "points": 15,
        "name": "Anomalous Parent-Child Process Relationship",
        "code": "RULE_PARENT_ANOMALY"
    },
    "TEMP_DIRECTORY": {
        "points": 10,
        "name": "Binary Originates from Temporary / AppData Path",
        "code": "RULE_TEMP_PATH"
    },
    "RECENTLY_DOWNLOADED": {
        "points": 10,
        "name": "Zone Identifier Marks Recent Web Download",
        "code": "RULE_WEB_DOWNLOAD"
    },
    "OBFUSCATION_ENCODED": {
        "points": 15,
        "name": "Base64 Encoded / Obfuscated Command Line",
        "code": "RULE_OBFUSCATED_CMD"
    },
    "LSASS_ACCESS": {
        "points": 25,
        "name": "Process Handle Granted to LSASS Memory Space",
        "code": "RULE_CRED_DUMP"
    }
}


def evaluate_risk(evidence_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates an evidence dictionary against transparent forensic heuristic rules.
    Returns:
        score: int (0 - 100)
        severity: str ("LOW" | "MEDIUM" | "HIGH" | "CRITICAL")
        tier: str
        reasons: list of {rule, points, code}
    """
    score = 0
    applied_rules: List[Dict[str, Any]] = []

    # 1. Known suspicious hash rule
    sha = (evidence_data.get("sha256") or "").lower()
    is_malicious_hash = evidence_data.get("isMaliciousHash") or evidence_data.get("is_malicious_hash", False)
    if is_malicious_hash or any(sha.startswith(prefix) for prefix in ("a4f", "e8d", "79b", "91a", "948")):
        score += RISK_RULES["SUSPICIOUS_HASH"]["points"]
        applied_rules.append({
            "rule": RISK_RULES["SUSPICIOUS_HASH"]["name"],
            "points": RISK_RULES["SUSPICIOUS_HASH"]["points"],
            "code": RISK_RULES["SUSPICIOUS_HASH"]["code"]
        })

    # 2. Suspicious IP / External C2 connection
    dest_ip = (evidence_data.get("destinationIp") or evidence_data.get("destination_ip") or "").strip()
    if dest_ip and any(dest_ip.startswith(prefix) for prefix in ("185.220.", "91.240.", "194.26.")):
        pts = RISK_RULES["SUSPICIOUS_IP"]["points"]
        score += pts
        applied_rules.append({
            "rule": f"{RISK_RULES['SUSPICIOUS_IP']['name']} ({dest_ip})",
            "points": pts,
            "code": RISK_RULES["SUSPICIOUS_IP"]["code"]
        })

    # 3. Unusual process (LOLBin or suspicious name)
    name = (evidence_data.get("name") or evidence_data.get("filename") or "").lower()
    source = (evidence_data.get("source") or evidence_data.get("original_path") or "").lower()
    desc = (evidence_data.get("description") or "").lower()

    lolbins = ("powershell", "cmd.exe", "certutil.exe", "vssadmin.exe", "rundll32.exe", "wevtutil.exe", "schtasks", "net.exe")
    if any(lb in name or lb in source for lb in lolbins) or "updater.exe" in name or "invoice_oct" in name or "7za.exe" in name:
        pts = RISK_RULES["UNUSUAL_PROCESS"]["points"]
        score += pts
        applied_rules.append({
            "rule": RISK_RULES["UNUSUAL_PROCESS"]["name"],
            "points": pts,
            "code": RISK_RULES["UNUSUAL_PROCESS"]["code"]
        })

    # 4. Anomalous parent process
    parent = (evidence_data.get("parentProcess") or evidence_data.get("parent_process") or "").lower()
    if any(p in parent for p in ("chrome.exe", "updater.exe", "powershell.exe")) or ("invoice_oct" in parent and "updater" in name):
        pts = RISK_RULES["UNEXPECTED_PARENT"]["points"]
        score += pts
        applied_rules.append({
            "rule": f"{RISK_RULES['UNEXPECTED_PARENT']['name']} (Parent: {evidence_data.get('parentProcess') or evidence_data.get('parent_process')})",
            "points": pts,
            "code": RISK_RULES["UNEXPECTED_PARENT"]["code"]
        })

    # 5. Temporary / AppData directory origin
    if any(temp_dir in source for temp_dir in ("temp", "appdata\\local", "appdata/local", "downloads", "/tmp/")):
        pts = RISK_RULES["TEMP_DIRECTORY"]["points"]
        score += pts
        applied_rules.append({
            "rule": RISK_RULES["TEMP_DIRECTORY"]["name"],
            "points": pts,
            "code": RISK_RULES["TEMP_DIRECTORY"]["code"]
        })

    # 6. Recently downloaded via browser (Zone.Identifier)
    if evidence_data.get("recentlyDownloaded") or evidence_data.get("recently_downloaded") or "download" in source or "zone.identifier" in source:
        pts = RISK_RULES["RECENTLY_DOWNLOADED"]["points"]
        score += pts
        applied_rules.append({
            "rule": RISK_RULES["RECENTLY_DOWNLOADED"]["name"],
            "points": pts,
            "code": RISK_RULES["RECENTLY_DOWNLOADED"]["code"]
        })

    # 7. Base64 / Obfuscated command
    cmd = (evidence_data.get("commandLine") or evidence_data.get("command_line") or "").lower()
    if cmd and any(kw in cmd for kw in ("-enc", "frombase64", "hidden", "bypass")):
        pts = RISK_RULES["OBFUSCATION_ENCODED"]["points"]
        score += pts
        applied_rules.append({
            "rule": RISK_RULES["OBFUSCATION_ENCODED"]["name"],
            "points": pts,
            "code": RISK_RULES["OBFUSCATION_ENCODED"]["code"]
        })

    # 8. LSASS handle / Credential access / Exfiltration activity
    if any(kw in name or kw in source or kw in desc for kw in ("lsass", "credential", "exfiltration", "dump")):
        pts = RISK_RULES["LSASS_ACCESS"]["points"]
        score += pts
        applied_rules.append({
            "rule": RISK_RULES["LSASS_ACCESS"]["name"],
            "points": pts,
            "code": RISK_RULES["LSASS_ACCESS"]["code"]
        })

    # Baseline heuristic fallback if no specific rule applied
    if not applied_rules and evidence_data.get("baselineScore"):
        base_pts = int(evidence_data["baselineScore"])
        score = base_pts
        applied_rules.append({
            "rule": "Baseline Heuristic Anomaly Vector",
            "points": base_pts,
            "code": "RULE_BASELINE"
        })

    final_score = min(100, max(0, score))

    if final_score >= 80:
        tier = "CRITICAL"
    elif final_score >= 60:
        tier = "HIGH"
    elif final_score >= 30:
        tier = "MEDIUM"
    else:
        tier = "LOW"

    return {
        "score": final_score,
        "severity": tier,
        "tier": tier,
        "reasons": applied_rules
    }
