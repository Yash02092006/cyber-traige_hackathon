"""
Rule-Based IOC Extraction Service for Digital Forensic Evidence.
Scans text content, file metadata, and command lines for Indicators of Compromise.
SIH1744 • SIH 2024
"""

import re
from typing import List, Dict, Any, Set

# Compiled regex patterns for forensic indicators
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63})\b")
URL_REGEX = re.compile(r"\b(?:https?|hxxps?|ftp)://[^\s<>\"'{}|\\^`]+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Excluded common false positives for domains
IGNORED_DOMAINS = {
    "microsoft.com", "google.com", "windows.com", "w3.org", "example.com",
    "github.com", "schema.org", "localhost", "local", "internal"
}


def extract_iocs_from_text(text: str, source_label: str = "Triage Ingestion") -> List[Dict[str, Any]]:
    """
    Extracts IPv4s, domains, URLs, emails, SHA-256, and MD5 hashes from raw text.
    Returns a deduplicated list of structured IOC dictionaries.
    """
    if not text:
        return []

    discovered: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    # 1. URLs (extract first before domain tokenizer splits them)
    urls = URL_REGEX.findall(text)
    for url in urls:
        clean_url = url.rstrip(".,;)>]").strip()
        if clean_url and clean_url not in seen:
            seen.add(clean_url)
            discovered.append({
                "ioc_type": "URL",
                "value": clean_url,
                "confidence": 85,
                "source": source_label,
                "status": "Extracted from Evidence",
                "risk": "HIGH" if "hxxp" in clean_url.lower() or "invoice" in clean_url.lower() else "MEDIUM"
            })

    # 2. SHA-256 Hashes
    sha256s = SHA256_REGEX.findall(text)
    for sha in sha256s:
        clean_sha = sha.lower()
        if clean_sha not in seen:
            seen.add(clean_sha)
            discovered.append({
                "ioc_type": "SHA-256",
                "value": clean_sha,
                "confidence": 95,
                "source": source_label,
                "status": "Cryptographic Checksum",
                "risk": "CRITICAL" if any(clean_sha.startswith(p) for p in ("a4f", "e8d", "79b")) else "MEDIUM"
            })

    # 3. MD5 Hashes (avoid matching substrings of SHA-256)
    md5s = MD5_REGEX.findall(text)
    for md5_val in md5s:
        clean_md5 = md5_val.lower()
        # Ensure it's not a slice of a 64-char hex hash already seen
        if clean_md5 not in seen and not any(clean_md5 in sha for sha in sha256s):
            seen.add(clean_md5)
            discovered.append({
                "ioc_type": "MD5",
                "value": clean_md5,
                "confidence": 90,
                "source": source_label,
                "status": "Cryptographic Hash",
                "risk": "MEDIUM"
            })

    # 4. IPv4 Addresses
    ips = IPV4_REGEX.findall(text)
    for ip in ips:
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            # Exclude loopback/broadcast unless relevant
            if ip not in ("0.0.0.0", "255.255.255.255") and ip not in seen:
                seen.add(ip)
                is_c2_candidate = any(ip.startswith(prefix) for prefix in ("185.220.", "91.240.", "194.26."))
                discovered.append({
                    "ioc_type": "IP",
                    "value": ip,
                    "confidence": 90 if is_c2_candidate else 75,
                    "source": source_label,
                    "status": "C2 Candidate" if is_c2_candidate else "Network Host",
                    "risk": "CRITICAL" if is_c2_candidate else "MEDIUM"
                })

    # 5. Domains
    domains = DOMAIN_REGEX.findall(text)
    for dom in domains:
        clean_dom = dom.lower().strip()
        # Avoid file extensions like .exe, .dll, .txt being matched as domains
        if clean_dom.endswith((".exe", ".dll", ".sys", ".txt", ".log", ".dmp", ".pdf", ".zip", ".7z")):
            continue
        if clean_dom not in IGNORED_DOMAINS and clean_dom not in seen:
            seen.add(clean_dom)
            discovered.append({
                "ioc_type": "Domain",
                "value": clean_dom,
                "confidence": 80,
                "source": source_label,
                "status": "Discovered Hostname",
                "risk": "HIGH" if "cloud-secure" in clean_dom or "telemetry" in clean_dom else "MEDIUM"
            })

    # 6. Emails
    emails = EMAIL_REGEX.findall(text)
    for email in emails:
        clean_email = email.lower().strip()
        if clean_email not in seen:
            seen.add(clean_email)
            discovered.append({
                "ioc_type": "Email",
                "value": clean_email,
                "confidence": 80,
                "source": source_label,
                "status": "Communication Endpoint",
                "risk": "MEDIUM"
            })

    return discovered
