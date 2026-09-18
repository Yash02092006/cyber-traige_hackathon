"""
Timeline Normalization and Ordering Service.
Standardizes heterogeneous timestamps across forensic artifacts into a correlated incident sequence.
SIH1744 • SIH 2024
"""

from datetime import datetime
from typing import List, Dict, Any, Optional


def normalize_timestamp(ts_str: Optional[str]) -> str:
    """
    Normalizes diverse timestamp strings to 'YYYY-MM-DD HH:MM:SS'.
    """
    if not ts_str:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    clean_ts = ts_str.strip().replace("T", " ")
    # Handle ISO formats with timezone or fractional seconds
    if "." in clean_ts:
        clean_ts = clean_ts.split(".")[0]
    if "+" in clean_ts:
        clean_ts = clean_ts.split("+")[0]
    if "Z" in clean_ts:
        clean_ts = clean_ts.replace("Z", "")

    # Common forensic date patterns
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            dt = datetime.strptime(clean_ts, fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

    return clean_ts


def sort_events_chronologically(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sorts a list of event dictionaries chronologically by normalized timestamp.
    """
    def get_sort_key(ev: Dict[str, Any]) -> str:
        date_part = ev.get("date") or ""
        time_part = ev.get("time") or ""
        ts_part = ev.get("timestamp") or ""
        if ts_part:
            return normalize_timestamp(str(ts_part))
        return f"{date_part} {time_part}".strip()

    return sorted(events, key=get_sort_key)
