"""
Streaming Hashing Service for Digital Forensic Evidence Ingestion.
Calculates SHA-256 and MD5 cryptographic hashes without loading entire files into RAM.
SIH1744 • SIH 2024
"""

import hashlib
import os
from typing import Dict, Any, BinaryIO

CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks


def calculate_hashes_for_file(file_path: str) -> Dict[str, Any]:
    """
    Computes SHA-256 and MD5 hashes for an existing file on disk using streaming chunks.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    total_bytes = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
            md5.update(chunk)
            total_bytes += len(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "size_bytes": total_bytes
    }


def calculate_hashes_from_stream(stream: BinaryIO) -> Dict[str, Any]:
    """
    Computes SHA-256 and MD5 from a binary file stream.
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    total_bytes = 0

    while chunk := stream.read(CHUNK_SIZE):
        sha256.update(chunk)
        md5.update(chunk)
        total_bytes += len(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "size_bytes": total_bytes
    }
