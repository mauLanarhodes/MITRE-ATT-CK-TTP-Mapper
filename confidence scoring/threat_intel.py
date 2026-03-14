"""
threat_intel.py — IOC extraction and pluggable threat intel enrichment.

Extracts IP addresses, URLs, domains, MD5, and SHA256 hashes from free text.
Includes stubs for AlienVault OTX, VirusTotal, and AbuseIPDB enrichment.
"""

import re
from typing import Dict, List


# --- IOC Extraction Patterns ---
IOC_PATTERNS = {
    "ips": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "urls": re.compile(
        r"https?://[^\s\"'<>)\]]+", re.IGNORECASE
    ),
    "domains": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|info|biz|xyz|top|ru|cn|uk|de)\b",
        re.IGNORECASE,
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract IOCs from free text.

    Returns:
        Dict with keys: ips, urls, domains, md5, sha256
        Each value is a deduplicated list of matches.
    """
    extracted = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = pattern.findall(text)
        extracted[ioc_type] = sorted(set(matches))
    return extracted


def classify_iocs(extracted: Dict[str, List[str]]) -> List[Dict[str, str]]:
    """
    Classify extracted IOCs into typed entries.

    Returns:
        List of dicts with keys: value, type
    """
    classified = []
    type_map = {
        "ips": "IPv4",
        "urls": "URL",
        "domains": "Domain",
        "md5": "MD5",
        "sha256": "SHA256",
    }
    for ioc_type, values in extracted.items():
        for v in values:
            classified.append({"value": v, "type": type_map.get(ioc_type, "Unknown")})
    return classified


# --- Enrichment Stubs ---
def enrich_otx(ioc_value: str, api_key: str = "") -> dict:
    """Stub: query AlienVault OTX for an IOC. Returns empty dict without key."""
    if not api_key:
        return {"source": "OTX", "status": "no_api_key", "data": {}}
    # Placeholder for real OTX API integration
    return {"source": "OTX", "status": "stub", "data": {}}


def enrich_virustotal(ioc_value: str, api_key: str = "") -> dict:
    """Stub: query VirusTotal for an IOC."""
    if not api_key:
        return {"source": "VirusTotal", "status": "no_api_key", "data": {}}
    return {"source": "VirusTotal", "status": "stub", "data": {}}


def enrich_abuseipdb(ip: str, api_key: str = "") -> dict:
    """Stub: query AbuseIPDB for an IP address."""
    if not api_key:
        return {"source": "AbuseIPDB", "status": "no_api_key", "data": {}}
    return {"source": "AbuseIPDB", "status": "stub", "data": {}}