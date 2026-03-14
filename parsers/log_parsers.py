"""
parsers/log_parsers.py — Parsers for common log formats.

Supports: plain text, JSON/NDJSON, Sysmon XML, CEF, CSV.
All parsers return List[str] of IOC strings compatible with map_iocs().
"""

import csv
import json
import io
import xml.etree.ElementTree as ET
from typing import List


def parse_plain_text(filepath: str) -> List[str]:
    """Parse a plain text file — one IOC/event per line."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        return [line.strip() for line in f if line.strip()]


def parse_json_log(filepath: str) -> List[str]:
    """Parse JSON or NDJSON log file. Flattens each record into a string."""
    results = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read().strip()

    # Try parsing as a JSON array first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for entry in data:
                results.append(_flatten_dict(entry))
            return results
        elif isinstance(data, dict):
            # Could be a wrapper with a records array
            for key in ("Records", "records", "events", "logs", "value", "entries"):
                if key in data and isinstance(data[key], list):
                    for entry in data[key]:
                        results.append(_flatten_dict(entry))
                    return results
            results.append(_flatten_dict(data))
            return results
    except json.JSONDecodeError:
        pass

    # Try NDJSON (one JSON object per line)
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append(_flatten_dict(obj))
        except json.JSONDecodeError:
            results.append(line)

    return results


def parse_sysmon_xml(filepath: str) -> List[str]:
    """Parse Sysmon XML event logs. Extracts key fields per event."""
    results = []
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError:
        # Try wrapping in root element for fragments
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f"<root>{f.read()}</root>"
        root = ET.fromstring(content)

    # Handle namespace
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    for event in root.iter(f"{ns}Event"):
        parts = []
        for data in event.iter(f"{ns}Data"):
            name = data.get("Name", "")
            text = data.text or ""
            if name and text:
                parts.append(f"{name}={text}")
        if parts:
            results.append(" | ".join(parts))

    # Fallback: if no events found, try generic element extraction
    if not results:
        for elem in root.iter():
            if elem.text and elem.text.strip():
                results.append(elem.text.strip())

    return results


def parse_cef(filepath: str) -> List[str]:
    """Parse CEF (Common Event Format) log file."""
    results = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("CEF:"):
                continue
            # CEF format: CEF:Version|Device Vendor|Device Product|...|Name|Severity|Extensions
            parts = line.split("|", 7)
            event_name = parts[4] if len(parts) > 4 else ""
            extensions = parts[7] if len(parts) > 7 else ""
            results.append(f"{event_name} {extensions}")
    return results


def parse_csv_log(filepath: str) -> List[str]:
    """Parse CSV log file. Concatenates all columns per row into a string."""
    results = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            return results
        for row in reader:
            parts = [f"{h}={v}" for h, v in zip(header, row) if v.strip()]
            if parts:
                results.append(" | ".join(parts))
    return results


def auto_detect_and_parse(filepath: str) -> List[str]:
    """
    Auto-detect log format and parse.

    Detection order:
    1. .xml → Sysmon XML
    2. .csv → CSV
    3. .cef → CEF
    4. .json / .ndjson → JSON
    5. Try JSON content detection
    6. Try CEF content detection
    7. Fallback to plain text
    """
    ext = filepath.lower().rsplit(".", 1)[-1] if "." in filepath else ""

    if ext == "xml":
        return parse_sysmon_xml(filepath)
    elif ext == "csv":
        return parse_csv_log(filepath)
    elif ext == "cef":
        return parse_cef(filepath)
    elif ext in ("json", "ndjson"):
        return parse_json_log(filepath)

    # Content-based detection
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        first_lines = f.read(2048)

    if first_lines.strip().startswith(("{", "[")):
        return parse_json_log(filepath)
    if first_lines.strip().startswith("CEF:"):
        return parse_cef(filepath)
    if first_lines.strip().startswith("<?xml") or first_lines.strip().startswith("<Event"):
        return parse_sysmon_xml(filepath)

    return parse_plain_text(filepath)


def _flatten_dict(d, prefix=""):
    """Recursively flatten a dict into a single string of key=value pairs."""
    parts = []
    if isinstance(d, dict):
        for k, v in d.items():
            new_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                parts.append(_flatten_dict(v, new_key))
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        parts.append(_flatten_dict(item, f"{new_key}[{i}]"))
                    else:
                        parts.append(f"{new_key}[{i}]={item}")
            else:
                parts.append(f"{new_key}={v}")
    else:
        parts.append(str(d))
    return " | ".join(parts)