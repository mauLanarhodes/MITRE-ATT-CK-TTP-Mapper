"""
utils.py — I/O helpers for MITRE ATT&CK TTP Mapper.

Provides CSV, JSON, and Markdown export plus IOC file loading.
"""

import csv
import json
import os


def load_iocs(file_path):
    """Load IOC strings from a text file (one per line)."""
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def write_csv(data, output_path):
    """Write a list of dicts to a CSV file."""
    if not data:
        return
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    keys = data[0].keys()
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)


def write_json(data, output_path, indent=2):
    """Write data structure to a JSON file."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, default=str)


def write_markdown(results, output_path):
    """Write mapping results as a Markdown table."""
    if not results:
        return
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    headers = list(results[0].keys())
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# MITRE ATT&CK TTP Mapping Report\n\n")
        f.write("| " + " | ".join(headers) + " |\n")
        f.write("| " + " | ".join(["---"] * len(headers)) + " |\n")
        for row in results:
            values = [str(row.get(h, "")).replace("|", "\\|") for h in headers]
            f.write("| " + " | ".join(values) + " |\n")