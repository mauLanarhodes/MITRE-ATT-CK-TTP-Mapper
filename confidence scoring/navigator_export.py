"""
navigator_export.py — ATT&CK Navigator v4.5 layer generator.

Generates fully compliant Navigator JSON layers with color-coded
confidence levels, match counts, and complete metadata.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Tactic display name → Navigator short name
# ---------------------------------------------------------------------------
TACTIC_MAP = {
    # Enterprise
    "Reconnaissance": "reconnaissance",
    "Resource Development": "resource-development",
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
    # Mobile
    "Mobile Initial Access": "initial-access",
    "Mobile Execution": "execution",
    "Mobile Persistence": "persistence",
    "Mobile Privilege Escalation": "privilege-escalation",
    "Mobile Defense Evasion": "defense-evasion",
    "Mobile Credential Access": "credential-access",
    "Mobile Discovery": "discovery",
    "Mobile Collection": "collection",
    "Mobile Command and Control": "command-and-control",
    "Mobile Exfiltration": "exfiltration",
    "Mobile Impact": "impact",
    "Mobile Network Effects": "network-effects",
    "Mobile Remote Service Effects": "remote-service-effects",
    # ICS
    "ICS Initial Access": "initial-access",
    "ICS Execution": "execution",
    "ICS Persistence": "persistence",
    "ICS Privilege Escalation": "privilege-escalation",
    "ICS Evasion": "evasion",
    "ICS Discovery": "discovery",
    "ICS Lateral Movement": "lateral-movement",
    "ICS Collection": "collection",
    "ICS Command and Control": "command-and-control",
    "ICS Inhibit Response Function": "inhibit-response-function",
    "ICS Impair Process Control": "impair-process-control",
    "ICS Impact": "impact",
}

# Confidence rank (used only for metadata / tie-breaking)
_CONF_RANK = {"Low": 1, "Medium": 2, "High": 3}

# Heat map gradient colours (cool → hot)
HEATMAP_GRADIENT = ["#ffffff", "#ffe766", "#ff9632", "#e60000"]


def _tactic_short(display_name: str) -> str:
    """Convert tactic display name to Navigator short name."""
    return TACTIC_MAP.get(display_name, display_name.lower().replace(" ", "-"))


def generate_navigator_layer(
    results: List[dict],
    name: str = "ATT&CK TTP Mapper Layer",
    description: str = "Auto-generated layer from MITRE ATT&CK TTP Mapper",
    domain: str = "enterprise-attack",
    version: str = "4.5",
) -> Dict[str, Any]:
    """
    Build a Navigator v4.5 layer JSON from map_iocs() results.

    Aggregates by technique ID, picks highest confidence, counts matches,
    and builds coloured technique entries.
    """

    # --- Aggregate results per technique ---
    tech_agg: Dict[str, Dict[str, Any]] = {}
    for r in results:
        tid = r["Technique ID"]
        conf = r.get("Confidence", "Low")
        tactic = r.get("Tactic", "")
        ioc = r.get("IOC Summary", "")

        if tid not in tech_agg:
            tech_agg[tid] = {
                "technique_id": tid,
                "tactic": tactic,
                "highest_conf": conf,
                "count": 0,
                "ioc_summaries": [],
            }

        entry = tech_agg[tid]
        entry["count"] += 1
        if _CONF_RANK.get(conf, 0) > _CONF_RANK.get(entry["highest_conf"], 0):
            entry["highest_conf"] = conf
        # Keep first N IOC summaries for the comment
        if len(entry["ioc_summaries"]) < 5:
            entry["ioc_summaries"].append(ioc[:120])

    # --- Synthesise parent technique entries from sub-techniques ---
    # When sub-techniques like T1136.001 and T1136.002 both match, the
    # parent T1136 should also appear in the layer (aggregated).
    parent_agg: Dict[str, Dict[str, Any]] = {}
    for tid, agg in tech_agg.items():
        if "." in tid:
            parent_id = tid.split(".")[0]
            if parent_id not in tech_agg:  # only synthesise if not already present
                if parent_id not in parent_agg:
                    parent_agg[parent_id] = {
                        "technique_id": parent_id,
                        "tactic": agg["tactic"],
                        "highest_conf": agg["highest_conf"],
                        "count": 0,
                        "ioc_summaries": [],
                    }
                pa = parent_agg[parent_id]
                pa["count"] += agg["count"]
                if _CONF_RANK.get(agg["highest_conf"], 0) > _CONF_RANK.get(pa["highest_conf"], 0):
                    pa["highest_conf"] = agg["highest_conf"]
                for s in agg["ioc_summaries"]:
                    if len(pa["ioc_summaries"]) < 5:
                        pa["ioc_summaries"].append(s)

    tech_agg.update(parent_agg)

    # --- Build technique entries ---
    # Score = raw match count so the gradient reflects true frequency (heat)
    techniques = []
    max_count = max((a["count"] for a in tech_agg.values()), default=1)

    for tid, agg in tech_agg.items():
        conf = agg["highest_conf"]
        ioc_lines = "; ".join(agg["ioc_summaries"])
        comment = f"Matches: {agg['count']} | Confidence: {conf} | IOCs: {ioc_lines}"

        techniques.append({
            "techniqueID": tid,
            "tactic": _tactic_short(agg["tactic"]),
            # No per-technique color — gradient drives the heat map coloring
            "comment": comment,
            "score": agg["count"],  # raw frequency → heat intensity
            "enabled": True,
            "showSubtechniques": "." in tid,
            "metadata": [
                {"name": "match_count", "value": str(agg["count"])},
                {"name": "confidence", "value": conf},
            ],
        })

    # --- Full layer structure (Navigator v4.5 spec) ---
    layer: Dict[str, Any] = {
        "name": name,
        "versions": {
            "attack": "14",
            "navigator": version,
            "layer": "4.5",
        },
        "domain": domain,
        "description": description,
        "filters": {
            "platforms": [
                "Windows", "Linux", "macOS", "Azure AD", "Office 365",
                "SaaS", "IaaS", "Network", "Containers", "Google Workspace",
            ]
        },
        "sorting": 3,  # sort by technique name
        "layout": {
            "layout": "flat",           # flat is best for heat map readability
            "aggregateFunction": "max",  # parent shows hottest child score
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": HEATMAP_GRADIENT,
            "minValue": 0,
            "maxValue": max_count,
        },
        "legendItems": [
            {"label": "0 matches (cold)", "color": "#ffffff"},
            {"label": "Low frequency",    "color": "#ffe766"},
            {"label": "Medium frequency", "color": "#ff9632"},
            {"label": "High frequency (hot)", "color": "#e60000"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": False,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
        "metadata": [
            {"name": "generated_by", "value": "MITRE ATT&CK TTP Mapper"},
            {"name": "generated_at", "value": datetime.now(timezone.utc).isoformat()},
        ],
    }

    return layer


def save_layer(layer: Dict[str, Any], output_path: str) -> str:
    """Write a Navigator layer dict to a JSON file."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)
    return output_path


def generate_and_save(
    results: List[dict],
    output_path: str = "output/navigator_layer.json",
    **kwargs,
) -> str:
    """Convenience: generate a Navigator layer and save it in one call."""
    layer = generate_navigator_layer(results, **kwargs)
    return save_layer(layer, output_path)