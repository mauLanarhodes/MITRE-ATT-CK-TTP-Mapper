"""
sigma_generator.py — Sigma rule auto-generator for MITRE ATT&CK TTP Mapper.

Takes map_iocs() output and generates Sigma YAML detection rules.
Covers 20+ ATT&CK technique IDs with templated logsource, detection fields,
severity levels, and false-positive guidance.
"""

import hashlib
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

# We handle YAML serialization manually to avoid a hard dependency on pyyaml
# at import time; if pyyaml is available we use it, otherwise fall back.
try:
    import yaml  # type: ignore

    def _dump_yaml(data):
        return yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)
except ImportError:
    yaml = None  # type: ignore

    def _dump_yaml(data):
        """Minimal YAML serialiser for flat / shallow structures."""
        return _simple_yaml_dump(data)


# ---------------------------------------------------------------------------
# SIGMA TEMPLATES — one per technique ID
# Each template defines: logsource, detection_fields, level, falsepositives
# ---------------------------------------------------------------------------
SIGMA_TEMPLATES: Dict[str, dict] = {
    "T1059.001": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "powershell", "-enc", "Invoke-Expression", "IEX",
                "DownloadString", "bypass"
            ],
            "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"],
        },
        "level": "high",
        "falsepositives": ["Legitimate PowerShell administration scripts"],
    },
    "T1059.003": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["cmd /c", "cmd.exe /c", "cmd /k"],
            "ParentImage|endswith": ["\\explorer.exe"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate batch scripts run by administrators"],
    },
    "T1059.004": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection_fields": {
            "CommandLine|contains": ["/bin/bash -c", "/bin/sh -c", "chmod +x", "/dev/tcp"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate shell scripts", "Configuration management tools"],
    },
    "T1003": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "mimikatz", "sekurlsa", "lsass", "procdump",
                "comsvcs", "MiniDump", "hashdump"
            ],
        },
        "level": "critical",
        "falsepositives": ["Legitimate credential management tools in controlled testing"],
    },
    "T1053": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["schtasks /create", "schtasks /run"],
            "Image|endswith": ["\\schtasks.exe"],
        },
        "level": "medium",
        "falsepositives": ["Scheduled maintenance tasks", "Software update agents"],
    },
    "T1105": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "certutil -urlcache", "bitsadmin /transfer",
                "Invoke-WebRequest", "curl ", "wget "
            ],
        },
        "level": "high",
        "falsepositives": ["Legitimate software download by IT", "Package managers"],
    },
    "T1218.011": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "Image|endswith": ["\\rundll32.exe"],
            "CommandLine|contains": ["javascript:", "http://", "https://"],
        },
        "level": "high",
        "falsepositives": ["Legitimate DLL operations by system processes"],
    },
    "T1547.001": {
        "logsource": {"category": "registry_set", "product": "windows"},
        "detection_fields": {
            "TargetObject|contains": [
                "CurrentVersion\\Run",
                "CurrentVersion\\RunOnce",
            ],
        },
        "level": "high",
        "falsepositives": ["Legitimate software auto-start entries"],
    },
    "T1136": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["net user /add", "net localgroup", "New-LocalUser"],
        },
        "level": "high",
        "falsepositives": ["IT provisioning scripts"],
    },
    "T1078": {
        "logsource": {"category": "authentication", "product": "windows"},
        "detection_fields": {
            "EventID": [4624, 4625],
            "LogonType": [10, 3],
        },
        "level": "medium",
        "falsepositives": ["Legitimate remote logins", "Service accounts"],
    },
    "T1110": {
        "logsource": {"category": "authentication", "product": "windows"},
        "detection_fields": {
            "EventID": [4625],
            "Status|contains": ["0xC000006D", "0xC000006A"],
        },
        "level": "high",
        "falsepositives": ["Users mistyping passwords", "Account lockout testing"],
    },
    "T1070": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "wevtutil cl", "Clear-EventLog",
                "del /f /q *.log", "Remove-Item *.log"
            ],
        },
        "level": "high",
        "falsepositives": ["Legitimate log rotation"],
    },
    "T1562": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "Set-MpPreference -DisableRealtimeMonitoring",
                "netsh advfirewall set allprofiles state off",
                "sc stop WinDefend",
            ],
        },
        "level": "critical",
        "falsepositives": ["IT maintenance disabling security temporarily"],
    },
    "T1027": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "-EncodedCommand", "certutil -decode",
                "base64", "FromBase64String"
            ],
        },
        "level": "medium",
        "falsepositives": ["Legitimate encoded deployment scripts"],
    },
    "T1021.001": {
        "logsource": {"category": "network_connection", "product": "windows"},
        "detection_fields": {
            "DestinationPort": [3389],
            "Initiated": ["true"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate RDP administration"],
    },
    "T1021.002": {
        "logsource": {"category": "network_connection", "product": "windows"},
        "detection_fields": {
            "DestinationPort": [445],
            "Image|endswith": ["\\cmd.exe", "\\powershell.exe"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate file sharing", "Domain controller communication"],
    },
    "T1566": {
        "logsource": {"category": "proxy", "product": ""},
        "detection_fields": {
            "c-uri|contains": [".doc", ".docm", ".xls", ".xlsm", ".hta"],
            "cs-method": ["GET"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate document downloads"],
    },
    "T1190": {
        "logsource": {"category": "webserver", "product": ""},
        "detection_fields": {
            "cs-uri-query|contains": [
                "UNION SELECT", "OR 1=1", "../../", "%00",
                "cmd.exe", "/bin/sh"
            ],
        },
        "level": "critical",
        "falsepositives": ["Security scanning tools", "Penetration testing"],
    },
    "T1486": {
        "logsource": {"category": "file_event", "product": "windows"},
        "detection_fields": {
            "TargetFilename|endswith": [
                ".encrypted", ".locked", ".crypto", ".ransom"
            ],
        },
        "level": "critical",
        "falsepositives": ["Legitimate encryption software"],
    },
    "T1548": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "runas /user:", "eventvwr.exe", "fodhelper.exe"
            ],
            "IntegrityLevel": ["High"],
        },
        "level": "high",
        "falsepositives": ["Legitimate elevation by IT staff"],
    },
}

# Tactic tag lookup (technique ID prefix → ATT&CK tactic tag)
_TACTIC_TAGS = {
    "Execution": "attack.execution",
    "Persistence": "attack.persistence",
    "Privilege Escalation": "attack.privilege_escalation",
    "Defense Evasion": "attack.defense_evasion",
    "Credential Access": "attack.credential_access",
    "Discovery": "attack.discovery",
    "Lateral Movement": "attack.lateral_movement",
    "Collection": "attack.collection",
    "Command and Control": "attack.command_and_control",
    "Exfiltration": "attack.exfiltration",
    "Impact": "attack.impact",
    "Initial Access": "attack.initial_access",
    "Resource Development": "attack.resource_development",
}


def _deterministic_id(technique_id: str) -> str:
    """Generate a deterministic UUID-like ID from a technique ID string."""
    h = hashlib.sha256(f"sigma-{technique_id}".encode()).hexdigest()
    # Format as UUID: 8-4-4-4-12
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def generate_sigma_rules(
    mapping_results: List[dict],
    author: str = "MITRE ATT&CK TTP Mapper",
) -> List[dict]:
    """
    Generate Sigma detection rules from map_iocs() output.

    Args:
        mapping_results: Output of map_iocs().
        author: Author name for the generated rules.

    Returns:
        List of complete Sigma rule dicts.
    """
    today = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    # Deduplicate by technique ID — keep first match per technique
    seen_techniques = {}
    for r in mapping_results:
        tid = r["Technique ID"]
        if tid not in seen_techniques:
            seen_techniques[tid] = r

    rules = []
    for tid, result in seen_techniques.items():
        template = SIGMA_TEMPLATES.get(tid)
        if template is None:
            # No template for this technique — skip
            continue

        tactic = result.get("Tactic", "")
        tactic_tag = _TACTIC_TAGS.get(tactic, f"attack.{tactic.lower().replace(' ', '_')}")
        # Build technique tag: "attack.t1059.001"
        technique_tag = f"attack.{tid.lower()}"

        # Build detection block
        detection = {
            "selection": template["detection_fields"],
            "condition": "selection",
        }

        rule = {
            "title": f"Suspicious Activity — {result['Mapped Technique']} ({tid})",
            "id": _deterministic_id(tid),
            "status": "experimental",
            "description": (
                f"Detects potential {result['Mapped Technique']} activity "
                f"({tid}) mapped via MITRE ATT&CK TTP Mapper. "
                f"Tactic: {tactic}."
            ),
            "references": [f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"],
            "author": author,
            "date": today,
            "tags": [tactic_tag, technique_tag],
            "logsource": template["logsource"],
            "detection": detection,
            "falsepositives": template["falsepositives"],
            "level": template["level"],
        }
        rules.append(rule)

    return rules


def save_sigma_rules(
    rules: List[dict],
    output_dir: str = "output/sigma",
    single_file: bool = False,
) -> List[str]:
    """
    Write Sigma rules to YAML files.

    Args:
        rules: List of Sigma rule dicts.
        output_dir: Directory for output files.
        single_file: If True, write all rules to one combined YAML file.

    Returns:
        List of created file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    paths = []

    if single_file:
        combined_path = os.path.join(output_dir, "all_sigma_rules.yml")
        with open(combined_path, "w", encoding="utf-8") as f:
            for i, rule in enumerate(rules):
                if i > 0:
                    f.write("\n---\n")
                f.write(_dump_yaml(rule))
        paths.append(combined_path)
    else:
        for rule in rules:
            # Use technique ID from the title for the filename
            tid = rule["tags"][-1].replace("attack.", "").upper()
            safe_name = tid.replace(".", "_")
            filepath = os.path.join(output_dir, f"sigma_{safe_name}.yml")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(_dump_yaml(rule))
            paths.append(filepath)

    return paths


def rules_to_markdown(rules: List[dict]) -> str:
    """
    Generate a Markdown index document for the generated Sigma rules.

    Includes a table of all rules and sigma-cli conversion commands
    for Splunk, Elastic, and Microsoft Sentinel.
    """
    lines = [
        "# Sigma Rule Index",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Total Rules: {len(rules)}",
        "",
        "## Rules",
        "",
        "| # | Title | Technique | Level | Tactic |",
        "|---|-------|-----------|-------|--------|",
    ]

    for i, rule in enumerate(rules, 1):
        tags = rule.get("tags", [])
        technique = tags[-1].replace("attack.", "").upper() if tags else "N/A"
        tactic = tags[0].replace("attack.", "").replace("_", " ").title() if tags else "N/A"
        lines.append(
            f"| {i} | {rule['title']} | {technique} | {rule['level']} | {tactic} |"
        )

    lines.extend([
        "",
        "## Usage — Converting with sigma-cli",
        "",
        "Convert these Sigma rules to SIEM-specific queries using "
        "[sigma-cli](https://github.com/SigmaHQ/sigma-cli):",
        "",
        "### Splunk",
        "```bash",
        "sigma convert -t splunk -p sysmon sigma_rules/",
        "```",
        "",
        "### Elastic (Lucene)",
        "```bash",
        "sigma convert -t elasticsearch -p ecs_windows sigma_rules/",
        "```",
        "",
        "### Microsoft Sentinel (KQL)",
        "```bash",
        "sigma convert -t microsoft365defender sigma_rules/",
        "```",
        "",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fallback YAML serializer (used when PyYAML is not installed)
# ---------------------------------------------------------------------------
def _simple_yaml_dump(data, indent=0):
    """Minimal YAML serialiser for Sigma rule structures."""
    lines = []
    prefix = "  " * indent

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                lines.append(_simple_yaml_dump(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{prefix}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        # Inline dict in list — not needed for Sigma but handle anyway
                        lines.append(f"{prefix}  -")
                        lines.append(_simple_yaml_dump(item, indent + 2))
                    else:
                        lines.append(f"{prefix}  - {_yaml_scalar(item)}")
            else:
                lines.append(f"{prefix}{key}: {_yaml_scalar(value)}")
    elif isinstance(data, list):
        for item in data:
            lines.append(f"{prefix}- {_yaml_scalar(item)}")
    else:
        lines.append(f"{prefix}{_yaml_scalar(data)}")

    return "\n".join(lines)


def _yaml_scalar(value):
    """Format a scalar value for YAML output."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(value)
    s = str(value)
    # Quote if it contains special chars
    if any(c in s for c in ":#{}[]|>&*!%@`'\"\\") or s.startswith("-"):
        return f'"{s}"'
    return s