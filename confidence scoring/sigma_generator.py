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
    # --- T1059: Command and Scripting Interpreter ---
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
    "T1059.002": {
        "logsource": {"category": "process_creation", "product": "macos"},
        "detection_fields": {
            "CommandLine|contains": ["osascript", "applescript", "do shell script"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate macOS automation scripts"],
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
    "T1059.005": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["cscript", "wscript", ".vbs", ".vba"],
            "Image|endswith": ["\\cscript.exe", "\\wscript.exe"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate VBScript administration"],
    },
    "T1059.006": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection_fields": {
            "CommandLine|contains": ["python -c", "python3 -c", "import os;", "import subprocess"],
        },
        "level": "low",
        "falsepositives": ["Legitimate Python scripts", "Data science workloads"],
    },
    "T1059.007": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["wscript .js", "cscript .js", "node -e", "mshta javascript"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate JavaScript automation"],
    },

    # --- T1003: OS Credential Dumping ---
    "T1003.001": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "mimikatz", "sekurlsa", "lsass", "procdump",
                "comsvcs", "MiniDump"
            ],
        },
        "level": "critical",
        "falsepositives": ["Legitimate credential management tools in controlled testing"],
    },
    "T1003.002": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["reg save HKLM\\SAM", "reg save HKLM\\SYSTEM"],
        },
        "level": "critical",
        "falsepositives": ["Disaster recovery backup procedures"],
    },
    "T1003.003": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["ntdsutil", "ntds.dit", "vssadmin create shadow"],
        },
        "level": "critical",
        "falsepositives": ["Legitimate Active Directory backup"],
    },
    "T1003.004": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["reg save HKLM\\SECURITY", "lsadump"],
        },
        "level": "critical",
        "falsepositives": ["Authorized security audits"],
    },
    "T1003.006": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["dcsync", "lsadump::dcsync", "GetChanges"],
        },
        "level": "critical",
        "falsepositives": ["Authorized penetration testing"],
    },
    "T1003.008": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection_fields": {
            "CommandLine|contains": ["cat /etc/shadow", "unshadow", "/etc/passwd"],
        },
        "level": "high",
        "falsepositives": ["Legitimate system administration"],
    },

    # --- T1053: Scheduled Task/Job ---
    "T1053.002": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["at.exe", "at /every"],
            "Image|endswith": ["\\at.exe"],
        },
        "level": "medium",
        "falsepositives": ["Legacy scheduled tasks"],
    },
    "T1053.003": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection_fields": {
            "CommandLine|contains": ["crontab -e", "crontab -l", "/etc/cron"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate cron jobs for maintenance"],
    },
    "T1053.005": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["schtasks /create", "schtasks /run"],
            "Image|endswith": ["\\schtasks.exe"],
        },
        "level": "medium",
        "falsepositives": ["Scheduled maintenance tasks", "Software update agents"],
    },
    "T1053.006": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection_fields": {
            "CommandLine|contains": ["systemctl enable", ".timer", "OnCalendarSec"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate systemd timer services"],
    },

    # --- T1105: Ingress Tool Transfer ---
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

    # --- T1218: System Binary Proxy Execution ---
    "T1218.001": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "Image|endswith": ["\\hh.exe"],
            "CommandLine|contains": [".chm"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate help file usage"],
    },
    "T1218.003": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "Image|endswith": ["\\cmstp.exe"],
            "CommandLine|contains": ["/s", "/au"],
        },
        "level": "high",
        "falsepositives": ["Legitimate CMSTP profile installations"],
    },
    "T1218.004": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "Image|endswith": ["\\installutil.exe"],
            "CommandLine|contains": ["/logfile=", "/LogToConsole"],
        },
        "level": "high",
        "falsepositives": ["Legitimate .NET assembly installations"],
    },
    "T1218.005": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "Image|endswith": ["\\mshta.exe"],
            "CommandLine|contains": ["vbscript:", "javascript:", "http://"],
        },
        "level": "high",
        "falsepositives": ["Legitimate HTA applications"],
    },
    "T1218.010": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "Image|endswith": ["\\regsvr32.exe"],
            "CommandLine|contains": ["/s", "scrobj.dll", "http://"],
        },
        "level": "high",
        "falsepositives": ["Legitimate COM registration"],
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
    "T1218.013": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "Image|endswith": ["\\mavinject.exe"],
            "CommandLine|contains": ["INJECTRUNNING"],
        },
        "level": "critical",
        "falsepositives": ["Very rare legitimate use"],
    },

    # --- T1547: Boot or Logon Autostart Execution ---
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
    "T1547.004": {
        "logsource": {"category": "registry_set", "product": "windows"},
        "detection_fields": {
            "TargetObject|contains": [
                "Winlogon\\Userinit",
                "Winlogon\\Shell",
                "Winlogon\\Notify",
            ],
        },
        "level": "high",
        "falsepositives": ["Legitimate Winlogon customizations"],
    },
    "T1547.009": {
        "logsource": {"category": "file_event", "product": "windows"},
        "detection_fields": {
            "TargetFilename|endswith": [".lnk"],
            "TargetFilename|contains": ["Startup"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate software startup shortcuts"],
    },

    # --- T1136: Create Account ---
    "T1136.001": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["net user /add", "New-LocalUser"],
        },
        "level": "high",
        "falsepositives": ["IT provisioning scripts"],
    },
    "T1136.002": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["dsadd user", "New-ADUser", "net user /add /domain"],
        },
        "level": "high",
        "falsepositives": ["Legitimate Active Directory provisioning"],
    },
    "T1136.003": {
        "logsource": {"category": "cloud", "product": "aws"},
        "detection_fields": {
            "eventName|contains": ["CreateUser", "CreateLoginProfile"],
        },
        "level": "high",
        "falsepositives": ["Legitimate IAM user creation by administrators"],
    },

    # --- T1078: Valid Accounts ---
    "T1078.001": {
        "logsource": {"category": "authentication", "product": "windows"},
        "detection_fields": {
            "EventID": [4624, 4625],
            "TargetUserName|contains": ["admin", "guest", "default"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate default account usage during setup"],
    },
    "T1078.002": {
        "logsource": {"category": "authentication", "product": "windows"},
        "detection_fields": {
            "EventID": [4624, 4625],
            "LogonType": [10, 3],
        },
        "level": "medium",
        "falsepositives": ["Legitimate remote logins", "Service accounts"],
    },
    "T1078.003": {
        "logsource": {"category": "authentication", "product": "windows"},
        "detection_fields": {
            "EventID": [4624],
            "LogonType": [2, 7],
        },
        "level": "low",
        "falsepositives": ["Normal interactive logins"],
    },
    "T1078.004": {
        "logsource": {"category": "cloud", "product": "aws"},
        "detection_fields": {
            "eventName|contains": ["ConsoleLogin"],
            "responseElements.ConsoleLogin": ["Success"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate cloud console access"],
    },

    # --- T1110: Brute Force ---
    "T1110.001": {
        "logsource": {"category": "authentication", "product": "windows"},
        "detection_fields": {
            "EventID": [4625],
            "Status|contains": ["0xC000006D", "0xC000006A"],
        },
        "level": "high",
        "falsepositives": ["Users mistyping passwords", "Account lockout testing"],
    },
    "T1110.002": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["hashcat", "john", "crack"],
            "Image|endswith": ["\\hashcat.exe", "\\john.exe"],
        },
        "level": "high",
        "falsepositives": ["Authorized password auditing"],
    },
    "T1110.003": {
        "logsource": {"category": "authentication", "product": "windows"},
        "detection_fields": {
            "EventID": [4625],
        },
        "level": "high",
        "falsepositives": ["Account lockout testing"],
    },
    "T1110.004": {
        "logsource": {"category": "authentication", "product": "windows"},
        "detection_fields": {
            "EventID": [4625],
            "Status|contains": ["0xC000006D"],
        },
        "level": "high",
        "falsepositives": ["Users reusing passwords across services"],
    },

    # --- T1070: Indicator Removal ---
    "T1070.001": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "wevtutil cl", "Clear-EventLog"
            ],
        },
        "level": "high",
        "falsepositives": ["Legitimate log rotation"],
    },
    "T1070.002": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection_fields": {
            "CommandLine|contains": [
                "rm /var/log", "shred", "truncate /var/log"
            ],
        },
        "level": "high",
        "falsepositives": ["Legitimate log rotation via logrotate"],
    },
    "T1070.003": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection_fields": {
            "CommandLine|contains": [
                "history -c", "rm .bash_history", "unset HISTFILE"
            ],
        },
        "level": "high",
        "falsepositives": ["Privacy-conscious users"],
    },
    "T1070.004": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "del /f /q *.log", "Remove-Item *.log", "sdelete"
            ],
        },
        "level": "high",
        "falsepositives": ["Legitimate cleanup scripts"],
    },
    "T1070.006": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["timestomp", "touch -t", "SetFileAttributes"],
        },
        "level": "high",
        "falsepositives": ["Build systems modifying timestamps"],
    },

    # --- T1562: Impair Defenses ---
    "T1562.001": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "Set-MpPreference -DisableRealtimeMonitoring",
                "sc stop WinDefend",
                "Disable-WindowsOptionalFeature",
            ],
        },
        "level": "critical",
        "falsepositives": ["IT maintenance disabling security temporarily"],
    },
    "T1562.002": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "auditpol /set", "Disable-EventLog",
            ],
        },
        "level": "critical",
        "falsepositives": ["Audit policy reconfiguration during compliance changes"],
    },
    "T1562.004": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "netsh advfirewall set allprofiles state off",
                "ufw disable",
                "iptables -F",
            ],
        },
        "level": "critical",
        "falsepositives": ["Firewall reconfiguration during maintenance"],
    },
    "T1562.008": {
        "logsource": {"category": "cloud", "product": "aws"},
        "detection_fields": {
            "eventName|contains": ["StopLogging", "DeleteTrail", "UpdateTrail"],
        },
        "level": "critical",
        "falsepositives": ["Authorized CloudTrail reconfiguration"],
    },

    # --- T1027: Obfuscated Files or Information ---
    "T1027.010": {
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
    "T1027.006": {
        "logsource": {"category": "file_event", "product": "windows"},
        "detection_fields": {
            "TargetFilename|endswith": [".html", ".htm"],
            "CommandLine|contains": ["msSaveOrOpenBlob", "Blob"],
        },
        "level": "high",
        "falsepositives": ["Legitimate web applications"],
    },

    # --- T1055: Process Injection ---
    "T1055.001": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "CreateRemoteThread", "LoadLibrary", "NtCreateThreadEx"
            ],
        },
        "level": "critical",
        "falsepositives": ["Legitimate DLL loading by trusted applications"],
    },
    "T1055.012": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "NtUnmapViewOfSection", "hollowing"
            ],
        },
        "level": "critical",
        "falsepositives": ["Very rare legitimate use"],
    },

    # --- T1021: Remote Services ---
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
    "T1021.004": {
        "logsource": {"category": "network_connection", "product": "linux"},
        "detection_fields": {
            "DestinationPort": [22],
        },
        "level": "low",
        "falsepositives": ["Legitimate SSH administration"],
    },
    "T1021.006": {
        "logsource": {"category": "network_connection", "product": "windows"},
        "detection_fields": {
            "DestinationPort": [5985, 5986],
        },
        "level": "medium",
        "falsepositives": ["Legitimate WinRM administration"],
    },

    # --- T1548: Abuse Elevation Control Mechanism ---
    "T1548.001": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection_fields": {
            "CommandLine|contains": ["chmod u+s", "chmod g+s", "chmod 4755"],
        },
        "level": "high",
        "falsepositives": ["Legitimate setuid configuration"],
    },
    "T1548.002": {
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
    "T1548.003": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection_fields": {
            "CommandLine|contains": ["sudo", "visudo", "sudoers"],
        },
        "level": "medium",
        "falsepositives": ["Normal sudo usage by administrators"],
    },

    # --- T1552: Unsecured Credentials ---
    "T1552.001": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["findstr /si password", "dir /s password"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate password file audits"],
    },
    "T1552.004": {
        "logsource": {"category": "file_access", "product": "linux"},
        "detection_fields": {
            "TargetFilename|endswith": [".pem", ".key", "id_rsa"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate key management"],
    },
    "T1552.006": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["Groups.xml", "cpassword"],
        },
        "level": "high",
        "falsepositives": ["Authorized GPP auditing"],
    },

    # --- T1566: Phishing ---
    "T1566.001": {
        "logsource": {"category": "proxy", "product": ""},
        "detection_fields": {
            "c-uri|contains": [".doc", ".docm", ".xls", ".xlsm", ".hta"],
            "cs-method": ["GET"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate document downloads"],
    },
    "T1566.002": {
        "logsource": {"category": "proxy", "product": ""},
        "detection_fields": {
            "c-uri|contains": ["click", "redirect", "track"],
            "cs-referer|contains": ["mail.google.com", "outlook.live.com"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate email link clicks"],
    },

    # --- Other techniques ---
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
    "T1560.001": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": [
                "rar a", "7z a", "zip", "tar -czf"
            ],
        },
        "level": "medium",
        "falsepositives": ["Legitimate backup and archiving"],
    },
    "T1543.003": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_fields": {
            "CommandLine|contains": ["sc create", "New-Service"],
        },
        "level": "medium",
        "falsepositives": ["Legitimate service installations"],
    },
}

# Tactic tag lookup (technique ID prefix → ATT&CK tactic tag)
_TACTIC_TAGS = {
    # Enterprise
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
    # Mobile
    "Mobile Initial Access": "attack.initial_access",
    "Mobile Execution": "attack.execution",
    "Mobile Persistence": "attack.persistence",
    "Mobile Privilege Escalation": "attack.privilege_escalation",
    "Mobile Defense Evasion": "attack.defense_evasion",
    "Mobile Credential Access": "attack.credential_access",
    "Mobile Discovery": "attack.discovery",
    "Mobile Collection": "attack.collection",
    "Mobile Command and Control": "attack.command_and_control",
    "Mobile Exfiltration": "attack.exfiltration",
    "Mobile Impact": "attack.impact",
    "Mobile Network Effects": "attack.network_effects",
    "Mobile Remote Service Effects": "attack.remote_service_effects",
    # ICS
    "ICS Initial Access": "attack.initial_access",
    "ICS Execution": "attack.execution",
    "ICS Persistence": "attack.persistence",
    "ICS Privilege Escalation": "attack.privilege_escalation",
    "ICS Evasion": "attack.evasion",
    "ICS Discovery": "attack.discovery",
    "ICS Lateral Movement": "attack.lateral_movement",
    "ICS Collection": "attack.collection",
    "ICS Command and Control": "attack.command_and_control",
    "ICS Inhibit Response Function": "attack.inhibit_response_function",
    "ICS Impair Process Control": "attack.impair_process_control",
    "ICS Impact": "attack.impact",
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