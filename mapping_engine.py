"""
mapping_engine.py — Core TTP matching engine for MITRE ATT&CK TTP Mapper.

Maps IOCs and log events to MITRE ATT&CK techniques using compiled regex
patterns with confidence scoring (High/Medium/Low) and multi-pattern boosting.
"""

import re
from datetime import datetime, timezone
from collections import Counter

# ---------------------------------------------------------------------------
# TECHNIQUE DATABASE
# Each entry: (technique_id, name, tactic, [regex_patterns], base_confidence)
# base_confidence: "High", "Medium", or "Low"
# ---------------------------------------------------------------------------
TECHNIQUE_DB = [
    # --- Execution ---
    ("T1059.001", "PowerShell", "Execution",
     [r"powershell", r"pwsh", r"invoke-expression", r"iex\s*\(", r"invoke-command",
      r"new-object\s+net\.webclient", r"downloadstring", r"encodedcommand",
      r"-enc\s+", r"bypass\s+executionpolicy", r"set-executionpolicy"],
     "High"),

    ("T1059.003", "Windows Command Shell", "Execution",
     [r"cmd\.exe", r"cmd\s+/c", r"cmd\s+/k", r"command\s+shell",
      r"bat\s+file", r"\.bat\b", r"\.cmd\b"],
     "Medium"),

    ("T1059.004", "Unix Shell", "Execution",
     [r"/bin/bash", r"/bin/sh", r"bash\s+-c", r"sh\s+-c",
      r"chmod\s+\+x", r"\.sh\b", r"/dev/tcp", r"mkfifo"],
     "Medium"),

    ("T1059.005", "Visual Basic", "Execution",
     [r"vbscript", r"cscript", r"wscript", r"\.vbs\b", r"\.vba\b",
      r"macro\s+enabled", r"createobject"],
     "Medium"),

    ("T1059.006", "Python", "Execution",
     [r"python\s+-c", r"python3?\s+.*\.py", r"import\s+os\s*;",
      r"import\s+subprocess", r"exec\(", r"eval\("],
     "Low"),

    ("T1059.007", "JavaScript", "Execution",
     [r"node\s+-e", r"\.js\b.*eval", r"wscript.*\.js",
      r"cscript.*\.js", r"mshta.*javascript"],
     "Low"),

    # --- Persistence ---
    ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence",
     [r"currentversion\\run", r"hklm\\software\\microsoft\\windows\\currentversion\\run",
      r"hkcu\\software\\microsoft\\windows\\currentversion\\run",
      r"startup\s+folder", r"shell:startup", r"autostart"],
     "High"),

    ("T1053", "Scheduled Task/Job", "Persistence",
     [r"schtasks", r"at\s+\d{1,2}:", r"crontab", r"cron\s+job",
      r"scheduled\s+task", r"task\s+scheduler", r"systemd\s+timer"],
     "High"),

    ("T1136", "Create Account", "Persistence",
     [r"net\s+user\s+/add", r"net\s+user\s+.*\s+/add", r"useradd",
      r"adduser", r"new-localuser", r"create\s+user", r"createuser",
      r"create\s+account", r"iam.*createuser"],
     "High"),

    ("T1543.003", "Windows Service", "Persistence",
     [r"sc\s+create", r"new-service", r"install\s+service",
      r"services\.exe", r"service\s+creation"],
     "Medium"),

    # --- Privilege Escalation ---
    ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation",
     [r"sudo", r"runas", r"uac\s+bypass", r"privilege\s+escalation",
      r"elevat", r"admin\s+rights", r"setuid", r"suid"],
     "High"),

    # --- Defense Evasion ---
    ("T1218.011", "Rundll32", "Defense Evasion",
     [r"rundll32", r"rundll32\.exe", r"dll\s+proxy",
      r"signed\s+binary\s+proxy"],
     "High"),

    ("T1070", "Indicator Removal", "Defense Evasion",
     [r"clear.*log", r"wevtutil\s+cl", r"del\s+.*\.log", r"rm\s+.*\.log",
      r"event\s+log\s+clear", r"remove.*evidence", r"indicator\s+removal",
      r"delete.*logs", r"log\s+tampering", r"stoplogging", r"deletetrail"],
     "High"),

    ("T1562", "Impair Defenses", "Defense Evasion",
     [r"disable.*firewall", r"disable.*antivirus", r"disable.*defender",
      r"tamper.*protection", r"stop.*security", r"kill.*av",
      r"disable.*logging", r"impair\s+defens"],
     "High"),

    ("T1027", "Obfuscated Files or Information", "Defense Evasion",
     [r"obfuscat", r"base64", r"encode", r"packed\s+binary",
      r"xor\s+encr", r"certutil\s+-decode", r"certutil\s+.*-encode"],
     "Medium"),

    ("T1036", "Masquerading", "Defense Evasion",
     [r"masquerad", r"renamed\s+binary", r"fake\s+extension",
      r"double\s+extension", r"\.exe\.txt"],
     "Medium"),

    ("T1055", "Process Injection", "Defense Evasion",
     [r"process\s+inject", r"dll\s+inject", r"createremotethread",
      r"ntcreatethreadex", r"virtualalloc", r"writeprocessmemory",
      r"hollowing"],
     "High"),

    ("T1140", "Deobfuscate/Decode Files", "Defense Evasion",
     [r"certutil\s+-decode", r"base64\s+-d", r"deobfuscat",
      r"decode\s+payload"],
     "Medium"),

    # --- Credential Access ---
    ("T1003", "OS Credential Dumping", "Credential Access",
     [r"mimikatz", r"lsass", r"credential\s+dump", r"hashdump",
      r"sekurlsa", r"procdump.*lsass", r"ntds\.dit", r"sam\s+database",
      r"password\s+dump", r"comsvcs.*minidump"],
     "High"),

    ("T1078", "Valid Accounts", "Credential Access",
     [r"valid\s+account", r"legitimate\s+credential", r"stolen\s+credential",
      r"compromised\s+account", r"credential\s+reuse", r"default\s+password",
      r"default\s+credential", r"consolelogin"],
     "Medium"),

    ("T1110", "Brute Force", "Credential Access",
     [r"brute\s*force", r"password\s+spray", r"credential\s+stuff",
      r"dictionary\s+attack", r"login\s+attempt", r"failed\s+login",
      r"authentication\s+fail", r"accessdenied", r"multiple.*fail.*login"],
     "High"),

    ("T1552", "Unsecured Credentials", "Credential Access",
     [r"password\s+in\s+file", r"credential\s+in\s+file", r"\.env\s+file",
      r"hardcoded\s+password", r"plaintext\s+password", r"getsecretvalue",
      r"get.*secret"],
     "Medium"),

    # --- Discovery ---
    ("T1082", "System Information Discovery", "Discovery",
     [r"systeminfo", r"uname\s+-a", r"hostname", r"whoami",
      r"describeinstances", r"describe\s+instance"],
     "Low"),

    ("T1083", "File and Directory Discovery", "Discovery",
     [r"dir\s+/s", r"find\s+/", r"ls\s+-la", r"tree\s+/f",
      r"file\s+enumerat"],
     "Low"),

    ("T1046", "Network Service Scanning", "Discovery",
     [r"nmap", r"port\s+scan", r"network\s+scan", r"masscan",
      r"service\s+scan"],
     "Medium"),

    ("T1018", "Remote System Discovery", "Discovery",
     [r"net\s+view", r"net\s+group", r"arp\s+-a", r"nbtscan",
      r"ping\s+sweep"],
     "Low"),

    # --- Lateral Movement ---
    ("T1021.001", "Remote Desktop Protocol", "Lateral Movement",
     [r"rdp", r"remote\s+desktop", r"mstsc", r"port\s+3389",
      r"terminal\s+service"],
     "Medium"),

    ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement",
     [r"smb", r"admin\$", r"c\$", r"ipc\$", r"net\s+use",
      r"psexec", r"windows\s+admin\s+share", r"port\s+445"],
     "Medium"),

    ("T1021.004", "SSH", "Lateral Movement",
     [r"ssh\s+", r"port\s+22\b", r"sshd", r"authorized_keys",
      r"id_rsa"],
     "Low"),

    ("T1570", "Lateral Tool Transfer", "Lateral Movement",
     [r"lateral\s+tool\s+transfer", r"copy.*remote", r"scp\s+",
      r"wmic.*process.*call.*create"],
     "Medium"),

    # --- Collection ---
    ("T1005", "Data from Local System", "Collection",
     [r"data\s+collect", r"file\s+collect", r"staging\s+directory",
      r"archive.*compress", r"sensitive\s+file"],
     "Low"),

    ("T1560", "Archive Collected Data", "Collection",
     [r"rar\s+a\s+", r"7z\s+a\s+", r"zip\s+", r"tar\s+-czf",
      r"compress.*exfil", r"archive.*data"],
     "Medium"),

    # --- Command and Control ---
    ("T1105", "Ingress Tool Transfer", "Command and Control",
     [r"curl\s+", r"wget\s+", r"certutil.*urlcache", r"bitsadmin.*transfer",
      r"invoke-webrequest", r"download.*file", r"tool\s+transfer",
      r"ingress.*transfer"],
     "High"),

    ("T1071", "Application Layer Protocol", "Command and Control",
     [r"c2\s+server", r"command\s+and\s+control", r"beacon",
      r"callback", r"c2\s+channel", r"covert\s+channel"],
     "Medium"),

    ("T1572", "Protocol Tunneling", "Command and Control",
     [r"tunnel", r"ssh\s+tunnel", r"port\s+forward",
      r"ngrok", r"chisel", r"dns\s+tunnel"],
     "Medium"),

    # --- Exfiltration ---
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
     [r"exfiltrat", r"data\s+theft", r"data\s+leak",
      r"steal\s+data", r"upload.*stolen"],
     "Medium"),

    ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration",
     [r"dns\s+exfil", r"icmp\s+exfil", r"exfil.*dns",
      r"exfil.*protocol"],
     "Medium"),

    # --- Impact ---
    ("T1486", "Data Encrypted for Impact", "Impact",
     [r"ransomware", r"encrypt.*file", r"ransom\s+note",
      r"\.locked\b", r"file\s+encrypt", r"crypto.*lock",
      r"your\s+files\s+have\s+been\s+encrypted"],
     "High"),

    ("T1489", "Service Stop", "Impact",
     [r"stop.*service", r"sc\s+stop", r"net\s+stop",
      r"systemctl\s+stop", r"kill.*process", r"terminateinstances"],
     "Medium"),

    ("T1485", "Data Destruction", "Impact",
     [r"wipe\s+disk", r"data\s+destruct", r"rm\s+-rf\s+/",
      r"format\s+c:", r"shred", r"destroy\s+data"],
     "High"),

    # --- Initial Access ---
    ("T1566", "Phishing", "Initial Access",
     [r"phish", r"spear.*phish", r"malicious\s+email",
      r"malicious\s+attachment", r"social\s+engineer",
      r"suspicious\s+email", r"clickbait\s+link"],
     "High"),

    ("T1190", "Exploit Public-Facing Application", "Initial Access",
     [r"exploit.*public", r"web\s+shell", r"sql\s+inject",
      r"remote\s+code\s+execution", r"rce\b", r"cve-\d{4}",
      r"vulnerability\s+exploit", r"0-day", r"zero.day"],
     "High"),

    ("T1078.004", "Cloud Accounts", "Initial Access",
     [r"cloud\s+account", r"iam\s+user", r"service\s+account\s+compromise",
      r"cloud\s+credential"],
     "Medium"),

    # --- Resource Development ---
    ("T1583", "Acquire Infrastructure", "Resource Development",
     [r"acquire\s+infrastructure", r"bulletproof\s+host",
      r"domain\s+registr", r"vps\s+provision"],
     "Low"),

    # --- Execution (additional) ---
    ("T1204", "User Execution", "Execution",
     [r"user\s+click", r"user\s+open", r"macro\s+enabl",
      r"lnk\s+file", r"shortcut\s+file", r"double.*click"],
     "Medium"),

    ("T1047", "Windows Management Instrumentation", "Execution",
     [r"wmic", r"wmi\s+", r"win32_process", r"management\s+instrumentation"],
     "Medium"),
]

# Compile all regex patterns for performance
_COMPILED_DB = []
for tech_id, name, tactic, patterns, confidence in TECHNIQUE_DB:
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    _COMPILED_DB.append((tech_id, name, tactic, compiled, confidence))

# Confidence ranking for comparisons
CONFIDENCE_RANK = {"High": 3, "Medium": 2, "Low": 1}


def map_iocs(ioc_list, min_confidence="Low", timestamp=None, source="manual"):
    """
    Map a list of IOC strings to MITRE ATT&CK techniques.

    Args:
        ioc_list: List of IOC/log event strings to analyze.
        min_confidence: Minimum confidence level to include ("Low", "Medium", "High").
        timestamp: Optional timestamp string; defaults to current UTC time.
        source: Label for the data source (e.g., "sysmon", "cloudtrail").

    Returns:
        List of dicts, each containing:
            IOC Summary, Technique ID, Mapped Technique, Tactic,
            Confidence, Matched Keywords, Timestamp, Source
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    min_rank = CONFIDENCE_RANK.get(min_confidence, 1)
    results = []

    for ioc in ioc_list:
        if not ioc or not ioc.strip():
            continue
        ioc_lower = ioc.lower()

        for tech_id, name, tactic, compiled_patterns, base_conf in _COMPILED_DB:
            matched_keywords = []
            for pattern in compiled_patterns:
                match = pattern.search(ioc_lower)
                if match:
                    matched_keywords.append(match.group())

            if not matched_keywords:
                continue

            # Multi-pattern boosting: if 3+ patterns match, boost confidence
            effective_conf = base_conf
            if len(matched_keywords) >= 3 and CONFIDENCE_RANK[base_conf] < 3:
                rank = CONFIDENCE_RANK[base_conf] + 1
                effective_conf = {v: k for k, v in CONFIDENCE_RANK.items()}[rank]

            if CONFIDENCE_RANK[effective_conf] < min_rank:
                continue

            results.append({
                "IOC Summary": ioc.strip(),
                "Technique ID": tech_id,
                "Mapped Technique": name,
                "Tactic": tactic,
                "Confidence": effective_conf,
                "Matched Keywords": ", ".join(sorted(set(matched_keywords))),
                "Timestamp": timestamp,
                "Source": source,
            })

    return results


def get_tactic_summary(results):
    """Return a Counter of tactic → count from mapping results."""
    return dict(Counter(r["Tactic"] for r in results))


def get_technique_frequency(results):
    """Return a Counter of 'TechniqueID: Name' → count from mapping results."""
    return dict(Counter(f"{r['Technique ID']}: {r['Mapped Technique']}" for r in results))


def get_all_techniques():
    """Return summary list of all techniques in the database."""
    return [
        {
            "technique_id": tech_id,
            "name": name,
            "tactic": tactic,
            "pattern_count": len(patterns),
            "base_confidence": confidence,
        }
        for tech_id, name, tactic, patterns, confidence in TECHNIQUE_DB
    ]


def get_all_tactics():
    """Return sorted list of unique tactics covered by the database."""
    return sorted(set(tactic for _, _, tactic, _, _ in TECHNIQUE_DB))