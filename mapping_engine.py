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
#
# Sub-techniques sourced from MITRE_ATTACK_Complete.xlsx (Enterprise sheet).
# ---------------------------------------------------------------------------
TECHNIQUE_DB = [
    # ===================================================================
    # EXECUTION (TA0002)
    # ===================================================================

    # --- T1059: Command and Scripting Interpreter ---
    ("T1059.001", "PowerShell", "Execution",
     [r"powershell", r"pwsh", r"invoke-expression", r"iex\s*\(", r"invoke-command",
      r"new-object\s+net\.webclient", r"downloadstring", r"encodedcommand",
      r"-enc\s+", r"bypass\s+executionpolicy", r"set-executionpolicy"],
     "High"),

    ("T1059.002", "AppleScript", "Execution",
     [r"osascript", r"applescript", r"tell\s+application",
      r"do\s+shell\s+script", r"osacompile"],
     "Medium"),

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

    ("T1059.008", "Network Device CLI", "Execution",
     [r"network\s+device\s+cli", r"cisco\s+ios", r"enable\s+mode",
      r"configure\s+terminal", r"show\s+running-config"],
     "Low"),

    ("T1059.009", "Cloud API", "Execution",
     [r"cloud\s+api", r"aws\s+cli", r"az\s+cli", r"gcloud\s+",
      r"invoke-restmethod.*azure", r"boto3", r"aws\s+sts"],
     "Low"),

    ("T1059.010", "AutoHotKey & AutoIT", "Execution",
     [r"autohotkey", r"autoit", r"\.ahk\b", r"\.au3\b",
      r"autoit3\.exe", r"autohotkey\.exe"],
     "Medium"),

    ("T1059.011", "Lua", "Execution",
     [r"lua\s+-e", r"\.lua\b", r"luajit", r"dofile\s*\(",
      r"loadstring\s*\(", r"require\s*\("],
     "Low"),

    # --- T1053: Scheduled Task/Job ---
    ("T1053.002", "At", "Persistence",
     [r"\bat\s+\d{1,2}:", r"\bat\.exe", r"at\s+/every"],
     "High"),

    ("T1053.003", "Cron", "Persistence",
     [r"crontab", r"cron\s+job", r"/etc/cron", r"cron\.d/",
      r"crontab\s+-e", r"crontab\s+-l"],
     "High"),

    ("T1053.005", "Scheduled Task", "Persistence",
     [r"schtasks", r"scheduled\s+task", r"task\s+scheduler",
      r"schtasks\s+/create", r"schtasks\s+/run", r"schtasks\s+/delete"],
     "High"),

    ("T1053.006", "Systemd Timers", "Persistence",
     [r"systemd\s+timer", r"\.timer\b", r"systemctl.*timer",
      r"ontimeactivesec", r"oncalendarsec"],
     "Medium"),

    ("T1053.007", "Container Orchestration Job", "Persistence",
     [r"cronjob.*kube", r"kubernetes.*job", r"kubectl.*create\s+job",
      r"container\s+orchestration\s+job"],
     "Low"),

    # --- T1204: User Execution ---
    ("T1204.001", "Malicious Link", "Execution",
     [r"malicious\s+link", r"user\s+click.*link", r"phishing\s+link",
      r"clickbait\s+link", r"click.*malicious"],
     "Medium"),

    ("T1204.002", "Malicious File", "Execution",
     [r"malicious\s+file", r"user\s+open.*file", r"macro\s+enabl",
      r"lnk\s+file", r"shortcut\s+file", r"double.*click",
      r"user\s+click", r"user\s+open"],
     "Medium"),

    ("T1204.003", "Malicious Image", "Execution",
     [r"malicious\s+image", r"malicious\s+container\s+image",
      r"trojanized\s+image", r"backdoor.*container\s+image"],
     "Low"),

    # --- T1047: Windows Management Instrumentation ---
    ("T1047", "Windows Management Instrumentation", "Execution",
     [r"wmic", r"wmi\s+", r"win32_process", r"management\s+instrumentation"],
     "Medium"),

    # ===================================================================
    # PERSISTENCE (TA0003)
    # ===================================================================

    # --- T1547: Boot or Logon Autostart Execution ---
    ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence",
     [r"currentversion\\run", r"hklm\\software\\microsoft\\windows\\currentversion\\run",
      r"hkcu\\software\\microsoft\\windows\\currentversion\\run",
      r"startup\s+folder", r"shell:startup", r"autostart"],
     "High"),

    ("T1547.002", "Authentication Package", "Persistence",
     [r"authentication\s+package", r"lsa\\.*authentication",
      r"hklm\\system\\currentcontrolset\\control\\lsa",
      r"security\s+package"],
     "Medium"),

    ("T1547.003", "Time Providers", "Persistence",
     [r"time\s+provider", r"w32time", r"w32tm",
      r"timeproviders", r"hklm\\system\\currentcontrolset\\services\\w32time"],
     "Medium"),

    ("T1547.004", "Winlogon Helper DLL", "Persistence",
     [r"winlogon", r"winlogon\s+helper", r"userinit",
      r"hklm\\software\\microsoft\\windows nt\\currentversion\\winlogon",
      r"shell\s+value.*winlogon", r"notify\s+value.*winlogon"],
     "Medium"),

    ("T1547.005", "Security Support Provider", "Persistence",
     [r"security\s+support\s+provider", r"ssp\s+dll",
      r"hklm\\system\\currentcontrolset\\control\\lsa\\security\s+packages",
      r"addsspprovider"],
     "Medium"),

    ("T1547.006", "Kernel Modules and Extensions", "Persistence",
     [r"insmod", r"modprobe", r"kernel\s+module", r"\.ko\b",
      r"kext\s+load", r"kernel\s+extension", r"lkm\b"],
     "Medium"),

    ("T1547.007", "Re-opened Applications", "Persistence",
     [r"re-opened\s+application", r"loginwindow.*plist",
      r"saved\s+application\s+state", r"nsquitappsonwindowsclose"],
     "Low"),

    ("T1547.008", "LSASS Driver", "Persistence",
     [r"lsass\s+driver", r"lsa\s+driver",
      r"hklm\\system\\currentcontrolset\\control\\lsa.*drivers"],
     "High"),

    ("T1547.009", "Shortcut Modification", "Persistence",
     [r"shortcut\s+modif", r"\.lnk\s+modif", r"lnk\s+hijack",
      r"modify.*shortcut", r"desktop\.ini\s+modif"],
     "Medium"),

    ("T1547.010", "Port Monitors", "Persistence",
     [r"port\s+monitor", r"addmonitor",
      r"hklm\\system\\currentcontrolset\\control\\print\\monitors"],
     "Medium"),

    ("T1547.012", "Print Processors", "Persistence",
     [r"print\s+processor",
      r"hklm\\system\\currentcontrolset\\control\\print\\environments.*print\s+processors",
      r"addprintprocessor"],
     "Medium"),

    ("T1547.013", "XDG Autostart Entries", "Persistence",
     [r"xdg\s+autostart", r"\.config/autostart", r"/etc/xdg/autostart",
      r"\.desktop\b.*autostart"],
     "Low"),

    ("T1547.014", "Active Setup", "Persistence",
     [r"active\s+setup", r"hklm\\software\\microsoft\\active\s+setup",
      r"stubpath"],
     "Medium"),

    ("T1547.015", "Login Items", "Persistence",
     [r"login\s+items", r"loginitems", r"smloginitemsetenabled",
      r"launchagent.*login"],
     "Low"),

    # --- T1136: Create Account ---
    ("T1136.001", "Local Account", "Persistence",
     [r"net\s+user\s+/add", r"net\s+user\s+.*\s+/add", r"useradd",
      r"adduser", r"new-localuser", r"create\s+local\s+account",
      r"local\s+account\s+creat"],
     "High"),

    ("T1136.002", "Domain Account", "Persistence",
     [r"net\s+user\s+/add\s+/domain", r"dsadd\s+user", r"new-aduser",
      r"create\s+domain\s+account", r"domain\s+account\s+creat",
      r"active\s+directory.*create\s+user"],
     "High"),

    ("T1136.003", "Cloud Account", "Persistence",
     [r"iam.*createuser", r"iam.*create-user", r"new-azureaduser",
      r"gcloud.*iam.*create", r"create\s+cloud\s+account",
      r"cloud\s+account\s+creat", r"create\s+user", r"createuser",
      r"create\s+account"],
     "High"),

    # --- T1543: Create or Modify System Process ---
    ("T1543.001", "Launch Agent", "Persistence",
     [r"launch\s*agent", r"launchagent", r"/library/launchagents",
      r"~/library/launchagents", r"launchctl\s+load.*agent"],
     "Medium"),

    ("T1543.002", "Systemd Service", "Persistence",
     [r"systemd\s+service", r"systemctl\s+enable", r"/etc/systemd/system",
      r"\.service\b.*\[unit\]", r"systemctl\s+daemon-reload"],
     "Medium"),

    ("T1543.003", "Windows Service", "Persistence",
     [r"sc\s+create", r"new-service", r"install\s+service",
      r"services\.exe", r"service\s+creation"],
     "Medium"),

    ("T1543.004", "Launch Daemon", "Persistence",
     [r"launch\s*daemon", r"launchdaemon", r"/library/launchdaemons",
      r"launchctl\s+load.*daemon"],
     "Medium"),

    ("T1543.005", "Container Service", "Persistence",
     [r"container\s+service", r"docker\s+service\s+create",
      r"kubernetes\s+daemonset", r"k8s\s+service\s+creat"],
     "Low"),

    # ===================================================================
    # PRIVILEGE ESCALATION (TA0004)
    # ===================================================================

    # --- T1548: Abuse Elevation Control Mechanism ---
    ("T1548.001", "Setuid and Setgid", "Privilege Escalation",
     [r"setuid", r"suid", r"setgid", r"sgid\b",
      r"chmod\s+[24]?[0-7]{3}", r"chmod\s+u\+s", r"chmod\s+g\+s"],
     "High"),

    ("T1548.002", "Bypass User Account Control", "Privilege Escalation",
     [r"uac\s+bypass", r"fodhelper", r"eventvwr\.exe.*bypass",
      r"sdclt.*bypass", r"cmstp.*uac", r"bypassuac",
      r"runas", r"admin\s+rights"],
     "High"),

    ("T1548.003", "Sudo and Sudo Caching", "Privilege Escalation",
     [r"sudo\b", r"sudo\s+cach", r"sudoers", r"visudo",
      r"sudo\s+-l", r"timestamp_timeout"],
     "High"),

    ("T1548.004", "Elevated Execution with Prompt", "Privilege Escalation",
     [r"elevated\s+execution", r"privilege\s+escalation",
      r"authorizationexecutewithprivileges", r"elevat.*prompt",
      r"admin\s+prompt"],
     "Medium"),

    ("T1548.005", "Temporary Elevated Cloud Access", "Privilege Escalation",
     [r"temporary\s+elevated\s+cloud", r"assume.*role",
      r"sts.*assume", r"cloud\s+privilege\s+escalat",
      r"elevated\s+cloud\s+access"],
     "Medium"),

    ("T1548.006", "TCC Manipulation", "Privilege Escalation",
     [r"tcc\s+manipulat", r"tcc\s+bypass", r"tcc\.db",
      r"transparency.*consent.*control", r"full\s+disk\s+access\s+bypass"],
     "Medium"),

    # ===================================================================
    # DEFENSE EVASION (TA0005)
    # ===================================================================

    # --- T1218: System Binary Proxy Execution ---
    ("T1218.001", "Compiled HTML File", "Defense Evasion",
     [r"hh\.exe", r"\.chm\b", r"compiled\s+html", r"html\s+help"],
     "Medium"),

    ("T1218.002", "Control Panel", "Defense Evasion",
     [r"control\.exe", r"\.cpl\b", r"control\s+panel\s+item"],
     "Medium"),

    ("T1218.003", "CMSTP", "Defense Evasion",
     [r"cmstp", r"cmstp\.exe", r"cmstp.*/s\b", r"cmstp.*/au"],
     "High"),

    ("T1218.004", "InstallUtil", "Defense Evasion",
     [r"installutil", r"installutil\.exe", r"/logfile=\s*/logtoconsole"],
     "High"),

    ("T1218.005", "Mshta", "Defense Evasion",
     [r"mshta", r"mshta\.exe", r"mshta.*vbscript",
      r"mshta.*javascript", r"hta\s+file"],
     "High"),

    ("T1218.007", "Msiexec", "Defense Evasion",
     [r"msiexec", r"msiexec\.exe", r"msiexec.*/q",
      r"msiexec.*http", r"msiexec.*/i"],
     "Medium"),

    ("T1218.008", "Odbcconf", "Defense Evasion",
     [r"odbcconf", r"odbcconf\.exe", r"regsvr.*odbcconf"],
     "Medium"),

    ("T1218.009", "Regsvcs/Regasm", "Defense Evasion",
     [r"regsvcs", r"regasm", r"regsvcs\.exe", r"regasm\.exe"],
     "Medium"),

    ("T1218.010", "Regsvr32", "Defense Evasion",
     [r"regsvr32", r"regsvr32\.exe", r"regsvr32.*/s\b",
      r"regsvr32.*scrobj", r"regsvr32.*http"],
     "High"),

    ("T1218.011", "Rundll32", "Defense Evasion",
     [r"rundll32", r"rundll32\.exe", r"dll\s+proxy",
      r"signed\s+binary\s+proxy"],
     "High"),

    ("T1218.012", "Verclsid", "Defense Evasion",
     [r"verclsid", r"verclsid\.exe"],
     "Medium"),

    ("T1218.013", "Mavinject", "Defense Evasion",
     [r"mavinject", r"mavinject\.exe", r"mavinject.*injectrunning"],
     "High"),

    ("T1218.014", "MMC", "Defense Evasion",
     [r"mmc\.exe", r"mmc.*\.msc", r"management\s+console"],
     "Low"),

    ("T1218.015", "Electron Applications", "Defense Evasion",
     [r"electron.*proxy", r"electron\s+app.*abuse",
      r"node\.exe.*electron"],
     "Low"),

    # --- T1070: Indicator Removal ---
    ("T1070.001", "Clear Windows Event Logs", "Defense Evasion",
     [r"wevtutil\s+cl", r"clear-eventlog", r"event\s+log\s+clear",
      r"wevtutil.*clear", r"clear.*windows.*log"],
     "High"),

    ("T1070.002", "Clear Linux or Mac System Logs", "Defense Evasion",
     [r"rm\s+.*\.log", r"rm\s+-rf\s+/var/log", r"shred.*log",
      r"truncate.*log", r"cat\s+/dev/null\s*>\s*/var/log",
      r"clear.*linux.*log", r"clear.*mac.*log"],
     "High"),

    ("T1070.003", "Clear Command History", "Defense Evasion",
     [r"history\s+-c", r"rm.*\.bash_history", r"unset\s+histfile",
      r"set\s+\+o\s+history", r"clear.*command\s+history",
      r"remove.*history", r"kill.*history"],
     "High"),

    ("T1070.004", "File Deletion", "Defense Evasion",
     [r"del\s+.*\.log", r"remove.*evidence", r"delete.*logs",
      r"sdelete", r"cipher\s+/w", r"secure\s+delet"],
     "High"),

    ("T1070.005", "Network Share Connection Removal", "Defense Evasion",
     [r"net\s+use.*delete", r"remove.*share.*connection",
      r"network\s+share.*remov"],
     "Medium"),

    ("T1070.006", "Timestomp", "Defense Evasion",
     [r"timestomp", r"touch\s+-t", r"setfileattributes.*time",
      r"nttimestampfile", r"modif.*timestamp"],
     "High"),

    ("T1070.007", "Clear Network Connection History and Configurations", "Defense Evasion",
     [r"arp\s+-d", r"ipconfig\s+/flushdns", r"netsh.*reset",
      r"clear.*network.*history", r"clear.*connection.*history"],
     "Medium"),

    ("T1070.008", "Clear Mailbox Data", "Defense Evasion",
     [r"clear.*mailbox", r"delete.*mailbox\s+data", r"purge.*mail",
      r"remove-mailboxexportrequest"],
     "Medium"),

    ("T1070.009", "Clear Persistence", "Defense Evasion",
     [r"clear\s+persistence", r"remove.*persistence\s+mechanism",
      r"delete.*registry.*run", r"schtasks\s+/delete",
      r"indicator\s+removal", r"log\s+tampering",
      r"stoplogging", r"deletetrail"],
     "High"),

    # --- T1562: Impair Defenses ---
    ("T1562.001", "Disable or Modify Tools", "Defense Evasion",
     [r"disable.*antivirus", r"disable.*defender", r"kill.*av",
      r"stop.*security", r"tamper.*protection",
      r"set-mppreference.*disable", r"disable.*edr"],
     "High"),

    ("T1562.002", "Disable Windows Event Logging", "Defense Evasion",
     [r"disable.*event\s+log", r"auditpol\s+/set.*disable",
      r"disable.*logging", r"stop.*eventlog"],
     "High"),

    ("T1562.003", "Impair Command History Logging", "Defense Evasion",
     [r"impair.*history\s+log", r"psreadlineoption.*savestyle\s+none",
      r"set.*histsize\s+0", r"unset\s+histfile"],
     "Medium"),

    ("T1562.004", "Disable or Modify System Firewall", "Defense Evasion",
     [r"disable.*firewall", r"netsh\s+advfirewall.*off",
      r"ufw\s+disable", r"iptables\s+-f",
      r"firewall.*disable", r"impair\s+defens"],
     "High"),

    ("T1562.006", "Indicator Blocking", "Defense Evasion",
     [r"indicator\s+block", r"etw\s+bypass", r"etw.*patch",
      r"nttracecontrol", r"block.*indicator"],
     "High"),

    ("T1562.007", "Disable or Modify Cloud Firewall", "Defense Evasion",
     [r"disable.*cloud\s+firewall", r"security\s+group.*delete",
      r"revoke.*security.*rule", r"nsg.*delete"],
     "Medium"),

    ("T1562.008", "Disable or Modify Cloud Logs", "Defense Evasion",
     [r"disable.*cloud\s+log", r"stoplogging", r"deletetrail",
      r"disable.*cloudtrail", r"cloud\s+log.*disable"],
     "High"),

    ("T1562.009", "Safe Mode Boot", "Defense Evasion",
     [r"safe\s+mode\s+boot", r"bcdedit.*safeboot",
      r"boot.*safe\s+mode", r"minimal\s+boot"],
     "Medium"),

    ("T1562.010", "Downgrade Attack", "Defense Evasion",
     [r"downgrade\s+attack", r"powershell.*version\s+2",
      r"force.*tls\s*1\.0", r"protocol\s+downgrad"],
     "Medium"),

    ("T1562.011", "Spoof Security Alerting", "Defense Evasion",
     [r"spoof.*security\s+alert", r"suppress.*alert",
      r"fake.*security\s+alert", r"spoof.*alerting"],
     "Medium"),

    ("T1562.012", "Disable or Modify Linux Audit System", "Defense Evasion",
     [r"auditctl\s+-e\s+0", r"disable.*auditd", r"service\s+auditd\s+stop",
      r"systemctl\s+stop\s+auditd", r"linux\s+audit.*disable"],
     "High"),

    # --- T1027: Obfuscated Files or Information ---
    ("T1027.001", "Binary Padding", "Defense Evasion",
     [r"binary\s+padding", r"append.*null\s+byte", r"inflate.*binary"],
     "Medium"),

    ("T1027.002", "Software Packing", "Defense Evasion",
     [r"packed\s+binary", r"upx", r"packer\b", r"software\s+pack",
      r"themida", r"vmprotect"],
     "Medium"),

    ("T1027.003", "Steganography", "Defense Evasion",
     [r"steganograph", r"hidden.*image", r"embed.*payload.*image",
      r"stego\b"],
     "Medium"),

    ("T1027.004", "Compile After Delivery", "Defense Evasion",
     [r"compile\s+after\s+delivery", r"csc\.exe.*compile",
      r"gcc\s+-o", r"cl\.exe.*compile", r"runtime\s+compil"],
     "Medium"),

    ("T1027.005", "Indicator Removal from Tools", "Defense Evasion",
     [r"indicator\s+removal.*tool", r"strip.*indicator",
      r"remove.*debug\s+info", r"clean.*artifact"],
     "Medium"),

    ("T1027.006", "HTML Smuggling", "Defense Evasion",
     [r"html\s+smuggl", r"javascript.*blob", r"mssaveoropenblob",
      r"html.*payload\s+delivery"],
     "High"),

    ("T1027.007", "Dynamic API Resolution", "Defense Evasion",
     [r"dynamic\s+api\s+resolution", r"getprocaddress.*runtime",
      r"loadlibrary.*resolve", r"api\s+hashing"],
     "Medium"),

    ("T1027.008", "Stripped Payloads", "Defense Evasion",
     [r"stripped\s+payload", r"strip.*symbol", r"remove.*debug"],
     "Low"),

    ("T1027.009", "Embedded Payloads", "Defense Evasion",
     [r"embedded\s+payload", r"payload.*embedded.*resource",
      r"resource\s+section.*payload"],
     "Medium"),

    ("T1027.010", "Command Obfuscation", "Defense Evasion",
     [r"obfuscat", r"base64", r"encode", r"xor\s+encr",
      r"certutil\s+-decode", r"certutil\s+.*-encode",
      r"command\s+obfuscat", r"char.*join.*obfuscat"],
     "Medium"),

    ("T1027.011", "Fileless Storage", "Defense Evasion",
     [r"fileless\s+storage", r"fileless\s+malware", r"registry.*payload",
      r"wmi.*payload\s+stor"],
     "High"),

    ("T1027.012", "LNK Icon Smuggling", "Defense Evasion",
     [r"lnk\s+icon\s+smuggl", r"shortcut.*icon.*payload",
      r"\.lnk.*smuggl"],
     "Medium"),

    ("T1027.013", "Encrypted/Encoded File", "Defense Evasion",
     [r"encrypted\s+file", r"encoded\s+file", r"encrypted\s+payload",
      r"encoded\s+payload", r"aes.*encrypt.*payload"],
     "Medium"),

    # --- T1036: Masquerading ---
    ("T1036.001", "Invalid Code Signature", "Defense Evasion",
     [r"invalid\s+code\s+signature", r"fake\s+signature",
      r"invalid\s+authenticode", r"forged\s+cert"],
     "Medium"),

    ("T1036.002", "Right-to-Left Override", "Defense Evasion",
     [r"right.to.left\s+override", r"rtlo", r"\u202e",
      r"unicode.*override"],
     "High"),

    ("T1036.003", "Rename System Utilities", "Defense Evasion",
     [r"rename.*system\s+utilit", r"renamed\s+binary",
      r"copy.*cmd\.exe", r"rename.*powershell"],
     "Medium"),

    ("T1036.004", "Masquerade Task or Service", "Defense Evasion",
     [r"masquerade.*task", r"masquerade.*service",
      r"fake\s+service\s+name", r"impersonat.*service"],
     "Medium"),

    ("T1036.005", "Match Legitimate Name or Location", "Defense Evasion",
     [r"masquerad", r"match\s+legitimate.*name",
      r"fake\s+extension", r"impersonat.*legitimate"],
     "Medium"),

    ("T1036.006", "Space after Filename", "Defense Evasion",
     [r"space\s+after\s+filename", r"trailing\s+space.*filename",
      r"\.exe\s+\b"],
     "Low"),

    ("T1036.007", "Double File Extension", "Defense Evasion",
     [r"double\s+extension", r"\.exe\.txt", r"\.pdf\.exe",
      r"\.doc\.exe", r"double\s+file\s+ext"],
     "Medium"),

    ("T1036.008", "Masquerade File Type", "Defense Evasion",
     [r"masquerade\s+file\s+type", r"fake\s+file\s+type",
      r"disguised\s+file"],
     "Medium"),

    ("T1036.009", "Break Process Trees", "Defense Evasion",
     [r"break\s+process\s+tree", r"parent\s+pid\s+spoof",
      r"ppid\s+spoof", r"reparent"],
     "High"),

    ("T1036.010", "Masquerade Account Name", "Defense Evasion",
     [r"masquerade\s+account\s+name", r"fake\s+account\s+name",
      r"impersonat.*account\s+name"],
     "Medium"),

    # --- T1055: Process Injection ---
    ("T1055.001", "Dynamic-link Library Injection", "Defense Evasion",
     [r"dll\s+inject", r"createremotethread", r"loadlibrary.*inject",
      r"ntcreatethreadex"],
     "High"),

    ("T1055.002", "Portable Executable Injection", "Defense Evasion",
     [r"pe\s+inject", r"portable\s+executable\s+inject",
      r"writeprocessmemory.*pe\b", r"virtualalloc.*inject"],
     "High"),

    ("T1055.003", "Thread Execution Hijacking", "Defense Evasion",
     [r"thread\s+hijack", r"suspendthread.*setthreadcontext",
      r"thread\s+execution\s+hijack"],
     "High"),

    ("T1055.004", "Asynchronous Procedure Call", "Defense Evasion",
     [r"apc\s+inject", r"queueuserapc", r"asynchronous\s+procedure\s+call"],
     "High"),

    ("T1055.005", "Thread Local Storage", "Defense Evasion",
     [r"tls\s+callback\s+inject", r"thread\s+local\s+storage\s+inject"],
     "Medium"),

    ("T1055.008", "Ptrace System Calls", "Defense Evasion",
     [r"ptrace\s+inject", r"ptrace.*poketext", r"ptrace\s+system\s+call"],
     "Medium"),

    ("T1055.009", "Proc Memory", "Defense Evasion",
     [r"proc\s+memory\s+inject", r"/proc/.*/mem", r"proc\s+mem\s+inject"],
     "Medium"),

    ("T1055.011", "Extra Window Memory Injection", "Defense Evasion",
     [r"extra\s+window\s+memory", r"ewm\s+inject",
      r"setwindowlong.*inject"],
     "High"),

    ("T1055.012", "Process Hollowing", "Defense Evasion",
     [r"process\s+hollow", r"hollowing", r"ntunmapviewofsection",
      r"process\s+inject.*hollow"],
     "High"),

    ("T1055.013", "Process Doppelganging", "Defense Evasion",
     [r"process\s+doppelgang", r"transactedfile", r"doppelgang"],
     "High"),

    ("T1055.014", "VDSO Hijacking", "Defense Evasion",
     [r"vdso\s+hijack", r"virtual\s+dynamic\s+shared\s+object"],
     "Medium"),

    ("T1055.015", "ListPlanting", "Defense Evasion",
     [r"listplanting", r"lvm_setitemposition", r"list.*plant.*inject"],
     "Medium"),

    # --- T1140: Deobfuscate/Decode Files (no sub-techniques) ---
    ("T1140", "Deobfuscate/Decode Files", "Defense Evasion",
     [r"certutil\s+-decode", r"base64\s+-d", r"deobfuscat",
      r"decode\s+payload"],
     "Medium"),

    # ===================================================================
    # CREDENTIAL ACCESS (TA0006)
    # ===================================================================

    # --- T1003: OS Credential Dumping ---
    ("T1003.001", "LSASS Memory", "Credential Access",
     [r"mimikatz", r"sekurlsa", r"lsass", r"procdump.*lsass",
      r"comsvcs.*minidump", r"lsass\s+dump", r"credential\s+dump"],
     "High"),

    ("T1003.002", "Security Account Manager", "Credential Access",
     [r"sam\s+database", r"sam\s+dump", r"reg\s+save.*sam",
      r"hklm\\sam", r"security\s+account\s+manager"],
     "High"),

    ("T1003.003", "NTDS", "Credential Access",
     [r"ntds\.dit", r"ntdsutil", r"ntds\s+dump",
      r"active\s+directory\s+dump", r"vssadmin.*ntds"],
     "High"),

    ("T1003.004", "LSA Secrets", "Credential Access",
     [r"lsa\s+secret", r"lsadump", r"reg\s+save.*security",
      r"hklm\\security"],
     "High"),

    ("T1003.005", "Cached Domain Credentials", "Credential Access",
     [r"cached\s+domain\s+cred", r"mscash", r"dcc2",
      r"cached\s+logon"],
     "High"),

    ("T1003.006", "DCSync", "Credential Access",
     [r"dcsync", r"drsuapi", r"replicat.*directory",
      r"getchanges", r"password\s+dump", r"hashdump"],
     "High"),

    ("T1003.007", "Proc Filesystem", "Credential Access",
     [r"/proc/.*/maps", r"proc\s+filesystem.*cred",
      r"/proc/.*/mem.*password"],
     "Medium"),

    ("T1003.008", "/etc/passwd and /etc/shadow", "Credential Access",
     [r"/etc/passwd", r"/etc/shadow", r"unshadow",
      r"cat\s+/etc/shadow", r"cat\s+/etc/passwd"],
     "High"),

    # --- T1078: Valid Accounts ---
    ("T1078.001", "Default Accounts", "Credential Access",
     [r"default\s+account", r"default\s+password", r"default\s+credential",
      r"factory\s+default.*login", r"admin/admin"],
     "Medium"),

    ("T1078.002", "Domain Accounts", "Credential Access",
     [r"domain\s+account", r"compromised\s+domain\s+account",
      r"stolen\s+domain\s+credential", r"valid\s+domain\s+account"],
     "Medium"),

    ("T1078.003", "Local Accounts", "Credential Access",
     [r"local\s+account", r"compromised\s+local\s+account",
      r"valid\s+local\s+account", r"stolen\s+local\s+credential"],
     "Medium"),

    ("T1078.004", "Cloud Accounts", "Credential Access",
     [r"cloud\s+account", r"iam\s+user", r"service\s+account\s+compromise",
      r"cloud\s+credential", r"valid\s+account",
      r"legitimate\s+credential", r"stolen\s+credential",
      r"compromised\s+account", r"credential\s+reuse", r"consolelogin"],
     "Medium"),

    # --- T1110: Brute Force ---
    ("T1110.001", "Password Guessing", "Credential Access",
     [r"password\s+guess", r"login\s+attempt", r"failed\s+login",
      r"authentication\s+fail", r"multiple.*fail.*login"],
     "High"),

    ("T1110.002", "Password Cracking", "Credential Access",
     [r"password\s+crack", r"hashcat", r"john\s+the\s+ripper",
      r"dictionary\s+attack", r"crack.*hash"],
     "High"),

    ("T1110.003", "Password Spraying", "Credential Access",
     [r"password\s+spray", r"spray.*password",
      r"single\s+password.*multiple\s+account", r"brute\s*force"],
     "High"),

    ("T1110.004", "Credential Stuffing", "Credential Access",
     [r"credential\s+stuff", r"stuffing\s+attack",
      r"reuse.*credential", r"accessdenied"],
     "High"),

    # --- T1552: Unsecured Credentials ---
    ("T1552.001", "Credentials In Files", "Credential Access",
     [r"password\s+in\s+file", r"credential\s+in\s+file",
      r"hardcoded\s+password", r"plaintext\s+password",
      r"\.env\s+file", r"config.*password"],
     "Medium"),

    ("T1552.002", "Credentials in Registry", "Credential Access",
     [r"credential.*registry", r"password.*registry",
      r"reg\s+query.*password", r"hklm.*password"],
     "Medium"),

    ("T1552.003", "Bash History", "Credential Access",
     [r"bash_history", r"\.bash_history", r"history\s+file",
      r"cat.*history"],
     "Medium"),

    ("T1552.004", "Private Keys", "Credential Access",
     [r"private\s+key", r"id_rsa", r"\.pem\b", r"\.key\b",
      r"ssh\s+key.*steal", r"steal.*private\s+key"],
     "Medium"),

    ("T1552.005", "Cloud Instance Metadata API", "Credential Access",
     [r"169\.254\.169\.254", r"metadata\s+api", r"instance\s+metadata",
      r"imds\b", r"getsecretvalue", r"get.*secret"],
     "Medium"),

    ("T1552.006", "Group Policy Preferences", "Credential Access",
     [r"gpp\s+password", r"group\s+policy\s+preference",
      r"cpassword", r"groups\.xml"],
     "High"),

    ("T1552.007", "Container API", "Credential Access",
     [r"container\s+api.*cred", r"kubernetes\s+secret",
      r"kubectl.*get\s+secret", r"docker.*secret"],
     "Medium"),

    ("T1552.008", "Chat Messages", "Credential Access",
     [r"chat.*credential", r"slack.*password", r"teams.*password",
      r"credential.*chat\s+message"],
     "Low"),

    # ===================================================================
    # DISCOVERY (TA0007)
    # ===================================================================

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

    # ===================================================================
    # LATERAL MOVEMENT (TA0008)
    # ===================================================================

    # --- T1021: Remote Services ---
    ("T1021.001", "Remote Desktop Protocol", "Lateral Movement",
     [r"rdp", r"remote\s+desktop", r"mstsc", r"port\s+3389",
      r"terminal\s+service"],
     "Medium"),

    ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement",
     [r"smb", r"admin\$", r"c\$", r"ipc\$", r"net\s+use",
      r"psexec", r"windows\s+admin\s+share", r"port\s+445"],
     "Medium"),

    ("T1021.003", "Distributed Component Object Model", "Lateral Movement",
     [r"dcom\b", r"distributed\s+com", r"mmc.*dcom",
      r"dcomexec", r"component\s+object\s+model.*remote"],
     "Medium"),

    ("T1021.004", "SSH", "Lateral Movement",
     [r"ssh\s+", r"port\s+22\b", r"sshd", r"authorized_keys",
      r"id_rsa"],
     "Low"),

    ("T1021.005", "VNC", "Lateral Movement",
     [r"vnc\b", r"vncviewer", r"port\s+5900", r"tightvnc",
      r"realvnc", r"virtual\s+network\s+computing"],
     "Medium"),

    ("T1021.006", "Windows Remote Management", "Lateral Movement",
     [r"winrm", r"windows\s+remote\s+management", r"wsman",
      r"invoke-command.*-computername", r"enter-pssession",
      r"evil-winrm", r"port\s+5985", r"port\s+5986"],
     "Medium"),

    ("T1021.007", "Cloud Services", "Lateral Movement",
     [r"cloud\s+service.*lateral", r"ssm\s+send-command",
      r"run-command.*azure", r"gcloud.*ssh"],
     "Low"),

    ("T1021.008", "Direct Cloud VM Connections", "Lateral Movement",
     [r"direct\s+cloud\s+vm", r"serial\s+console.*cloud",
      r"cloud\s+vm.*connect"],
     "Low"),

    ("T1570", "Lateral Tool Transfer", "Lateral Movement",
     [r"lateral\s+tool\s+transfer", r"copy.*remote", r"scp\s+",
      r"wmic.*process.*call.*create"],
     "Medium"),

    # ===================================================================
    # COLLECTION (TA0009)
    # ===================================================================

    ("T1005", "Data from Local System", "Collection",
     [r"data\s+collect", r"file\s+collect", r"staging\s+directory",
      r"archive.*compress", r"sensitive\s+file"],
     "Low"),

    # --- T1560: Archive Collected Data ---
    ("T1560.001", "Archive via Utility", "Collection",
     [r"rar\s+a\s+", r"7z\s+a\s+", r"zip\s+", r"tar\s+-czf",
      r"compress.*exfil", r"archive.*data"],
     "Medium"),

    ("T1560.002", "Archive via Library", "Collection",
     [r"zipfile.*python", r"shutil\.make_archive",
      r"system\.io\.compression", r"archive\s+via\s+library"],
     "Low"),

    ("T1560.003", "Archive via Custom Method", "Collection",
     [r"custom.*archive", r"custom.*compress",
      r"xor.*archive", r"encrypt.*archive.*custom"],
     "Low"),

    # ===================================================================
    # COMMAND AND CONTROL (TA0011)
    # ===================================================================

    ("T1105", "Ingress Tool Transfer", "Command and Control",
     [r"curl\s+", r"wget\s+", r"certutil.*urlcache", r"bitsadmin.*transfer",
      r"invoke-webrequest", r"download.*file", r"tool\s+transfer",
      r"ingress.*transfer"],
     "High"),

    # --- T1071: Application Layer Protocol ---
    ("T1071.001", "Web Protocols", "Command and Control",
     [r"c2\s+server", r"command\s+and\s+control", r"beacon",
      r"callback", r"c2\s+channel", r"covert\s+channel",
      r"http.*c2", r"https.*c2", r"web.*c2"],
     "Medium"),

    ("T1071.002", "File Transfer Protocols", "Command and Control",
     [r"ftp\s+exfil", r"ftp\s+c2", r"ftp\s+upload",
      r"file\s+transfer\s+protocol.*c2"],
     "Medium"),

    ("T1071.003", "Mail Protocols", "Command and Control",
     [r"smtp\s+c2", r"email\s+c2", r"mail\s+protocol.*c2",
      r"imap\s+c2", r"pop3\s+c2"],
     "Medium"),

    ("T1071.004", "DNS", "Command and Control",
     [r"dns\s+c2", r"dns\s+tunnel", r"dns\s+beacon",
      r"dns.*command\s+and\s+control", r"dnscat"],
     "Medium"),

    ("T1572", "Protocol Tunneling", "Command and Control",
     [r"tunnel", r"ssh\s+tunnel", r"port\s+forward",
      r"ngrok", r"chisel", r"dns\s+tunnel"],
     "Medium"),

    # ===================================================================
    # EXFILTRATION (TA0010)
    # ===================================================================

    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
     [r"exfiltrat", r"data\s+theft", r"data\s+leak",
      r"steal\s+data", r"upload.*stolen"],
     "Medium"),

    # --- T1048: Exfiltration Over Alternative Protocol ---
    ("T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "Exfiltration",
     [r"exfil.*symmetric.*encrypt", r"exfil.*aes",
      r"encrypted.*exfil.*non-c2"],
     "Medium"),

    ("T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", "Exfiltration",
     [r"exfil.*asymmetric.*encrypt", r"exfil.*rsa",
      r"exfil.*https\s+non-c2"],
     "Medium"),

    ("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", "Exfiltration",
     [r"dns\s+exfil", r"icmp\s+exfil", r"exfil.*dns",
      r"exfil.*protocol", r"exfil.*unencrypt"],
     "Medium"),

    # ===================================================================
    # IMPACT (TA0040)
    # ===================================================================

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

    # ===================================================================
    # INITIAL ACCESS (TA0001)
    # ===================================================================

    # --- T1566: Phishing ---
    ("T1566.001", "Spearphishing Attachment", "Initial Access",
     [r"spear.*phish.*attach", r"malicious\s+attachment",
      r"phish.*attach", r"suspicious\s+attachment"],
     "High"),

    ("T1566.002", "Spearphishing Link", "Initial Access",
     [r"spear.*phish.*link", r"phish.*link", r"clickbait\s+link",
      r"malicious\s+email", r"suspicious\s+email",
      r"phish", r"social\s+engineer"],
     "High"),

    ("T1566.003", "Spearphishing via Service", "Initial Access",
     [r"spear.*phish.*service", r"phish.*social\s+media",
      r"phish.*linkedin", r"phish.*via\s+service"],
     "Medium"),

    ("T1566.004", "Spearphishing Voice", "Initial Access",
     [r"vishing", r"spear.*phish.*voice", r"phish.*phone\s+call",
      r"voice\s+phish"],
     "Medium"),

    ("T1190", "Exploit Public-Facing Application", "Initial Access",
     [r"exploit.*public", r"web\s+shell", r"sql\s+inject",
      r"remote\s+code\s+execution", r"rce\b", r"cve-\d{4}",
      r"vulnerability\s+exploit", r"0-day", r"zero.day"],
     "High"),

    # --- T1078: Valid Accounts (Initial Access mapping) ---
    ("T1078.001", "Default Accounts", "Initial Access",
     [r"default\s+account.*initial", r"default\s+login.*access"],
     "Medium"),

    ("T1078.002", "Domain Accounts", "Initial Access",
     [r"domain\s+account.*initial\s+access",
      r"compromised\s+domain.*initial"],
     "Medium"),

    ("T1078.003", "Local Accounts", "Initial Access",
     [r"local\s+account.*initial\s+access",
      r"compromised\s+local.*initial"],
     "Medium"),

    ("T1078.004", "Cloud Accounts", "Initial Access",
     [r"cloud\s+account.*initial", r"iam\s+user.*initial",
      r"service\s+account\s+compromise.*initial"],
     "Medium"),

    # ===================================================================
    # RESOURCE DEVELOPMENT (TA0042)
    # ===================================================================

    # --- T1583: Acquire Infrastructure ---
    ("T1583.001", "Domains", "Resource Development",
     [r"domain\s+registr", r"acquire.*domain",
      r"register.*domain.*attack"],
     "Low"),

    ("T1583.002", "DNS Server", "Resource Development",
     [r"acquire.*dns\s+server", r"malicious\s+dns\s+server",
      r"rogue\s+dns"],
     "Low"),

    ("T1583.003", "Virtual Private Server", "Resource Development",
     [r"vps\s+provision", r"acquire.*vps", r"bulletproof\s+host",
      r"bulletproof\s+vps"],
     "Low"),

    ("T1583.004", "Server", "Resource Development",
     [r"acquire\s+server", r"dedicated\s+server.*attack",
      r"provision.*server.*c2"],
     "Low"),

    ("T1583.005", "Botnet", "Resource Development",
     [r"acquire.*botnet", r"botnet\s+rental",
      r"rent.*botnet", r"botnet\s+infra"],
     "Low"),

    ("T1583.006", "Web Services", "Resource Development",
     [r"acquire.*web\s+service", r"github.*c2",
      r"pastebin.*c2", r"cloud\s+storage.*c2",
      r"acquire\s+infrastructure"],
     "Low"),

    ("T1583.007", "Serverless", "Resource Development",
     [r"serverless.*c2", r"lambda.*c2", r"cloud\s+function.*c2",
      r"acquire.*serverless"],
     "Low"),

    ("T1583.008", "Malvertising", "Resource Development",
     [r"malvertis", r"malicious\s+advertis",
      r"ad\s+network.*malware"],
     "Low"),

    # ###################################################################
    # MOBILE ATT&CK (domain: mobile-attack)
    # Techniques sourced from MITRE_ATTACK_Complete.xlsx (Mobile sheet).
    # ###################################################################

    # ===================================================================
    # MOBILE — INITIAL ACCESS
    # ===================================================================

    ("T1664", "Exploitation via Charging Station or USB", "Mobile Initial Access",
     [r"juice\s+jack", r"malicious\s+charging\s+station",
      r"usb\s+exploit.*mobile", r"charging\s+station\s+attack",
      r"exploit.*usb.*mobile"],
     "Medium"),

    ("T1458", "Replication Through Removable Media", "Mobile Initial Access",
     [r"removable\s+media.*android", r"usb\s+debug.*sideload",
      r"adb\s+install", r"sideload.*apk"],
     "Medium"),

    ("T1660", "Phishing (Mobile)", "Mobile Initial Access",
     [r"mobile\s+phish", r"smish", r"sms\s+phish",
      r"phish.*android", r"phish.*ios", r"malicious\s+app\s+link"],
     "High"),

    ("T1660.001", "Spearphishing Link (Mobile)", "Mobile Initial Access",
     [r"spear.*phish.*link.*mobile", r"smishing\s+link",
      r"sms.*malicious\s+link", r"targeted.*mobile.*phish"],
     "High"),

    ("T1456", "Drive-By Compromise (Mobile)", "Mobile Initial Access",
     [r"drive.by.*mobile", r"malicious\s+website.*mobile",
      r"watering\s+hole.*mobile", r"browser\s+exploit.*android",
      r"browser\s+exploit.*ios"],
     "High"),

    ("T1474", "Supply Chain Compromise (Mobile)", "Mobile Initial Access",
     [r"supply\s+chain.*mobile", r"trojanized\s+app",
      r"compromised\s+app\s+store", r"malicious\s+sdk"],
     "High"),

    ("T1474.001", "Compromise Software Dependencies and Development Tools", "Mobile Initial Access",
     [r"compromised\s+sdk", r"malicious\s+library.*mobile",
      r"trojanized\s+development\s+tool", r"supply\s+chain.*sdk"],
     "High"),

    ("T1474.002", "Compromise Software Supply Chain", "Mobile Initial Access",
     [r"compromised\s+app\s+update", r"supply\s+chain.*app\s+store",
      r"trojanized\s+app\s+update", r"compromised\s+software\s+supply"],
     "High"),

    ("T1474.003", "Compromise Hardware Supply Chain", "Mobile Initial Access",
     [r"compromised\s+hardware.*mobile", r"supply\s+chain.*device",
      r"backdoor.*firmware.*mobile", r"pre-installed\s+malware"],
     "High"),

    ("T1476", "Deliver Malicious App via Authorized App Store", "Mobile Initial Access",
     [r"malicious\s+app.*app\s+store", r"trojan.*play\s+store",
      r"malware.*google\s+play", r"malicious\s+app.*apple\s+store"],
     "High"),

    ("T1477", "Exploit via Radio Interfaces", "Mobile Initial Access",
     [r"radio\s+interface\s+exploit", r"baseband\s+exploit",
      r"bluetooth\s+exploit.*mobile", r"nfc\s+exploit",
      r"cellular\s+exploit"],
     "High"),

    ("T1478", "Install Insecure or Malicious Configuration", "Mobile Initial Access",
     [r"malicious\s+config.*mobile", r"malicious\s+profile\s+install",
      r"mdm.*malicious\s+config", r"rogue\s+wifi\s+profile"],
     "Medium"),

    ("T1461", "Lockscreen Bypass", "Mobile Initial Access",
     [r"lockscreen\s+bypass", r"lock\s+screen\s+bypass",
      r"bypass.*device\s+lock", r"biometric\s+bypass"],
     "High"),

    # ===================================================================
    # MOBILE — EXECUTION
    # ===================================================================

    ("T1623", "Command and Scripting Interpreter (Mobile)", "Mobile Execution",
     [r"mobile.*command\s+interpreter", r"android.*shell\s+command",
      r"adb\s+shell", r"termux"],
     "Medium"),

    ("T1623.001", "Unix Shell (Mobile)", "Mobile Execution",
     [r"adb\s+shell", r"termux.*bash", r"android.*sh\s+-c",
      r"mobile.*unix\s+shell"],
     "Medium"),

    ("T1575", "Native API (Mobile)", "Mobile Execution",
     [r"android\s+native\s+api", r"ios\s+native\s+api",
      r"jni\s+call", r"objc_msgsend.*malicious",
      r"ndk.*exploit"],
     "Medium"),

    ("T1603", "Scheduled Task/Job (Mobile)", "Mobile Execution",
     [r"android\s+alarm\s+manager", r"jobscheduler.*android",
      r"workmanager.*malicious", r"mobile.*scheduled\s+task"],
     "Low"),

    ("T1624", "Event Triggered Execution (Mobile)", "Mobile Execution",
     [r"event\s+trigger.*mobile", r"boot_completed.*receiver",
      r"broadcast\s+receiver.*malicious"],
     "Medium"),

    ("T1624.001", "Broadcast Receivers", "Mobile Execution",
     [r"broadcast\s+receiver", r"boot_completed",
      r"android.*intent.*receiver", r"sms_received.*receiver"],
     "Medium"),

    # ===================================================================
    # MOBILE — PERSISTENCE
    # ===================================================================

    ("T1625", "Hijack Execution Flow (Mobile)", "Mobile Persistence",
     [r"hijack.*execution.*mobile", r"android.*hook",
      r"xposed\s+framework", r"frida.*hook.*android"],
     "High"),

    ("T1625.001", "System Runtime API Hijacking", "Mobile Persistence",
     [r"runtime\s+api\s+hijack", r"xposed.*hook",
      r"frida.*hook", r"substrate.*hook.*android"],
     "High"),

    ("T1577", "Compromise Application Executable", "Mobile Persistence",
     [r"repackage.*apk", r"trojanized\s+apk",
      r"modify.*application\s+executable", r"patch.*apk"],
     "High"),

    ("T1645", "Compromise Client Software Binary", "Mobile Persistence",
     [r"compromise.*client\s+binary.*mobile", r"modified\s+system\s+binary.*android",
      r"patched\s+ios\s+binary", r"tampered.*mobile\s+app"],
     "High"),

    ("T1541", "Foreground Persistence", "Mobile Persistence",
     [r"foreground\s+persistence", r"foreground\s+service.*persist",
      r"android.*foreground\s+notification\s+persist"],
     "Medium"),

    ("T1403", "Modify System Partition", "Mobile Persistence",
     [r"modify\s+system\s+partition", r"mount.*system.*rw",
      r"remount.*system.*android", r"/system/app.*malicious"],
     "High"),

    # ===================================================================
    # MOBILE — PRIVILEGE ESCALATION
    # ===================================================================

    ("T1626", "Abuse Elevation Control Mechanism (Mobile)", "Mobile Privilege Escalation",
     [r"mobile.*privilege\s+escalat", r"android.*root\s+exploit",
      r"ios.*jailbreak\s+exploit", r"device\s+admin.*abuse"],
     "High"),

    ("T1626.001", "Device Administrator Permissions", "Mobile Privilege Escalation",
     [r"device\s+administrator\s+permission", r"device\s+admin.*abuse",
      r"android.*device\s+admin\s+api", r"dpm.*activate"],
     "High"),

    ("T1404", "Exploitation for Privilege Escalation (Mobile)", "Mobile Privilege Escalation",
     [r"android.*priv.*esc.*exploit", r"ios.*priv.*esc.*exploit",
      r"kernel\s+exploit.*mobile", r"root.*exploit.*android",
      r"jailbreak.*exploit"],
     "High"),

    # ===================================================================
    # MOBILE — DEFENSE EVASION
    # ===================================================================

    ("T1628", "Hide Artifacts (Mobile)", "Mobile Defense Evasion",
     [r"hide.*artifact.*mobile", r"hidden\s+app.*android",
      r"conceal.*mobile\s+malware"],
     "Medium"),

    ("T1628.001", "Suppress Application Icon", "Mobile Defense Evasion",
     [r"suppress.*app.*icon", r"hide.*app.*icon.*android",
      r"remove.*launcher\s+icon", r"setcomponentenabledsetting"],
     "Medium"),

    ("T1628.002", "User Evasion", "Mobile Defense Evasion",
     [r"user\s+evasion.*mobile", r"hide.*from\s+user.*mobile",
      r"stealth.*mobile\s+malware", r"background.*no\s+ui"],
     "Medium"),

    ("T1628.003", "Steganography (Mobile)", "Mobile Defense Evasion",
     [r"steganograph.*mobile", r"hidden\s+data.*image.*mobile",
      r"mobile.*stego"],
     "Medium"),

    ("T1629", "Impair Defenses (Mobile)", "Mobile Defense Evasion",
     [r"impair.*defens.*mobile", r"disable.*mobile\s+security",
      r"disable.*play\s+protect", r"disable.*mobile\s+av"],
     "High"),

    ("T1629.001", "Prevent Application Removal", "Mobile Defense Evasion",
     [r"prevent.*app.*removal", r"device\s+admin.*prevent\s+uninstall",
      r"block.*uninstall.*android"],
     "High"),

    ("T1629.002", "Device Lockout", "Mobile Defense Evasion",
     [r"device\s+lockout.*malicious", r"lock\s+device.*ransom",
      r"android.*resetpassword.*lock"],
     "High"),

    ("T1629.003", "Disable or Modify Tools (Mobile)", "Mobile Defense Evasion",
     [r"disable.*security\s+tool.*mobile", r"kill.*mobile\s+av",
      r"disable.*play\s+protect", r"disable.*verify\s+apps"],
     "High"),

    ("T1630", "Indicator Removal on Host (Mobile)", "Mobile Defense Evasion",
     [r"indicator\s+removal.*mobile", r"delete.*logs.*android",
      r"clear.*mobile.*evidence"],
     "Medium"),

    ("T1630.001", "Uninstall Malicious Application", "Mobile Defense Evasion",
     [r"uninstall.*malicious\s+app", r"self-destruct.*mobile",
      r"auto.*uninstall.*after.*exfil"],
     "Medium"),

    ("T1630.002", "File Deletion (Mobile)", "Mobile Defense Evasion",
     [r"file\s+deletion.*mobile", r"delete.*evidence.*android",
      r"wipe.*traces.*mobile"],
     "Medium"),

    ("T1630.003", "Disguise Root/Jailbreak Indicators", "Mobile Defense Evasion",
     [r"disguise.*root\s+indicator", r"hide.*jailbreak",
      r"magisk\s+hide", r"disguise.*su\s+binary"],
     "High"),

    ("T1406", "Obfuscated Files or Information (Mobile)", "Mobile Defense Evasion",
     [r"obfuscat.*mobile", r"obfuscat.*apk",
      r"dex.*obfuscat", r"proguard.*malicious",
      r"packed.*android"],
     "Medium"),

    ("T1631", "Process Injection (Mobile)", "Mobile Defense Evasion",
     [r"process\s+inject.*android", r"inject.*mobile\s+app",
      r"ptrace.*android"],
     "High"),

    ("T1631.001", "Ptrace System Calls (Mobile)", "Mobile Defense Evasion",
     [r"ptrace.*android", r"ptrace.*mobile",
      r"android.*ptrace\s+inject"],
     "High"),

    ("T1632", "Subvert Trust Controls (Mobile)", "Mobile Defense Evasion",
     [r"subvert.*trust.*mobile", r"bypass.*ssl\s+pin",
      r"certificate.*bypass.*mobile"],
     "High"),

    ("T1632.001", "Code Signing Policy Modification", "Mobile Defense Evasion",
     [r"code\s+signing.*bypass.*mobile", r"bypass.*signature\s+verif.*android",
      r"allow\s+unknown\s+sources", r"disable.*app\s+verification"],
     "High"),

    ("T1633", "Virtualization/Sandbox Evasion (Mobile)", "Mobile Defense Evasion",
     [r"sandbox\s+evasion.*mobile", r"emulator\s+detect.*android",
      r"anti-emulation.*mobile"],
     "Medium"),

    ("T1633.001", "System Checks (Mobile)", "Mobile Defense Evasion",
     [r"emulator\s+detect", r"sandbox\s+detect.*mobile",
      r"isemulator\s+check", r"robolectric\s+detect"],
     "Medium"),

    # ===================================================================
    # MOBILE — CREDENTIAL ACCESS
    # ===================================================================

    ("T1634", "Credentials from Password Store (Mobile)", "Mobile Credential Access",
     [r"credential.*password\s+store.*mobile", r"keystore.*android.*dump",
      r"keychain.*dump.*ios"],
     "High"),

    ("T1634.001", "Keychain", "Mobile Credential Access",
     [r"keychain\s+dump", r"keychain\s+access.*ios",
      r"steal.*keychain", r"ios\s+keychain\s+extract"],
     "High"),

    ("T1634.002", "Credentials from Web Browsers (Mobile)", "Mobile Credential Access",
     [r"browser.*credential.*android", r"chrome.*password.*android",
      r"steal.*browser.*password.*mobile"],
     "High"),

    ("T1417", "Input Capture (Mobile)", "Mobile Credential Access",
     [r"input\s+capture.*mobile", r"keylog.*android",
      r"keylog.*ios", r"screen\s+overlay.*capture"],
     "High"),

    ("T1417.001", "Keylogging (Mobile)", "Mobile Credential Access",
     [r"keylog.*mobile", r"keylog.*android", r"keylog.*ios",
      r"custom\s+keyboard.*capture", r"accessibility.*keylog"],
     "High"),

    ("T1417.002", "GUI Input Capture (Mobile)", "Mobile Credential Access",
     [r"gui\s+input\s+capture.*mobile", r"overlay\s+attack",
      r"screen\s+overlay.*phish", r"tapjack"],
     "High"),

    ("T1635", "Steal Application Access Token (Mobile)", "Mobile Credential Access",
     [r"steal.*token.*mobile", r"oauth\s+token.*steal.*android",
      r"access\s+token.*steal.*mobile"],
     "High"),

    ("T1635.001", "URI Hijacking", "Mobile Credential Access",
     [r"uri\s+hijack", r"deep\s+link\s+hijack",
      r"intent.*hijack.*android", r"scheme\s+hijack"],
     "High"),

    ("T1411", "Input Prompt (Mobile)", "Mobile Credential Access",
     [r"input\s+prompt.*mobile", r"fake\s+login.*android",
      r"phishing\s+overlay", r"fake\s+auth.*prompt"],
     "High"),

    # ===================================================================
    # MOBILE — DISCOVERY
    # ===================================================================

    ("T1636", "Protected User Data (Mobile)", "Mobile Discovery",
     [r"protected\s+user\s+data.*mobile", r"access.*personal\s+data.*android",
      r"read.*contacts.*malicious"],
     "Medium"),

    ("T1636.001", "Calendar Entries", "Mobile Discovery",
     [r"calendar.*access.*mobile", r"read.*calendar.*android",
      r"steal.*calendar\s+entries"],
     "Low"),

    ("T1636.002", "Call Log", "Mobile Discovery",
     [r"call\s+log.*access.*mobile", r"read.*call\s+log.*android",
      r"steal.*call\s+history"],
     "Medium"),

    ("T1636.003", "Contact List", "Mobile Discovery",
     [r"contact\s+list.*access.*mobile", r"read.*contacts.*android",
      r"steal.*contact\s+list", r"exfil.*contacts"],
     "Medium"),

    ("T1636.004", "SMS Messages", "Mobile Discovery",
     [r"sms.*access.*malicious", r"read.*sms.*android",
      r"intercept.*sms", r"steal.*sms\s+message"],
     "High"),

    ("T1637", "Device Configuration Discovery (Mobile)", "Mobile Discovery",
     [r"device\s+config.*discovery.*mobile", r"build\.prop",
      r"getprop.*android", r"device\s+info.*enumerate"],
     "Low"),

    ("T1420", "File and Directory Discovery (Mobile)", "Mobile Discovery",
     [r"file.*discovery.*mobile", r"enumerate.*files.*android",
      r"directory\s+scan.*mobile", r"ls\s+.*sdcard"],
     "Low"),

    ("T1430", "Location Tracking (Mobile)", "Mobile Discovery",
     [r"location\s+track.*mobile", r"gps\s+track.*malicious",
      r"geofenc.*spy", r"location\s+spy.*android",
      r"corelocation.*spy.*ios"],
     "High"),

    ("T1423", "Network Service Scanning (Mobile)", "Mobile Discovery",
     [r"network\s+scan.*android", r"port\s+scan.*mobile",
      r"service\s+scan.*mobile"],
     "Low"),

    ("T1424", "Process Discovery (Mobile)", "Mobile Discovery",
     [r"process.*discovery.*mobile", r"ps\s+.*android",
      r"running\s+apps.*enumerate"],
     "Low"),

    ("T1418", "Software Discovery (Mobile)", "Mobile Discovery",
     [r"software.*discovery.*mobile", r"installed\s+apps.*enumerate",
      r"package\s+manager.*list.*android", r"list\s+packages"],
     "Low"),

    ("T1426", "System Information Discovery (Mobile)", "Mobile Discovery",
     [r"system\s+info.*mobile", r"android\s+version.*enumerate",
      r"ios\s+version.*enumerate", r"device\s+model.*enumerate"],
     "Low"),

    ("T1421", "System Network Connections Discovery (Mobile)", "Mobile Discovery",
     [r"network\s+connection.*mobile", r"netstat.*android",
      r"active\s+connections.*mobile"],
     "Low"),

    ("T1422", "System Network Configuration Discovery (Mobile)", "Mobile Discovery",
     [r"network\s+config.*mobile", r"wifi\s+info.*android",
      r"ifconfig.*mobile", r"ip\s+addr.*android"],
     "Low"),

    ("T1639", "Account Discovery (Mobile)", "Mobile Discovery",
     [r"account.*discovery.*mobile", r"accounts.*enumerate.*android",
      r"list\s+accounts.*mobile"],
     "Low"),

    # ===================================================================
    # MOBILE — LATERAL MOVEMENT
    # ===================================================================

    # T1458 (Replication Through Removable Media) — already defined above under Mobile Initial Access

    # ===================================================================
    # MOBILE — COLLECTION
    # ===================================================================

    ("T1432", "Access Contact List (Mobile)", "Mobile Collection",
     [r"access.*contact\s+list.*mobile", r"steal.*contacts.*android",
      r"read_contacts.*permission.*abuse"],
     "Medium"),

    ("T1433", "Access Call Log (Mobile)", "Mobile Collection",
     [r"access.*call\s+log.*mobile", r"steal.*call\s+log",
      r"read_call_log.*permission.*abuse"],
     "Medium"),

    ("T1517", "Access Notifications (Mobile)", "Mobile Collection",
     [r"access.*notification.*mobile", r"notification\s+listener",
      r"intercept.*notification.*android"],
     "Medium"),

    ("T1429", "Audio Capture (Mobile)", "Mobile Collection",
     [r"audio\s+capture.*mobile", r"record.*microphone.*android",
      r"record.*microphone.*ios", r"spy.*audio.*mobile"],
     "High"),

    ("T1616", "Call Control (Mobile)", "Mobile Collection",
     [r"call\s+control.*mobile", r"redirect.*phone\s+call",
      r"process_outgoing_calls.*abuse"],
     "High"),

    ("T1414", "Clipboard Data (Mobile)", "Mobile Collection",
     [r"clipboard.*mobile", r"clipboard.*android.*steal",
      r"pasteboard.*ios.*steal", r"clipboard\s+monitor"],
     "Medium"),

    ("T1533", "Data from Local System (Mobile)", "Mobile Collection",
     [r"data.*local\s+system.*mobile", r"exfil.*sdcard",
      r"steal.*local\s+data.*android", r"read.*external\s+storage"],
     "Medium"),

    ("T1412", "Capture SMS Messages (Mobile)", "Mobile Collection",
     [r"capture.*sms", r"intercept.*sms", r"sms\s+spy",
      r"receive_sms.*permission.*abuse", r"sms\s+intercept"],
     "High"),

    ("T1409", "Access Stored Application Data (Mobile)", "Mobile Collection",
     [r"access.*stored.*app\s+data", r"steal.*app\s+data.*mobile",
      r"shared_prefs.*steal", r"sqlite.*steal.*android"],
     "Medium"),

    ("T1513", "Screen Capture (Mobile)", "Mobile Collection",
     [r"screen\s+capture.*mobile", r"screenshot.*android",
      r"screenshot.*ios", r"screen\s+record.*mobile"],
     "High"),

    # ===================================================================
    # MOBILE — COMMAND AND CONTROL
    # ===================================================================

    ("T1437", "Application Layer Protocol (Mobile)", "Mobile Command and Control",
     [r"c2.*mobile", r"mobile.*command\s+and\s+control",
      r"android.*c2\s+server", r"ios.*c2\s+callback"],
     "Medium"),

    ("T1521", "Encrypted Channel (Mobile)", "Mobile Command and Control",
     [r"encrypted\s+channel.*mobile", r"ssl.*c2.*mobile",
      r"tls.*c2.*mobile"],
     "Medium"),

    ("T1521.001", "Symmetric Cryptography (Mobile)", "Mobile Command and Control",
     [r"aes.*c2.*mobile", r"symmetric.*encrypt.*c2.*mobile",
      r"rc4.*mobile.*c2"],
     "Medium"),

    ("T1521.002", "Asymmetric Cryptography (Mobile)", "Mobile Command and Control",
     [r"rsa.*c2.*mobile", r"asymmetric.*encrypt.*c2.*mobile",
      r"public\s+key.*mobile.*c2"],
     "Medium"),

    ("T1509", "Non-Standard Port (Mobile)", "Mobile Command and Control",
     [r"non-standard\s+port.*mobile", r"unusual\s+port.*android",
      r"custom\s+port.*mobile\s+c2"],
     "Low"),

    ("T1481", "Web Service (Mobile C2)", "Mobile Command and Control",
     [r"web\s+service.*mobile\s+c2", r"social\s+media.*c2.*mobile",
      r"cloud\s+storage.*c2.*mobile"],
     "Medium"),

    ("T1481.001", "Dead Drop Resolver (Mobile)", "Mobile Command and Control",
     [r"dead\s+drop.*mobile", r"twitter.*c2.*mobile",
      r"pastebin.*c2.*mobile"],
     "Medium"),

    ("T1481.002", "Bidirectional Communication (Mobile)", "Mobile Command and Control",
     [r"bidirectional.*c2.*mobile", r"two-way.*c2.*mobile",
      r"interactive.*c2.*mobile"],
     "Medium"),

    ("T1481.003", "One-Way Communication (Mobile)", "Mobile Command and Control",
     [r"one-way.*c2.*mobile", r"push\s+notification.*c2",
      r"sms.*c2.*command"],
     "Medium"),

    # ===================================================================
    # MOBILE — EXFILTRATION
    # ===================================================================

    ("T1646", "Exfiltration Over C2 Channel (Mobile)", "Mobile Exfiltration",
     [r"exfil.*c2.*mobile", r"mobile.*data\s+exfil.*c2",
      r"upload.*stolen.*mobile"],
     "Medium"),

    ("T1438", "Exfiltration Over Alternative Protocol (Mobile)", "Mobile Exfiltration",
     [r"exfil.*alternative.*mobile", r"sms.*exfil",
      r"bluetooth.*exfil", r"nfc.*exfil"],
     "Medium"),

    ("T1532", "Archive Collected Data (Mobile)", "Mobile Exfiltration",
     [r"archive.*data.*mobile", r"compress.*exfil.*mobile",
      r"zip.*stolen.*mobile"],
     "Low"),

    # ===================================================================
    # MOBILE — IMPACT
    # ===================================================================

    ("T1640", "Account Access Removal (Mobile)", "Mobile Impact",
     [r"account\s+access\s+removal.*mobile", r"lock\s+out.*account.*mobile",
      r"change\s+password.*mobile.*malicious"],
     "High"),

    ("T1448", "Carrier Billing Fraud", "Mobile Impact",
     [r"carrier\s+billing\s+fraud", r"premium\s+sms",
      r"wap\s+billing\s+fraud", r"toll\s+fraud"],
     "High"),

    ("T1471", "Data Encrypted for Impact (Mobile)", "Mobile Impact",
     [r"ransomware.*mobile", r"encrypt.*files.*android",
      r"mobile.*ransom", r"android.*crypto.*lock"],
     "High"),

    ("T1447", "Delete Device Data", "Mobile Impact",
     [r"delete.*device\s+data", r"wipe.*device.*malicious",
      r"factory\s+reset.*malicious", r"remote\s+wipe.*attack"],
     "High"),

    ("T1446", "Device Lockout (Impact)", "Mobile Impact",
     [r"device\s+lockout.*impact", r"lock\s+device.*ransom",
      r"android.*lock\s+screen.*ransom"],
     "High"),

    ("T1643", "Generate Traffic from Victim", "Mobile Impact",
     [r"generate\s+traffic.*victim", r"mobile.*ddos\s+bot",
      r"click\s+fraud.*mobile", r"ad\s+fraud.*mobile"],
     "Medium"),

    ("T1642", "Endpoint Denial of Service (Mobile)", "Mobile Impact",
     [r"dos.*mobile", r"endpoint\s+denial.*mobile",
      r"crash.*mobile\s+device", r"battery\s+drain.*attack"],
     "Medium"),

    # ===================================================================
    # MOBILE — NETWORK EFFECTS
    # ===================================================================

    ("T1463", "Manipulate Device Communication", "Mobile Network Effects",
     [r"manipulate.*device\s+communication", r"man.in.the.middle.*mobile",
      r"rogue\s+base\s+station", r"imsi\s+catcher",
      r"stingray.*intercept"],
     "High"),

    ("T1464", "Network Denial of Service (Mobile)", "Mobile Network Effects",
     [r"network\s+dos.*mobile", r"jamming.*cellular",
      r"signal\s+jam.*mobile", r"cellular\s+dos"],
     "Medium"),

    ("T1449", "Exploit SS7 to Redirect Phone Calls/SMS", "Mobile Network Effects",
     [r"ss7\s+exploit", r"ss7.*redirect", r"ss7.*intercept",
      r"signaling\s+system\s+7.*attack"],
     "High"),

    # ===================================================================
    # MOBILE — REMOTE SERVICE EFFECTS
    # ===================================================================

    ("T1468", "Remotely Track Device Without Authorization", "Mobile Remote Service Effects",
     [r"remote.*track.*device", r"unauthorized.*location\s+track",
      r"find\s+my.*abuse", r"icloud.*track.*unauthorized"],
     "High"),

    ("T1469", "Remotely Wipe Data Without Authorization", "Mobile Remote Service Effects",
     [r"remote.*wipe.*unauthorized", r"mdm.*wipe.*unauthorized",
      r"find\s+my.*wipe.*abuse"],
     "High"),

    ("T1470", "Obtain Device Cloud Backups", "Mobile Remote Service Effects",
     [r"obtain.*cloud\s+backup", r"icloud\s+backup.*steal",
      r"google\s+backup.*steal", r"device\s+backup.*exfil"],
     "High"),

    # ###################################################################
    # ICS ATT&CK (domain: ics-attack)
    # Techniques sourced from MITRE_ATTACK_Complete.xlsx (ICS sheet).
    # ###################################################################

    # ===================================================================
    # ICS — INITIAL ACCESS
    # ===================================================================

    ("T0817", "Drive-by Compromise (ICS)", "ICS Initial Access",
     [r"drive.by.*ics", r"drive.by.*scada", r"drive.by.*hmi",
      r"watering\s+hole.*industrial", r"browser\s+exploit.*ot"],
     "High"),

    ("T0866", "Exploitation of Remote Services (ICS)", "ICS Initial Access",
     [r"exploit.*remote\s+service.*ics", r"exploit.*scada\s+service",
      r"exploit.*ot\s+service", r"modbus\s+exploit",
      r"dnp3\s+exploit"],
     "High"),

    ("T0883", "Internet Accessible Device", "ICS Initial Access",
     [r"internet\s+accessible\s+device", r"exposed\s+plc",
      r"exposed\s+hmi", r"shodan.*scada", r"shodan.*ics",
      r"internet.*facing.*ics"],
     "High"),

    ("T0886", "Remote Services (ICS)", "ICS Initial Access",
     [r"remote\s+service.*ics", r"rdp.*ot\s+network",
      r"vnc.*ics", r"ssh.*scada", r"remote\s+access.*plc"],
     "Medium"),

    ("T0847", "Replication Through Removable Media (ICS)", "ICS Initial Access",
     [r"removable\s+media.*ics", r"usb.*plc", r"usb.*hmi",
      r"removable\s+media.*scada", r"usb.*industrial"],
     "High"),

    ("T0848", "Rogue Master", "ICS Initial Access",
     [r"rogue\s+master", r"rogue.*plc\s+master",
      r"rogue.*controller", r"unauthorized\s+master\s+device"],
     "High"),

    ("T0862", "Supply Chain Compromise (ICS)", "ICS Initial Access",
     [r"supply\s+chain.*ics", r"supply\s+chain.*scada",
      r"compromised\s+firmware.*plc", r"trojanized.*ics\s+software"],
     "High"),

    ("T0860", "Wireless Compromise (ICS)", "ICS Initial Access",
     [r"wireless\s+compromise.*ics", r"rogue.*wireless.*industrial",
      r"wifi.*ics\s+network", r"zigbee\s+exploit.*industrial"],
     "High"),

    ("T0865", "Spearphishing Attachment (ICS)", "ICS Initial Access",
     [r"spearphish.*ics", r"phish.*scada", r"phish.*industrial",
      r"malicious\s+attach.*ot\s+network"],
     "High"),

    # ===================================================================
    # ICS — EXECUTION
    # ===================================================================

    ("T0858", "Change Operating Mode", "ICS Execution",
     [r"change\s+operating\s+mode", r"switch.*mode.*plc",
      r"program\s+mode.*plc", r"run\s+mode.*plc"],
     "High"),

    ("T0807", "Command-Line Interface (ICS)", "ICS Execution",
     [r"command.line.*ics", r"cli.*ics\s+device",
      r"shell.*engineering\s+workstation", r"cmd.*scada"],
     "Medium"),

    ("T0871", "Execution through API (ICS)", "ICS Execution",
     [r"api.*ics\s+execut", r"api.*plc\s+command",
      r"opc\s+ua.*execute", r"api.*scada\s+command"],
     "Medium"),

    ("T0823", "Graphical User Interface (ICS)", "ICS Execution",
     [r"gui.*ics", r"hmi\s+interface.*malicious",
      r"scada\s+gui.*attack", r"operator\s+interface.*abuse"],
     "Low"),

    ("T0821", "Modify Controller Tasking", "ICS Execution",
     [r"modify\s+controller\s+task", r"plc\s+logic\s+modif",
      r"change.*plc\s+program", r"alter.*controller\s+logic"],
     "High"),

    ("T0834", "Native API (ICS)", "ICS Execution",
     [r"native\s+api.*ics", r"api.*plc\s+native",
      r"firmware\s+api.*ics"],
     "Medium"),

    ("T0853", "Scripting (ICS)", "ICS Execution",
     [r"script.*ics", r"python.*scada", r"script.*plc",
      r"automation\s+script.*ot"],
     "Medium"),

    ("T0863", "User Execution (ICS)", "ICS Execution",
     [r"user\s+execution.*ics", r"operator.*click.*malicious",
      r"hmi.*user\s+execution"],
     "Medium"),

    ("T0874", "Hooking (ICS)", "ICS Execution",
     [r"hook.*ics", r"api\s+hook.*scada",
      r"hook.*engineering\s+workstation"],
     "Medium"),

    # ===================================================================
    # ICS — PERSISTENCE
    # ===================================================================

    ("T0895", "Autorun Image", "ICS Persistence",
     [r"autorun\s+image.*ics", r"autorun.*plc",
      r"boot\s+image.*persist.*ics"],
     "High"),

    ("T0839", "Module Firmware", "ICS Persistence",
     [r"module\s+firmware.*ics", r"firmware\s+modif.*plc",
      r"malicious\s+firmware.*ics", r"flash.*firmware.*plc"],
     "High"),

    ("T0873", "Project File Infection", "ICS Persistence",
     [r"project\s+file\s+infect", r"infect.*plc\s+project",
      r"trojanized.*project\s+file", r"step\s+7.*infect"],
     "High"),

    ("T0857", "System Firmware (ICS)", "ICS Persistence",
     [r"system\s+firmware.*ics", r"firmware\s+flash.*plc",
      r"firmware.*persist.*ics", r"flash.*controller\s+firmware"],
     "High"),

    ("T0859", "Valid Accounts (ICS)", "ICS Persistence",
     [r"valid\s+account.*ics", r"default\s+credential.*plc",
      r"stolen\s+credential.*scada", r"legitimate\s+account.*ot"],
     "Medium"),

    # ===================================================================
    # ICS — PRIVILEGE ESCALATION
    # ===================================================================

    ("T0890", "Exploitation for Privilege Escalation (ICS)", "ICS Privilege Escalation",
     [r"priv.*esc.*ics", r"exploit.*priv.*ics",
      r"privilege\s+escalat.*scada", r"exploit.*engineering\s+workstation"],
     "High"),

    # ===================================================================
    # ICS — EVASION
    # ===================================================================

    ("T0820", "Exploitation for Evasion (ICS)", "ICS Evasion",
     [r"exploit.*evasion.*ics", r"exploit.*bypass.*ics\s+security"],
     "High"),

    ("T0872", "Indicator Removal on Host (ICS)", "ICS Evasion",
     [r"indicator\s+removal.*ics", r"clear.*logs.*ics",
      r"delete.*evidence.*scada", r"log\s+tamper.*ot"],
     "High"),

    ("T0849", "Masquerading (ICS)", "ICS Evasion",
     [r"masquerad.*ics", r"masquerad.*scada",
      r"disguise.*ics\s+traffic", r"spoof.*ot\s+protocol"],
     "Medium"),

    ("T0851", "Rootkit (ICS)", "ICS Evasion",
     [r"rootkit.*ics", r"rootkit.*plc", r"rootkit.*scada",
      r"rootkit.*engineering\s+workstation"],
     "High"),

    ("T0856", "Spoof Reporting Message", "ICS Evasion",
     [r"spoof.*report.*message", r"fake.*plc\s+report",
      r"spoof.*sensor\s+data", r"false.*process\s+data",
      r"manipulat.*report.*ics"],
     "High"),

    # ===================================================================
    # ICS — DISCOVERY
    # ===================================================================

    ("T0840", "Network Connection Enumeration (ICS)", "ICS Discovery",
     [r"network\s+enum.*ics", r"network\s+scan.*ot",
      r"enumerate.*ics\s+network", r"arp.*scan.*ics"],
     "Medium"),

    ("T0842", "Network Sniffing (ICS)", "ICS Discovery",
     [r"sniff.*ics", r"pcap.*scada", r"wireshark.*modbus",
      r"capture.*ics\s+traffic", r"sniff.*ot\s+network"],
     "Medium"),

    ("T0846", "Remote System Discovery (ICS)", "ICS Discovery",
     [r"remote\s+system.*discovery.*ics", r"discover.*plc",
      r"scan.*ics\s+device", r"enumerate.*scada\s+host"],
     "Low"),

    ("T0888", "Remote System Information Discovery (ICS)", "ICS Discovery",
     [r"remote\s+system\s+info.*ics", r"fingerprint.*plc",
      r"identify.*ics\s+device", r"firmware\s+version.*plc"],
     "Low"),

    ("T0887", "Wireless Sniffing (ICS)", "ICS Discovery",
     [r"wireless\s+sniff.*ics", r"zigbee\s+sniff",
      r"wifi\s+sniff.*industrial", r"rf\s+sniff.*ics"],
     "Medium"),

    # ===================================================================
    # ICS — LATERAL MOVEMENT
    # ===================================================================

    ("T0812", "Default Credentials (ICS)", "ICS Lateral Movement",
     [r"default\s+credential.*ics", r"default\s+password.*plc",
      r"default\s+login.*scada", r"factory\s+password.*ics"],
     "High"),

    ("T0867", "Lateral Tool Transfer (ICS)", "ICS Lateral Movement",
     [r"lateral\s+tool\s+transfer.*ics", r"copy.*tool.*ics\s+network",
      r"transfer.*malware.*ot"],
     "Medium"),

    ("T0843", "Program Download", "ICS Lateral Movement",
     [r"program\s+download.*plc", r"download.*logic.*plc",
      r"upload.*program.*controller", r"transfer.*plc\s+program"],
     "High"),

    # ===================================================================
    # ICS — COLLECTION
    # ===================================================================

    ("T0802", "Automated Collection (ICS)", "ICS Collection",
     [r"automated\s+collect.*ics", r"auto.*collect.*scada\s+data",
      r"periodic.*harvest.*ics"],
     "Medium"),

    ("T0811", "Data from Information Repositories (ICS)", "ICS Collection",
     [r"data.*repository.*ics", r"historian\s+data.*steal",
      r"scada\s+database.*exfil"],
     "Medium"),

    ("T0868", "Detect Operating Mode (ICS)", "ICS Collection",
     [r"detect.*operating\s+mode", r"enumerate.*plc\s+mode",
      r"read.*controller\s+state"],
     "Low"),

    ("T0877", "I/O Image", "ICS Collection",
     [r"i/o\s+image", r"io\s+image.*plc", r"read.*plc\s+i/o",
      r"input.*output\s+image.*read"],
     "Medium"),

    ("T0830", "Man in the Middle (ICS)", "ICS Collection",
     [r"man.in.the.middle.*ics", r"mitm.*modbus",
      r"arp\s+poison.*ics", r"intercept.*ics\s+traffic"],
     "High"),

    ("T0801", "Monitor Process State", "ICS Collection",
     [r"monitor\s+process\s+state", r"read.*process\s+variable",
      r"poll.*plc\s+register", r"monitor.*sensor\s+value"],
     "Low"),

    ("T0861", "Point & Tag Identification", "ICS Collection",
     [r"point.*tag\s+ident", r"enumerate.*tag.*plc",
      r"discover.*ics\s+tag", r"opc.*tag\s+enumerat"],
     "Medium"),

    ("T0845", "Program Upload", "ICS Collection",
     [r"program\s+upload", r"upload.*plc\s+logic",
      r"read.*plc\s+program", r"exfil.*controller\s+logic"],
     "High"),

    ("T0852", "Screen Capture (ICS)", "ICS Collection",
     [r"screen\s+capture.*ics", r"screenshot.*hmi",
      r"screen\s+capture.*scada", r"capture.*operator\s+screen"],
     "Medium"),

    # ===================================================================
    # ICS — COMMAND AND CONTROL
    # ===================================================================

    ("T0885", "Commonly Used Port (ICS)", "ICS Command and Control",
     [r"commonly\s+used\s+port.*ics", r"port\s+80.*ics\s+c2",
      r"port\s+443.*ics\s+c2", r"standard\s+port.*ot\s+c2"],
     "Low"),

    ("T0884", "Connection Proxy (ICS)", "ICS Command and Control",
     [r"connection\s+proxy.*ics", r"proxy.*ics\s+network",
      r"tunnel.*ot\s+network", r"pivot.*ics"],
     "Medium"),

    ("T0869", "Standard Application Layer Protocol (ICS)", "ICS Command and Control",
     [r"application\s+layer.*ics\s+c2", r"http.*ics\s+c2",
      r"dns.*ics\s+c2", r"standard\s+protocol.*ot\s+c2"],
     "Medium"),

    # ===================================================================
    # ICS — INHIBIT RESPONSE FUNCTION
    # ===================================================================

    ("T0800", "Activate Firmware Update Mode", "ICS Inhibit Response Function",
     [r"firmware\s+update\s+mode", r"activate.*firmware.*update",
      r"plc.*update\s+mode", r"bootloader\s+mode.*plc"],
     "High"),

    ("T0878", "Alarm Suppression", "ICS Inhibit Response Function",
     [r"alarm\s+suppress", r"suppress.*alarm.*ics",
      r"disable.*alarm.*plc", r"mute.*alarm.*scada"],
     "High"),

    ("T0803", "Block Command Message", "ICS Inhibit Response Function",
     [r"block\s+command\s+message", r"drop.*command.*ics",
      r"filter.*command.*plc", r"block.*control\s+message"],
     "High"),

    ("T0804", "Block Reporting Message", "ICS Inhibit Response Function",
     [r"block\s+reporting\s+message", r"drop.*report.*ics",
      r"suppress.*status\s+report", r"block.*telemetry.*plc"],
     "High"),

    ("T0805", "Block Serial COM", "ICS Inhibit Response Function",
     [r"block\s+serial\s+com", r"block.*serial\s+port",
      r"disable.*serial.*plc", r"serial\s+comm.*block"],
     "High"),

    ("T0892", "Change Credential (ICS)", "ICS Inhibit Response Function",
     [r"change\s+credential.*ics", r"change.*password.*plc",
      r"lock\s+out.*operator", r"modify.*credential.*scada"],
     "High"),

    ("T0816", "Device Restart/Shutdown", "ICS Inhibit Response Function",
     [r"device\s+restart.*ics", r"shutdown.*plc",
      r"restart.*controller", r"reboot.*ics\s+device",
      r"power\s+cycle.*plc"],
     "High"),

    ("T0835", "Manipulate I/O Image", "ICS Inhibit Response Function",
     [r"manipulate.*i/o\s+image", r"modify.*io\s+image",
      r"write.*plc\s+i/o.*malicious", r"alter.*input.*output\s+image"],
     "High"),

    ("T0838", "Modify Alarm Settings", "ICS Inhibit Response Function",
     [r"modify\s+alarm\s+setting", r"change.*alarm.*threshold",
      r"disable.*safety\s+alarm", r"alter.*alarm.*ics"],
     "High"),

    ("T0881", "Service Stop (ICS)", "ICS Inhibit Response Function",
     [r"service\s+stop.*ics", r"stop.*ics\s+service",
      r"halt.*scada\s+service", r"terminate.*plc\s+service"],
     "High"),

    # ===================================================================
    # ICS — IMPAIR PROCESS CONTROL
    # ===================================================================

    ("T0806", "Brute Force I/O", "ICS Impair Process Control",
     [r"brute\s+force.*i/o", r"flood.*plc\s+i/o",
      r"overwhelm.*controller\s+i/o", r"dos.*plc\s+i/o"],
     "High"),

    ("T0836", "Modify Parameter", "ICS Impair Process Control",
     [r"modify\s+parameter.*ics", r"change.*setpoint",
      r"alter.*process\s+parameter", r"write.*register.*plc",
      r"modify.*plc\s+register"],
     "High"),

    ("T0855", "Unauthorized Command Message", "ICS Impair Process Control",
     [r"unauthorized\s+command.*ics", r"rogue\s+command.*plc",
      r"inject.*command.*controller", r"send.*unauthorized.*command"],
     "High"),

    # ===================================================================
    # ICS — IMPACT
    # ===================================================================

    ("T0879", "Damage to Property", "ICS Impact",
     [r"damage.*property.*ics", r"physical\s+damage.*plc",
      r"equipment\s+damage.*industrial", r"destroy.*ics\s+equipment"],
     "High"),

    ("T0813", "Denial of Control", "ICS Impact",
     [r"denial\s+of\s+control", r"lose\s+control.*plc",
      r"cannot\s+control.*process", r"control\s+denied.*ics"],
     "High"),

    ("T0815", "Denial of View", "ICS Impact",
     [r"denial\s+of\s+view", r"hmi.*blank", r"lose\s+visibility",
      r"operator.*cannot\s+see", r"blind.*operator"],
     "High"),

    ("T0826", "Loss of Availability", "ICS Impact",
     [r"loss.*availability.*ics", r"ics.*outage",
      r"scada.*unavailable", r"plc.*offline.*attack"],
     "High"),

    ("T0827", "Loss of Control", "ICS Impact",
     [r"loss.*control.*ics", r"lose\s+control.*process",
      r"uncontrolled.*industrial\s+process"],
     "High"),

    ("T0828", "Loss of Productivity and Revenue", "ICS Impact",
     [r"loss.*productivity.*ics", r"production\s+halt.*attack",
      r"revenue\s+loss.*ics", r"shutdown.*production.*attack"],
     "High"),

    ("T0837", "Loss of Protection", "ICS Impact",
     [r"loss.*protection.*ics", r"safety\s+system.*disable",
      r"sis.*bypass", r"safety\s+instrument.*disable"],
     "High"),

    ("T0880", "Loss of Safety", "ICS Impact",
     [r"loss.*safety.*ics", r"safety.*compromise.*industrial",
      r"sis.*compromise", r"safety\s+interlock.*disable"],
     "High"),

    ("T0829", "Loss of View", "ICS Impact",
     [r"loss.*view.*ics", r"hmi.*display.*fail",
      r"operator\s+view.*lost", r"process\s+view.*lost"],
     "High"),

    ("T0831", "Manipulation of Control", "ICS Impact",
     [r"manipulation.*control.*ics", r"manipulate.*plc\s+output",
      r"alter.*control\s+signal", r"tamper.*control.*industrial"],
     "High"),

    ("T0832", "Manipulation of View", "ICS Impact",
     [r"manipulation.*view.*ics", r"fake.*hmi\s+display",
      r"falsify.*operator\s+view", r"manipulate.*scada\s+display"],
     "High"),

    ("T0882", "Theft of Operational Information", "ICS Impact",
     [r"theft.*operational\s+info", r"steal.*ics\s+data",
      r"exfil.*scada\s+data", r"steal.*process\s+data",
      r"industrial\s+espionage"],
     "High"),
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
    """Return a Counter of tactic -> count from mapping results."""
    return dict(Counter(r["Tactic"] for r in results))


def get_technique_frequency(results):
    """Return a Counter of 'TechniqueID: Name' -> count from mapping results."""
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
