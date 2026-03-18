<div align="center">

```
███╗   ███╗██╗████████╗██████╗ ███████╗    ████████╗████████╗██████╗
████╗ ████║██║╚══██╔══╝██╔══██╗██╔════╝    ╚══██╔══╝╚══██╔══╝██╔══██╗
██╔████╔██║██║   ██║   ██████╔╝█████╗         ██║      ██║   ██████╔╝
██║╚██╔╝██║██║   ██║   ██╔══██╗██╔══╝         ██║      ██║   ██╔═══╝
██║ ╚═╝ ██║██║   ██║   ██║  ██║███████╗       ██║      ██║   ██║
╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝       ╚═╝      ╚═╝   ╚═╝

    ████████╗████████╗██████╗     ███╗   ███╗ █████╗ ██████╗ ██████╗ ███████╗██████╗
    ╚══██╔══╝╚══██╔══╝██╔══██╗    ████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
       ██║      ██║   ██████╔╝    ██╔████╔██║███████║██████╔╝██████╔╝█████╗  ██████╔╝
       ██║      ██║   ██╔═══╝     ██║╚██╔╝██║██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
       ██║      ██║   ██║         ██║ ╚═╝ ██║██║  ██║██║     ██║     ███████╗██║  ██║
       ╚═╝      ╚═╝   ╚═╝         ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
```

# 🛡️ MITRE ATT&CK TTP Mapper

### *Instantly map IOCs and security events to MITRE ATT&CK techniques*

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-E60000?style=for-the-badge)](https://attack.mitre.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)

---

**Transform raw logs and indicators into actionable threat intelligence — in seconds.**

[🚀 Quick Start](#-quick-start) · [📖 How It Works](#-how-it-works) · [✨ Features](#-features) · [🗺️ Roadmap](#️-future-roadmap) · [🤝 Contributing](#-contributing)

</div>

---

## 📌 Table of Contents

- [🎯 Project Overview](#-project-overview)
- [💡 Motivation & Goals](#-motivation--goals)
- [✨ Features](#-features)
- [⚙️ How It Works — Deep Dive](#️-how-it-works--deep-dive)
- [🏗️ Architecture Diagrams](#️-architecture-diagrams)
- [🔀 Complete Code Flowchart](#-complete-code-flowchart)
- [📁 Project Structure](#-project-structure)
- [🚀 Quick Start](#-quick-start)
- [🖥️ Running the Dashboard](#️-running-the-dashboard)
- [💻 Using the CLI](#-using-the-cli)
- [🐳 Docker Deployment](#-docker-deployment)
- [📤 Export Formats](#-export-formats)
- [📋 Supported Log Formats](#-supported-log-formats)
- [🗺️ Future Roadmap](#️-future-roadmap)
- [🤝 Contributing](#-contributing)

---

## 🎯 Project Overview

**MITRE ATT&CK TTP Mapper** is an open-source Python tool designed to bridge the gap between raw security data and structured threat intelligence. Security analysts spend significant time manually cross-referencing logs, alerts, and indicators against the MITRE ATT&CK framework — a process that is slow, error-prone, and difficult to scale.

This tool automates that process entirely. Given any collection of Indicators of Compromise (IOCs), log entries, or incident descriptions, the mapper:

1. Parses them from any common format (plaintext, JSON, CSV, XML, CEF, or cloud logs)
2. Runs each entry through a compiled pattern-matching engine
3. Maps matches to specific ATT&CK Technique IDs with confidence scoring
4. Produces visual reports, Navigator layers, Sigma detection rules, and heat maps

Whether you are triaging a live incident, threat hunting across historical logs, or building detection content, this tool accelerates every step.

---

## 💡 Motivation & Goals

### The Problem

The MITRE ATT&CK framework is the gold standard for describing adversary behavior. Yet the process of connecting raw evidence to ATT&CK techniques remains largely manual:

- **SOC analysts** copy-paste IOCs into search engines or internal wikis to identify techniques
- **Incident responders** spend hours correlating log events to the ATT&CK matrix during investigations
- **Detection engineers** struggle to identify which techniques have adequate detection coverage vs. which are blind spots
- **Threat intelligence teams** produce reports without machine-readable ATT&CK mappings

### The Goal

Build a fast, portable, analyst-friendly tool that:

| Goal | Description |
|------|-------------|
| 🔍 **Automate correlation** | Map IOCs to ATT&CK techniques without manual lookup |
| 📊 **Visualize coverage** | Show which tactics and techniques are most active |
| 🎯 **Prioritize response** | Surface high-confidence matches first |
| 🔧 **Generate detections** | Auto-produce Sigma rules from matched techniques |
| 🌐 **Stay format-agnostic** | Accept logs from any SIEM, cloud provider, or endpoint |
| 🚀 **Reduce time-to-insight** | Cut technique correlation from hours to seconds |

### Who Is This For?

- 🔵 **Blue Team / SOC Analysts** — Rapid triage during incident response
- 🟣 **Threat Hunters** — Structured hypothesis generation across log data
- 🟠 **Detection Engineers** — Coverage gap analysis and Sigma rule generation
- 🔴 **Red Team / Purple Team** — Validate detections against simulated TTPs
- 📚 **Security Researchers** — Map malware behavior to ATT&CK systematically

---

## ✨ Features

### Core Capabilities

```
┌─────────────────────────────────────────────────────────────────────┐
│                     FEATURE OVERVIEW                                │
├───────────────────────────┬─────────────────────────────────────────┤
│  🔍 Pattern Matching      │  50+ compiled regex patterns across     │
│                           │  40+ ATT&CK techniques                  │
├───────────────────────────┼─────────────────────────────────────────┤
│  📈 Confidence Scoring    │  High / Medium / Low with multi-pattern │
│                           │  boosting when 3+ keywords match        │
├───────────────────────────┼─────────────────────────────────────────┤
│  📁 Multi-Format Input    │  TXT, JSON, CSV, XML (Sysmon), CEF,     │
│                           │  CloudTrail, Azure Activity, GCP Audit  │
├───────────────────────────┼─────────────────────────────────────────┤
│  🗺️  Navigator Export     │  ATT&CK Navigator v4.5 heat map layers  │
├───────────────────────────┼─────────────────────────────────────────┤
│  🔥 HTML Heat Map         │  Self-contained visual heat map         │
│                           │  styled after ATT&CK Navigator          │
├───────────────────────────┼─────────────────────────────────────────┤
│  📜 Sigma Rules           │  Auto-generated YAML detection rules    │
│                           │  for Splunk, Elastic, Sentinel          │
├───────────────────────────┼─────────────────────────────────────────┤
│  🌐 Web Dashboard         │  Streamlit UI with charts and           │
│                           │  interactive export options             │
├───────────────────────────┼─────────────────────────────────────────┤
│  🖥️  REST API             │  FastAPI service for programmatic       │
│                           │  integration with other tools           │
├───────────────────────────┼─────────────────────────────────────────┤
│  🐳 Docker Support        │  Multi-stage Dockerfile for CLI,        │
│                           │  API, and Dashboard targets             │
└───────────────────────────┴─────────────────────────────────────────┘
```

### Tactics Covered

The tool covers all 14 MITRE ATT&CK Enterprise tactics:

`Reconnaissance` · `Resource Development` · `Initial Access` · `Execution` · `Persistence` · `Privilege Escalation` · `Defense Evasion` · `Credential Access` · `Discovery` · `Lateral Movement` · `Collection` · `Command & Control` · `Exfiltration` · `Impact`

---

## ⚙️ How It Works — Deep Dive

The pipeline has five distinct stages. Here is what happens from the moment you provide an input to the moment a report lands in your hands.

### Stage 1 — Input Ingestion

The tool accepts input through three channels:

- **CLI file path** (`-i path/to/file`) — batch processing via `main.py`
- **Streamlit dashboard** — paste text or drag-and-drop a log file via the web UI
- **REST API** — POST a JSON payload to `/map` for programmatic integration

Once the input is received, a **format-aware parser** is selected automatically or manually:

```
Input File
    │
    ▼
┌─────────────────────────────────────┐
│         Format Detection            │
│                                     │
│  .xml  ──► Sysmon XML Parser        │
│  .csv  ──► CSV Log Parser           │
│  .cef  ──► CEF Parser               │
│  .json ──► JSON / NDJSON Parser     │
│            ├─► CloudTrail Parser    │
│            ├─► Azure Activity Log   │
│            └─► GCP Cloud Audit Log  │
│  .txt  ──► Plain Text Parser        │
│  ?     ──► Auto-detect (content)    │
└─────────────────────────────────────┘
    │
    ▼
List[str]  ← normalized IOC strings
```

Each parser normalizes its format into a flat list of strings — one entry per log event or IOC. Cloud parsers additionally **enrich** each event by appending ATT&CK-relevant keywords based on the event name (e.g., `StopLogging` → `"indicator removal defense evasion disable logging"`), dramatically improving match quality on cloud logs.

---

### Stage 2 — Pattern Matching Engine

This is the core of the tool, implemented in `mapping_engine.py`.

The **Technique Database** defines 40+ ATT&CK techniques, each with:
- A unique Technique ID (e.g., `T1059.001`)
- The technique name and parent tactic
- A list of regex patterns that indicate this technique
- A base confidence level (`High`, `Medium`, or `Low`)

All patterns are **pre-compiled** at module load time for maximum throughput.

```
For each IOC string:
    │
    ▼
┌───────────────────────────────────────────────────────┐
│              Technique Database (40+ entries)         │
│                                                       │
│  T1059.001 PowerShell  ── [r"powershell", r"-enc",    │
│                            r"invoke-expression", …]   │
│  T1003     Credential  ── [r"mimikatz", r"lsass",     │
│            Dumping         r"sekurlsa", …]            │
│  T1486     Ransomware  ── [r"ransomware", r"\.locked",│
│                            r"encrypt.*file", …]       │
│  … (40+ more)                                         │
└───────────────────────────────────────────────────────┘
    │
    ▼ regex.search() for each pattern against IOC string
    │
    ▼
┌─────────────────────────────────┐
│      Confidence Scoring         │
│                                 │
│  matched_keywords = 1–2         │
│    → use base_confidence        │
│                                 │
│  matched_keywords ≥ 3           │
│    → BOOST confidence by +1     │
│      (Low→Medium, Medium→High)  │
└─────────────────────────────────┘
    │
    ▼
┌──────────────────────┐
│  Confidence Filter   │  (min_confidence threshold applied)
└──────────────────────┘
    │
    ▼
Result: { IOC, TechniqueID, Name, Tactic, Confidence, Keywords }
```

**Multi-pattern boosting** is a key design choice. A single keyword match for `T1059.001` on the word `powershell` gets a `High` base confidence. But a string containing `powershell + -enc + invoke-expression` earns that same `High` rating even for a `Medium` base technique — because multiple corroborating signals mean a stronger indicator.

---

### Stage 3 — Aggregation & Analytics

Raw results are a flat list of match records. Before export or display, two aggregation functions transform them:

**Tactic Summary** — groups results by tactic and counts matches, used for the bar chart:
```
Execution          ──── 8 matches
Defense Evasion    ──── 5 matches
Credential Access  ──── 3 matches
Persistence        ──── 3 matches
```

**Technique Frequency** — counts how many IOCs triggered each technique, used for the heat map intensity:
```
T1059.001: PowerShell     ──── 4 matches  → hot cell (orange/red)
T1105: Ingress Transfer   ──── 2 matches  → warm cell (yellow)
T1003: Credential Dump    ──── 1 match    → cool cell (pale yellow)
```

---

### Stage 4 — Export & Visualization

Results can be exported in multiple formats simultaneously:

#### CSV / JSON / Markdown
Flat tabular exports containing all match records — suitable for ingestion into SIEMs, ticketing systems, or documentation.

#### ATT&CK Navigator Layer (JSON)
A fully compliant Navigator v4.5 layer with:
- Color gradient from white (0 matches) → yellow → orange → red (max matches)
- Per-technique comments showing match count, confidence, and triggering IOCs
- Metadata including generation timestamp and source tool
- Compatible with the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) web app

#### HTML Heat Map
A self-contained HTML file (no dependencies) with:
- ATT&CK tactic columns across the top
- Technique cells colored by frequency intensity
- Interactive hover tooltips with match details
- Stats bar showing totals, confidence breakdown, and peak hits

#### Sigma Rules (YAML)
For each matched technique that has a template defined, a complete Sigma YAML rule is generated with:
- Logsource (`category`, `product`)
- Detection fields (condition: selection)
- ATT&CK tactic and technique tags
- False positive guidance
- Severity level (`low` / `medium` / `high` / `critical`)
- Sigma CLI conversion commands for Splunk, Elastic, and Microsoft Sentinel

---

### Stage 5 — IOC Extraction (Bonus Layer)

In addition to technique mapping, the tool runs a secondary pass over all input text to extract structured IOCs using regex:

| IOC Type | Pattern | Example |
|----------|---------|---------|
| IPv4 Address | RFC-compliant octet regex | `192.168.1.50` |
| URL | HTTP/HTTPS scheme match | `http://evil.com/payload` |
| Domain | TLD-anchored domain regex | `malicious.example.com` |
| MD5 Hash | 32-char hex string | `d41d8cd98f00b204...` |
| SHA256 Hash | 64-char hex string | `e3b0c44298fc1c...` |

These are displayed in the dashboard separately and can be fed into threat intel platforms.

---

## 🏗️ Architecture Diagrams

### System Architecture

```
╔═══════════════════════════════════════════════════════════════════╗
║                    MITRE ATT&CK TTP MAPPER                        ║
║                     System Architecture                           ║
╠══════════════════╦═══════════════════════╦════════════════════════╣
║   INPUT LAYER    ║    PROCESSING LAYER   ║     OUTPUT LAYER       ║
║                  ║                       ║                        ║
║  ┌────────────┐  ║  ┌─────────────────┐  ║  ┌──────────────────┐  ║
║  │ Plain Text │──╬──►                 │  ║  │   CSV Report     │  ║
║  └────────────┘  ║  │  Log Parsers    │  ║  └──────────────────┘  ║
║  ┌────────────┐  ║  │  ┌───────────┐  │  ║  ┌──────────────────┐  ║
║  │ JSON / NDJSON──╬──► │  Generic  │  ├──╬──►  JSON Report     │  ║
║  └────────────┘  ║  │  │  Parsers  │  │  ║  └──────────────────┘  ║
║  ┌────────────┐  ║  │  └───────────┘  │  ║  ┌──────────────────┐  ║
║  │  Sysmon XML│──╬──►  ┌───────────┐  │  ║  │ Markdown Report  │  ║
║  └────────────┘  ║  │  │  Cloud    │  │  ║  └──────────────────┘  ║
║  ┌────────────┐  ║  │  │  Parsers  │  │  ║  ┌──────────────────┐  ║
║  │    CEF     │──╬──►  │ (AWS/AZ/  │  │  ║  │ Navigator Layer  │  ║
║  └────────────┘  ║  │  │   GCP)    │  │  ║  │    (JSON)        │  ║
║  ┌────────────┐  ║  │  └───────────┘  │  ║  └──────────────────┘  ║
║  │CloudTrail  │──╬──►                 │  ║  ┌─────────────────┐   ║
║  └────────────┘  ║  └────────┬────────┘  ║  │  HTML Heat Map  │   ║
║  ┌────────────┐  ║           │           ║  └─────────────────┘   ║
║  │  Azure Log │──╬──►  ┌────▼────────┐   ║ ┌──────────────────┐   ║
║  └────────────┘  ║  │  │  Mapping    │   ║ │  Sigma Rules     │   ║
║  ┌────────────┐  ║  │  │  Engine     │   ║ │  (YAML)          │   ║
║  │  GCP Audit │──╬──►  │             │   ║ └──────────────────┘   ║
║  └────────────┘  ║  │  │ • Pattern   │   ║ ┌──────────────────┐   ║
║                  ║  │  │   Match     │   ║ │ IOC Extraction   │   ║
║  ┌────────────┐  ║  │  │ • Confidence├───╬─►  (IPs/URLs/      │   ║
║  │  CSV / TSV │──╬──►  │   Scoring   │   ║ │   Hashes)        │   ║
║  └────────────┘  ║  │  │ • Tactic    │   ║ └──────────────────┘   ║
║                  ║  │  │   Summary   │   ║                        ║
╠══════════════════╣  │  └─────────────┘   ╠════════════════════════╣
║  INTERFACES      ║  │                    ║   VISUALIZATION        ║
║                  ║  │                    ║                        ║
║  ┌────────────┐  ║  │                    ║  ┌──────────────────┐  ║
║  │  CLI Tool  │──╬──┘                    ║  │ Streamlit UI     │  ║
║  │ (main.py)  │  ║                       ║  │ • Charts         │  ║
║  └────────────┘  ║                       ║  │ • Tables         │  ║
║  ┌────────────┐  ║                       ║  │ • Export Buttons │  ║
║  │ REST API   │  ║                       ║  └──────────────────┘  ║
║  │ (FastAPI)  │  ║                       ║                        ║
║  └────────────┘  ║                       ║                        ║
╚══════════════════╩═══════════════════════╩════════════════════════╝
```

---

### Processing Pipeline (Sequence)

```
User / Analyst
     │
     │  1. Provide Input (text / file / API call)
     ▼
┌─────────────────────────┐
│   Interface Layer       │  CLI / Dashboard / API
└────────────┬────────────┘
             │  2. Raw input string or file path
             ▼
┌─────────────────────────┐
│   Format Detector       │  auto_detect_and_parse()
└────────────┬────────────┘
             │  3. Select appropriate parser
             ▼
┌─────────────────────────┐
│   Parser Module         │  log_parsers.py / cloud_parsers.py
│   + Cloud Enrichment    │  Appends ATT&CK keywords to cloud events
└────────────┬────────────┘
             │  4. List[str] — normalized IOC strings
             ▼
┌─────────────────────────┐
│   Mapping Engine        │  map_iocs()
│                         │
│   For each IOC:         │
│   ├─ Match 40+ techs    │
│   ├─ Score confidence   │
│   └─ Apply threshold    │
└────────────┬────────────┘
             │  5. List[dict] — match records
             ▼
┌─────────────────────────┐
│   Analytics Layer       │  get_tactic_summary() / get_technique_frequency()
└────────────┬────────────┘
             │  6. Aggregated stats
             ▼
┌────────────────────────────────────────────────┐
│                 Export Layer                   │
│                                                │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐  │
│  │ CSV  │ │ JSON │ │  MD  │ │ NAV  │ │  HM  │  │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘  │
│                    ┌───────┐                   │
│                    │ SIGMA │                   │
│                    └───────┘                   │
└────────────────────────────────────────────────┘
             │
             ▼
        Analyst Consumes Reports
```

---

### Confidence Scoring Logic

```
             IOC String Input
                   │
                   ▼
         ┌──────────────────┐
         │ Pattern Matching │
         │  (regex search)  │
         └────────┬─────────┘
                  │
         ┌────────▼────────┐
         │  Count matched  │
         │  keywords       │
         └────────┬────────┘
                  │
       ┌──────────┴──────────────┐
       │                         │
   0 matches               1+ matches
       │                         │
    SKIP                  ┌──────▼──────────┐
                          │ base_confidence? │
                          └──┬──────────────┘
                             │
              ┌──────────────┼──────────────┐
           "High"         "Medium"        "Low"
              │               │              │
              │          ┌────▼───┐     ┌────▼───┐
              │          │ ≥3 kw? │     │ ≥3 kw? │
              │          └──┬──┬──┘     └──┬──┬──┘
              │            Yes No         Yes No
              │             │  │           │  │
              │           High Med        Med Low
              │
           Always High (no boost needed)

    Final: apply min_confidence threshold filter
```

---

## 🔀 Complete Code Flowchart

This flowchart traces every code path through the entire project — from the moment a user provides input, through every module, to each possible output artifact.

---

### MASTER FLOWCHART — Full Project Execution

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                                 USER ENTRY POINTS                                 ║
╠═══════════════════════╦════════════════════════╦══════════════════════════════════╣
║                       ║                        ║                                  ║
║   ┌───────────────┐   ║   ┌─────────────────┐  ║   ┌───────────────────────────┐  ║
║   │  CLI          │   ║   │  Streamlit      │  ║   │  FastAPI REST             │  ║
║   │  main.py      │   ║   │  app.py         │  ║   │  api.py                   │  ║
║   │               │   ║   │                 │  ║   │                           │  ║
║   │ python main.py│   ║   │  streamlit run  │  ║   │  POST /map                │  ║
║   │  -i file.txt  │   ║   │  app.py         │  ║   │  { "iocs": [...] }        │  ║
║   └──────┬────────┘   ║   └────────┬────────┘  ║   └─────────────┬─────────────┘  ║
║          │            ║            │           ║                 │                ║
╚══════════╪════════════╩════════════╪═══════════╩═════════════════╪════════════════╝
           │                         │                             │
           │   ┌─────────────────────┘                             │
           │   │                                                   │
           ▼   ▼                                                   ▼
┌──────────────────────────────────────────┐        ┌───────────────────────────────┐
│         INPUT HANDLING                   │        │   API INPUT HANDLING          │
│                                          │        │                               │
│  ┌──────────────────────────────────┐    │        │  Raw JSON body with ioc_list  │
│  │  args.input  ─► file path?  Y/N  │    │        │  OR file upload endpoint      │
│  └──────────────┬──────────┬────────┘    │        └────────────────┬──────────────┘
│                 │ YES      │ NO          │                         │
│                 ▼          ▼             │                         │
│         file exists?    ERROR +          │                         │
│              │          sys.exit(1)      │                         │
│              ▼                           │                         │
│    ┌─────────────────┐                   │                         │
│    │ args.format     │                   │                         │
│    │ selection:      │                   │                         │
│    │ auto / text /   │                   │                         │
│    │ json / sysmon / │                   │                         │
│    │ cef / csv /     │                   │                         │
│    │ cloudtrail /    │                   │                         │
│    │ azure / gcp     │                   │                         │ 
│    └────────┬────────┘                   │                         │
└─────────────┼──────────────────────────--┘                         │
              │                                                      │
              ▼                                                      │
╔═════════════════════════════════════════════════════════════════╗  │
║              PARSER SELECTION MODULE                            ║  │
║            parsers/log_parsers.py  +  parsers/cloud_parsers.py  ║  │
╠═════════════════════════════════════════════════════════════════╣  │
║                                                                 ║  │
║   FORMAT_PARSERS dict dispatch:                                 ║  │
║                                                                 ║  │
║   "text"        ──► parse_plain_text(filepath)                  ║  │
║                     • reads file line by line                   ║  │
║                     • strips whitespace                         ║  │
║                     • returns List[str]                         ║  │
║                                                                 ║  │
║   "json"        ──► parse_json_log(filepath)                    ║  │
║                     • tries JSON array parse                    ║  │
║                     • checks wrapper keys:                      ║  │
║                       Records / records / events /              ║  │
║                       logs / value / entries                    ║  │
║                     • falls back to NDJSON line-by-line         ║  │
║                     • calls _flatten_dict() on each entry       ║  │
║                       └─► recursively flattens nested dicts     ║  │
║                           into "key=value | key2=value2" str    ║  │
║                                                                 ║  │
║   "sysmon"      ──► parse_sysmon_xml(filepath)                  ║  │
║                     • ET.parse() XML tree                       ║  │
║                     • detects + strips namespace prefix         ║  │
║                     • iterates <Event> elements                 ║  │
║                     • extracts <Data Name="X">value</Data>      ║  │
║                     • joins as "Name=value | Name2=value2"      ║  │
║                                                                 ║  │
║   "cef"         ──► parse_cef(filepath)                         ║  │
║                     • filters lines starting with "CEF:"        ║  │
║                     • splits on pipe "|" delimiter              ║  │
║                     • extracts event name + extension fields    ║  │
║                                                                 ║  │
║   "csv"         ──► parse_csv_log(filepath)                     ║  │
║                     • reads header row                          ║  │
║                     • for each data row: "header=value | ..."   ║  │
║                                                                 ║  │
║   "cloudtrail"  ──► parse_cloudtrail(filepath)  ◄───────────────╬──┘
║                     • loads JSON, extracts "Records" array      ║
║                     • per event: eventName, eventSource,        ║
║                       sourceIPAddress, userIdentity.arn,        ║
║                       errorCode, errorMessage                   ║
║                     • ENRICHMENT: looks up eventName in         ║
║                       AWS_SUSPICIOUS_EVENTS dict (20 entries)   ║
║                       └─► appends ATT&CK keywords               ║
║                           e.g. StopLogging → "indicator removal ║
║                                defense evasion disable logging" ║
║                     • flags AccessDenied → brute force keywords ║
║                     • flags ConsoleLogin Failure → spray kw     ║
║                                                                 ║
║   "azure"       ──► parse_azure_activity(filepath)              ║
║                     • handles "value" or "records" wrapper      ║
║                     • extracts nested operationName.value       ║
║                     • extracts nested status.value              ║
║                     • ENRICHMENT: AZURE_SUSPICIOUS_OPS dict     ║
║                       (10 entries) → appends ATT&CK keywords    ║
║                     • flags Failed/Forbidden → auth fail kw     ║
║                                                                 ║
║   "gcp"         ──► parse_gcp_audit(filepath)                   ║
║                     • handles "entries" or "logEntries" wrapper ║
║                     • extracts protoPayload: methodName,        ║
║                       serviceName, principalEmail, status       ║
║                     • ENRICHMENT: GCP_SUSPICIOUS_METHODS dict   ║
║                       (10 entries) → appends ATT&CK keywords    ║
║                     • flags PERMISSION_DENIED (code 7) → kw     ║
║                                                                 ║
║   "auto"        ──► auto_detect_and_parse(filepath)             ║
║                     • checks file extension first               ║
║                     • reads first 2048 bytes for content sniff  ║
║                     • detects: { / [ → JSON                     ║
║                     •           CEF: → CEF                      ║
║                     •           <?xml / <Event → XML            ║
║                     • falls back to plain text                  ║
║                     • for .json: also tries parse_cloud_log()   ║
║                       which auto-detects AWS/Azure/GCP          ║
╠═════════════════════════════════════════════════════════════════╣
║                         OUTPUT                                  ║
║              ioc_list: List[str]  (normalized strings)          ║
╚══════════════════════════════════════┬══════════════════════════╝
                                       │
                                       │ ioc_list (empty?) → sys.exit
                                       │
                                       ▼
╔════════════════════════════════════════════════════════════════════════════════════╗
║                     MAPPING ENGINE — mapping_engine.py                             ║
║                         map_iocs(ioc_list, min_confidence, source)                 ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                    ║
║   MODULE LOAD (one-time at import):                                                ║
║   ┌─────────────────────────────────────────────────────────────────────────┐      ║
║   │  TECHNIQUE_DB  (defined as list of tuples)                              │      ║
║   │                                                                         │      ║
║   │  40+ entries, each:                                                     │      ║
║   │  ( tech_id, name, tactic, [pattern_strings], base_confidence )          │      ║
║   │                                                                         │      ║
║   │  Examples:                                                              │      ║
║   │  ("T1059.001", "PowerShell",        "Execution",         [...], "High") │      ║
║   │  ("T1003",     "OS Cred Dumping",   "Credential Access", [...], "High") │      ║
║   │  ("T1486",     "Data Encrypted",    "Impact",            [...], "High") │      ║
║   │  ("T1021.001", "Remote Desktop",    "Lateral Movement",  [...], "Med")  │      ║
║   │  ("T1082",     "System Info Disc.", "Discovery",         [...], "Low")  │      ║
║   │  … (35+ more)                                                           │      ║
║   │                                                                         │      ║
║   │  _COMPILED_DB = [ re.compile(p, IGNORECASE) for p in patterns ]         │      ║
║   │                  ↑ ALL PATTERNS PRE-COMPILED AT IMPORT                  │      ║
║   └─────────────────────────────────────────────────────────────────────────┘      ║
║                                                                                    ║
║   ─────────────────────────────────────────────────────────────────────────────    ║
║                                                                                    ║
║   RUNTIME LOOP:                                                                    ║
║                                                                                    ║
║   timestamp = datetime.utcnow()                                                    ║
║   min_rank  = CONFIDENCE_RANK[min_confidence]  →  Low=1, Medium=2, High=3          ║
║   results   = []                                                                   ║
║                                                                                    ║
║   FOR each ioc_string IN ioc_list:                                                 ║
║   │                                                                                ║
║   │   ioc_lower = ioc_string.lower()                                               ║
║   │                                                                                ║
║   │   FOR each (tech_id, name, tactic, compiled_patterns, base_conf)               ║
║   │            IN _COMPILED_DB:                                                    ║
║   │   │                                                                            ║
║   │   │   matched_keywords = []                                                    ║
║   │   │                                                                            ║
║   │   │   FOR each compiled_pattern IN compiled_patterns:                          ║
║   │   │       match = pattern.search(ioc_lower)                                    ║
║   │   │       IF match:                                                            ║
║   │   │           matched_keywords.append(match.group())                           ║
║   │   │                                                                            ║
║   │   │   IF NOT matched_keywords:  ──► CONTINUE (no match, skip)                  ║
║   │   │                                                                            ║
║   │   │   ┌──────────────────────────────────────────────────────────┐             ║
║   │   │   │           CONFIDENCE SCORING                             │             ║
║   │   │   │                                                          │             ║
║   │   │   │   effective_conf = base_conf                             │             ║
║   │   │   │                                                          │             ║
║   │   │   │   IF len(matched_keywords) >= 3                          │             ║
║   │   │   │   AND CONFIDENCE_RANK[base_conf] < 3 (not already High): │             ║
║   │   │   │       rank = CONFIDENCE_RANK[base_conf] + 1              │             ║
║   │   │   │       effective_conf = reverse_lookup[rank]              │             ║
║   │   │   │       ► Low  becomes Medium                              │             ║
║   │   │   │       ► Medium becomes High                              │             ║
║   │   │   │       ► High stays High                                  │             ║
║   │   │   └──────────────────────────────────────────────────────────┘             ║
║   │   │                                                                            ║
║   │   │   IF CONFIDENCE_RANK[effective_conf] < min_rank:                           ║
║   │   │       CONTINUE  (below threshold, skip)                                    ║
║   │   │                                                                            ║
║   │   │   results.append({                                                         ║
║   │   │       "IOC Summary":      ioc_string.strip(),                              ║
║   │   │       "Technique ID":     tech_id,                                         ║
║   │   │       "Mapped Technique": name,                                            ║
║   │   │       "Tactic":           tactic,                                          ║
║   │   │       "Confidence":       effective_conf,                                  ║
║   │   │       "Matched Keywords": ", ".join(sorted(set(matched_keywords))),        ║
║   │   │       "Timestamp":        timestamp,                                       ║
║   │   │       "Source":           source,                                          ║
║   │   │   })                                                                       ║
║   │                                                                                ║
║   RETURN results  →  List[dict]                                                    ║
║                                                                                    ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║   HELPER FUNCTIONS (called after map_iocs):                                        ║
║                                                                                    ║
║   get_tactic_summary(results)                                                      ║
║   └─► Counter(r["Tactic"] for r in results)                                        ║
║       returns  {"Execution": 8, "Defense Evasion": 5, ...}                         ║
║                                                                                    ║
║   get_technique_frequency(results)                                                 ║
║   └─► Counter("TechID: Name" for r in results)                                     ║
║       returns  {"T1059.001: PowerShell": 4, "T1105: Ingress": 2, ...}              ║
╚══════════════════════════════════════════════╤═════════════════════════════════════╝
                                               │
                                               │  results: List[dict]
                                               │  tactic_summary: dict
                                               │  tech_freq: dict
                                               ▼
╔════════════════════════════════════════════════════════════════════════════════════╗
║                                RESULTS EMPTY CHECK                                 ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║  IF len(results) == 0:                                                             ║
║      CLI   → print "No ATT&CK techniques matched." + sys.exit(0)                   ║
║      UI    → st.warning(...) + st.stop()                                           ║
║      API   → return 200 { "matches": 0, "results": [] }                            ║
╚══════════════════════════════════════════════╤═════════════════════════════════════╝
                                               │  results NOT empty
                                               │
               ┌───────────────────────────────┴──────────────────────────────────────┐
               │                                                                      │
               ▼                                                                      ▼
  ┌────────────────────────┐                                        ┌─────────────────────────────┐
  │   SECONDARY PASS:      │                                        │   EXPORT DISPATCH           │
  │   IOC EXTRACTION       │                                        │                             │
  │   threat_intel.py      │                                        │  CLI flags / UI buttons     │
  │                        │                                        │  determine which exporters  │
  │  extract_iocs(text)    │                                        │  run (can be all at once)   │
  │                        │                                        └──────────────┬──────────────┘
  │  IOC_PATTERNS dict:    │                                                       │
  │  • ips    → regex      │            ┌──────────────────────────────────────────┼──────────────────────────────────────────┐
  │  • urls   → regex      │            │                          │               │               │              │           │
  │  • domains→ regex      │            ▼                          ▼               ▼               ▼              ▼           ▼
  │  • md5    → regex      │   ┌────────────────┐   ┌──────────────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐
  │  • sha256 → regex      │   │  CSV EXPORT    │   │  JSON EXPORT     │  │  MARKDOWN    │  │NAVIGATOR │  │ HEATMAP  │  │   SIGMA    │
  │                        │   │  utils.py      │   │  utils.py        │  │  EXPORT      │  │ EXPORT   │  │ EXPORT   │  │  EXPORT    │
  │  Returns:              │   │                │   │                  │  │  utils.py    │  │          │  │          │  │            │
  │  { "ips": [...],       │   │ write_csv()    │   │ write_json()     │  │              │  │navigator_│  │heatmap_  │  │sigma_      │
  │    "urls": [...],      │   │                │   │                  │  │write_        │  │export.py │  │export.py │  │generator   │
  │    "domains": [...],   │   │ • creates dirs │   │ • creates dirs   │  │markdown()    │  │          │  │          │  │.py         │
  │    "md5": [...],       │   │ • DictWriter   │   │ • json.dump()    │  │              │  │          │  │          │  │            │
  │    "sha256": [...] }   │   │ • writes header│   │   with indent=2  │  │ • writes     │  │          │  │          │  │            │
  │                        │   │ • writes rows  │   │ • default=str    │  │   MD table   │  │          │  │          │  │            │
  │  classify_iocs()       │   │                │   │                  │  │   header +   │  │          │  │          │  │            │
  │  └─► typed list        │   │ OUTPUT:        │   │ OUTPUT:          │  │   rows       │  │          │  │          │  │            │
  │      [{ value,type }]  │   │ report.csv     │   │ report.json      │  │              │  │          │  │          │  │            │
  └────────────────────────┘   └────────────────┘   └──────────────────┘  │ OUTPUT:      │  │          │  │          │  │            │
                                                                          │ report.md    │  │          │  │          │  │            │
                                                                          └──────────────┘  └────┬─────┘  └────┬─────┘  └─────┬──────┘
                                                                                                 │              │              │
                                                                                                 ▼              ▼              ▼
```

---

### NAVIGATOR EXPORT FLOWCHART — `navigator_export.py`

```
  generate_navigator_layer(results, name, description, domain, version)
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────────┐
          │           AGGREGATION PHASE                          │
          │                                                      │
          │  tech_agg = {}    ← keyed by Technique ID            │
          │                                                      │
          │  FOR each result in results:                         │
          │      tid  = result["Technique ID"]                   │
          │      conf = result["Confidence"]                     │
          │                                                      │
          │      IF tid NOT in tech_agg:                         │
          │          create entry {count:0, highest_conf, iocs}  │
          │                                                      │
          │      entry["count"] += 1                             │
          │                                                      │
          │      IF _CONF_RANK[conf] > current highest:          │
          │          update highest_conf                         │
          │                                                      │
          │      IF len(ioc_summaries) < 5:                      │
          │          append ioc[:120]  (truncated for comment)   │
          └───────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
          ┌──────────────────────────────────────────────────────┐
          │           BUILD TECHNIQUE ENTRIES                    │
          │                                                      │
          │  max_count = max(entry["count"] for all entries)     │
          │                                                      │
          │  FOR each (tid, agg) in tech_agg:                    │
          │      comment = "Matches: N | Confidence: X | IOCs…"  │
          │                                                      │
          │      techniques.append({                             │
          │          "techniqueID":       tid,                   │
          │          "tactic":            _tactic_short(tactic), │
          │          "comment":           comment,               │
          │          "score":             agg["count"],  ← HEAT  │
          │          "enabled":           True,                  │
          │          "showSubtechniques": "." in tid,            │
          │          "metadata": [                               │
          │              {"name":"match_count", "value": N},     │
          │              {"name":"confidence",  "value": conf},  │
          │          ]                                           │
          │      })                                              │
          └───────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
          ┌───────────────────────────────────────────────────────────┐
          │         ASSEMBLE FULL NAVIGATOR v4.5 LAYER                │
          │                                                           │
          │  {                                                        │
          │    "name":        layer_name,                             │
          │    "versions":    {attack:14, navigator:4.5, ...}         │
          │    "domain":      "enterprise-attack",                    │
          │    "filters":     { platforms: [Win,Lin,Mac,...] }        │
          │    "layout":      flat, aggregateFunction:max,            │
          │                   showID+Name: true                       │
          │    "techniques":  [ ...entries built above... ]           │
          │    "gradient": {                                          │
          │        "colors":   [#fff → #ffe766 → #ff9632 → #e60]│
          │        "minValue": 0,                                     │
          │        "maxValue": max_count                              │
          │    }                                                      │
          │    "legendItems": [ cold → low → medium → hot ]           │
          │    "metadata":    [ generated_by, generated_at ]          │
          │  }                                                        │
          └───────────────────────┬───────────────────────────────────┘
                                  │
                          ┌───────┴────────┐
                          │                │
                          ▼                ▼
                   return dict        save_layer()
                   (to Streamlit      └─► json.dump()
                    for download)          to .json file
```

---

### HEATMAP EXPORT FLOWCHART — `heatmap_export.py`

```
  generate_heatmap_html(results, layer_name)
                        │
                        ▼
     ┌──────────────────────────────────────────────────────┐
     │  SAME aggregation logic as Navigator export          │
     │  tech_agg keyed by Technique ID                      │
     │                                                      │
     │  ADDITIONALLY: normalise tactic name strings         │
     │  e.g. "command and control" → "command-and-control"  │
     └──────────────────────┬───────────────────────────────┘
                            │
                            ▼
     ┌──────────────────────────────────────────────────────┐
     │  GROUP TECHNIQUES BY TACTIC                          │
     │                                                      │
     │  tactic_techs = { tactic: [list of tech entries] }   │
     │  for each tactic in TACTIC_ORDER (14 tactics):       │
     │      sort each column by count descending            │
     │  active_tactics = [tactics with ≥ 1 technique hit]   │
     └──────────────────────┬───────────────────────────────┘
                            │
                            ▼
     ┌──────────────────────────────────────────────────────┐
     │  COLOR CALCULATION — per technique cell              │
     │                                                      │
     │  _score_to_color(score, max_score):                  │
     │      t = score / max_score  (0.0 → 1.0)              │
     │                                                      │
     │      color stops:                                    │
     │      0.0  → (255, 231, 102)  pale yellow             │
     │      0.4  → (255, 150,  50)  orange                  │
     │      1.0  → (230,   0,   0)  red                     │
     │                                                      │
     │      linear interpolation between stops              │
     │      returns hex color string  e.g. "#ff7a28"      │
     │                                                      │
     │  _text_color(bg_hex):                                │
     │      luminance = 0.299R + 0.587G + 0.114B            │
     │      luminance > 0.5 → black text                    │
     │      luminance ≤ 0.5 → white text                    │
     └──────────────────────┬───────────────────────────────┘
                            │
                            ▼
     ┌──────────────────────────────────────────────────────┐
     │  BUILD HTML STRUCTURE (f-string template)            │
     │                                                      │
     │  FOR each active tactic:                             │
     │      build <div class="tactic-col">                  │
     │          FOR each technique in column:               │
     │              build <div class="tech-cell"            │
     │                    style="background:{bg};color:{fg}"│
     │                    data-tooltip="{escaped_html}">    │
     │                  <span>{tech_id}</span>              │
     │                  <span class="badge">{count}</span>  │
     │              </div>                                  │
     │                                                      │
     │  Embed self-contained CSS (dark theme, gradients)    │
     │  Embed vanilla JS tooltip (mousemove positioning)    │
     │                                                      │
     │  Stats bar: Techniques / Tactics / Matches /         │
     │             Peak Hits / High / Medium / Low conf     │
     │                                                      │
     │  Legend: gradient bar  0 matches → max_count         │
     └──────────────────────┬───────────────────────────────┘
                            │
                            ▼
                     return HTML string
                     └─► save_heatmap() writes to .html file
```

---

### SIGMA GENERATOR FLOWCHART — `sigma_generator.py`

```
  generate_sigma_rules(mapping_results, author)
                            │
                            ▼
     ┌──────────────────────────────────────────────────────┐
     │  DEDUPLICATION                                       │
     │                                                      │
     │  seen_techniques = {}                                │
     │  FOR each result in mapping_results:                 │
     │      tid = result["Technique ID"]                    │
     │      IF tid NOT in seen_techniques:                  │
     │          seen_techniques[tid] = result               │
     │  (keeps first occurrence per technique only)         │
     └──────────────────────┬───────────────────────────────┘
                            │
                            ▼
     ┌──────────────────────────────────────────────────────┐
     │  TEMPLATE LOOKUP                                     │
     │                                                      │
     │  SIGMA_TEMPLATES dict — 20 predefined entries:       │
     │  T1059.001 → PowerShell process creation             │
     │  T1059.003 → Windows CMD shell                       │
     │  T1059.004 → Unix shell                              │
     │  T1003     → Credential dumping (mimikatz etc.)      │
     │  T1053     → Scheduled tasks                         │
     │  T1105     → Ingress tool transfer                   │
     │  T1218.011 → Rundll32                                │
     │  T1547.001 → Registry run keys                       │
     │  T1136     → Account creation                        │
     │  T1078     → Valid accounts (auth events)            │
     │  T1110     → Brute force (event 4625)                │
     │  T1070     → Log clearing                            │
     │  T1562     → Impair defenses / disable AV            │
     │  T1027     → Obfuscation / base64                    │
     │  T1021.001 → RDP (port 3389)                         │
     │  T1021.002 → SMB (port 445)                          │
     │  T1566     → Phishing                                │
     │  T1190     → Public-facing exploit                   │
     │  T1486     → Ransomware / file encryption            │
     │  T1548     → Privilege escalation / UAC bypass       │
     │                                                      │
     │  IF tid NOT in SIGMA_TEMPLATES: SKIP                 │
     └──────────────────────┬───────────────────────────────┘
                            │
                            ▼
     ┌──────────────────────────────────────────────────────┐
     │  RULE ASSEMBLY                                       │
     │                                                      │
     │  tactic_tag   = _TACTIC_TAGS[tactic]                 │
     │                 e.g. "attack.credential_access"      │
     │  technique_tag= "attack.t1003"  (lowercased tid)     │
     │                                                      │
     │  _deterministic_id(tid):                             │
     │      sha256("sigma-T1003") → formatted as UUID       │
     │      ensures same rule ID on every run               │
     │                                                      │
     │  rule = {                                            │
     │    "title":        "Suspicious Activity — Name (ID)",│
     │    "id":           deterministic UUID,               │
     │    "status":       "experimental",                   │
     │    "description":  auto-generated from technique,    │
     │    "references":   ["https://attack.mitre.org/..."], │
     │    "author":       author param,                     │
     │    "date":         today (YYYY/MM/DD),               │
     │    "tags":         [tactic_tag, technique_tag],      │
     │    "logsource":    template["logsource"],            │
     │    "detection": {                                    │
     │        "selection": template["detection_fields"],    │
     │        "condition": "selection"                      │
     │    },                                                │
     │    "falsepositives": template["falsepositives"],     │
     │    "level":        template["level"],                │
     │  }                                                   │
     └──────────────────────┬───────────────────────────────┘
                            │
                            ▼
     ┌──────────────────────────────────────────────────────┐
     │  YAML SERIALIZATION                                  │
     │                                                      │
     │  IF pyyaml installed:                                │
     │      yaml.dump(rule, ...)                            │
     │  ELSE:                                               │
     │      _simple_yaml_dump(rule)  ← built-in fallback    │
     │      handles: dict, list, str, int, bool scalars     │
     │      quotes strings with special chars automatically │
     └──────────────────────┬───────────────────────────────┘
                            │
                   ┌────────┴──────────┐
                   │                   │
                   ▼                   ▼
         single_file=True        single_file=False
              │                        │
              ▼                        ▼
     all_sigma_rules.yml      sigma_T1059_001.yml
     (all rules joined         sigma_T1003.yml
      with "---" separator)    sigma_T1486.yml
                               … (one file per rule)
                               SIGMA_INDEX.md
                               (markdown table + CLI usage)
```

---

### CLOUD PARSER ENRICHMENT DETAIL — `parsers/cloud_parsers.py`

```
  AWS CloudTrail Event: "StopLogging"
                │
                ▼
  ┌─────────────────────────────────────────────────────────┐
  │  AWS_SUSPICIOUS_EVENTS["StopLogging"]                   │
  │  = "stop logging indicator removal defense evasion      │
  │     stoplogging disable logging"                        │
  └─────────────────────────┬───────────────────────────────┘
                            │  appended to IOC string
                            ▼
  "CloudTrail:StopLogging | source=cloudtrail.amazonaws.com |
   ip=198.51.100.42 | user=arn:…backdoor-user |
   [stop logging indicator removal defense evasion stoplogging disable logging]"
                            │
                            ▼  fed into mapping_engine
  ┌─────────────────────────────────────────────────────────┐
  │  T1070 Indicator Removal patterns match:                │
  │     r"stoplogging"      ✓ matched                       │
  │     r"disable.*logging" ✓ matched                       │
  │     r"indicator\s+removal" ✓ matched                    │
  │                                                         │
  │  3+ matches → CONFIDENCE BOOST applied                  │
  │  base: High → stays High                                │
  └─────────────────────────────────────────────────────────┘
```

---

### STREAMLIT DASHBOARD FLOW — `app.py`

```
  streamlit run app.py
            │
            ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PAGE CONFIG + SIDEBAR                                          │
  │  • min_confidence selectbox  (Low / Medium / High)              │
  │  • layer_name text_input                                        │
  └──────────────────────────────┬──────────────────────────────────┘
                                 │
               ┌─────────────────┴──────────────────┐
               │                                    │
               ▼                                    ▼
    ┌──────────────────────┐            ┌────────────────────────┐
    │  tab_paste           │            │  tab_upload            │
    │                      │            │                        │
    │  st.text_area()      │            │  st.file_uploader()    │
    │  raw_text → split    │            │  → save to tempfile    │
    │  on newlines         │            │  → detect extension    │
    │  → ioc_list          │            │  → call parser:        │
    │                      │            │    .json → cloud or    │
    │                      │            │            generic     │
    │                      │            │    .xml  → sysmon      │
    │                      │            │    .csv  → csv         │
    │                      │            │    .cef  → cef         │
    │                      │            │    else  → plain text  │
    │                      │            │  → delete tempfile     │
    │                      │            │  → ioc_list            │
    └──────────┬───────────┘            └───────────┬────────────┘
               │                                    │
               └────────────────┬───────────────────┘
                                │
                  ioc_list not empty?
                                │
                                ▼
              ┌────────────────────────────────────┐
              │  map_iocs(ioc_list, min_confidence) │
              └──────────────────┬─────────────────┘
                                 │
                     no results? → st.warning + st.stop
                                 │
                                 ▼
              ┌────────────────────────────────────────────────────┐
              │  METRICS ROW (4 columns)                           │
              │  IOCs Analyzed │ Technique Matches │               │
              │  Unique Techs  │ Tactics Covered                   │
              └──────────────────────────┬─────────────────────────┘
                                         │
                                         ▼
              ┌────────────────────────────────────────────────────┐
              │  RESULTS TABLE                                     │
              │  pd.DataFrame(results)                             │
              │  .style.applymap(_color_confidence)                │
              │  • High   → red   background, white text           │
              │  • Medium → orange background, black text          │
              │  • Low    → yellow background, black text          │
              │  st.dataframe(styled, height=400)                  │
              └──────────────────────────┬─────────────────────────┘
                                         │
                                         ▼
              ┌─────────────────────────────────────────────────────┐
              │  ANALYTICS CHARTS (Plotly)                          │
              │                                                     │
              │  chart_left:  Tactic Distribution                   │
              │  ├─ px.bar(tactic_df, orientation="h",              │
              │  │         color_scale="Reds")                      │
              │                                                     │
              │  chart_right: Confidence Breakdown                  │
              │  ├─ px.pie(conf_counts, hole=0.45,                  │
              │  │         color_map={High:red,Med:orange,Low:yel}) │
              │                                                     │
              │  full_width:  Technique Frequency                   │
              │  └─ px.bar(freq_df, orientation="h",                │
              │            color_scale="YlOrRd")                    │
              └──────────────────────────┬──────────────────────────┘
                                         │
                                         ▼
              ┌────────────────────────────────────────────────────┐
              │  IOC EXTRACTION PANEL                              │
              │  extract_iocs(" ".join(ioc_list))                  │
              │  displays IPs / URLs / Domains in 3 columns        │
              └──────────────────────────┬─────────────────────────┘
                                         │
                                         ▼
              ┌────────────────────────────────────────────────────┐
              │  EXPORT BUTTONS (3 columns)                        │
              │                                                    │
              │  [📄 Download CSV Report]                          │
              │  └─► df.to_csv() → st.download_button              │
              │                                                    │
              │  [🗺️ Download Navigator Layer]                     │
              │  └─► generate_navigator_layer(results, name)       │
              │      json.dumps() → st.download_button             │
              │                                                    │
              │  [📦 Download Full Analysis JSON]                  │
              │  └─► builds full_export dict with:                 │
              │      timestamp, totals, tactic_summary,            │
              │      tech_freq, results, navigator_layer           │
              │      → st.download_button                          │
              └────────────────────────────────────────────────────┘
```

---

### END-TO-END EXAMPLE — SAMPLE INPUT TO OUTPUT

```
INPUT:
  "mimikatz sekurlsa::logonpasswords"
         │
         ▼  parse_plain_text() → string as-is
         │
         ▼  map_iocs() iterates TECHNIQUE_DB
         │
         │  T1003 patterns tested:
         │  ├─ r"mimikatz"       → match: "mimikatz"   ✓
         │  ├─ r"lsass"         → no match
         │  ├─ r"sekurlsa"      → match: "sekurlsa"   ✓
         │  ├─ r"credential\s+dump" → no match
         │  ├─ r"hashdump"      → no match
         │  └─ r"comsvcs.*minidump" → no match
         │
         │  matched_keywords = ["mimikatz", "sekurlsa"]
         │  len = 2  → no boost (need ≥3)
         │  base_confidence = "High"  → effective = "High"
         │
         ▼
  RESULT:
  {
    "IOC Summary":      "mimikatz sekurlsa::logonpasswords",
    "Technique ID":     "T1003",
    "Mapped Technique": "OS Credential Dumping",
    "Tactic":           "Credential Access",
    "Confidence":       "High",
    "Matched Keywords": "mimikatz, sekurlsa",
    "Timestamp":        "2025-01-15T08:00:00Z",
    "Source":           "cli"
  }
         │
         ▼ navigator_export.py
         │  score = 1 (one IOC triggered this)
         │  color = #ffe766 (1 match, low heat)
         │  comment = "Matches: 1 | Confidence: High | ..."
         │
         ▼ sigma_generator.py
         │  template found for T1003
         │  detection_fields:
         │    CommandLine|contains: [mimikatz, sekurlsa, lsass, ...]
         │  level: critical
         │
         ▼ heatmap_export.py
            cell placed in "Credential Access" column
            color = #ffe766 (1 match intensity)
            tooltip shows IOC summary on hover
```

---

## 📁 Project Structure

```
mitre_mapper/
│
├── 📄 main.py                     # CLI entry point
├── 📄 mapping_engine.py           # Core TTP matching engine
├── 📄 app.py                      # Streamlit web dashboard
├── 📄 api.py                      # FastAPI REST API
│
├── 📁 parsers/
│   ├── 📄 __init__.py
│   ├── 📄 log_parsers.py          # TXT / JSON / XML / CEF / CSV parsers
│   └── 📄 cloud_parsers.py        # AWS CloudTrail / Azure / GCP parsers
│
├── 📁 confidence scoring/
│   ├── 📄 navigator_export.py     # ATT&CK Navigator v4.5 layer generator
│   ├── 📄 heatmap_export.py       # Standalone HTML heat map generator
│   ├── 📄 sigma_generator.py      # Sigma YAML detection rule generator
│   ├── 📄 threat_intel.py         # IOC extraction + enrichment stubs
│   └── 📄 utils.py                # CSV / JSON / Markdown I/O helpers
│
├── 📁 exports/
│   ├── 📄 dockerfile              # Multi-stage Docker build
│   ├── 📄 docker-compose.yml      # Dashboard + API compose stack
│   ├── 📄 requirements.txt        # Python dependencies
│   └── 📁 samples/
│       ├── 📄 sample_input.txt    # Example IOC/log entries
│       └── 📄 sample_cloudtrail.json  # Example AWS CloudTrail log
│
├── 📁 mitre_data/                 # (optional) Cached ATT&CK dataset
├── 📁 output/                     # Generated reports (gitignored)
└── 📄 .gitignore
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.12 or higher
- pip

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/mitre-ttp-mapper.git
cd mitre-ttp-mapper
```

### 2. Install Dependencies

```bash
pip install -r exports/requirements.txt
```

### 3. Run Your First Mapping

```bash
# Map the included sample file
python main.py -i exports/samples/sample_input.txt

# Map with all export formats
python main.py -i exports/samples/sample_input.txt --all-exports

# Map a CloudTrail log
python main.py -i exports/samples/sample_cloudtrail.json -f cloudtrail --all-exports
```

That's it. Output files will appear in the `output/` directory.

---

## 🖥️ Running the Dashboard

The Streamlit dashboard provides a full GUI for non-CLI users:

```bash
streamlit run app.py
```

Then navigate to **http://localhost:8501** in your browser.

### Dashboard Walkthrough

```
┌──────────────────────────────────────────────────────────────────┐
│  🛡️ MITRE ATT&CK TTP Mapper                          Sidebar     │
│                                                   ┌───────────┐  │ 
│  ┌─────────────────┐  ┌──────────────────────┐    │ Min Conf  │  │
│  │  📝 Paste IOCs  │  │  📁 Upload File     │    │ [Low ▼]   │  │
│  └─────────────────┘  └──────────────────────┘    │           │  │
│                                                   │ Layer Name│  │
│  ┌───────────────────────────────────────────┐    │ [______]  │  │
│  │ powershell -enc ZABv...                   │    └───────────┘  │
│  │ mimikatz sekurlsa::logonpasswords         │                   │
│  │ schtasks /create /tn backdoor ...         │                   │
│  └───────────────────────────────────────────┘                   │
│                                                                  │
│  ┌──────────┐ ┌───────────────┐ ┌───────────┐ ┌─────────────┐    │
│  │ IOCs: 15 │ │ Matches:  28  │ │ Techs:  9 │ │ Tactics:  6 │    │
│  └──────────┘ └───────────────┘ └───────────┘ └─────────────┘    │
│                                                                  │
│  MAPPING RESULTS TABLE (color-coded confidence)                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ IOC Summary │ Technique ID │ Tactic │ [High] [Med] [Low] │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ANALYTICS  ┌───────────────────┐  ┌───────────────────────┐     │
│             │  Tactic Bar Chart │  │  Confidence Pie Chart │     │
│             └───────────────────┘  └───────────────────────┘     │
│                                                                  │
│ EXPORT  [📄 CSV]  [🗺️ Navigator Layer]  [📦 Full Analysis JSON] |
└──────────────────────────────────────────────────────────────────┘
```

---

## 💻 Using the CLI

The CLI supports rich options for batch processing and automation pipelines:

```bash
python main.py -i <input_file> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i / --input` | Path to input file | Required |
| `-f / --format` | Input format: `auto`, `text`, `json`, `sysmon`, `cef`, `csv`, `cloudtrail`, `azure`, `gcp` | `auto` |
| `-o / --output-dir` | Output directory | `output/` |
| `--min-confidence` | Minimum confidence: `Low`, `Medium`, `High` | `Low` |
| `--csv` | Export CSV report | — |
| `--json` | Export JSON report | — |
| `--markdown` | Export Markdown report | — |
| `--navigator` | Export Navigator layer JSON | — |
| `--heatmap` | Export HTML heat map | — |
| `--sigma` | Export Sigma detection rules | — |
| `--sigma-single-file` | Combine all Sigma rules into one file | — |
| `--all-exports` | Enable all export formats at once | — |
| `--layer-name` | Custom name for Navigator layer | `"CLI TTP Mapper Layer"` |

### CLI Examples

```bash
# Basic mapping — default CSV output
python main.py -i incident_log.txt

# Only High confidence matches, with Navigator layer
python main.py -i sysmon.xml -f sysmon --min-confidence High --navigator

# CloudTrail with all exports
python main.py -i cloudtrail.json -f cloudtrail --all-exports

# Generate Sigma rules in a single combined file
python main.py -i events.csv --sigma --sigma-single-file

# Auto-detect format, export heat map only
python main.py -i unknown_log.json --heatmap --layer-name "IR-2024-001 Heat Map"
```

---

## 🐳 Docker Deployment

Three build targets are available via the multi-stage Dockerfile:

### Run the Dashboard (default)

```bash
docker build -t ttp-mapper .
docker run -p 8501:8501 -v $(pwd)/output:/app/output ttp-mapper
```

### Run the REST API

```bash
docker build --target api -t ttp-mapper-api .
docker run -p 8000:8000 ttp-mapper-api
```

### Full Stack with Docker Compose

```bash
docker-compose up
```

This starts both the **Streamlit dashboard** on port `8501` and the **FastAPI REST API** on port `8000`.

---

## 📤 Export Formats

| Format | File | Use Case |
|--------|------|----------|
| **CSV** | `report.csv` | Import into Excel, SIEMs, or ticketing systems |
| **JSON** | `report.json` | Programmatic consumption, API integration |
| **Markdown** | `report.md` | Incident reports, wiki pages |
| **Navigator Layer** | `navigator_layer.json` | Load into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for visual coverage mapping |
| **HTML Heat Map** | `heatmap.html` | Self-contained visual — share with stakeholders with no dependencies |
| **Sigma Rules** | `sigma/*.yml` | Deploy directly to Splunk, Elastic, or Microsoft Sentinel |
| **Sigma Index** | `sigma/SIGMA_INDEX.md` | Human-readable index of all generated rules |
| **Full Analysis JSON** | `full_analysis.json` | Complete export including stats, results, and Navigator layer |

---

## 📋 Supported Log Formats

| Format | Parser | Auto-Detect | Notes |
|--------|--------|-------------|-------|
| Plain Text | `parse_plain_text` | ✅ | One IOC / event per line |
| JSON / NDJSON | `parse_json_log` | ✅ | Handles arrays, objects, and NDJSON streams |
| Sysmon XML | `parse_sysmon_xml` | ✅ | Extracts named Data fields per event |
| CEF | `parse_cef` | ✅ | Common Event Format (ArcSight, etc.) |
| CSV | `parse_csv_log` | ✅ | Header-aware; concatenates fields per row |
| AWS CloudTrail | `parse_cloudtrail` | ✅ | ATT&CK keyword enrichment per event type |
| Azure Activity Log | `parse_azure_activity` | ✅ | Handles nested `operationName.value` structure |
| GCP Cloud Audit | `parse_gcp_audit` | ✅ | Parses `protoPayload` structure |

---

## 🗺️ Future Roadmap

The following enhancements are planned or under active consideration:

### 🔜 Near-Term (v1.1)

```
[ ] Live threat intel enrichment via OTX, VirusTotal, AbuseIPDB APIs
    (stubs already exist in threat_intel.py — needs API key integration)

[ ] STIX 2.1 export for sharing with threat intel platforms

[ ] ATT&CK sub-technique expansion with deeper regex coverage

[ ] LLM-assisted mapping for ambiguous or natural-language descriptions
    (call an AI API to handle IOCs that regex cannot match confidently)
```

### 🔮 Medium-Term (v1.2 – v1.5)

```
[ ] Elasticsearch / OpenSearch direct log ingestion
    (query logs directly rather than exporting first)

[ ] Splunk Add-on packaging

[ ] Scheduled scan mode — watch a directory for new log files and
    auto-map them with configurable alerting thresholds

[ ] Technique coverage gap analysis — identify ATT&CK techniques
    with NO Sigma rules or detections in the current environment

[ ] Multi-source correlation — link IOCs across multiple log files
    to build an attack timeline with unified technique coverage
```

### 🌟 Long-Term Vision (v2.0+)

```
[ ] ATT&CK Groups and Software correlation
    (link TTPs to known threat actor profiles automatically)

[ ] Custom technique database support — bring your own patterns
    via YAML config without modifying Python code

[ ] D3FEND integration — map each detected technique to its
    corresponding defensive countermeasures automatically

[ ] Jupyter Notebook integration for threat hunting workflows

[ ] Web API authentication + multi-tenant support for enterprise
    SOC platform deployment
```

---

## 🤝 Contributing

Contributions are welcome! Here is how to get involved:

### Adding New Technique Patterns

Edit the `TECHNIQUE_DB` list in `mapping_engine.py`:

```python
("T1XXX", "Technique Name", "Tactic Name",
 [r"pattern_one", r"pattern_two", r"pattern_three"],
 "High"),   # or "Medium" / "Low"
```

### Adding New Sigma Templates

Add an entry to `SIGMA_TEMPLATES` in `sigma_generator.py`:

```python
"T1XXX": {
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection_fields": {
        "CommandLine|contains": ["suspicious_keyword"],
    },
    "level": "high",
    "falsepositives": ["Legitimate administrative use"],
},
```

### Adding a New Log Parser

1. Add a `parse_<format>()` function to `parsers/log_parsers.py` or `parsers/cloud_parsers.py`
2. Register it in the `FORMAT_PARSERS` dict in `main.py`
3. Add auto-detection logic in `auto_detect_and_parse()`

### Running Tests

```bash
# Run a full pipeline test with the sample inputs
python main.py -i exports/samples/sample_input.txt --all-exports
python main.py -i exports/samples/sample_cloudtrail.json -f cloudtrail --all-exports
```

---

## 🙏 Acknowledgements

- [MITRE ATT&CK](https://attack.mitre.org/) — for the industry-standard adversary behavior framework
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — for the heat map visualization standard
- [Sigma Project](https://github.com/SigmaHQ/sigma) — for the generic SIEM detection rule format
- [Streamlit](https://streamlit.io/) — for making Python dashboards effortless

---

<div align="center">

**Built for defenders. Powered by ATT&CK.**

```
  🛡️  Detect faster. Hunt smarter. Respond better.  🛡️
```

[⬆ Back to Top](#-mitre-attck-ttp-mapper)

</div>
