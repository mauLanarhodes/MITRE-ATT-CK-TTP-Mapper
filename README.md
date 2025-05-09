# MITRE ATT&CK TTP Mapper

A Python tool to map observed Indicators of Compromise (IOCs) or log events to MITRE ATT&CK techniques.

## Features
- Input incident descriptions or logs
- Match against MITRE ATT&CK techniques
- Export to CSV or Navigator layer JSON

## How it Works
1. Load or fetch MITRE ATT&CK dataset
2. Parse inputs (text/JSON/CSV)
3. Match text patterns to ATT&CK TTPs
4. Output human-readable and visual reports

## Example Use Case
- Input: 'powershell downloading file from IP'
- Output: T1059 - Command and Scripting Interpreter

## Folder Structure
```
mitre_mapper/
├── mitre_data/       # Cached MITRE ATT&CK dataset
├── samples/          # Sample incident logs
├── output/           # Reports and exports
├── main.py           # Entry point for the tool
├── mapping_engine.py # TTP matching logic
├── utils.py          # Helpers
```

MITRE ATT&CK: https://attack.mitre.org/
