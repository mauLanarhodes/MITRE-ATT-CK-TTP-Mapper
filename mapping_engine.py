# Match IOCs to MITRE techniques (placeholder)
def map_iocs(ioc_list):
    # Simplified static map (expandable)
    technique_map = {
        "powershell": ("T1059", "Command and Scripting Interpreter", "Execution"),
        "curl": ("T1105", "Ingress Tool Transfer", "Command and Control"),
        "rundll32": ("T1218", "Signed Binary Proxy Execution", "Defense Evasion")
    }
    results = []
    for ioc in ioc_list:
        for keyword, (tech_id, name, tactic) in technique_map.items():
            if keyword in ioc.lower():
                results.append({
                    "IOC Summary": ioc,
                    "Technique ID": tech_id,
                    "Mapped Technique": name,
                    "Tactic": tactic
                })
    return results
