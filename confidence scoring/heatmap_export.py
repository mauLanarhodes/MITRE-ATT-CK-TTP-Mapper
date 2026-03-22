"""
heatmap_export.py — Redesigned ATT&CK heatmap with contribution-graph aesthetic.
Inspired by: GitHub contributions, Heat.js, seaborn heatmaps, LeetCode profiles.

Provides save_heatmap(results, output_path, layer_name=...) for use as a module,
and can also be run as a standalone script.
"""

import json, glob, os, re, math
from collections import defaultdict
from datetime import datetime, timezone


# ── Tactic ordering ────────────────────────────────────────────────────────

TACTIC_ORDER = [
    "reconnaissance","resource-development","initial-access","execution",
    "persistence","privilege-escalation","defense-evasion","credential-access",
    "discovery","lateral-movement","collection","command-and-control",
    "exfiltration","impact",
    "network-effects","remote-service-effects",
    "evasion","inhibit-response-function","impair-process-control",
]
TACTIC_LABELS = {
    "reconnaissance":"Recon","resource-development":"Resource Dev",
    "initial-access":"Initial Access","execution":"Execution",
    "persistence":"Persistence","privilege-escalation":"Priv Esc",
    "defense-evasion":"Def Evasion","credential-access":"Cred Access",
    "discovery":"Discovery","lateral-movement":"Lateral Mov",
    "collection":"Collection","command-and-control":"C2",
    "exfiltration":"Exfiltration","impact":"Impact",
    "network-effects":"Net Effects","remote-service-effects":"Remote Svc",
    "evasion":"Evasion","inhibit-response-function":"Inhibit Response",
    "impair-process-control":"Impair Process",
}
TACTIC_FULL = {
    "reconnaissance":"Reconnaissance","resource-development":"Resource Development",
    "initial-access":"Initial Access","execution":"Execution",
    "persistence":"Persistence","privilege-escalation":"Privilege Escalation",
    "defense-evasion":"Defense Evasion","credential-access":"Credential Access",
    "discovery":"Discovery","lateral-movement":"Lateral Movement",
    "collection":"Collection","command-and-control":"Command & Control",
    "exfiltration":"Exfiltration","impact":"Impact",
    "network-effects":"Network Effects","remote-service-effects":"Remote Service Effects",
    "evasion":"Evasion","inhibit-response-function":"Inhibit Response Function",
    "impair-process-control":"Impair Process Control",
}

_TACTIC_NORM = {
    "command-and-control":"command-and-control","lateral-movement":"lateral-movement",
    "privilege-escalation":"privilege-escalation","defense-evasion":"defense-evasion",
    "credential-access":"credential-access","initial-access":"initial-access",
    "resource-development":"resource-development",
    "mobile-initial-access":"initial-access","mobile-execution":"execution",
    "mobile-persistence":"persistence","mobile-privilege-escalation":"privilege-escalation",
    "mobile-defense-evasion":"defense-evasion","mobile-credential-access":"credential-access",
    "mobile-discovery":"discovery","mobile-collection":"collection",
    "mobile-command-and-control":"command-and-control","mobile-exfiltration":"exfiltration",
    "mobile-impact":"impact","mobile-network-effects":"network-effects",
    "mobile-remote-service-effects":"remote-service-effects",
    "ics-initial-access":"initial-access","ics-execution":"execution",
    "ics-persistence":"persistence","ics-privilege-escalation":"privilege-escalation",
    "ics-evasion":"evasion","ics-discovery":"discovery","ics-lateral-movement":"lateral-movement",
    "ics-collection":"collection","ics-command-and-control":"command-and-control",
    "ics-inhibit-response-function":"inhibit-response-function",
    "ics-impair-process-control":"impair-process-control","ics-impact":"impact",
}

CONF_WEIGHT = {"Low": 1, "Medium": 2, "High": 3}
CONF_RANK = {"Low": 1, "Medium": 2, "High": 3}


# ── Color scale ────────────────────────────────────────────────────────────

def risk_color(risk, max_r):
    """5-stop heat scale: near-black -> cool green -> warm yellow -> orange -> red."""
    if max_r == 0 or risk == 0:
        return "#1a1e24"
    t = min(risk / max_r, 1.0)
    stops = [
        (0.00, (40, 50, 56)),
        (0.15, (22, 101, 52)),
        (0.35, (56, 176, 0)),
        (0.60, (255, 214, 0)),
        (0.80, (255, 140, 30)),
        (1.00, (230, 30, 30)),
    ]
    for i in range(len(stops) - 1):
        t0, c0 = stops[i]
        t1, c1 = stops[i + 1]
        if t <= t1:
            f = (t - t0) / (t1 - t0) if t1 > t0 else 0
            r = int(c0[0] + f * (c1[0] - c0[0]))
            g = int(c0[1] + f * (c1[1] - c0[1]))
            b = int(c0[2] + f * (c1[2] - c0[2]))
            return f"#{r:02x}{g:02x}{b:02x}"
    return "#e61e1e"


def esc(s):
    return s.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")


def donut_svg(high, med, low, size=80):
    total = high + med + low
    if total == 0:
        return ""
    r = 32
    cx, cy = size/2, size/2
    stroke_w = 8
    circ = 2 * math.pi * r

    segments = []
    offset = 0
    for val, col in [(high, "#f85149"), (med, "#d29922"), (low, "#6e7681")]:
        if val == 0:
            continue
        pct = val / total
        dash = pct * circ
        gap = circ - dash
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="{col}" stroke-width="{stroke_w}" '
            f'stroke-dasharray="{dash:.1f} {gap:.1f}" '
            f'stroke-dashoffset="{-offset:.1f}" '
            f'transform="rotate(-90 {cx} {cy})" />'
        )
        offset += dash

    return f'''<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
        <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#21262d" stroke-width="{stroke_w}" />
        {"".join(segments)}
        <text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="central"
              fill="#e6edf3" font-size="14" font-weight="700" font-family="ui-monospace,monospace">{total}</text>
    </svg>'''


def save_heatmap(results, output_path, layer_name="TTP Mapper Layer", sigma_dir=None):
    """
    Generate a standalone HTML heatmap from mapping results and write to output_path.

    Parameters
    ----------
    results : list[dict]
        Mapping results from map_iocs().
    output_path : str
        File path to write the HTML heatmap.
    layer_name : str
        Display name for the heatmap header.
    sigma_dir : str | None
        Optional directory to scan for sigma rule YAML files to show coverage.
    """
    # Load sigma coverage
    covered_tids = set()
    if sigma_dir and os.path.isdir(sigma_dir):
        for path in glob.glob(os.path.join(sigma_dir, "sigma_T*.yml")):
            m = re.match(r"sigma_(T[\d_]+)\.yml", os.path.basename(path))
            if m:
                covered_tids.add(m.group(1).replace("_", "."))

    # ── Aggregate ──────────────────────────────────────────────────────────
    tech_agg = {}
    for r in results:
        tid = r["Technique ID"]
        conf = r.get("Confidence", "Low")
        tactic = _TACTIC_NORM.get(
            r.get("Tactic", "").lower().replace(" ", "-"),
            r.get("Tactic", "").lower().replace(" ", "-"),
        )
        ioc = r.get("IOC Summary", "")
        if tid not in tech_agg:
            tech_agg[tid] = {
                "tactic": tactic,
                "highest_conf": conf,
                "alert_count": 0,
                "risk_score": 0.0,
                "iocs": [],
                "name": r.get("Mapped Technique", tid),
            }
        e = tech_agg[tid]
        e["alert_count"] += 1
        e["risk_score"] += CONF_WEIGHT.get(conf, 1)
        if CONF_RANK.get(conf, 0) > CONF_RANK.get(e["highest_conf"], 0):
            e["highest_conf"] = conf
        if len(e["iocs"]) < 5:
            e["iocs"].append(ioc[:110])

    # Synthesise parents
    parent_agg = {}
    for tid, agg in tech_agg.items():
        if "." in tid:
            pid = tid.split(".")[0]
            if pid not in tech_agg:
                if pid not in parent_agg:
                    parent_agg[pid] = {
                        "tactic": agg["tactic"],
                        "highest_conf": agg["highest_conf"],
                        "alert_count": 0,
                        "risk_score": 0.0,
                        "iocs": [],
                        "name": pid,
                    }
                pa = parent_agg[pid]
                pa["alert_count"] += agg["alert_count"]
                pa["risk_score"] += agg["risk_score"]
                if CONF_RANK.get(agg["highest_conf"], 0) > CONF_RANK.get(pa["highest_conf"], 0):
                    pa["highest_conf"] = agg["highest_conf"]
                for s in agg["iocs"]:
                    if len(pa["iocs"]) < 5:
                        pa["iocs"].append(s)
                if tid in covered_tids:
                    covered_tids.add(pid)
    tech_agg.update(parent_agg)

    max_risk = max((a["risk_score"] for a in tech_agg.values()), default=1.0)

    # Group by tactic
    tactic_techs = {t: [] for t in TACTIC_ORDER}
    for tid, agg in tech_agg.items():
        tac = agg["tactic"]
        if tac in tactic_techs:
            tactic_techs[tac].append({"id": tid, **agg})

    def sort_key(x):
        return (0, -x["risk_score"]) if x["alert_count"] > 0 else \
               (1, 0) if x["id"] in covered_tids else (2, 0)

    for tac in tactic_techs:
        tactic_techs[tac].sort(key=sort_key)

    active_tactics = [t for t in TACTIC_ORDER if tactic_techs[t]]

    # Stats
    total_alerts = sum(a["alert_count"] for a in tech_agg.values())
    total_risk = sum(a["risk_score"] for a in tech_agg.values())
    active_count = sum(1 for a in tech_agg.values() if a["alert_count"] > 0)
    covered_with_alerts = sum(1 for tid, a in tech_agg.items() if tid in covered_tids and a["alert_count"] > 0)
    covered_only = sum(1 for tid, a in tech_agg.items() if tid in covered_tids and a["alert_count"] == 0)
    no_sigma_count = sum(1 for tid in tech_agg if tid not in covered_tids)
    gap_count = sum(1 for tid, a in tech_agg.items() if tid not in covered_tids and a["alert_count"] == 0)
    hc = sum(1 for a in tech_agg.values() if a["alert_count"] > 0 and a["highest_conf"] == "High")
    mc = sum(1 for a in tech_agg.values() if a["alert_count"] > 0 and a["highest_conf"] == "Medium")
    lc = sum(1 for a in tech_agg.values() if a["alert_count"] > 0 and a["highest_conf"] == "Low")
    max_techs_in_tactic = max(len(tactic_techs[t]) for t in active_tactics) if active_tactics else 0
    generated_at = datetime.now(timezone.utc).strftime("%b %d, %Y · %H:%M UTC")

    # ── Build cell data as JSON for JS rendering ──────────────────────────
    cells_data = []
    for tac in active_tactics:
        row_cells = []
        for tech in tactic_techs[tac]:
            has_alerts = tech["alert_count"] > 0
            is_covered = tech["id"] in covered_tids

            if has_alerts:
                state = "active"
                color = risk_color(tech["risk_score"], max_risk)
            elif is_covered:
                state = "covered"
                color = "#0e4429"
            else:
                state = "gap"
                color = "#161b22"

            has_sigma = tech["id"] in covered_tids

            row_cells.append({
                "id": tech["id"],
                "name": tech.get("name", tech["id"]),
                "state": state,
                "color": color,
                "alerts": tech["alert_count"],
                "risk": round(tech["risk_score"], 1),
                "conf": tech["highest_conf"],
                "iocs": tech["iocs"][:3],
                "sigma": has_sigma,
            })
        cells_data.append({
            "tactic": tac,
            "label": TACTIC_LABELS.get(tac, tac),
            "full_label": TACTIC_FULL.get(tac, tac),
            "count": len(row_cells),
            "active": sum(1 for c in row_cells if c["state"] == "active"),
            "cells": row_cells,
        })

    cells_json = json.dumps(cells_data)

    # ── Confidence donut SVG ─────────────────────────────────────────────
    donut = donut_svg(hc, mc, lc)
    cov_donut = donut_svg(active_count, covered_only, gap_count, 80)

    # ── Legend squares ───────────────────────────────────────────────────
    legend_colors = []
    for i in range(6):
        t = i / 5
        risk_val = t * max_risk
        legend_colors.append(risk_color(risk_val, max_risk))

    # ── HTML ───────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ATT&CK Detection Heat Map</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');

:root {{
  --bg-primary: #0d1117;
  --bg-surface: #161b22;
  --bg-elevated: #1c2128;
  --bg-overlay: #21262d;
  --border: #30363d;
  --border-subtle: #21262d;
  --fg: #e6edf3;
  --fg-muted: #8b949e;
  --fg-subtle: #6e7681;
  --accent: #58a6ff;
  --green: #3fb950;
  --red: #f85149;
  --yellow: #d29922;
  --purple: #a371f7;
  --mono: 'JetBrains Mono', ui-monospace, monospace;
  --sans: 'DM Sans', -apple-system, sans-serif;
  --cell-size: 28px;
  --cell-gap: 3px;
  --cell-radius: 4px;
}}

*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ scroll-behavior: smooth; }}
body {{
  font-family: var(--sans);
  background: var(--bg-primary);
  color: var(--fg);
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}}

.topbar {{
  background: rgba(1,4,9,.85);
  backdrop-filter: blur(16px) saturate(180%);
  -webkit-backdrop-filter: blur(16px) saturate(180%);
  border-bottom: 1px solid var(--border-subtle);
  position: sticky; top: 0; z-index: 100;
  padding: 0 32px; height: 52px;
  display: flex; align-items: center; gap: 12px;
}}
.topbar-logo {{
  display: flex; align-items: center; gap: 8px;
  font-family: var(--mono); font-weight: 700; font-size: 13px;
  color: var(--fg); letter-spacing: -.2px;
}}
.topbar-logo svg {{ width: 20px; height: 20px; fill: var(--green); opacity: .85; }}
.topbar-sep {{ color: var(--fg-subtle); font-size: 18px; }}
.topbar-crumb {{ color: var(--fg-muted); font-size: 13px; font-weight: 500; }}
.topbar-crumb a {{ color: var(--accent); text-decoration: none; }}
.topbar-spacer {{ flex: 1; }}
.topbar-badge {{
  font-family: var(--mono); font-size: 11px; font-weight: 600;
  padding: 3px 10px; border-radius: 20px;
  background: rgba(56,139,253,.12); color: var(--accent);
  border: 1px solid rgba(56,139,253,.3);
}}

.page {{ max-width: 1440px; margin: 0 auto; padding: 28px 32px 80px; }}

.stats-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px; margin-bottom: 24px;
}}
.stat-card {{
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 10px; padding: 16px 20px;
  display: flex; align-items: center; gap: 16px;
  transition: border-color .15s;
}}
.stat-card:hover {{ border-color: var(--border); }}
.stat-card-icon {{
  width: 40px; height: 40px; border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  font-size: 18px; flex-shrink: 0;
}}
.stat-card-body {{ min-width: 0; }}
.stat-card-value {{
  font-family: var(--mono); font-size: 22px; font-weight: 700;
  line-height: 1.1;
}}
.stat-card-label {{
  font-size: 12px; color: var(--fg-muted); margin-top: 2px;
  font-weight: 500;
}}

.donut-section {{
  display: flex; gap: 32px; align-items: center; flex-wrap: wrap;
  margin-bottom: 24px;
  padding: 20px 24px;
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
}}
.donut-block {{ display: flex; align-items: center; gap: 14px; }}
.donut-legend {{ display: flex; flex-direction: column; gap: 5px; }}
.donut-legend-item {{
  display: flex; align-items: center; gap: 8px;
  font-size: 12px; color: var(--fg-muted);
}}
.donut-legend-dot {{
  width: 8px; height: 8px; border-radius: 2px; flex-shrink: 0;
}}
.donut-legend-val {{
  font-family: var(--mono); font-weight: 600;
  color: var(--fg); min-width: 24px;
}}
.donut-divider {{
  width: 1px; height: 56px; background: var(--border-subtle); flex-shrink: 0;
}}

.section-title {{
  font-size: 15px; font-weight: 700; color: var(--fg);
  margin-bottom: 12px;
  display: flex; align-items: center; gap: 10px;
}}
.section-title::before {{
  content: ''; width: 3px; height: 16px;
  background: var(--accent); border-radius: 2px;
}}
.section-subtitle {{
  font-size: 12px; color: var(--fg-subtle); margin-bottom: 16px;
}}

.heatmap-card {{
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
  padding: 20px 24px;
  margin-bottom: 16px;
  overflow: hidden;
}}
.heatmap-scroll {{
  overflow-x: auto; overflow-y: visible;
  padding-bottom: 8px;
}}
.heatmap-grid {{
  display: flex; flex-direction: column; gap: 6px;
  min-width: max-content;
}}
.heatmap-row {{
  display: flex; align-items: center; gap: 0;
}}
.heatmap-row-label {{
  width: 120px; flex-shrink: 0;
  font-size: 11px; font-weight: 600;
  color: var(--fg-muted);
  text-align: right; padding-right: 14px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  font-family: var(--mono);
  letter-spacing: -.3px;
}}
.heatmap-row-cells {{
  display: flex; gap: var(--cell-gap); align-items: center;
}}
.heatmap-row-count {{
  margin-left: 10px;
  font-size: 10px; font-family: var(--mono);
  color: var(--fg-subtle); white-space: nowrap;
}}

.cell {{
  width: var(--cell-size); height: var(--cell-size);
  border-radius: var(--cell-radius);
  cursor: pointer;
  position: relative;
  transition: transform .08s ease, outline-color .08s ease;
  outline: 2px solid transparent; outline-offset: 1px;
}}
.cell:hover {{
  transform: scale(1.35);
  z-index: 20;
}}
.cell-active:hover {{ outline-color: rgba(248,81,73,.6); }}
.cell-covered:hover {{ outline-color: rgba(63,185,80,.5); }}
.cell-gap {{
  outline: 1px dashed var(--border-subtle);
  outline-offset: -1px;
}}
.cell-gap:hover {{ outline: 2px solid var(--fg-subtle); outline-offset: 1px; }}

.tooltip {{
  display: none; position: fixed; z-index: 9999;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 8px;
  max-width: 320px; pointer-events: none;
  box-shadow: 0 8px 30px rgba(0,0,0,.6), 0 0 1px rgba(0,0,0,.3);
  overflow: hidden;
  font-size: 12px;
}}
.tt-head {{
  padding: 10px 14px;
  background: var(--bg-overlay);
  border-bottom: 1px solid var(--border-subtle);
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
}}
.tt-tid {{
  font-family: var(--mono); font-weight: 700; font-size: 13px;
  color: var(--fg);
}}
.tt-name {{
  font-size: 11px; color: var(--fg-muted); font-weight: 500;
  max-width: 160px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}}
.tt-state {{
  font-size: 9px; font-weight: 800; padding: 2px 8px;
  border-radius: 20px; text-transform: uppercase; letter-spacing: .8px;
  flex-shrink: 0;
}}
.tt-state-active {{ background: #da3633; color: #fff; }}
.tt-state-covered {{ background: #238636; color: #fff; }}
.tt-state-gap {{ background: var(--border); color: var(--fg-subtle); }}
.tt-body {{ padding: 10px 14px; display: flex; flex-direction: column; gap: 6px; }}
.tt-metric {{
  display: flex; justify-content: space-between; align-items: center;
}}
.tt-metric-key {{ color: var(--fg-subtle); font-size: 11px; }}
.tt-metric-val {{ font-family: var(--mono); font-weight: 600; color: var(--fg); }}
.tt-conf-High {{ color: var(--red); }}
.tt-conf-Medium {{ color: var(--yellow); }}
.tt-conf-Low {{ color: var(--fg-subtle); }}
.tt-divider {{ height: 1px; background: var(--border-subtle); }}
.tt-ioc {{
  font-size: 10.5px; color: var(--fg-muted); line-height: 1.4;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  max-width: 290px;
}}
.tt-formula {{
  font-size: 10px; color: var(--fg-subtle); font-family: var(--mono);
}}

.legend-bar {{
  display: flex; flex-wrap: wrap; align-items: center; gap: 20px;
  padding: 14px 20px;
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
  margin-bottom: 16px;
}}
.legend-group {{
  display: flex; align-items: center; gap: 6px;
  font-size: 11px; color: var(--fg-muted);
}}
.legend-squares {{
  display: flex; gap: 2px;
}}
.legend-sq {{
  width: 12px; height: 12px; border-radius: 3px;
}}
.legend-sep {{
  width: 1px; height: 18px; background: var(--border-subtle);
}}
.legend-item {{
  display: flex; align-items: center; gap: 5px;
  font-size: 11px; color: var(--fg-muted);
}}
.legend-dot {{
  width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0;
}}

.formula-note {{
  font-size: 12px; color: var(--fg-subtle);
  padding: 12px 16px;
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-left: 3px solid var(--yellow);
  border-radius: 0 8px 8px 0;
  margin-bottom: 20px;
  font-family: var(--mono);
  line-height: 1.7;
}}
.formula-note strong {{ color: var(--fg-muted); }}

.footer {{
  border-top: 1px solid var(--border-subtle);
  padding: 20px; text-align: center;
  font-size: 11px; color: var(--fg-subtle);
  font-family: var(--mono);
  display: flex; align-items: center; justify-content: center;
  gap: 12px; flex-wrap: wrap;
}}
.footer a {{ color: var(--accent); text-decoration: none; }}
.footer a:hover {{ text-decoration: underline; }}

::-webkit-scrollbar {{ height: 6px; width: 6px; }}
::-webkit-scrollbar-track {{ background: transparent; }}
::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--fg-subtle); }}

@keyframes fadeRow {{
  from {{ opacity: 0; transform: translateX(-8px); }}
  to {{ opacity: 1; transform: translateX(0); }}
}}
.heatmap-row {{
  animation: fadeRow .3s ease forwards;
  opacity: 0;
}}

.filter-bar {{
  display: flex; gap: 6px; margin-bottom: 16px; flex-wrap: wrap;
}}
.filter-pill {{
  font-family: var(--mono); font-size: 11px; font-weight: 600;
  padding: 5px 12px; border-radius: 20px;
  border: 1px solid var(--border);
  background: transparent; color: var(--fg-muted);
  cursor: pointer; transition: all .15s;
}}
.filter-pill:hover {{ border-color: var(--accent); color: var(--accent); }}
.filter-pill.active {{
  background: rgba(56,139,253,.15); border-color: var(--accent); color: var(--accent);
}}

@media (prefers-reduced-motion: reduce) {{
  *, *::before, *::after {{ transition-duration: .01ms !important; animation-duration: .01ms !important; }}
}}
</style>
</head>
<body>

<nav class="topbar">
  <div class="topbar-logo">Attack Heatmap</div>
  <div class="topbar-spacer"></div>
</nav>

<main class="page">

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-card-icon" style="background:rgba(56,139,253,.12);color:var(--accent);">&#9889;</div>
      <div class="stat-card-body">
        <div class="stat-card-value">{len(tech_agg)}</div>
        <div class="stat-card-label">Techniques mapped</div>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-card-icon" style="background:rgba(248,81,73,.12);color:var(--red);">&#128293;</div>
      <div class="stat-card-body">
        <div class="stat-card-value">{active_count}</div>
        <div class="stat-card-label">Active alerts</div>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-card-icon" style="background:rgba(163,113,247,.12);color:var(--purple);">&#9888;</div>
      <div class="stat-card-body">
        <div class="stat-card-value" style="color:var(--purple)">{total_risk:.0f}</div>
        <div class="stat-card-label">Total risk score</div>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-card-icon" style="background:rgba(63,185,80,.12);color:var(--green);">&#10003;</div>
      <div class="stat-card-body">
        <div class="stat-card-value" style="color:var(--green)">{len(covered_tids)}</div>
        <div class="stat-card-label">Sigma rules loaded</div>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-card-icon" style="background:rgba(210,153,34,.12);color:var(--yellow);">&#10007;</div>
      <div class="stat-card-body">
        <div class="stat-card-value" style="color:var(--yellow)">{no_sigma_count}</div>
        <div class="stat-card-label">Without Sigma rules</div>
      </div>
    </div>
  </div>

  <div class="donut-section">
    <div class="donut-block">
      {donut}
      <div class="donut-legend">
        <div class="donut-legend-item">
          <div class="donut-legend-dot" style="background:var(--red)"></div>
          <span class="donut-legend-val">{hc}</span> High
        </div>
        <div class="donut-legend-item">
          <div class="donut-legend-dot" style="background:var(--yellow)"></div>
          <span class="donut-legend-val">{mc}</span> Medium
        </div>
        <div class="donut-legend-item">
          <div class="donut-legend-dot" style="background:var(--fg-subtle)"></div>
          <span class="donut-legend-val">{lc}</span> Low
        </div>
      </div>
    </div>
    <div class="donut-divider"></div>
    <div style="display:flex;flex-direction:column;gap:4px">
      <div style="font-size:12px;color:var(--fg-muted);font-weight:600">Confidence breakdown</div>
      <div style="font-size:11px;color:var(--fg-subtle)">
        {total_alerts} total alerts across {len(active_tactics)} tactics<br>
        Generated {generated_at}
      </div>
    </div>
  </div>

  <div class="legend-bar">
    <div class="legend-group">
      <span>Less</span>
      <div class="legend-squares">
        {"".join(f'<div class="legend-sq" style="background:{c}"></div>' for c in legend_colors)}
      </div>
      <span>More</span>
    </div>
    <div class="legend-sep"></div>
    <div class="legend-item">
      <div class="legend-dot" style="background:#0e4429;border:1px solid #238636"></div>
      Covered - quiet
    </div>
    <div class="legend-item">
      <div class="legend-dot" style="background:#161b22;border:1px dashed #30363d"></div>
      Gap - no rule
    </div>
    <div class="legend-sep"></div>
    <div class="legend-item">
      <div style="width:12px;height:12px;border-radius:3px;background:#ff9632;position:relative;flex-shrink:0">
        <div style="position:absolute;top:1px;right:1px;width:4px;height:4px;border-radius:50%;background:#3fb950"></div>
      </div>
      Green dot = Sigma rule exists
    </div>
    <div class="legend-sep"></div>
    <div class="legend-group" style="font-family:var(--mono);font-size:10px;color:var(--fg-subtle)">
      Risk = alerts x conf weight &nbsp;(H=3 M=2 L=1)
    </div>
  </div>

  <div class="filter-bar">
    <button class="filter-pill active" data-filter="all">All</button>
    <button class="filter-pill" data-filter="active">Active only</button>
    <button class="filter-pill" data-filter="covered">Covered only</button>
    <button class="filter-pill" data-filter="gap">Gaps only</button>
  </div>

  <div class="section-title">Detection activity</div>
  <div class="section-subtitle">Each square is a technique -- hover for details - sorted by risk score within each tactic</div>

  <div class="heatmap-card">
    <div class="heatmap-scroll">
      <div class="heatmap-grid" id="heatmapGrid">
      </div>
    </div>
  </div>

</main>

<footer class="footer">
  <span>MITRE ATT&CK TTP Mapper</span>
  <span>-</span>
  <span>SIEM-style heat map</span>
  <span>-</span>
  <span>{generated_at}</span>
  <span>-</span>
  <a href="https://attack.mitre.org" target="_blank" rel="noopener">attack.mitre.org</a>
</footer>

<div class="tooltip" id="tooltip"></div>

<script>
const DATA = {cells_json};

const grid = document.getElementById('heatmapGrid');
const tooltip = document.getElementById('tooltip');
let currentFilter = 'all';

function renderGrid() {{
  grid.innerHTML = '';
  DATA.forEach((row, ri) => {{
    const rowEl = document.createElement('div');
    rowEl.className = 'heatmap-row';
    rowEl.style.animationDelay = (ri * 0.04) + 's';

    const label = document.createElement('div');
    label.className = 'heatmap-row-label';
    label.textContent = row.label;
    label.title = row.full_label;
    rowEl.appendChild(label);

    const cellsWrap = document.createElement('div');
    cellsWrap.className = 'heatmap-row-cells';

    let visCount = 0;
    row.cells.forEach(c => {{
      if (currentFilter !== 'all' && c.state !== currentFilter) return;
      visCount++;
      const cell = document.createElement('div');
      cell.className = 'cell cell-' + c.state;
      cell.style.background = c.color;
      cell.dataset.tip = JSON.stringify(c);
      cell.dataset.tactic = row.full_label;

      if (c.sigma && c.state === 'active') {{
        const dot = document.createElement('div');
        dot.style.cssText = 'position:absolute;top:2px;right:2px;width:5px;height:5px;border-radius:50%;background:#3fb950;';
        cell.style.position = 'relative';
        cell.appendChild(dot);
      }}

      cell.addEventListener('mouseenter', showTip);
      cell.addEventListener('mousemove', moveTip);
      cell.addEventListener('mouseleave', hideTip);

      cellsWrap.appendChild(cell);
    }});

    rowEl.appendChild(cellsWrap);

    if (visCount > 0) {{
      const count = document.createElement('div');
      count.className = 'heatmap-row-count';
      const activeInRow = row.cells.filter(c => c.state === 'active').length;
      count.textContent = activeInRow > 0 ? activeInRow + ' alert' + (activeInRow !== 1 ? 's' : '') : '';
      rowEl.appendChild(count);
      grid.appendChild(rowEl);
    }}
  }});
}}

function showTip(e) {{
  const c = JSON.parse(e.target.dataset.tip);
  const tactic = e.target.dataset.tactic;
  let stateClass = 'tt-state-' + c.state;
  let stateLabel = c.state === 'active' ? 'ACTIVE' : c.state === 'covered' ? 'COVERED' : 'GAP';

  let body = '';
  if (c.state === 'active') {{
    body = `
      <div class="tt-body">
        <div class="tt-metric"><span class="tt-metric-key">Alerts</span><span class="tt-metric-val">${{c.alerts}}</span></div>
        <div class="tt-metric"><span class="tt-metric-key">Risk score</span><span class="tt-metric-val">${{c.risk}}</span></div>
        <div class="tt-metric"><span class="tt-metric-key">Confidence</span><span class="tt-metric-val tt-conf-${{c.conf}}">${{c.conf}}</span></div>
        <div class="tt-metric"><span class="tt-metric-key">Sigma rule</span><span class="tt-metric-val" style="color:${{c.sigma?'var(--green)':'var(--yellow)'}}">${{c.sigma?'Yes':'Missing'}}</span></div>
        <div class="tt-formula">${{c.alerts}} alerts x ${{{{High:3,Medium:2,Low:1}}[c.conf]}} weight = ${{c.risk}}</div>
        ${{c.iocs.length ? '<div class="tt-divider"></div>' + c.iocs.map(i => '<div class="tt-ioc">- ' + i.replace(/</g,'&lt;') + '</div>').join('') : ''}}
      </div>`;
  }} else if (c.state === 'covered') {{
    body = '<div class="tt-body"><div class="tt-ioc">Sigma rule exists -- no alerts fired</div><div class="tt-ioc" style="color:var(--fg-subtle)">Environment clean or rule needs tuning</div></div>';
  }} else {{
    body = '<div class="tt-body"><div class="tt-ioc">No detection rule</div><div class="tt-ioc" style="color:var(--fg-subtle)">Consider authoring a Sigma rule</div></div>';
  }}

  tooltip.innerHTML = `
    <div class="tt-head">
      <div>
        <div class="tt-tid">${{c.id}}</div>
        <div class="tt-name">${{c.name}} - ${{tactic}}</div>
      </div>
      <span class="tt-state ${{stateClass}}">${{stateLabel}}</span>
    </div>
    ${{body}}`;
  tooltip.style.display = 'block';
  moveTip(e);
}}

function moveTip(e) {{
  let x = e.clientX + 14, y = e.clientY + 14;
  const tw = tooltip.offsetWidth, th = tooltip.offsetHeight;
  if (x + tw > window.innerWidth - 10) x = e.clientX - tw - 14;
  if (y + th > window.innerHeight - 10) y = e.clientY - th - 14;
  if (x < 4) x = 4;
  if (y < 4) y = 4;
  tooltip.style.left = x + 'px';
  tooltip.style.top = y + 'px';
}}

function hideTip() {{
  tooltip.style.display = 'none';
}}

document.querySelectorAll('.filter-pill').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter;
    renderGrid();
  }});
}});

renderGrid();
</script>
</body>
</html>"""

    # ── Write output ──────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def _normalize_records(raw):
    """Convert IOC log format (mitre_attack nested) to the flat format save_heatmap expects."""
    out = []
    severity_to_conf = {"low": "Low", "medium": "Medium", "high": "High", "critical": "High"}
    for entry in raw:
        ma = entry.get("mitre_attack")
        if not ma:
            continue
        out.append({
            "Technique ID": ma.get("technique", ""),
            "Mapped Technique": ma.get("technique_name", ""),
            "Tactic": ma.get("tactic", ""),
            "Confidence": severity_to_conf.get(entry.get("severity", "").lower(), "Medium"),
            "IOC Summary": entry.get("description", ""),
        })
    return out


if __name__ == "__main__":
    # Standalone script mode — read from report.json in current directory
    report_path = os.environ.get("REPORT_PATH", "report.json")
    with open(report_path) as f:
        results = json.load(f)
    # Auto-detect IOC log format vs flat report format
    if results and isinstance(results[0], dict) and "mitre_attack" in results[0]:
        results = _normalize_records(results)
    output_path = os.environ.get("OUTPUT_PATH", "heatmap.html")
    save_heatmap(results, output_path)
    print(f"Written to {output_path}")
