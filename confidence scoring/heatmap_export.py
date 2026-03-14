"""
heatmap_export.py — Generates a self-contained HTML visual heat map
of ATT&CK technique matches, styled after MITRE ATT&CK Navigator.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

# Canonical ATT&CK Enterprise tactic order
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_LABELS = {
    "reconnaissance":       "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion":      "Defense Evasion",
    "credential-access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral Movement",
    "collection":           "Collection",
    "command-and-control":  "Command & Control",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
}


def _score_to_color(score: int, max_score: int) -> str:
    """Interpolate white → yellow → orange → red based on score ratio."""
    if max_score == 0 or score == 0:
        return "#f0f0f0"
    stops = [
        (0.0,  (255, 231, 102)),  # yellow  — any hit
        (0.4,  (255, 150,  50)),  # orange
        (1.0,  (230,   0,   0)),  # red     — max hits
    ]
    t = min(score / max_score, 1.0)
    for i in range(len(stops) - 1):
        t0, c0 = stops[i]
        t1, c1 = stops[i + 1]
        if t <= t1:
            frac = (t - t0) / (t1 - t0) if t1 > t0 else 0
            r = int(c0[0] + frac * (c1[0] - c0[0]))
            g = int(c0[1] + frac * (c1[1] - c0[1]))
            b = int(c0[2] + frac * (c1[2] - c0[2]))
            # Pick black or white text based on luminance
            return f"#{r:02x}{g:02x}{b:02x}"
    return "#e60000"


def _text_color(bg_hex: str) -> str:
    """Return black or white text color for readability on bg_hex."""
    h = bg_hex.lstrip("#")
    if len(h) != 6:
        return "#000000"
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
    return "#000000" if luminance > 0.5 else "#ffffff"


def generate_heatmap_html(
    results: List[dict],
    layer_name: str = "ATT&CK TTP Heat Map",
) -> str:
    """
    Build a self-contained HTML heat map from map_iocs() results.
    Returns the full HTML string.
    """

    # --- Aggregate by technique (same logic as navigator_export) ---
    _conf_rank = {"Low": 1, "Medium": 2, "High": 3}
    tech_agg: Dict[str, Dict[str, Any]] = {}

    for r in results:
        tid  = r["Technique ID"]
        conf = r.get("Confidence", "Low")
        tactic = r.get("Tactic", "").lower().replace(" ", "-")
        # normalise tactic name
        tactic = {
            "command and control": "command-and-control",
            "lateral movement":    "lateral-movement",
            "privilege escalation":"privilege-escalation",
            "defense evasion":     "defense-evasion",
            "credential access":   "credential-access",
            "initial access":      "initial-access",
            "resource development":"resource-development",
        }.get(tactic, tactic)

        ioc = r.get("IOC Summary", "")

        if tid not in tech_agg:
            tech_agg[tid] = {
                "tactic": tactic,
                "highest_conf": conf,
                "count": 0,
                "iocs": [],
            }
        entry = tech_agg[tid]
        entry["count"] += 1
        if _conf_rank.get(conf, 0) > _conf_rank.get(entry["highest_conf"], 0):
            entry["highest_conf"] = conf
        if len(entry["iocs"]) < 5:
            entry["iocs"].append(ioc[:120])

    if not tech_agg:
        return "<html><body><p>No techniques matched.</p></body></html>"

    max_count = max(a["count"] for a in tech_agg.values())

    # --- Group techniques by tactic ---
    tactic_techs: Dict[str, List[dict]] = {t: [] for t in TACTIC_ORDER}
    for tid, agg in tech_agg.items():
        tac = agg["tactic"]
        if tac in tactic_techs:
            tactic_techs[tac].append({"id": tid, **agg})

    # Sort each tactic column by count descending
    for tac in tactic_techs:
        tactic_techs[tac].sort(key=lambda x: -x["count"])

    # Only include tactics that have hits
    active_tactics = [t for t in TACTIC_ORDER if tactic_techs[t]]

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # --- Build technique cells ---
    def make_cells(tac: str) -> str:
        techs = tactic_techs[tac]
        if not techs:
            return '<div class="empty-cell">—</div>'
        cells = []
        for tech in techs:
            bg   = _score_to_color(tech["count"], max_count)
            fg   = _text_color(bg)
            ioc_list = "<br>".join(f"• {i}" for i in tech["iocs"]) if tech["iocs"] else "No IOC detail"
            tooltip  = (
                f"<strong>{tech['id']}</strong><br>"
                f"Matches: {tech['count']}<br>"
                f"Confidence: {tech['highest_conf']}<br>"
                f"<hr style='border-color:#555;margin:4px 0'>{ioc_list}"
            )
            cells.append(
                f'<div class="tech-cell" style="background:{bg};color:{fg}" '
                f'data-tooltip="{_esc(tooltip)}">'
                f'  <span class="tech-id">{tech["id"]}</span>'
                f'  <span class="tech-badge">{tech["count"]}</span>'
                f'</div>'
            )
        return "\n".join(cells)

    # --- Build tactic columns ---
    columns_html = ""
    for tac in active_tactics:
        label = TACTIC_LABELS.get(tac, tac.replace("-", " ").title())
        count = len(tactic_techs[tac])
        columns_html += f"""
        <div class="tactic-col">
          <div class="tactic-header">
            <div class="tactic-name">{label}</div>
            <div class="tactic-count">{count} technique{"s" if count != 1 else ""}</div>
          </div>
          <div class="tactic-body">
            {make_cells(tac)}
          </div>
        </div>"""

    # --- Legend gradient bar ---
    legend_stops = ", ".join([
        "#f0f0f0 0%",
        "#ffe766 20%",
        "#ff9632 60%",
        "#e60000 100%",
    ])

    # --- Build stats bar ---
    total_matches = sum(a["count"] for a in tech_agg.values())
    conf_counts   = {"High": 0, "Medium": 0, "Low": 0}
    for a in tech_agg.values():
        conf_counts[a["highest_conf"]] = conf_counts.get(a["highest_conf"], 0) + 1

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc_html(layer_name)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #1a1a2e;
    color: #e0e0e0;
    min-height: 100vh;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #16213e 0%, #0f3460 100%);
    padding: 20px 30px;
    border-bottom: 2px solid #e94560;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
  }}
  .header-title {{
    font-size: 1.5rem;
    font-weight: 700;
    color: #fff;
    letter-spacing: 0.5px;
  }}
  .header-title span {{ color: #e94560; }}
  .header-meta {{
    font-size: 0.78rem;
    color: #a0a0b0;
  }}

  /* ── Stats bar ── */
  .stats-bar {{
    background: #16213e;
    padding: 12px 30px;
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
    border-bottom: 1px solid #2a2a4a;
  }}
  .stat {{
    display: flex;
    flex-direction: column;
    align-items: center;
  }}
  .stat-value {{
    font-size: 1.4rem;
    font-weight: 700;
    color: #fff;
  }}
  .stat-label {{
    font-size: 0.7rem;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .stat-high   .stat-value {{ color: #e60000; }}
  .stat-medium .stat-value {{ color: #ff9632; }}
  .stat-low    .stat-value {{ color: #ffe766; }}

  /* ── Heat map grid ── */
  .heatmap-wrapper {{
    overflow-x: auto;
    padding: 24px 30px;
  }}
  .heatmap-grid {{
    display: flex;
    gap: 10px;
    min-width: max-content;
  }}

  .tactic-col {{
    width: 140px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }}

  .tactic-header {{
    background: #205b8f;
    border-radius: 6px 6px 0 0;
    padding: 8px 6px;
    text-align: center;
    border-bottom: 2px solid #e94560;
  }}
  .tactic-name {{
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #fff;
    word-break: break-word;
  }}
  .tactic-count {{
    font-size: 0.65rem;
    color: #a0c4e8;
    margin-top: 3px;
  }}

  .tactic-body {{
    display: flex;
    flex-direction: column;
    gap: 4px;
    background: #12122a;
    padding: 6px;
    border-radius: 0 0 6px 6px;
    flex: 1;
  }}

  .tech-cell {{
    border-radius: 4px;
    padding: 5px 6px;
    cursor: pointer;
    position: relative;
    display: flex;
    justify-content: space-between;
    align-items: center;
    transition: transform 0.1s, box-shadow 0.1s;
    min-height: 30px;
  }}
  .tech-cell:hover {{
    transform: scale(1.04);
    box-shadow: 0 0 10px rgba(255,255,255,0.25);
    z-index: 10;
  }}
  .tech-id {{
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.3px;
  }}
  .tech-badge {{
    font-size: 0.65rem;
    font-weight: 700;
    background: rgba(0,0,0,0.25);
    border-radius: 10px;
    padding: 1px 5px;
    min-width: 18px;
    text-align: center;
  }}
  .empty-cell {{
    color: #444;
    font-size: 0.8rem;
    text-align: center;
    padding: 8px;
  }}

  /* ── Tooltip ── */
  .tooltip-box {{
    display: none;
    position: fixed;
    z-index: 9999;
    background: #1e1e3a;
    border: 1px solid #444;
    border-radius: 6px;
    padding: 10px 12px;
    font-size: 0.78rem;
    line-height: 1.5;
    max-width: 320px;
    pointer-events: none;
    box-shadow: 0 4px 20px rgba(0,0,0,0.6);
    color: #e0e0e0;
    word-break: break-word;
  }}

  /* ── Legend ── */
  .legend {{
    margin: 0 30px 30px;
    background: #16213e;
    border-radius: 8px;
    padding: 16px 20px;
    display: flex;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
  }}
  .legend-title {{
    font-size: 0.78rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #a0a0b0;
    white-space: nowrap;
  }}
  .legend-bar-wrap {{
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 200px;
  }}
  .legend-bar {{
    height: 16px;
    flex: 1;
    border-radius: 8px;
    background: linear-gradient(to right, {legend_stops});
    border: 1px solid #333;
  }}
  .legend-label {{
    font-size: 0.72rem;
    color: #888;
    white-space: nowrap;
  }}

  /* ── Footer ── */
  .footer {{
    text-align: center;
    padding: 14px;
    font-size: 0.7rem;
    color: #555;
    border-top: 1px solid #2a2a4a;
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-title">
    <span>&#9632;</span> {_esc_html(layer_name)}
  </div>
  <div class="header-meta">Generated {generated_at} &nbsp;|&nbsp; MITRE ATT&amp;CK TTP Mapper</div>
</div>

<div class="stats-bar">
  <div class="stat">
    <div class="stat-value">{len(tech_agg)}</div>
    <div class="stat-label">Techniques</div>
  </div>
  <div class="stat">
    <div class="stat-value">{len(active_tactics)}</div>
    <div class="stat-label">Tactics</div>
  </div>
  <div class="stat">
    <div class="stat-value">{total_matches}</div>
    <div class="stat-label">Total Matches</div>
  </div>
  <div class="stat">
    <div class="stat-value">{max_count}</div>
    <div class="stat-label">Peak Hits</div>
  </div>
  <div class="stat stat-high">
    <div class="stat-value">{conf_counts.get('High', 0)}</div>
    <div class="stat-label">High Conf</div>
  </div>
  <div class="stat stat-medium">
    <div class="stat-value">{conf_counts.get('Medium', 0)}</div>
    <div class="stat-label">Medium Conf</div>
  </div>
  <div class="stat stat-low">
    <div class="stat-value">{conf_counts.get('Low', 0)}</div>
    <div class="stat-label">Low Conf</div>
  </div>
</div>

<div class="heatmap-wrapper">
  <div class="heatmap-grid">
    {columns_html}
  </div>
</div>

<div class="legend">
  <div class="legend-title">Heat Intensity</div>
  <div class="legend-bar-wrap">
    <span class="legend-label">0 matches</span>
    <div class="legend-bar"></div>
    <span class="legend-label">{max_count} matches</span>
  </div>
</div>

<div class="footer">
  MITRE ATT&amp;CK TTP Mapper &mdash; Heat map generated {generated_at}
  &nbsp;|&nbsp; Hover over a cell for details
</div>

<!-- Tooltip element -->
<div class="tooltip-box" id="tooltip"></div>

<script>
(function() {{
  const tip = document.getElementById('tooltip');
  document.querySelectorAll('.tech-cell').forEach(function(cell) {{
    cell.addEventListener('mouseenter', function(e) {{
      tip.innerHTML = cell.dataset.tooltip;
      tip.style.display = 'block';
      positionTip(e);
    }});
    cell.addEventListener('mousemove', positionTip);
    cell.addEventListener('mouseleave', function() {{
      tip.style.display = 'none';
    }});
  }});

  function positionTip(e) {{
    var x = e.clientX + 14, y = e.clientY + 14;
    var tw = tip.offsetWidth, th = tip.offsetHeight;
    if (x + tw > window.innerWidth  - 10) x = e.clientX - tw - 14;
    if (y + th > window.innerHeight - 10) y = e.clientY - th - 14;
    tip.style.left = x + 'px';
    tip.style.top  = y + 'px';
  }}
}})();
</script>
</body>
</html>"""

    return html


def _esc(s: str) -> str:
    """Escape a string for use inside an HTML attribute value."""
    return (s
        .replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _esc_html(s: str) -> str:
    """Escape a string for use as HTML text content."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def save_heatmap(results: List[dict], output_path: str, layer_name: str = "ATT&CK TTP Heat Map") -> str:
    """Generate and save the HTML heat map. Returns the output path."""
    html = generate_heatmap_html(results, layer_name=layer_name)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
