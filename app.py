"""
Sentinel-AI — Streamlit Dashboard
Main UI for the forensic investigation workbench.

Run: streamlit run dashboard/app.py
"""

import streamlit as st
import requests
import os
import json
from datetime import datetime

API_URL = "http://localhost:8000"

def _run_direct(case_id, summary, net_file, mal_file, url, social, rn, rm, rp, rs):
    """Run engines directly without API server (fallback mode)."""
    import sys, os, tempfile
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    results = {}

    if net_file and rn:
        from engines.network_analyser import analyse as an
        from engines.zeroday_detector import analyse_csv as az
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            tmp.write(net_file.getvalue())
            tmp_path = tmp.name
        results["network"] = an(tmp_path)
        results["zeroday"] = az(tmp_path)

    if url and rp:
        from engines.phishing_analyser import analyse as ap
        results["phishing"] = ap(url)

    if mal_file and rm:
        from engines.malware_engine import analyse as am
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(mal_file.getvalue())
            tmp_path = tmp.name
        results["malware"] = am(tmp_path)

    if social and rs:
        from engines.social_media_detector import analyse as asc
        results["social"] = asc(social)

    from utils.report_generator import generate_report
    pdf = generate_report(
        case_id=case_id, incident_summary=summary,
        network_result=results.get("network"),
        phishing_result=results.get("phishing"),
        malware_result=results.get("malware"),
        social_result=results.get("social"),
        zeroday_result=results.get("zeroday"),
    )
    return {"status": "success", "case_id": case_id, "results": results, "report_pdf": pdf}






# ─── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Sentinel-AI | Forensic Workbench",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── CSS ──────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .sentinel-header {
        background: linear-gradient(135deg, #0C447C, #185FA5);
        color: white;
        padding: 20px 28px;
        border-radius: 12px;
        margin-bottom: 20px;
    }
    .sentinel-header h1 { color: white; margin: 0; font-size: 2rem; }
    .sentinel-header p  { color: #B5D4F4; margin: 4px 0 0; font-size: 0.95rem; }

    .verdict-danger  { background:#FCEBEB; border-left:4px solid #A32D2D; padding:12px 16px; border-radius:6px; color:#501313; font-weight:600; }
    .verdict-safe    { background:#EAF3DE; border-left:4px solid #3B6D11; padding:12px 16px; border-radius:6px; color:#173404; font-weight:600; }
    .verdict-warn    { background:#FAEEDA; border-left:4px solid #854F0B; padding:12px 16px; border-radius:6px; color:#412402; font-weight:600; }
    .metric-card     { background:#F1EFE8; border-radius:10px; padding:14px 18px; text-align:center; }
    .metric-card h3  { margin:0; font-size:1.6rem; color:#0C447C; }
    .metric-card p   { margin:4px 0 0; font-size:0.82rem; color:#5F5E5A; }
    .engine-badge    { display:inline-block; padding:3px 10px; border-radius:12px; font-size:0.8rem; font-weight:600; margin-right:6px; }
    .badge-blue      { background:#E6F1FB; color:#0C447C; }
    .badge-red       { background:#FCEBEB; color:#A32D2D; }
    .badge-green     { background:#EAF3DE; color:#3B6D11; }
</style>
""", unsafe_allow_html=True)

# ─── Header ───────────────────────────────────────────────────────────────────
st.markdown("""
<div class="sentinel-header">
    <h1>🛡️ Sentinel-AI</h1>
    <p>AI Forensic Workbench for Cybercrime Investigation &nbsp;·&nbsp; All analysis runs locally &nbsp;·&nbsp; No data leaves your machine</p>
</div>
""", unsafe_allow_html=True)

# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### Investigation Setup")
    case_id = st.text_input("Case ID", value=f"CASE-{datetime.now().strftime('%Y%m%d-%H%M')}")
    incident_summary = st.text_area(
        "Incident Summary",
        value="Suspicious network activity detected. Automated forensic investigation initiated.",
        height=100,
    )
    st.markdown("---")
    st.markdown("### Engines")
    run_network = st.checkbox("Network Traffic Analyser", value=True)
    run_phishing = st.checkbox("Phishing URL Analyser", value=True)
    run_malware = st.checkbox("Malware Investigator", value=True)
    run_social = st.checkbox("Social Media Detector", value=True)
    st.markdown("---")
    st.markdown("**Sentinel-AI v1.0**")
    st.caption("Built by Soumya Jena\nApexDevs Internship 2026")

# ─── Main tabs ────────────────────────────────────────────────────────────────
tab_upload, tab_results, tab_report = st.tabs(["📁 Upload & Analyse", "📊 Results", "📄 Forensic Report"])

# ── Tab 1: Upload ─────────────────────────────────────────────────────────────
with tab_upload:
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Network Log")
        network_file = st.file_uploader("Upload network log CSV (CICIDS format)", type=["csv"], key="net")
        st.subheader("Suspicious File")
        malware_file = st.file_uploader("Upload suspicious file (.exe, .dll, .bin)", key="mal")

    with col2:
        st.subheader("URL Analysis")
        url_input = st.text_input("Enter URL to analyse", placeholder="https://suspicious-site.com/login")
        st.subheader("Social Media Text")
        social_input = st.text_area("Paste social media post or text", height=120,
                                    placeholder="Enter text to scan for criminal activity...")

    st.markdown("---")
    analyse_btn = st.button("🔍 Run Forensic Analysis", type="primary", use_container_width=True)

    if analyse_btn:
        has_input = any([network_file, malware_file, url_input, social_input])
        if not has_input:
            st.warning("Please provide at least one input to analyse.")
        else:
            with st.spinner("Running AI forensic engines..."):
                # Build multipart form data
                files = {}
                data = {
                    "case_id": case_id,
                    "incident_summary": incident_summary,
                }

                if network_file and run_network:
                    files["network_log"] = (network_file.name, network_file.getvalue(), "text/csv")
                if malware_file and run_malware:
                    files["suspicious_file"] = (malware_file.name, malware_file.getvalue(), "application/octet-stream")
                if url_input and run_phishing:
                    data["url"] = url_input
                if social_input and run_social:
                    data["social_text"] = social_input

                try:
                    response = requests.post(f"{API_URL}/investigate", files=files, data=data, timeout=120)
                    if response.status_code == 200:
                        result = response.json()
                        st.session_state["last_result"] = result
                        st.success("Analysis complete! Switch to the Results tab.")
                    else:
                        st.error(f"API error {response.status_code}: {response.text}")
                except requests.exceptions.ConnectionError:
                    # Fallback: run engines directly (no API server needed)
                    st.info("API server not running — executing engines directly...")
                    result = _run_direct(
                        case_id, incident_summary,
                        network_file, malware_file, url_input, social_input,
                        run_network, run_malware, run_phishing, run_social
                    )
                    st.session_state["last_result"] = result
                    st.success("Direct analysis complete! Switch to the Results tab.")




# ── Tab 2: Results ────────────────────────────────────────────────────────────
with tab_results:
    if "last_result" not in st.session_state:
        st.info("Run an analysis first to see results here.")
    else:
        res = st.session_state["last_result"]
        modules = res.get("results", {})

        # Summary row
        total_threats = sum(
            1 for k, v in modules.items()
            if isinstance(v, dict) and v.get("verdict", "").upper() not in ("CLEAN", "LEGITIMATE", "NORMAL", "KNOWN PATTERN", "")
        )
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(f'<div class="metric-card"><h3>{len(modules)}</h3><p>Engines run</p></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="metric-card"><h3 style="color:{"#A32D2D" if total_threats else "#3B6D11"}">{total_threats}</h3><p>Threats found</p></div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="metric-card"><h3>{res.get("case_id","—")}</h3><p>Case ID</p></div>', unsafe_allow_html=True)
        with col4:
            st.markdown(f'<div class="metric-card"><h3>{"THREAT" if total_threats else "CLEAN"}</h3><p>Overall verdict</p></div>', unsafe_allow_html=True)

        st.markdown("---")

        # Per-engine results
        def verdict_class(v):
            v = v.upper()
            if any(x in v for x in ["ATTACK", "PHISHING", "MALWARE", "TROJAN", "RANSOMWARE", "THREAT", "CRIMINAL", "ZERO-DAY"]):
                return "verdict-danger"
            if any(x in v for x in ["WARN", "SUSPICIOUS"]):
                return "verdict-warn"
            return "verdict-safe"

        for engine_key, label in [("network", "Network Traffic Analysis"), ("phishing", "Phishing URL"),
                                   ("malware", "Malware Investigation"), ("social", "Social Media"),
                                   ("zeroday", "Zero-Day Detection")]:
            if engine_key in modules:
                r = modules[engine_key]
                verdict = r.get("verdict", "N/A")
                conf = r.get("confidence", r.get("anomaly_confidence", 0))
                with st.expander(f"**{label}** — {verdict}", expanded=True):
                    st.markdown(f'<div class="{verdict_class(verdict)}">Verdict: {verdict} &nbsp;|&nbsp; Confidence: {conf}%</div>', unsafe_allow_html=True)
                    st.json(r)


# ── Tab 3: Report ─────────────────────────────────────────────────────────────
with tab_report:
    if "last_result" not in st.session_state:
        st.info("Run an analysis first to generate a forensic report.")
    else:
        res = st.session_state["last_result"]
        pdf_path = res.get("report_pdf", "")

        if pdf_path and os.path.exists(pdf_path):
            st.success(f"Report ready: `{os.path.basename(pdf_path)}`")
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="⬇️ Download Forensic PDF Report",
                    data=f.read(),
                    file_name=os.path.basename(pdf_path),
                    mime="application/pdf",
                    use_container_width=True,
                )
            st.markdown("---")
            st.markdown("**Report contents:**")
            st.markdown("""
- Case metadata (ID, date, time, classification)
- Incident summary
- Network traffic analysis findings
- Phishing URL analysis
- Malware classification + description
- Social media crime detection
- Zero-day anomaly detection
- Confidence scores for all modules
- Legal disclaimer
""")
        else:
            st.warning("PDF not found. Ensure ReportLab is installed: `pip install reportlab`")
