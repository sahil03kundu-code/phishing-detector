import streamlit as st
from phising_detector import run_analysis, capture_screenshot
import re
import os

# --- UI CONFIGURATION ---
st.set_page_config(page_title="PhishGuard AI: Forensic Lab", page_icon="🛡️", layout="wide")

# --- CUSTOM CSS FOR DARK MODE CYBER AESTHETIC ---
st.markdown("""
    <style>
    .main { background-color: #0e1117; color: #c9d1d9; }
    .stMetric { background-color: #161b22; padding: 15px; border-radius: 10px; border: 1.5px solid #30363d; }
    .stSidebar { background-color: #0d1117; border-right: 1px solid #30363d; }
    .stButton>button { width: 100%; border-radius: 5px; height: 3em; background-color: #238636; color: white; border: none; }
    .stButton>button:hover { background-color: #2ea043; border: none; }
    .clear-btn>button { background-color: #da3633 !important; }
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE FOR HISTORY ---
if "history" not in st.session_state:
    st.session_state.history = []

# --- SCORING LOGIC ENGINE ---
def calculate_risk_score(url, ai_report):
    score = 0
    report = ai_report.lower()
    url_clean = url.lower()
    
    # 1. AI SEMANTIC OVERRIDE
    danger_phrases = ["do not click", "report as spam", "suspicious indicators", "phishing", "verdict: danger"]
    if any(p in report for p in danger_phrases): score += 80

    # 2. PUNYCODE / HOMOGRAPH
    if "punycode_attack: true" in report: return 100

    # 3. BRAND PROTECTION
    trusted = ["google.com", "paypal.com", "microsoft.com", "amazon.com", "apple.com", "github.com"]
    is_trusted = any(d in url_clean and (url_clean.endswith(d) or f"{d}/" in url_clean) for d in trusted)
    
    if is_trusted and "cloaked_redirect: false" in report: return 0
    if "brand_spoofing: true" in report: score += 70

    # 4. REDIRECTS & ENTROPY
    if "cloaked_redirect: true" in report or "bit.ly" in url_clean: score += 40
    ent_match = re.search(r'str_entropy: (\d+\.\d+)', report)
    if ent_match and float(ent_match.group(1)) > 4.2: score += 40
    
    return min(score, 100)

# --- SIDEBAR: LOGO & HISTORY ---
with st.sidebar:
    # Cybersecurity Logo Placeholder (Using a professional Icon & Text)
    st.markdown("<h1 style='text-align: center; color: #58a6ff;'>🛡️ PHISHGUARD</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; font-size: 0.8em;'>v3.0 Neural-Forensic Engine</p>", unsafe_allow_html=True)
    st.divider()
    
    st.subheader("📜 Investigation History")
    if st.session_state.history:
        for idx, item in enumerate(reversed(st.session_state.history)):
            st.info(f"**{item['type']}**: {item['url'][:30]}...")
            
        st.markdown("---")
        if st.button("🗑️ Clear History", key="clear_hist"):
            st.session_state.history = []
            st.rerun()
    else:
        st.write("No recent scans.")

# --- MAIN UI LAYOUT ---
st.title("🛡️ Forensic Intelligence Dashboard")
st.caption("AI-Powered Real-time Threat Decryption & Visual Verification")
st.divider()

col1, col2 = st.columns([3, 2])

with col1:
    user_input = st.text_area("🔍 Input Analysis Target (URL or Email Body):", height=150, placeholder="Paste suspicious links here...")
    
    col_run, col_clear = st.columns([4, 1])
    
    with col_run:
        run_btn = st.button("🚀 EXECUTE NEURAL SCAN")
    with col_clear:
        # Styled as a Red button via CSS class 'clear-btn'
        st.markdown('<div class="clear-btn">', unsafe_allow_html=True)
        clear_input = st.button("❌ Clear")
        st.markdown('</div>', unsafe_allow_html=True)

    if clear_input:
        st.rerun()

    if run_btn:
        if user_input.strip():
            # 1. AI AGENT ANALYSIS
            with st.spinner("🕵️ Agents investigating infrastructure..."):
                final_report = run_analysis(user_input)
                risk_pct = calculate_risk_score(user_input, final_report)
            
            # 2. SCREENSHOT EVIDENCE
            with st.spinner("📸 Capturing Visual Evidence Sandbox..."):
                img_path = capture_screenshot(user_input)
            
            # 3. LOG TO HISTORY
            st.session_state.history.append({"url": user_input, "type": "DANGER" if risk_pct > 50 else "SAFE"})

            # 4. DISPLAY RESULTS
            if risk_pct >= 75:
                st.error(f"### 🚩 CRITICAL THREAT DETECTED ({risk_pct}%)")
                st.progress(risk_pct)
            elif risk_pct >= 35:
                st.warning(f"### ⚠️ SUSPICIOUS ACTIVITY ({risk_pct}%)")
                st.progress(risk_pct)
            else:
                st.success(f"### ✅ VERIFIED SAFE ({risk_pct}%)")
                st.progress(max(risk_pct, 5))

            st.subheader("📋 Forensic Narrative")
            st.markdown(final_report)
            
            if img_path and os.path.exists(img_path):
                st.subheader("🖼️ Visual Sandbox Evidence")
                st.image(img_path, caption="Automated Headless Capture", use_container_width=True)
        else:
            st.warning("Please provide a target for analysis.")

with col2:
    st.subheader("📊 Technical Metadata")
    if 'final_report' in locals():
        # Extraction logic
        entropy = re.search(r'str_entropy: (\d+\.\d+)', final_report)
        age = re.search(r'domain_age: (\d+)', final_report)
        puny = "Detected" if "punycode_attack: true" in final_report.lower() else "None"
        tld = "High Risk" if "high_risk_tld: true" in final_report.lower() else "Standard"
        
        m1, m2 = st.columns(2)
        with m1:
            st.metric("Shannon Entropy", entropy.group(1) if entropy else "N/A")
            st.metric("Homograph Status", puny)
        with m2:
            st.metric("Domain Age", f"{age.group(1)} Days" if age else "New")
            st.metric("TLD Reputation", tld)
        
        st.divider()
        st.write("**Security Modules Active:**")
        st.write("✅ SSL/TLS Certificate Verification")
        st.write("✅ Recursive URL Unmasking")
        st.write("✅ DGA Randomness Detection")
        st.write("✅ Headless Browser Sandboxing")
    else:
        # Just a cool graphic or info box when empty
        st.info("System Ready. Awaiting Forensic Input.")
        st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=200)

    st.divider()
    st.json({
        "Status": "Scanning Local Network",
        "Agents": "SOC Investigator, Threat Lead",
        "Engine": "Deterministic Hybrid"
    })