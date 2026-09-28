"""
ThreatCorrelate Dashboard - Updated with PDF Report Generation
Automated Multi-Source IOC Correlation Engine with MITRE ATT&CK Mapping
"""

import streamlit as st
import pandas as pd
import csv
import io
from datetime import datetime
import sys
import os

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ioc_handler import IOCHandler
from api_connector import APIConnector
from scoring_engine import ScoringEngine
from attack_mapper import AttackMapper
from report_generator import ReportGenerator

# Configure Streamlit page
st.set_page_config(
    page_title="ThreatCorrelate",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom styling
st.markdown("""
    <style>
    .main {
        padding: 20px;
    }
    .metric-box {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    </style>
    """, unsafe_allow_html=True)

# Page title
st.title("🛡️ ThreatCorrelate")
st.markdown("### Automated Multi-Source IOC Correlation Engine with MITRE ATT&CK Mapping")

# Initialize session state
if 'results' not in st.session_state:
    st.session_state.results = None
if 'iocs' not in st.session_state:
    st.session_state.iocs = []

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # Input method selection
    input_method = st.radio(
        "Select Input Method:",
        ["Manual Input", "Upload CSV", "Sample Dataset"]
    )
    
    st.markdown("---")
    
    # About section
    st.markdown("### 📖 About ThreatCorrelate")
    st.markdown("""
    **ThreatCorrelate** automates threat intelligence lookups across multiple sources:
    
    - **VirusTotal**: Aggregated AV detections (50% weight)
    - **AbuseIPDB**: IP reputation scoring (30% weight)
    - **AlienVault OTX**: Threat pulse correlation (20% weight)
    
    **Features:**
    - Automated IOC type detection
    - Weighted confidence scoring
    - MITRE ATT&CK technique mapping
    - Professional PDF reports
    """)

# Main content area
tab1, tab2, tab3 = st.tabs(["📊 Analysis", "📄 Report", "ℹ️ Help"])

with tab1:
    st.header("IOC Correlation & Analysis")
    
    # Input section
    st.subheader("Step 1: Load IOCs")
    
    if input_method == "Manual Input":
        ioc_input = st.text_area(
            "Enter IOCs (one per line):",
            height=150,
            placeholder="192.168.1.1\nmalicious.com\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        if st.button("📥 Load IOCs", key="manual_load"):
            if ioc_input.strip():
                iocs = [line.strip() for line in ioc_input.split('\n') if line.strip()]
                st.session_state.iocs = iocs
                st.success(f"✓ Loaded {len(iocs)} IOC(s)")
    
    elif input_method == "Upload CSV":
        uploaded_file = st.file_uploader(
            "Upload CSV file (with 'ioc' column):",
            type="csv"
        )
        
        if uploaded_file is not None:
            df = pd.read_csv(uploaded_file)
            
            if 'ioc' not in df.columns:
                st.error("❌ CSV must contain 'ioc' column")
            else:
                iocs = df['ioc'].tolist()
                st.session_state.iocs = iocs
                st.success(f"✓ Loaded {len(iocs)} IOC(s) from CSV")
                st.dataframe(df, use_container_width=True)
    
    elif input_method == "Sample Dataset":
        sample_iocs = [
            "8.8.8.8",
            "1.1.1.1",
            "malicious.com",
            "phishing-site.org",
            "5d41402abc4b2a76b9719d911017c592",
        ]
        
        if st.button("📊 Load Sample IOCs", key="sample_load"):
            st.session_state.iocs = sample_iocs
            st.success(f"✓ Loaded {len(sample_iocs)} sample IOC(s)")
    
    # Display loaded IOCs
    if st.session_state.iocs:
        st.subheader("Step 2: Loaded IOCs")
        
        ioc_df = pd.DataFrame({
            'IOC': st.session_state.iocs,
            'Type': [IOCHandler.detect_ioc_type(ioc) for ioc in st.session_state.iocs]
        })
        
        st.dataframe(ioc_df, use_container_width=True)
        
        # Enrichment button
        if st.button("🔍 Run Enrichment & Correlation", key="run_enrichment"):
            with st.spinner("Querying threat intelligence sources..."):
                
                # Initialize connector
                connector = APIConnector()
                
                all_results = []
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                for idx, ioc in enumerate(st.session_state.iocs):
                    # Update progress
                    progress = (idx + 1) / len(st.session_state.iocs)
                    progress_bar.progress(progress)
                    status_text.text(f"Processing: {ioc} ({idx + 1}/{len(st.session_state.iocs)})")
                    
                    # Detect IOC type
                    ioc_type = IOCHandler.detect_ioc_type(ioc)
                    
                    if ioc_type == 'unknown':
                        continue
                    
                    # Query all sources
                    api_results = connector.query_all_sources(ioc, ioc_type)
                    
                    # Extract data
                    vt_data = api_results.get('virustotal', {})
                    abuseipdb_data = api_results.get('abuseipdb', {})
                    otx_data = api_results.get('otx', {})
                    
                    # Calculate score
                    score_result = ScoringEngine.score_ioc(
                        vt_data,
                        abuseipdb_data,
                        otx_data,
                        ioc_type
                    )
                    
                    # Get combined tags
                    tags = connector.get_combined_tags(api_results)
                    
                    # Map to MITRE ATT&CK
                    attack_summary = AttackMapper.generate_attack_summary(
                        tags,
                        score_result['score'],
                        score_result['verdict']
                    )
                    
                    # Compile result
                    result = {
                        'ioc': ioc,
                        'type': ioc_type,
                        'score': score_result['score'],
                        'verdict': score_result['verdict'],
                        'color': score_result['color'],
                        'vt_detections': score_result['vt_detections'],
                        'abuseipdb_score': score_result['abuseipdb_score'],
                        'otx_pulses': score_result['otx_pulses'],
                        'tags': tags,
                        'primary_technique': attack_summary['primary_technique'],
                        'technique_name': attack_summary['technique_name'],
                        'techniques': attack_summary['all_techniques'],
                        'tactics': attack_summary['tactics'],
                        'raw_data': {
                            'virustotal': vt_data,
                            'abuseipdb': abuseipdb_data,
                            'otx': otx_data
                        }
                    }
                    
                    all_results.append(result)
                
                st.session_state.results = all_results
                status_text.text("✓ Enrichment complete!")
                progress_bar.empty()
                st.success(f"✓ Analyzed {len(all_results)} IOC(s)")
    
    # Display results
    if st.session_state.results:
        st.subheader("Step 3: Correlation Results")
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        malicious_count = sum(1 for r in st.session_state.results if r['verdict'] == 'Malicious')
        suspicious_count = sum(1 for r in st.session_state.results if r['verdict'] == 'Suspicious')
        low_risk_count = sum(1 for r in st.session_state.results if r['verdict'] == 'Low Risk')
        clean_count = sum(1 for r in st.session_state.results if r['verdict'] == 'Clean')
        
        with col1:
            st.metric("Total IOCs", len(st.session_state.results))
        with col2:
            st.metric("🔴 Malicious", malicious_count)
        with col3:
            st.metric("🟠 Suspicious", suspicious_count)
        with col4:
            st.metric("🟢 Clean", clean_count + low_risk_count)
        
        # Results table
        results_data = []
        for result in st.session_state.results:
            results_data.append({
                'IOC': result['ioc'],
                'Type': result['type'],
                'Score': result['score'],
                'Verdict': result['verdict'],
                'VT Detections': result['vt_detections'],
                'AbuseIPDB': result['abuseipdb_score'],
                'OTX Pulses': result['otx_pulses'],
                'Primary Technique': result['technique_name'],
                'Tags': ', '.join(result['tags'][:3]) if result['tags'] else 'N/A'
            })
        
        results_df = pd.DataFrame(results_data)
        
        st.dataframe(
            results_df,
            use_container_width=True,
            height=400
        )
        
        # Detailed view
        st.subheader("Detailed Analysis")
        
        for result in st.session_state.results:
            with st.expander(f"🔍 {result['ioc']} - {result['verdict']}"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Confidence Score", f"{result['score']}/100")
                    st.metric("Verdict", result['verdict'])
                
                with col2:
                    st.metric("VT Detections", result['vt_detections'])
                    st.metric("AbuseIPDB Score", result['abuseipdb_score'])
                
                with col3:
                    st.metric("OTX Pulses", result['otx_pulses'])
                    st.metric("MITRE Technique", result['primary_technique'])
                
                st.markdown("**Tags:**")
                if result['tags']:
                    st.write(', '.join(result['tags']))
                else:
                    st.write("No tags detected")
                
                st.markdown("**MITRE ATT&CK Tactics:**")
                tactics_str = ', '.join(result['tactics'].keys()) if result['tactics'] else "N/A"
                st.write(tactics_str)

with tab2:
    st.header("📄 Threat Report")
    
    if st.session_state.results:
        st.subheader("Generate & Download Report")
        
        # Generate PDF button
        if st.button("📥 Generate PDF Report", key="generate_pdf"):
            with st.spinner("Generating PDF report..."):
                try:
                    # Generate PDF
                    generator = ReportGenerator()
                    pdf_bytes = generator.generate_pdf_bytes(st.session_state.results)
                    
                    # Prepare download
                    st.download_button(
                        label="⬇️ Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf",
                        key="download_pdf"
                    )
                    st.success("✓ PDF report generated successfully!")
                    
                except Exception as e:
                    st.error(f"Error generating PDF: {str(e)}")
        
        # Show report preview
        st.subheader("Report Preview")
        
        report_text = "# ThreatCorrelate Analysis Report\n\n"
        report_text += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        report_text += f"## Summary\n"
        
        malicious_count = sum(1 for r in st.session_state.results if r['verdict'] == 'Malicious')
        suspicious_count = sum(1 for r in st.session_state.results if r['verdict'] == 'Suspicious')
        clean_count = sum(1 for r in st.session_state.results if r['verdict'] == 'Clean')
        
        report_text += f"- **Total IOCs:** {len(st.session_state.results)}\n"
        report_text += f"- **Malicious:** {malicious_count}\n"
        report_text += f"- **Suspicious:** {suspicious_count}\n"
        report_text += f"- **Clean:** {clean_count}\n\n"
        
        report_text += "## Detailed Findings\n\n"
        
        for result in st.session_state.results:
            report_text += f"### {result['ioc']}\n"
            report_text += f"- **Type:** {result['type']}\n"
            report_text += f"- **Verdict:** {result['verdict']}\n"
            report_text += f"- **Score:** {result['score']}/100\n"
            report_text += f"- **Primary Technique:** {result['primary_technique']} ({result['technique_name']})\n"
            report_text += f"- **VT Detections:** {result['vt_detections']}\n"
            report_text += f"- **OTX Pulses:** {result['otx_pulses']}\n"
            report_text += f"- **Tags:** {', '.join(result['tags']) if result['tags'] else 'N/A'}\n\n"
        
        st.markdown(report_text)
    else:
        st.info("Run enrichment analysis first to generate a report")

with tab3:
    st.header("ℹ️ Help & Documentation")
    
    st.markdown("""
    ## What is ThreatCorrelate?
    
    ThreatCorrelate is an automated threat intelligence correlation tool that:
    
    1. **Accepts IOCs** (Indicators of Compromise) - IPs, domains, or file hashes
    2. **Queries Multiple Sources**:
       - VirusTotal (AV detections)
       - AbuseIPDB (IP reputation)
       - AlienVault OTX (Threat pulses)
    3. **Scores Results** using weighted formula:
       - VirusTotal: 50% weight
       - AbuseIPDB: 30% weight
       - OTX: 20% weight
    4. **Maps to MITRE ATT&CK** techniques
    5. **Generates Reports** with findings
    
    ## Scoring Interpretation
    
    | Score | Verdict | Meaning |
    |-------|---------|---------|
    | 80-100 | 🔴 Malicious | High confidence threat |
    | 50-79 | 🟠 Suspicious | Requires investigation |
    | 20-49 | 🟡 Low Risk | Minor concerns |
    | 0-19 | 🟢 Clean | Appears safe |
    
    ## Supported IOC Types
    
    - **IPv4**: 192.168.1.1
    - **IPv6**: 2001:db8::1
    - **Domains**: malicious.com
    - **Hashes**: MD5, SHA1, SHA256
    
    ## MITRE ATT&CK Framework
    
    Techniques are mapped to MITRE ATT&CK, a globally recognized framework of attacker tactics and techniques.
    
    Examples:
    - **T1566**: Phishing
    - **T1486**: Data Encrypted for Impact (Ransomware)
    - **T1110**: Brute Force
    - **T1071**: Command and Control
    - **T1041**: Exfiltration Over C2 Channel
    
    ## PDF Report Features
    
    - Executive summary with statistics
    - Detailed findings table
    - Individual IOC analysis
    - MITRE ATT&CK technique mapping
    - Scoring methodology explanation
    - Professional formatting for presentations
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center'>
    <p><strong>ThreatCorrelate v1.0</strong> | Automated Threat Intelligence Correlation Engine</p>
    <p>Data sources: VirusTotal, AbuseIPDB, AlienVault OTX | Framework: MITRE ATT&CK</p>
</div>
""", unsafe_allow_html=True)
