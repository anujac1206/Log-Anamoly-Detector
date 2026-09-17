
import streamlit as st
import pandas as pd
from log_parser import LogParser, infer_log_type
from anomaly_detector import AnomalyDetector
from ai_analyzer import AIAnalyzer
import os
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from fpdf import FPDF
import json
# from dotenv import load_dotenv
# load_dotenv()
api_key = (
    st.secrets.get("GEMINI_API_KEY", None)
    # or os.getenv("GEMINI_API_KEY")
)


# Page config
st.set_page_config(
    page_title="Log Anomaly Detector",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .critical { color: #ff4444; font-weight: bold; }
    .high { color: #ff8c00; font-weight: bold; }
    .medium { color: #ffd700; }
    .low { color: #90ee90; }
    </style>
""", unsafe_allow_html=True)

# Helper function to generate PDF
def generate_pdf_report(stats, anomalies):
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("helvetica", "B", 18)
    pdf.set_text_color(33, 37, 41)
    pdf.cell(0, 10, "LOG ANOMALY DETECTOR REPORT", ln=True, align="C")
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(108, 117, 125)
    pdf.cell(0, 8, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
    pdf.ln(10)
    
    # Statistics Section
    pdf.set_font("helvetica", "B", 14)
    pdf.set_text_color(33, 37, 41)
    pdf.cell(0, 10, "1. Log Statistics Summary", ln=True)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
    pdf.ln(4)
    
    pdf.set_font("helvetica", "", 11)
    pdf.set_text_color(51, 51, 51)
    stats_data = [
        ("Total Log Events Analyzed", str(stats['total_logs'])),
        ("Failed Login Attempts", str(stats['failed_logins'])),
        ("Successful Login Events", str(stats['successful_logins'])),
        ("Unique User Accounts Detected", str(stats['unique_users'])),
        ("Unique Source IP Addresses", str(stats['unique_ips'])),
        ("Authentication Failure Rate", f"{stats['failure_rate']}%"),
        ("Log Time Span Duration", str(stats['time_span']))
    ]
    
    for label, val in stats_data:
        pdf.cell(90, 8, label, border=1)
        pdf.cell(100, 8, val, border=1, ln=True)
    
    pdf.ln(10)
    
    # Anomalies Section
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "2. Detected Threat Anomalies", ln=True)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
    pdf.ln(4)
    
    if len(anomalies) == 0:
        pdf.set_font("helvetica", "I", 11)
        pdf.cell(0, 10, "No anomalies or security threats were detected in the provided logs.", ln=True)
    else:
        for i, a in enumerate(anomalies[:10], 1):
            pdf.set_font("helvetica", "B", 11)
            if a['severity'] == 'CRITICAL':
                pdf.set_text_color(220, 53, 69)
            elif a['severity'] == 'HIGH':
                pdf.set_text_color(253, 126, 20)
            elif a['severity'] == 'MEDIUM':
                pdf.set_text_color(255, 193, 7)
            else:
                pdf.set_text_color(40, 167, 69)
                
            pdf.cell(0, 8, f"#{i} {a['type']} [Severity: {a['severity']} | Confidence: {a['confidence']}%]", ln=True)
            
            pdf.set_font("helvetica", "", 10)
            pdf.set_text_color(51, 51, 51)
            pdf.multi_cell(0, 6, f"Description: {a['description']}")
            
            # Print key details
            details_str = ", ".join(f"{k}: {v}" for k, v in a['details'].items() if not isinstance(v, (list, dict)))
            if details_str:
                pdf.multi_cell(0, 6, f"Details: {details_str}")
            
            pdf.ln(4)
            
    return pdf.output()

# Title
st.title("🔍 Log Anomaly Detector")
st.markdown("AI-powered security log analysis for threat detection and incident response")

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # API Key selection
    api_provider = st.radio("AI Provider", ["Google Gemini (Free)", "OpenAI"], key="provider")
    
    if api_provider == "Google Gemini (Free)":
        gemini_key = st.text_input(
        "Gemini API Key",
        value=os.getenv("GEMINI_API_KEY", ""),
        type="password",
        key="gemini_key"
    )

    if not gemini_key:
        st.warning("⚠️ No API key provided. Get one free at https://ai.google.dev/")
        if not gemini_key:
            st.warning("⚠️ No API key provided. Get one free at https://ai.google.dev/")
    else:
        openai_key = st.text_input("OpenAI API Key", type="password", key="openai_key")
        if not openai_key:
            st.warning("⚠️ No API key provided. Get one at https://platform.openai.com/api-keys")
    
    st.markdown("---")
    
    # Detection settings
    st.subheader("Detection Settings")
    min_confidence = st.slider("Min Confidence Threshold", 0, 100, 50, key="confidence")
    
    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    **Log Anomaly Detector** analyzes security logs to identify:
    - 🚨 Brute force attacks
    - 🔐 Credential stuffing
    - 🌍 Geographical anomalies
    - ⚡ Rate spikes
    - 📈 Privilege escalation
    - 🔒 Account lockouts
    
    Uses AI for intelligent analysis and recommendations.
    """)

# Main content tabs
tab1, tab2, tab3, tab4 = st.tabs(["Upload & Analyze", "Detailed Findings", "AI Analysis", "Report"])

# TAB 1: Upload and Analyze
with tab1:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📤 Upload Security Logs")
        uploaded_file = st.file_uploader(
            "Choose a log file (.log, .txt, .csv)",
            type=['log', 'txt', 'csv'],
            help="Supports syslog, auth.log, Apache access logs, Windows Event logs, and CSV formats"
        )
    
    with col2:
        st.subheader("📝 Or Try Demo")
        use_demo = st.button("Load Demo Data", key="demo_button")
    
    # Process uploaded file or demo
    if uploaded_file or use_demo:
        if use_demo:
            # Create rich demo data triggering multiple anomalies
            demo_logs = """2024-01-15 08:00:01 Failed password for root from 45.22.30.1
2024-01-15 08:00:02 Failed password for root from 45.22.30.1
2024-01-15 08:00:03 Failed password for root from 45.22.30.1
2024-01-15 08:00:04 Failed password for root from 45.22.30.1
2024-01-15 08:00:05 Failed password for root from 45.22.30.1
2024-01-15 08:00:06 Failed password for root from 45.22.30.1
2024-01-15 08:05:10 Accepted password for bob from 8.8.8.8
2024-01-15 08:06:15 Accepted password for bob from 1.1.1.1
2024-01-15 08:10:00 Failed password for target_user from 185.190.140.2
2024-01-15 08:10:02 Failed password for target_user from 91.200.12.4
2024-01-15 08:10:04 Failed password for target_user from 203.0.113.5
2024-01-15 08:15:00 Failed password for admin from 192.168.1.50
2024-01-15 08:15:01 Failed password for admin from 192.168.1.50
2024-01-15 08:15:02 Failed password for admin from 192.168.1.50
2024-01-15 08:15:03 Failed password for admin from 192.168.1.50
2024-01-15 08:15:04 Failed password for admin from 192.168.1.50
"""
            file_content = demo_logs
            filename = "auth.log"
            st.info("✨ Loaded multi-anomaly demo data (includes brute force, impossible travel, and credential stuffing)")
        else:
            file_content = uploaded_file.read().decode('utf-8')
            filename = uploaded_file.name
        
        # Parse logs
        try:
            st.subheader("📊 Log Parsing & Statistics")
            
            parser = LogParser()
            file_type = infer_log_type(filename)
            df = parser.parse_file(file_content, file_type)
            
            st.success(f"✅ Successfully parsed {len(df)} log entries (Format: {file_type.upper()})")
            
            # Show statistics
            col1, col2, col3, col4, col5 = st.columns(5)
            
            with col1:
                st.metric("Total Logs", len(df))
            
            with col2:
                failed = len(df[df['status'].str.upper() == 'FAILED'])
                st.metric("Failed Logins", failed)
            
            with col3:
                success = len(df[df['status'].str.upper() == 'SUCCESS'])
                st.metric("Successful Logins", success)
            
            with col4:
                st.metric("Unique Users", df['username'].nunique())
            
            with col5:
                st.metric("Unique IPs", df['source_ip'].nunique())
            
            # Show log preview
            with st.expander("📋 Log Preview", expanded=False):
                st.dataframe(df.head(20), use_container_width=True)
            
            # Detect anomalies
            st.subheader("🚨 Anomaly Detection")
            
            with st.spinner("Analyzing logs for anomalies..."):
                detector = AnomalyDetector(df)
                anomalies = detector.detect_all_anomalies()
                stats = detector.get_statistics()
            
            # Filter by confidence threshold
            anomalies = [a for a in anomalies if a['confidence'] >= min_confidence]
            
            # Store in session for other tabs
            st.session_state.anomalies = anomalies
            st.session_state.stats = stats
            st.session_state.df = df
            st.session_state.has_analysis = True
            
            # Summary
            st.write(f"**Found {len(anomalies)} anomalies meeting threshold ({min_confidence}%)**")
            
            if len(anomalies) > 0:
                severity_counts = {}
                for a in anomalies:
                    severity = a['severity']
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                col1, col2, col3, col4 = st.columns(4)
                
                critical = severity_counts.get('CRITICAL', 0)
                high = severity_counts.get('HIGH', 0)
                medium = severity_counts.get('MEDIUM', 0)
                low = severity_counts.get('LOW', 0)
                
                if critical > 0:
                    with col1:
                        st.error(f"🔴 Critical: {critical}")
                
                if high > 0:
                    with col2:
                        st.warning(f"🟠 High: {high}")
                
                if medium > 0:
                    with col3:
                        st.info(f"🟡 Medium: {medium}")
                
                if low > 0:
                    with col4:
                        st.success(f"🟢 Low: {low}")
                
                # Visualization
                col1, col2 = st.columns(2)
                
                with col1:
                    # Anomaly type distribution
                    anomaly_types = {}
                    for a in anomalies:
                        t = a['type']
                        anomaly_types[t] = anomaly_types.get(t, 0) + 1
                    
                    fig = px.bar(
                        x=list(anomaly_types.keys()),
                        y=list(anomaly_types.values()),
                        title="Anomaly Types Detected",
                        labels={"x": "Type", "y": "Count"}
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    # Severity distribution
                    severity_data = pd.DataFrame(
                        list(severity_counts.items()),
                        columns=['Severity', 'Count']
                    )
                    
                    colors = {
                        'CRITICAL': '#ff4444',
                        'HIGH': '#ff8c00',
                        'MEDIUM': '#ffd700',
                        'LOW': '#90ee90'
                    }
                    
                    fig = px.pie(
                        severity_data,
                        values='Count',
                        names='Severity',
                        title="Severity Distribution",
                        color='Severity',
                        color_discrete_map=colors
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.success("✅ No anomalies detected. Logs appear clean.")
        
        except Exception as e:
            st.error(f"❌ Error parsing logs: {str(e)}")
            st.info("Supported formats: Linux syslog/auth.log, Windows security CSV, Apache access, Fail2ban, or raw text logs")

# TAB 2: Detailed Findings
with tab2:
    if st.session_state.get('has_analysis'):
        anomalies = st.session_state.anomalies
        
        if len(anomalies) > 0:
            # Filter by severity
            severity_filter = st.multiselect(
                "Filter by Severity",
                ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                default=['CRITICAL', 'HIGH', 'MEDIUM']
            )
            
            filtered_anomalies = [a for a in anomalies if a['severity'] in severity_filter]
            
            for i, anomaly in enumerate(filtered_anomalies[:10]):  # Show top 10
                # Color coding
                severity_color = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }
                
                with st.expander(
                    f"{severity_color[anomaly['severity']]} {anomaly['type']} | "
                    f"Confidence: {anomaly['confidence']}% | {anomaly['description']}"
                ):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.markdown(f"**Description:** {anomaly['description']}")
                        st.markdown(f"**Severity:** {anomaly['severity']}")
                        st.markdown("**Details:**")
                        for key, value in anomaly['details'].items():
                            if isinstance(value, list):
                                st.markdown(f"- **{key}:** {', '.join(map(str, value))}")
                            elif isinstance(value, dict):
                                st.markdown(f"- **{key}:**")
                                for sub_k, sub_v in value.items():
                                    st.markdown(f"  - **{sub_k}:** {sub_v}")
                            else:
                                st.markdown(f"- **{key}:** {value}")
                    
                    with col2:
                        st.markdown(f"### Confidence")
                        st.progress(anomaly['confidence'] / 100)
                        st.markdown(f"{anomaly['confidence']}%")
                        
                        st.markdown("---")
                        # AI Verification Action
                        api_key = st.session_state.get('gemini_key') or st.session_state.get('openai_key')
                        provider = "gemini" if st.session_state.get('provider') == "Google Gemini (Free)" else "openai"
                        
                        if st.button(f"Verify Threat with AI", key=f"verify_btn_{i}"):
                            if api_key:
                                with st.spinner("AI is calculating threat verification..."):
                                    analyzer = AIAnalyzer(api_key=api_key, provider=provider)
                                    verif = analyzer.validate_confidence(anomaly)
                                    
                                    st.markdown("### Verification Result:")
                                    is_valid = verif.get('is_valid_threat', True)
                                    st.markdown(f"**Is Valid Threat:** {'✅ Yes' if is_valid else '❌ False Positive'}")
                                    st.markdown(f"**Revised Confidence:** {verif.get('revised_confidence', anomaly['confidence'])}%")
                                    st.markdown(f"**False Positive Risk:** {verif.get('false_positive_risk', 'low').upper()}")
                                    st.markdown(f"**AI Explanation:** {verif.get('explanation', '')}")
                            else:
                                st.warning("Please provide an API key in the sidebar")
                    
                    st.markdown("---")
                    # Detailed AI Analysis
                    if st.button(f"Get AI Incident Analysis", key=f"ai_btn_{i}"):
                        if api_key:
                            with st.spinner("Analyzing with AI..."):
                                analyzer = AIAnalyzer(api_key=api_key, provider=provider)
                                analysis = analyzer.analyze_anomaly(anomaly)
                                st.markdown(analysis)
                        else:
                            st.warning("Please provide an API key in the sidebar")
        else:
            st.success("No anomalies found!")
    else:
        st.info("👈 Upload logs in the first tab to analyze them")

# TAB 3: AI Analysis
with tab3:
    if st.session_state.get('has_analysis'):
        anomalies = st.session_state.anomalies
        stats = st.session_state.stats
        
        if len(anomalies) > 0:
            st.subheader("🤖 AI-Powered Incident Analysis")
            
            analysis_type = st.radio(
                "Select Analysis Type",
                ["Executive Report", "Remediation Guide", "Simple Explanation"]
            )
            
            if st.button("Generate Analysis"):
                api_key = st.session_state.get('gemini_key') or st.session_state.get('openai_key')
                provider = "gemini" if st.session_state.get('provider') == "Google Gemini (Free)" else "openai"
                
                if api_key:
                    with st.spinner("Generating analysis with AI..."):
                        analyzer = AIAnalyzer(api_key=api_key, provider=provider)
                        
                        if analysis_type == "Executive Report":
                            result = analyzer.generate_incident_report(anomalies, stats)
                        elif analysis_type == "Remediation Guide":
                            top_anomaly = anomalies[0]
                            result = analyzer.suggest_remediation(top_anomaly['type'], top_anomaly['details'])
                        else:
                            top_anomaly = anomalies[0]
                            result = analyzer.explain_simply(top_anomaly)
                    
                    st.markdown(result)
                    
                    # Download button
                    st.download_button(
                        label="📥 Download Analysis",
                        data=result,
                        file_name=f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                        mime="text/markdown"
                    )
                else:
                    st.warning("Please provide an API key in the sidebar")
        else:
            st.success("No anomalies to analyze")
    else:
        st.info("👈 Upload logs in the first tab to analyze them")

# TAB 4: Report
with tab4:
    if st.session_state.get('has_analysis'):
        st.subheader("📊 Incident Report")
        
        stats = st.session_state.stats
        anomalies = st.session_state.anomalies
        
        # Report summary
        st.markdown(f"""
        ## Incident Summary Report
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        ### Log Statistics
        - **Total Events:** {stats['total_logs']}
        - **Failed Logins:** {stats['failed_logins']}
        - **Successful Logins:** {stats['successful_logins']}
        - **Unique Users:** {stats['unique_users']}
        - **Unique Source IPs:** {stats['unique_ips']}
        - **Failure Rate:** {stats['failure_rate']}%
        - **Time Span:** {stats['time_span']}
        
        ### Threat Assessment
        - **Total Anomalies Found:** {len(anomalies)}
        - **Critical Issues:** {len([a for a in anomalies if a['severity'] == 'CRITICAL'])}
        - **High Priority Issues:** {len([a for a in anomalies if a['severity'] == 'HIGH'])}
        """)
        
        if len(anomalies) > 0:
            st.markdown("### Detected Threats")
            
            report_df = pd.DataFrame([
                {
                    'Threat Type': a['type'],
                    'Severity': a['severity'],
                    'Confidence': f"{a['confidence']}%",
                    'Description': a['description']
                }
                for a in anomalies[:10]
            ])
            
            st.dataframe(report_df, use_container_width=True)
        
        # Export report
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📥 Export as CSV"):
                report_data = pd.DataFrame([
                    {
                        'Type': a['type'],
                        'Severity': a['severity'],
                        'Confidence': a['confidence'],
                        'Description': a['description'],
                        'Details': str(a['details'])
                    }
                    for a in anomalies
                ])
                csv = report_data.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"anomalies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📋 Export as JSON"):
                import json
                json_data = json.dumps({
                    'timestamp': datetime.now().isoformat(),
                    'statistics': stats,
                    'anomalies': anomalies
                }, indent=2)
                st.download_button(
                    label="Download JSON",
                    data=json_data,
                    file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
                
        with col3:
            if st.button("📄 Export as PDF"):
                try:
                    with st.spinner("Generating beautiful PDF report..."):
                        pdf_data = generate_pdf_report(stats, anomalies)
                        
                    st.download_button(
                        label="Download PDF Report",
                        data=pdf_data,
                        file_name=f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf"
                    )
                except Exception as e:
                    st.error(f"Failed to generate PDF: {str(e)}")
    else:
        st.info("👈 Upload logs in the first tab to generate a report")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center'>
    <p>Log Anomaly Detector v1.1 | Built for Security Teams</p>
    <p style='font-size: 0.8em'>⚠️ For demonstration purposes. Always verify findings with your SOC team.</p>
</div>
""", unsafe_allow_html=True)
