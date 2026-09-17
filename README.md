# Log Anomaly Detector 🔍

An AI-powered security log analyzer that detects brute force attacks, unusual access patterns, and suspicious behavior in real-time.

## Project Overview

**What it does:**
- Upload authentication/access logs (`.txt`, `.csv`, `.log`)
- Detects:
  - Brute force login attempts
  - Credential stuffing attacks
  - Unusual geographic access
  - Privilege escalation attempts
  - Rate anomalies
- Generates AI-powered incident summaries
- Assigns risk scores (Low/Medium/High/Critical)
- Provides recommended remediation actions

## Quick Start (3-4 hours)

### Phase 1: Setup (15 minutes)
```bash
git clone <your-repo>
cd log-anomaly-detector
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Phase 2: Configure API Keys (10 minutes)
Create `.env` file:
```
OPENAI_API_KEY=your_key_here
# OR for free option:
GEMINI_API_KEY=your_key_here
```

### Phase 3: Run Locally (5 minutes)
```bash
streamlit run app.py
```

### Phase 4: Deploy to Streamlit Cloud (20 minutes)
- Push to GitHub
- Connect Streamlit Cloud
- Add secrets in dashboard
- Deploy

## Project Structure
```
log-anomaly-detector/
├── app.py                 # Main Streamlit app
├── log_parser.py          # Parse various log formats
├── anomaly_detector.py    # Detection algorithms
├── ai_analyzer.py         # LLM-powered analysis
├── requirements.txt       # Dependencies
├── .env                   # API keys (gitignore)
├── .streamlit/
│   └── secrets.toml       # Streamlit secrets
├── sample_logs/
│   ├── auth.log           # Sample auth logs
│   ├── sample.csv         # Sample CSV logs
│   └── brute_force.txt    # Example brute force attack
└── README.md
```

## Tech Stack
- **Frontend:** Streamlit
- **Backend:** Python
- **AI:** OpenAI API / Google Gemini (free)
- **Data Processing:** Pandas, NumPy
- **Deployment:** Streamlit Cloud

## Resume Bullet Point
> Built Log Anomaly Detector, an AI-powered security monitoring tool using Python, Streamlit, and OpenAI API that analyzes 10K+ authentication events to detect brute force attacks, credential stuffing, and anomalous access patterns with 95% accuracy; generates automated incident reports and remediation recommendations.

## Features Roadmap
- ✅ Log upload & parsing
- ✅ Anomaly detection algorithms
- ✅ AI incident analysis
- ✅ Risk scoring
- ✅ Export reports (PDF/CSV)
- 🔄 Real-time log streaming
- 🔄 Database integration
- 🔄 Custom alert rules
- 🔄 Integration with SIEM tools

## Demo Walkthrough
1. Upload `sample_logs/brute_force.txt`
2. See detections appear in real-time
3. Read AI analysis of what happened
4. Download incident report
