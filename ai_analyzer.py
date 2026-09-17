import os
from typing import Dict, List
import json
from google import genai
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

class AIAnalyzer:
    """Use LLM to generate incident reports and analysis."""
    
    def __init__(self, api_key: str = None, provider: str = "gemini"):
        # Normalize provider name to be case-insensitive
        self.provider = "gemini" if "gemini" in str(provider).lower() else "openai"
        self.api_key = api_key
        
        if self.provider == "gemini":
            if not api_key:
                api_key = os.getenv("GEMINI_API_KEY")
            self.client = genai.Client(api_key=api_key)
        else:
            if not api_key:
                api_key = os.getenv("OPENAI_API_KEY")
            self.client = OpenAI(api_key=api_key)
    
    def _call_llm(self, prompt: str) -> str:
        """Call the appropriate LLM provider."""
        if self.provider == "gemini":
            response = self.client.models.generate_content(
                model="gemini-3.6-flash",
                contents=prompt
            )
            return response.text
        else:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2
            )
            return response.choices[0].message.content

    def analyze_anomaly(self, anomaly: Dict) -> str:
        """Generate detailed analysis of an anomaly."""
        
        prompt = f"""You are a cybersecurity expert analyzing a security incident.

Analyze this security anomaly and provide a concise but detailed report:

{json.dumps(anomaly, indent=2)}

Provide your response in this format:
**What happened:** [2-3 sentences explaining the attack]
**Why it's dangerous:** [Impact and risk assessment]
**Likely attacker goal:** [Motivation/objective]
**Immediate actions:** [2-3 urgent remediation steps]
**Prevention:** [Long-term security measures]

Keep it technical but understandable."""
        
        try:
            return self._call_llm(prompt)
        except Exception as e:
            return f"Analysis Error: {str(e)}"
    
    def generate_incident_report(self, anomalies: List[Dict], statistics: Dict) -> str:
        """Generate comprehensive incident report."""
        
        critical_count = len([a for a in anomalies if a['severity'] == 'CRITICAL'])
        high_count = len([a for a in anomalies if a['severity'] == 'HIGH'])
        
        prompt = f"""You are a Security Operations Center (SOC) analyst. Generate an executive incident report based on this security analysis:

**Log Statistics:**
{json.dumps(statistics, indent=2)}

**Detected Anomalies (Top 5):**
{json.dumps([a for a in anomalies[:5]], indent=2)}

Write a professional security incident report with:

## EXECUTIVE SUMMARY
[1-2 sentences describing overall threat level]

## THREAT OVERVIEW
- Critical Issues Found: {critical_count}
- High Priority Issues: {high_count}
- Total Anomalies: {len(anomalies)}

## KEY FINDINGS
[List top 3 threats with impact assessment]

## RISK ASSESSMENT
[Rate overall risk: Low/Medium/High/Critical with justification]

## IMMEDIATE ACTIONS REQUIRED
[Numbered list of urgent remediation steps]

## INVESTIGATION CHECKLIST
- [ ] Block identified attacking IPs
- [ ] Force password reset for targeted accounts
- [ ] Review account activity logs
- [ ] Check for privilege escalation
- [ ] Monitor for lateral movement

## RECOMMENDED SECURITY IMPROVEMENTS
[3-4 security measures to prevent recurrence]

Keep it concise but comprehensive. Use markdown formatting."""
        
        try:
            return self._call_llm(prompt)
        except Exception as e:
            return f"Report Generation Error: {str(e)}"
    
    def suggest_remediation(self, anomaly_type: str, details: Dict) -> str:
        """Generate specific remediation recommendations."""
        
        prompt = f"""As a cybersecurity incident response expert, provide step-by-step remediation for this incident:

Type: {anomaly_type}
Details: {json.dumps(details, indent=2)}

Provide remediation steps in this format:

**Immediate (Next 1 hour):**
1. [Action]
2. [Action]

**Short-term (Next 24 hours):**
1. [Action]
2. [Action]

**Long-term (Next 30 days):**
1. [Action]
2. [Action]

**Monitoring Setup:**
- [Detection rule/alert to set up]
- [Metric to track]

Keep it practical and actionable."""
        
        try:
            return self._call_llm(prompt)
        except Exception as e:
            return f"Remediation Error: {str(e)}"
    
    def validate_confidence(self, anomaly: Dict) -> Dict:
        """Use AI to validate confidence of anomaly detection."""
        
        prompt = f"""Analyze this security anomaly detection and rate its confidence:

{json.dumps(anomaly, indent=2)}

Respond ONLY with valid JSON (no markdown, no code blocks):
{{
  "is_valid_threat": true/false,
  "revised_confidence": 0-100,
  "false_positive_risk": "low/medium/high",
  "additional_indicators": ["indicator1", "indicator2"],
  "explanation": "brief explanation"
}}"""
        
        try:
            if self.provider == "gemini":
                response = self.client.models.generate_content(
                    model="gemini-3.6-flash",
                    contents=prompt
                )
                response_text = response.text.strip()
            else:
                response = self.client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1
                )
                response_text = response.choices[0].message.content.strip()
            
            # Remove markdown code blocks if present
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            
            return json.loads(response_text.strip())
        except Exception as e:
            return {
                "is_valid_threat": True,
                "revised_confidence": anomaly.get('confidence', 50),
                "false_positive_risk": "medium",
                "explanation": f"Could not validate: {str(e)}"
            }
    
    def explain_simply(self, anomaly: Dict) -> str:
        """Explain anomaly in simple, non-technical language."""
        
        prompt = f"""Explain this security incident in simple terms that a non-technical person can understand:

{json.dumps(anomaly, indent=2)}

Explain:
1. What happened (simple terms)
2. Why it matters
3. What should be done about it

Use analogies if helpful. Avoid technical jargon."""
        
        try:
            return self._call_llm(prompt)
        except Exception as e:
            return f"Explanation Error: {str(e)}"
