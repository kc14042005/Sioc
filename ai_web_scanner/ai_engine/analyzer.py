import os
import json
from typing import List, Dict, Optional
from openai import OpenAI

# Load API key from environment
def get_openai_client():
    """Get OpenAI client with API key"""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        # Try to load from .env file
        try:
            from dotenv import load_dotenv
            load_dotenv()
            api_key = os.getenv("OPENAI_API_KEY")
        except:
            pass
    
    if not api_key:
        raise ValueError("OpenAI API key not found. Please set OPENAI_API_KEY in .env file.")
    
    return OpenAI(api_key=api_key)


class AIAnalyzer:
    def __init__(self):
        try:
            self.client = get_openai_client()
            self.model = "gpt-4"
        except Exception as e:
            print(f"Warning: Could not initialize AI client: {e}")
            self.client = None
    
    def analyze_vulnerabilities(self, url: str, vulnerabilities: List[Dict]) -> Dict:
        """Analyze vulnerabilities and provide AI-powered insights"""
        if not vulnerabilities:
            return {
                'summary': 'No vulnerabilities detected.',
                'risk_level': 'Low',
                'risk_score': 0.0,
                'recommendations': ['Continue regular security monitoring.'],
                'executive_summary': 'The security scan completed successfully with no significant vulnerabilities detected.'
            }
        
        if not self.client:
            # Fallback to basic analysis if no AI client
            return self._basic_analysis(vulnerabilities)
        
        try:
            return self._ai_analysis(url, vulnerabilities)
        except Exception as e:
            print(f"AI analysis failed: {e}")
            return self._basic_analysis(vulnerabilities)
    
    def _ai_analysis(self, url: str, vulnerabilities: List[Dict]) -> Dict:
        """Use OpenAI for vulnerability analysis"""
        
        # Prepare vulnerability summary for AI
        vuln_summary = []
        for v in vulnerabilities:
            vuln_summary.append({
                'type': v.get('type', 'Unknown'),
                'description': v.get('description', ''),
                'severity': v.get('severity', 'Unknown'),
                'cvss_score': v.get('cvss_score', 0)
            })
        
        prompt = f"""You are a senior cybersecurity expert analyzing web vulnerability scan results.
        
Target URL: {url}

Vulnerabilities Found:
{json.dumps(vuln_summary, indent=2)}

Based on the scan results, provide a detailed analysis in JSON format with the following fields:
1. "summary" - A brief summary (2-3 sentences) of the security posture
2. "risk_level" - Overall risk level: Low, Medium, High, or Critical
3. "risk_score" - A score from 0-10 representing overall risk
4. "recommendations" - Array of 3-5 specific remediation recommendations
5. "executive_summary" - A one-paragraph executive summary suitable for management

Consider CVSS scores, severity levels, and the types of vulnerabilities found. Prioritize critical and high severity issues.
"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in web application security. Provide detailed, actionable security analysis."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1000
        )
        
        # Parse the AI response
        try:
            result = json.loads(response.choices[0].message.content)
            return result
        except json.JSONDecodeError:
            # If AI response isn't valid JSON, create a structured response
            return {
                'summary': response.choices[0].message.content[:500],
                'risk_level': self._calculate_risk_level(vulnerabilities),
                'risk_score': self._calculate_risk_score(vulnerabilities),
                'recommendations': self._get_default_recommendations(vulnerabilities),
                'executive_summary': response.choices[0].message.content[:1000]
            }
    
    def _basic_analysis(self, vulnerabilities: List[Dict]) -> Dict:
        """Fallback analysis without AI"""
        risk_score = self._calculate_risk_score(vulnerabilities)
        risk_level = self._calculate_risk_level(vulnerabilities)
        
        return {
            'summary': f'Found {len(vulnerabilities)} vulnerabilities with {risk_level} overall risk level.',
            'risk_level': risk_level,
            'risk_score': risk_score,
            'recommendations': self._get_default_recommendations(vulnerabilities),
            'executive_summary': f'Security scan of target identified {len(vulnerabilities)} security issues. The most severe findings require immediate attention to prevent potential exploitation.'
        }
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate risk score from vulnerabilities"""
        if not vulnerabilities:
            return 0.0
        
        total_score = 0
        for v in vulnerabilities:
            score = v.get('cvss_score', 0)
            severity = v.get('severity', 'Low')
            
            # Weight by severity
            weights = {'Critical': 1.0, 'High': 0.8, 'Medium': 0.5, 'Low': 0.2}
            weight = weights.get(severity, 0.2)
            total_score += score * weight
        
        avg_score = total_score / len(vulnerabilities)
        return min(10.0, round(avg_score, 1))
    
    def _calculate_risk_level(self, vulnerabilities: List[Dict]) -> str:
        """Determine overall risk level"""
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        if risk_score >= 8.0:
            return 'Critical'
        elif risk_score >= 6.0:
            return 'High'
        elif risk_score >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    def _get_default_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Get default recommendations based on vulnerability types"""
        vuln_types = set(v.get('type', '') for v in vulnerabilities)
        
        recommendations = []
        
        if any('XSS' in t for t in vuln_types):
            recommendations.append('Implement Content Security Policy (CSP) and sanitize user inputs')
        
        if any('SQL' in t for t in vuln_types):
            recommendations.append('Use parameterized queries and input validation to prevent SQL injection')
        
        if any('SSL' in t or 'HTTPS' in t for t in vuln_types):
            recommendations.append('Obtain and configure valid SSL/TLS certificates')
        
        if any('Header' in t for t in vuln_types):
            recommendations.append('Configure security headers on the web server')
        
        recommendations.append('Conduct regular security audits and penetration testing')
        recommendations.append('Keep all software and dependencies up to date')
        
        return recommendations[:5]


# Convenience function
def analyze_vulnerabilities(url: str, vulnerabilities: List[Dict]) -> Dict:
    """Simple function to analyze vulnerabilities"""
    analyzer = AIAnalyzer()
    return analyzer.analyze_vulnerabilities(url, vulnerabilities)
