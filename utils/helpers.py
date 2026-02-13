import requests
from urllib.parse import urljoin, urlparse
import time
from typing import List, Dict, Optional

class NetworkHelper:
    @staticmethod
    def get_page_content(url: str, timeout: int = 10) -> Optional[str]:
        """Fetch page content with error handling"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Error fetching {url}: {str(e)}")
            return None
    
    @staticmethod
    def get_http_headers(url: str, timeout: int = 10) -> Dict[str, str]:
        """Get HTTP headers from URL"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True)
            return dict(response.headers)
        except Exception as e:
            print(f"Error getting headers for {url}: {str(e)}")
            return {}
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if URL is valid and accessible"""
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            return response.status_code < 500
        except:
            return False

class DataProcessor:
    @staticmethod
    def calculate_risk_score(vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score from vulnerabilities"""
        if not vulnerabilities:
            return 0.0
        
        # Severity to score mapping
        severity_scores = {'Critical': 9.0, 'High': 7.5, 'Medium': 5.0, 'Low': 2.5}
        
        total_score = 0
        weighted_score = 0
        count = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            # Use cvss_score if available, otherwise use severity mapping
            score = vuln.get('cvss_score', severity_scores.get(severity, 2.5))
            weight = {'Critical': 1.0, 'High': 0.8, 'Medium': 0.5, 'Low': 0.2}.get(severity, 0.2)
            weighted_score += score * weight
            total_score += score
            count += 1
        
        if count > 0:
            return min(10.0, weighted_score / count)
        return 0.0
    
    @staticmethod
    def severity_to_cvss(severity: str) -> float:
        """Convert severity level to CVSS-like score"""
        severity_map = {
            'Critical': 9.0,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5
        }
        return severity_map.get(severity, 2.5)
    
    @staticmethod
    def format_timestamp(timestamp_str: str) -> str:
        """Format timestamp for display"""
        from datetime import datetime
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return timestamp_str

class TextHelper:
    @staticmethod
    def truncate_text(text: str, max_length: int = 100) -> str:
        """Truncate text with ellipsis"""
        if len(text) <= max_length:
            return text
        return text[:max_length] + "..."
    
    @staticmethod
    def clean_html(html_content: str) -> str:
        """Remove HTML tags from content"""
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            return soup.get_text()
        except:
            return html_content

# Global instances
network_helper = NetworkHelper()
data_processor = DataProcessor()
text_helper = TextHelper()