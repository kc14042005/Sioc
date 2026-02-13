from typing import Dict, List
from utils.helpers import network_helper

class SecurityHeaderChecker:
    def __init__(self):
        self.security_headers = {
            'Content-Security-Policy': {
                'description': 'Prevents XSS attacks by controlling which resources can be loaded',
                'severity': 'High',
                'remediation': 'Add Content-Security-Policy header with appropriate directives'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks by controlling frame embedding',
                'severity': 'Medium',
                'remediation': 'Add X-Frame-Options header with DENY or SAMEORIGIN value'
            },
            'X-XSS-Protection': {
                'description': 'Enables XSS filtering in browsers',
                'severity': 'Medium',
                'remediation': 'Add X-XSS-Protection header with value "1; mode=block"'
            },
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'severity': 'High',
                'remediation': 'Add Strict-Transport-Security header with max-age directive (e.g., max-age=31536000)'
            },
            'Referrer-Policy': {
                'description': 'Controls how much referrer information is sent',
                'severity': 'Low',
                'remediation': 'Add Referrer-Policy header with appropriate value (e.g., strict-origin-when-cross-origin)'
            }
        }
    
    def check_headers(self, url: str) -> List[Dict]:
        """Check for missing security headers"""
        vulnerabilities = []
        headers = network_helper.get_http_headers(url)
        
        if not headers:
            return [{
                'type': 'Header Check Failed',
                'description': 'Unable to retrieve HTTP headers',
                'severity': 'Medium',
                'cvss_score': 5.0,
                'remediation': 'Ensure the server is accessible and responding to HTTP requests'
            }]
        
        # Check each security header
        for header_name, header_info in self.security_headers.items():
            if header_name not in headers:
                vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'description': f'{header_name} header is missing. {header_info["description"]}',
                    'severity': header_info['severity'],
                    'cvss_score': self._get_cvss_score(header_info['severity']),
                    'remediation': header_info['remediation']
                })
            else:
                # Check header values for common issues
                issues = self._validate_header_value(header_name, headers[header_name])
                if issues:
                    for issue in issues:
                        vulnerabilities.append({
                            'type': 'Weak Security Header',
                            'description': f'{header_name}: {issue}',
                            'severity': header_info['severity'],
                            'cvss_score': self._get_cvss_score(header_info['severity']) * 0.7,  # Reduced for weak implementation
                            'remediation': header_info['remediation']
                        })
        
        return vulnerabilities
    
    def _validate_header_value(self, header_name: str, header_value: str) -> List[str]:
        """Validate security header values"""
        issues = []
        
        if header_name == 'X-Frame-Options':
            valid_values = ['DENY', 'SAMEORIGIN']
            if header_value.upper() not in valid_values:
                issues.append(f'Weak value "{header_value}". Should be DENY or SAMEORIGIN')
        
        elif header_name == 'X-XSS-Protection':
            if header_value != '1; mode=block':
                issues.append(f'Weak value "{header_value}". Should be "1; mode=block"')
        
        elif header_name == 'Strict-Transport-Security':
            if 'max-age' not in header_value.lower():
                issues.append('Missing max-age directive')
            elif 'max-age=0' in header_value.lower():
                issues.append('max-age set to 0 (disabled)')
        
        elif header_name == 'Content-Security-Policy':
            weak_directives = ['unsafe-inline', 'unsafe-eval']
            for directive in weak_directives:
                if directive in header_value:
                    issues.append(f'Contains weak directive: {directive}')
        
        elif header_name == 'Referrer-Policy':
            weak_values = ['unsafe-url', 'origin-when-cross-origin']
            if header_value.lower() in weak_values:
                issues.append(f'Weak referrer policy: {header_value}')
        
        return issues
    
    def _get_cvss_score(self, severity: str) -> float:
        """Convert severity to CVSS score"""
        severity_scores = {
            'Critical': 9.0,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5
        }
        return severity_scores.get(severity, 2.5)

# Convenience function
def check_security_headers(url: str) -> List[Dict]:
    """Simple function to check security headers"""
    checker = SecurityHeaderChecker()
    return checker.check_headers(url)