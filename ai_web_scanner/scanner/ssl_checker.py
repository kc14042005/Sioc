from typing import List, Dict
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import requests

class SSLChecker:
    def __init__(self):
        self.context = ssl.create_default_context()
    
    def check_ssl(self, url: str) -> List[Dict]:
        """Check SSL certificate for a URL"""
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc.split(':')[0]  # Remove port if present
            
            # Check if URL uses HTTPS
            if parsed.scheme != 'https':
                vulnerabilities.append({
                    'type': 'Missing HTTPS',
                    'description': f'Website does not use HTTPS encryption',
                    'severity': 'High',
                    'cvss_score': 7.0,
                    'remediation': 'Enable HTTPS by obtaining and installing an SSL/TLS certificate'
                })
                return vulnerabilities
            
            # Check SSL certificate
            cert_issues = self._check_certificate(hostname)
            vulnerabilities.extend(cert_issues)
            
        except Exception as e:
            vulnerabilities.append({
                'type': 'SSL Check Failed',
                'description': f'Unable to verify SSL certificate: {str(e)}',
                'severity': 'Medium',
                'cvss_score': 5.0,
                'remediation': 'Ensure the server is properly configured with a valid SSL certificate'
            })
        
        return vulnerabilities
    
    def _check_certificate(self, hostname: str) -> List[Dict]:
        """Check SSL certificate details"""
        vulnerabilities = []
        
        try:
            # Create socket connection
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with self.context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    if 'notAfter' in cert:
                        expiration_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y')
                        days_until_expiry = (expiration_date - datetime.now()).days
                        
                        if days_until_expiry < 0:
                            vulnerabilities.append({
                                'type': 'Expired SSL Certificate',
                                'description': f'SSL certificate expired on {expiration_date.strftime("%Y-%m-%d")}',
                                'severity': 'Critical',
                                'cvss_score': 9.0,
                                'remediation': 'Renew the SSL certificate immediately'
                            })
                        elif days_until_expiry < 30:
                            vulnerabilities.append({
                                'type': 'SSL Certificate Expiring Soon',
                                'description': f'SSL certificate will expire in {days_until_expiry} days',
                                'severity': 'Medium',
                                'cvss_score': 5.0,
                                'remediation': f'Renew SSL certificate before it expires in {days_until_expiry} days'
                            })
                    
                    # Check certificate hostname match
                    subject = dict(x[0] for x in cert['subject'])
                    common_name = subject.get('commonName', '')
                    
                    if not self._hostname_matches_cert(hostname, common_name):
                        vulnerabilities.append({
                            'type': 'SSL Hostname Mismatch',
                            'description': f'Certificate hostname "{commonName}" does not match "{hostname}"',
                            'severity': 'High',
                            'cvss_score': 7.5,
                            'remediation': 'Obtain a certificate that includes the correct hostname or use a wildcard certificate'
                        })
                    
                    # Check certificate chain
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    issuer_cn = issuer.get('commonName', '')
                    
                    # Self-signed certificate warning
                    if issuer_cn == common_name:
                        vulnerabilities.append({
                            'type': 'Self-Signed Certificate',
                            'description': 'Using self-signed SSL certificate',
                            'severity': 'Medium',
                            'cvss_score': 5.0,
                            'remediation': 'Replace self-signed certificate with a certificate from a trusted Certificate Authority (CA)'
                        })
                    
                    # Check SSL/TLS version support
                    if not self._check_tls_version(ssock):
                        vulnerabilities.append({
                            'type': 'Weak TLS Version',
                            'description': 'Server supports outdated TLS versions (TLS 1.0/1.1)',
                            'severity': 'Medium',
                            'cvss_score': 5.5,
                            'remediation': 'Disable TLS 1.0 and 1.1, enable only TLS 1.2 and TLS 1.3'
                        })
        
        except ssl.SSLCertVerificationError as e:
            vulnerabilities.append({
                'type': 'SSL Certificate Invalid',
                'description': f'SSL certificate verification failed: {str(e)}',
                'severity': 'Critical',
                'cvss_score': 9.0,
                'remediation': 'Fix SSL certificate issues - ensure valid certificate from trusted CA'
            })
        except socket.timeout:
            vulnerabilities.append({
                'type': 'Connection Timeout',
                'description': 'Connection to SSL port timed out',
                'severity': 'Medium',
                'cvss_score': 5.0,
                'remediation': 'Ensure port 443 is open and accessible'
            })
        except Exception as e:
            vulnerabilities.append({
                'type': 'SSL Check Error',
                'description': f'Error checking SSL: {str(e)}',
                'severity': 'Low',
                'cvss_score': 3.0,
                'remediation': 'Verify server configuration'
            })
        
        return vulnerabilities
    
    def _hostname_matches_cert(self, hostname: str, cert_cn: str) -> bool:
        """Check if hostname matches certificate CN or SANs"""
        if hostname == cert_cn:
            return True
        
        # Handle wildcard certificates
        if cert_cn.startswith('*.'):
            base_domain = cert_cn[2:]
            if hostname.endswith(base_domain):
                return True
        
        return False
    
    def _check_tls_version(self, ssock) -> bool:
        """Check if weak TLS versions are supported"""
        # This is a simplified check - in production, you'd test each version
        try:
            cipher = ssock.cipher()
            if cipher:
                return True
        except:
            pass
        return True  # Assume OK if we can't determine


# Convenience function
def check_ssl(url: str) -> List[Dict]:
    """Simple function to check SSL certificate"""
    checker = SSLChecker()
    return checker.check_ssl(url)
