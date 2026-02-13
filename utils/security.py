import bcrypt
import re
from urllib.parse import urlparse
import time
from functools import wraps

class SecurityUtils:
    @staticmethod
    def hash_password(password: str) -> bytes:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    @staticmethod
    def verify_password(password: str, hashed: bytes) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed)
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def sanitize_input(text: str) -> str:
        """Sanitize user input"""
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '`', '|', '*', '?', '~', '^', '(', ')', '[', ']', '{', '}']
        for char in dangerous_chars:
            text = text.replace(char, '')
        return text.strip()
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Validate domain format"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(pattern, domain) is not None

def rate_limit(max_calls: int = 5, period: int = 3600):
    """Rate limiting decorator"""
    calls = []
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            # Remove calls older than the period
            calls[:] = [call for call in calls if call > now - period]
            
            if len(calls) >= max_calls:
                raise Exception(f"Rate limit exceeded. Maximum {max_calls} calls per {period//3600} hours.")
            
            calls.append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator

def timeout_handler(timeout: int = 30):
    """Timeout decorator for scan functions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError(f"Function timed out after {timeout} seconds")
            
            # Set the timeout handler
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout)
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                # Reset the alarm
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
        return wrapper
    return decorator