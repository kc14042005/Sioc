# In-memory database for demo
import bcrypt
from datetime import datetime

class MongoDBManager:
    users = {}
    scans = []
    
    def __init__(self):
        if "admin@aisentinel.com" not in self.users:
            hashed = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
            self.users["admin@aisentinel.com"] = {"name": "Admin", "email": "admin@aisentinel.com", "password": hashed}
    
    def create_user(self, name, email, password):
        if email in self.users:
            return False
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        self.users[email] = {"name": name, "email": email, "password": hashed}
        return True
    
    def authenticate_user(self, email, password):
        if email not in self.users:
            return None
        if bcrypt.checkpw(password.encode(), self.users[email]["password"]):
            return email
        return None
    
    def get_user_by_email(self, email):
        return self.users.get(email)
    
    def save_scan(self, user_id, url, vulnerabilities, score, ai_analysis):
        scan = {"user_id": user_id, "url": url, "vulnerabilities": vulnerabilities, "score": score, "ai_analysis": ai_analysis, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        self.scans.insert(0, scan)
        return scan
    
    def get_scan_history(self, user_id, limit=20):
        return [s for s in self.scans if s.get("user_id") == user_id][:limit]
    
    def reset_password(self, email, new_password):
        if email in self.users:
            hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
            self.users[email]["password"] = hashed
            return True
        return False

db = MongoDBManager()
