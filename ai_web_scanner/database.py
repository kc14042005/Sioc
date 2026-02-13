import sqlite3
import hashlib
import bcrypt
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import os
import re
from pymongo import MongoClient
from bson import ObjectId

# MongoDB Connection
MONGO_URI = "mongodb+srv://kc14012005_db_user:Wh5bow4cTyyMmxR1@cluster0.7hcfpwu.mongodb.net/"
MONGO_DB = "vulnerability_scanner"

class MongoDBManager:
    """MongoDB Manager for cloud database"""
    
    def __init__(self):
        try:
            self.client = MongoClient(MONGO_URI)
            self.db = self.client[MONGO_DB]
            self.users = self.db.users
            self.scans = self.db.scans
            self.vulnerabilities = self.db.vulnerabilities
            # Create indexes
            self.users.create_index("email", unique=True)
            self.scans.create_index([("user_id", 1), ("created_at", -1)])
            self.vulnerabilities.create_index("scan_id")
            print("MongoDB connected successfully!")
        except Exception as e:
            print(f"MongoDB connection error: {e}")
            self.client = None
            self.db = None
    
    def create_user(self, name: str, email: str, password: str) -> bool:
        if self.db is None: return False
        try:
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                return False
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            self.users.insert_one({
                "name": name,
                "email": email,
                "password_hash": password_hash,
                "created_at": datetime.now()
            })
            return True
        except Exception as e:
            print(f"Create user error: {e}")
            return False
    
    def authenticate_user(self, email: str, password: str) -> Optional[str]:
        if self.db is None: return None
        user = self.users.find_one({"email": email})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return str(user['_id'])
        return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        if self.db is None: return None
        user = self.users.find_one({"email": email})
        if user:
            user['_id'] = str(user['_id'])
            return user
        return None
    
    def create_scan(self, user_id: str, url: str, score: float, summary: str) -> str:
        if self.db is None: return ""
        result = self.scans.insert_one({
            "user_id": user_id,
            "url": url,
            "score": score,
            "summary": summary,
            "created_at": datetime.now()
        })
        return str(result.inserted_id)
    
    def add_vulnerability(self, scan_id: str, vuln_type: str, description: str, severity: str, remediation: str):
        if self.db is None: return
        self.vulnerabilities.insert_one({
            "scan_id": scan_id,
            "type": vuln_type,
            "description": description,
            "severity": severity,
            "remediation": remediation
        })
    
    def get_dashboard_stats(self, user_id: str) -> Dict:
        if self.db is None:
            return {'total_scans': 0, 'today_scans': 0, 'avg_score': 0, 'severity_counts': {}, 'recent_scans': []}
        
        today = datetime.now().date()
        total_scans = self.scans.count_documents({"user_id": user_id})
        today_scans = self.scans.count_documents({"user_id": user_id, "created_at": {"$gte": datetime.combine(today, datetime.min.time())}})
        
        pipeline = [
            {"$match": {"user_id": user_id, "score": {"$ne": None}}},
            {"$group": {"_id": None, "avg": {"$avg": "$score"}}}
        ]
        avg_result = list(self.scans.aggregate(pipeline))
        avg_score = avg_result[0]['avg'] if avg_result else 0
        
        pipeline = [
            {"$lookup": {"as": "scan", "from": "scans", "let": {"scan_id": "$scan_id"}, "match": {"$expr": {"$eq": ["$_id", "$$scan_id"]}}}},
            {"$unwind": "$scan"},
            {"$match": {"scan.user_id": user_id}},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
        ]
        severity_counts = {r['_id']: r['count'] for r in self.vulnerabilities.aggregate(pipeline)}
        
        recent = list(self.scans.find({"user_id": user_id, "score": {"$ne": None}}).sort("created_at", -1).limit(10))
        recent_scans = [{'created_at': str(s['created_at']), 'score': s['score']} for s in recent]
        
        return {
            'total_scans': total_scans,
            'today_scans': today_scans,
            'avg_score': round(avg_score, 2),
            'severity_counts': severity_counts,
            'recent_scans': recent_scans
        }
    
    def get_scan_history(self, user_id: str, limit: int = 50) -> List[Dict]:
        if self.db is None: return []
        scans = list(self.scans.find({"user_id": user_id}).sort("created_at", -1).limit(limit))
        history = []
        for s in scans:
            vuln_count = self.vulnerabilities.count_documents({"scan_id": str(s['_id'])})
            history.append({
                '_id': str(s['_id']),
                'url': s['url'],
                'created_at': str(s['created_at']),
                'score': s.get('score', 0),
                'summary': s.get('summary', ''),
                'vulnerability_count': vuln_count
            })
        return history

class DatabaseManager:
    def __init__(self, db_path: str = "vulnerability_scanner.db"):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Get database connection with row factory"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Create users table with new schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                url TEXT NOT NULL,
                score REAL,
                summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                type TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        # Create password reset table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        ''')
        
        # Create default admin user if not exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = 'admin@scanner.com'")
        if cursor.fetchone()[0] == 0:
            password_hash = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
            cursor.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                ("Administrator", "admin@scanner.com", password_hash)
            )
        
        conn.commit()
        conn.close()
    
    def create_user(self, name: str, email: str, password: str) -> bool:
        """Create new user"""
        try:
            # Validate email format
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                return False
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            cursor.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, password_hash)
            )
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def authenticate_user(self, email: str, password: str) -> Optional[int]:
        """Authenticate user and return user ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, password_hash FROM users WHERE email = ?",
            (email,)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        if result and bcrypt.checkpw(password.encode('utf-8'), result['password_hash']):
            return result['id']
        return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        result = cursor.fetchone()
        conn.close()
        
        return dict(result) if result else None
    
    def create_scan(self, user_id: int, url: str, score: float, summary: str) -> int:
        """Create new scan record and return scan ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO scans (user_id, url, score, summary) VALUES (?, ?, ?, ?)",
            (user_id, url, score, summary)
        )
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return scan_id
    
    def add_vulnerability(self, scan_id: int, vuln_type: str, description: str, 
                         severity: str, remediation: str):
        """Add vulnerability to scan"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO vulnerabilities (scan_id, type, description, severity, remediation)
            VALUES (?, ?, ?, ?, ?)
        ''', (scan_id, vuln_type, description, severity, remediation))
        
        conn.commit()
        conn.close()
    
    def get_user_scans(self, user_id: int) -> List[Dict]:
        """Get all scans for a user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        )
        
        scans = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return scans
    
    def get_scan_details(self, scan_id: int) -> Dict:
        """Get detailed scan information including vulnerabilities"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Get scan details
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = dict(cursor.fetchone())
        
        # Get vulnerabilities
        cursor.execute(
            "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity DESC",
            (scan_id,)
        )
        vulnerabilities = [dict(row) for row in cursor.fetchall()]
        
        scan['vulnerabilities'] = vulnerabilities
        conn.close()
        
        return scan
    
    def get_dashboard_stats(self, user_id: int) -> Dict:
        """Get dashboard statistics for user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Total scans
        cursor.execute(
            "SELECT COUNT(*) as total_scans FROM scans WHERE user_id = ?",
            (user_id,)
        )
        total_scans = cursor.fetchone()['total_scans']
        
        # Today's scans
        cursor.execute(
            "SELECT COUNT(*) as today_scans FROM scans WHERE user_id = ? AND DATE(created_at) = DATE('now')",
            (user_id,)
        )
        today_scans = cursor.fetchone()['today_scans']
        
        # Average score
        cursor.execute(
            "SELECT AVG(score) as avg_score FROM scans WHERE user_id = ? AND score IS NOT NULL",
            (user_id,)
        )
        avg_score = cursor.fetchone()['avg_score'] or 0
        
        # Vulnerabilities by severity
        cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            WHERE s.user_id = ?
            GROUP BY severity
        ''', (user_id,))
        
        severity_counts = {}
        for row in cursor.fetchall():
            severity_counts[row['severity']] = row['count']
        
        # Recent scans for timeline
        cursor.execute('''
            SELECT created_at, score 
            FROM scans 
            WHERE user_id = ? AND score IS NOT NULL
            ORDER BY created_at DESC 
            LIMIT 10
        ''', (user_id,))
        
        recent_scans = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'today_scans': today_scans,
            'avg_score': round(avg_score, 2),
            'severity_counts': severity_counts,
            'recent_scans': recent_scans
        }
    
    def get_scan_history(self, user_id: int, limit: int = 50) -> List[Dict]:
        """Get scan history with vulnerability counts"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT s.id, s.url, s.created_at, s.score, s.summary,
                   COUNT(v.id) as vulnerability_count
            FROM scans s
            LEFT JOIN vulnerabilities v ON s.id = v.scan_id
            WHERE s.user_id = ?
            GROUP BY s.id
            ORDER BY s.created_at DESC
            LIMIT ?
        ''', (user_id, limit))
        
        history = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return history
    
    def update_password(self, email: str, new_password: str) -> bool:
        """Update user password"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE email = ?",
                (password_hash, email)
            )
            
            conn.commit()
            conn.close()
            return True
        except:
            return False

# Global database instance
db = DatabaseManager()