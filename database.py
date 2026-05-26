"""
Database Operations - SQL Injection Protected
Built by Nkul Suthar | Internship 2026
"""

import sqlite3
from datetime import datetime
from contextlib import contextmanager
import hashlib

class Database:
    """Secure database handler with parameterized queries"""
    
    def __init__(self, db_path="secure_login.db"):
        self.db_path = db_path
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_db(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    two_factor_enabled BOOLEAN DEFAULT 0,
                    two_factor_secret TEXT,
                    is_admin BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    last_ip TEXT
                )
            ''')
            
            # Login history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    success BOOLEAN,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Session table (optional, for server-side sessions)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    session_token TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Failed login attempts (for rate limiting)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS failed_logins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    username TEXT,
                    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            print("✅ Database initialized successfully")
    
    # ==================== USER OPERATIONS ====================
    
    def create_user(self, username: str, email: str, password_hash: str, is_admin: bool = False) -> int:
        """Create a new user - SQL injection protected"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, is_admin)
                VALUES (?, ?, ?, ?)
            ''', (username, email, password_hash, is_admin))
            return cursor.lastrowid
    
    def get_user_by_id(self, user_id: int):
        """Get user by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            return cursor.fetchone()
    
    def get_user_by_username(self, username: str):
        """Get user by username"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            return cursor.fetchone()
    
    def get_user_by_email(self, email: str):
        """Get user by email"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            return cursor.fetchone()
    
    def update_password(self, user_id: int, new_hash: str):
        """Update user password"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user_id))
    
    def update_email(self, user_id: int, email: str):
        """Update user email"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET email = ? WHERE id = ?', (email, user_id))
    
    def update_last_login(self, user_id: int, ip_address: str):
        """Update last login information"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP, last_ip = ?
                WHERE id = ?
            ''', (ip_address, user_id))
    
    def enable_2fa(self, user_id: int, secret: str):
        """Enable two-factor authentication"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET two_factor_enabled = 1, two_factor_secret = ?
                WHERE id = ?
            ''', (secret, user_id))
    
    def disable_2fa(self, user_id: int):
        """Disable two-factor authentication"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL
                WHERE id = ?
            ''', (user_id,))
    
    def get_all_users(self):
        """Get all users (for admin)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, email, is_admin, created_at, last_login FROM users')
            return cursor.fetchall()
    
    # ==================== LOGIN HISTORY ====================
    
    def log_login_attempt(self, user_id: int, success: bool, ip_address: str):
        """Log login attempt"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO login_history (user_id, success, ip_address)
                VALUES (?, ?, ?)
            ''', (user_id, success, ip_address))
            
            if success:
                self.update_last_login(user_id, ip_address)
    
    def log_logout(self, user_id: int):
        """Log logout (optional)"""
        pass  # Can implement if needed
    
    def get_login_history(self, user_id: int, limit: int = 10):
        """Get user's login history"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT success, ip_address, timestamp
                FROM login_history
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (user_id, limit))
            return cursor.fetchall()
    
    # ==================== RATE LIMITING ====================
    
    def log_failed_attempt(self, ip_address: str, username: str):
        """Log failed login attempt for rate limiting"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO failed_logins (ip_address, username)
                VALUES (?, ?)
            ''', (ip_address, username))
    
    def get_failed_attempts(self, ip_address: str, minutes: int = 15):
        """Get number of failed attempts from IP in last X minutes"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) as count FROM failed_logins
                WHERE ip_address = ?
                AND attempt_time > datetime('now', '-' || ? || ' minutes')
            ''', (ip_address, minutes))
            result = cursor.fetchone()
            return result['count'] if result else 0
    
    def clear_failed_attempts(self, ip_address: str):
        """Clear failed attempts after successful login"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM failed_logins WHERE ip_address = ?', (ip_address,))
