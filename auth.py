"""
Authentication Manager - Password Hashing & Verification
Built by Nkul Suthar | Internship 2026
"""

import bcrypt
import re
from datetime import datetime, timedelta

class AuthManager:
    """Secure authentication manager with bcrypt hashing"""
    
    def __init__(self, database=None):
        self.db = database
        self.MAX_LOGIN_ATTEMPTS = 5
        self.LOCKOUT_MINUTES = 15
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt
        bcrypt automatically handles salting
        """
        # Convert password to bytes
        password_bytes = password.encode('utf-8')
        
        # Generate salt and hash (cost factor = 12)
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        # Return as string for storage
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, stored_hash: str) -> bool:
        """
        Verify password against stored bcrypt hash
        """
        try:
            password_bytes = password.encode('utf-8')
            stored_bytes = stored_hash.encode('utf-8')
            
            # bcrypt.compare handles timing attack protection
            return bcrypt.checkpw(password_bytes, stored_bytes)
        except Exception:
            return False
    
    def validate_password_strength(self, password: str) -> tuple:
        """
        Validate password strength
        Returns: (is_valid, list_of_issues)
        """
        issues = []
        
        if len(password) < 8:
            issues.append("Password must be at least 8 characters")
        
        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            issues.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            issues.append("Password must contain at least one number")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password must contain at least one special character")
        
        # Check for common patterns
        common_patterns = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if any(pattern in password.lower() for pattern in common_patterns):
            issues.append("Password contains common patterns")
        
        return len(issues) == 0, issues
    
    def is_rate_limited(self, ip_address: str) -> bool:
        """
        Check if IP is rate limited due to too many failed attempts
        """
        if not self.db:
            return False
        
        attempts = self.db.get_failed_attempts(ip_address, self.LOCKOUT_MINUTES)
        return attempts >= self.MAX_LOGIN_ATTEMPTS
    
    def record_failed_attempt(self, ip_address: str, username: str):
        """Record failed login attempt"""
        if self.db:
            self.db.log_failed_attempt(ip_address, username)
    
    def generate_reset_token(self, user_id: int) -> str:
        """
        Generate password reset token (for future enhancement)
        """
        import secrets
        token = secrets.token_urlsafe(32)
        # Store token in database with expiry
        return token
    
    def verify_reset_token(self, token: str) -> bool:
        """Verify password reset token"""
        # Implementation for password reset feature
        pass
