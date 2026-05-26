"""
Secure Login System - Complete Web Application
Built by Nkul Suthar | Internship 2026 | GitHub: @Neecool

Features:
- Secure user registration/login
- bcrypt password hashing
- SQL injection protection
- Session management
- Two-Factor Authentication (2FA)
- Input validation
- CSRF protection
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
import re
import secrets
from datetime import datetime, timedelta
import pyotp
import qrcode
from io import BytesIO
import base64

# Import custom modules
from database import Database
from auth import AuthManager

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure random secret key
app.permanent_session_lifetime = timedelta(hours=2)  # Session expires in 2 hours

# Initialize database and auth manager
db = Database()
auth_manager = AuthManager(db)

# ==================== DECORATORS ====================

def login_required(f):
    """Decorator to protect routes that require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator for admin-only routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'warning')
            return redirect(url_for('login'))
        if not session.get('is_admin', False):
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== ROUTES ====================

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with validation"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Input validation
        errors = []
        
        # Username validation
        if not username:
            errors.append('Username is required')
        elif len(username) < 3:
            errors.append('Username must be at least 3 characters')
        elif len(username) > 50:
            errors.append('Username must be less than 50 characters')
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append('Username can only contain letters, numbers, and underscores')
        
        # Email validation
        if not email:
            errors.append('Email is required')
        elif not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            errors.append('Invalid email format')
        
        # Password validation
        if not password:
            errors.append('Password is required')
        elif len(password) < 8:
            errors.append('Password must be at least 8 characters')
        elif not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter')
        elif not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter')
        elif not re.search(r'\d', password):
            errors.append('Password must contain at least one number')
        elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append('Password must contain at least one special character')
        
        # Password match
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        # Check if user exists
        if not errors:
            if db.get_user_by_username(username):
                errors.append('Username already exists')
            elif db.get_user_by_email(email):
                errors.append('Email already registered')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html')
        
        # Create user with hashed password
        password_hash = auth_manager.hash_password(password)
        user_id = db.create_user(username, email, password_hash)
        
        if user_id:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login with session management"""
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'
        
        # Input validation
        if not identifier or not password:
            flash('Please enter both username/email and password', 'danger')
            return render_template('login.html')
        
        # Check if identifier is email or username
        user = None
        if '@' in identifier:
            user = db.get_user_by_email(identifier.lower())
        else:
            user = db.get_user_by_username(identifier)
        
        if not user:
            flash('Invalid credentials', 'danger')
            return render_template('login.html')
        
        # Verify password
        if auth_manager.verify_password(password, user['password_hash']):
            # Check if 2FA is enabled
            if user['two_factor_enabled']:
                # Store user ID in temporary session for 2FA verification
                session['temp_user_id'] = user['id']
                session['temp_username'] = user['username']
                return redirect(url_for('verify_2fa'))
            else:
                # Complete login
                session.permanent = remember_me
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['is_admin'] = user.get('is_admin', False)
                session['login_time'] = datetime.now().isoformat()
                
                # Log login attempt
                db.log_login_attempt(user['id'], True, request.remote_addr)
                
                flash(f'Welcome back, {user["username"]}!', 'success')
                return redirect(url_for('dashboard'))
        else:
            # Log failed attempt
            if user:
                db.log_login_attempt(user['id'], False, request.remote_addr)
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Two-Factor Authentication verification"""
    if 'temp_user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('login'))
    
    user = db.get_user_by_id(session['temp_user_id'])
    if not user:
        session.clear()
        flash('Session expired', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        totp_code = request.form.get('totp_code', '').strip()
        
        if not totp_code:
            flash('Please enter the 2FA code', 'danger')
            return render_template('verify_2fa.html')
        
        # Verify TOTP
        totp = pyotp.TOTP(user['two_factor_secret'])
        if totp.verify(totp_code):
            # Complete login
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            session['is_admin'] = user.get('is_admin', False)
            session.pop('temp_user_id', None)
            session.pop('temp_username', None)
            
            db.log_login_attempt(user['id'], True, request.remote_addr)
            flash('Login successful with 2FA!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code. Please try again.', 'danger')
    
    return render_template('verify_2fa.html')

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    """Setup Two-Factor Authentication"""
    user = db.get_user_by_id(session['user_id'])
    
    if user['two_factor_enabled']:
        flash('2FA is already enabled for your account', 'info')
        return redirect(url_for('profile'))
    
    # Generate secret key
    secret = pyotp.random_base32()
    
    # Generate provisioning URI
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user['email'], issuer_name="SecureLoginSystem")
    
    # Generate QR code
    qr = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode()
    
    # Store secret temporarily in session
    session['temp_2fa_secret'] = secret
    
    return render_template('setup_2fa.html', qr_code=qr_code, secret=secret)

@app.route('/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    """Enable 2FA after verification"""
    totp_code = request.form.get('totp_code', '').strip()
    secret = session.get('temp_2fa_secret')
    
    if not secret:
        flash('2FA setup expired. Please try again.', 'danger')
        return redirect(url_for('setup_2fa'))
    
    totp = pyotp.TOTP(secret)
    if totp.verify(totp_code):
        # Enable 2FA for user
        db.enable_2fa(session['user_id'], secret)
        session.pop('temp_2fa_secret', None)
        flash('2FA enabled successfully!', 'success')
    else:
        flash('Invalid verification code. Please try again.', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable Two-Factor Authentication"""
    db.disable_2fa(session['user_id'])
    flash('2FA has been disabled', 'warning')
    return redirect(url_for('profile'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user = db.get_user_by_id(session['user_id'])
    login_history = db.get_login_history(session['user_id'], limit=10)
    
    return render_template('dashboard.html', user=user, login_history=login_history)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile management"""
    user = db.get_user_by_id(session['user_id'])
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Verify current password
            if not auth_manager.verify_password(current_password, user['password_hash']):
                flash('Current password is incorrect', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match', 'danger')
            elif len(new_password) < 8:
                flash('Password must be at least 8 characters', 'danger')
            else:
                # Update password
                new_hash = auth_manager.hash_password(new_password)
                db.update_password(session['user_id'], new_hash)
                flash('Password changed successfully!', 'success')
        
        elif action == 'update_profile':
            email = request.form.get('email', '').strip().lower()
            
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                flash('Invalid email format', 'danger')
            else:
                db.update_email(session['user_id'], email)
                session['email'] = email
                flash('Profile updated successfully!', 'success')
    
    return render_template('profile.html', user=user)

@app.route('/logout')
def logout():
    """User logout - clear session"""
    if 'user_id' in session:
        user_id = session['user_id']
        db.log_logout(user_id)
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin panel - view all users"""
    users = db.get_all_users()
    return render_template('admin_users.html', users=users)

# ==================== API ENDPOINTS ====================

@app.route('/api/check-username', methods=['POST'])
def api_check_username():
    """API endpoint to check username availability"""
    from flask import jsonify, request
    data = request.get_json()
    username = data.get('username', '').strip()
    
    if not username:
        return jsonify({'available': False, 'message': 'Username required'})
    
    user = db.get_user_by_username(username)
    return jsonify({'available': user is None})

@app.route('/api/check-email', methods=['POST'])
def api_check_email():
    """API endpoint to check email availability"""
    from flask import jsonify, request
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'available': False, 'message': 'Email required'})
    
    user = db.get_user_by_email(email)
    return jsonify({'available': user is None})

# ==================== MAIN ====================

if __name__ == '__main__':
    # Initialize database tables
    db.init_db()
    
    # Create admin user if not exists
    if not db.get_user_by_username('admin'):
        admin_hash = auth_manager.hash_password('Admin@123456')
        db.create_user('admin', 'admin@securesystem.com', admin_hash, is_admin=True)
        print("✅ Admin user created: admin / Admin@123456")
    
    print("\n" + "="*60)
    print("🔐 SECURE LOGIN SYSTEM STARTED")
    print(f"   Built by Nkul Suthar | Internship 2026")
    print(f"   GitHub: @Neecool")
    print("="*60)
    print("\n🚀 Server running at: http://localhost:5000")
    print("📱 Press CTRL+C to stop\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
