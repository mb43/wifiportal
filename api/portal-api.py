#!/usr/bin/env python3
"""
WiFi Captive Portal API Backend
Handles authentication, user management, and configuration
"""

from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import subprocess
import sqlite3
import time
from datetime import datetime, timedelta
import hashlib
import requests
from ldap3 import Server, Connection, ALL, NTLM
import jwt
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////opt/captive-portal/portal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configuration file path
CONFIG_FILE = '/opt/captive-portal/config.json'

# ===========================
# Database Models
# ===========================

class User(db.Model):
    """User sessions table"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    email = db.Column(db.String(150))
    ip_address = db.Column(db.String(50), unique=True)
    mac_address = db.Column(db.String(50))
    auth_method = db.Column(db.String(50))  # password, google, facebook, email, ldap
    connected_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    bytes_uploaded = db.Column(db.BigInteger, default=0)
    bytes_downloaded = db.Column(db.BigInteger, default=0)
    session_token = db.Column(db.String(200))
    active = db.Column(db.Boolean, default=True)

class AuthUser(db.Model):
    """Permanent user accounts for username/password auth"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))
    email = db.Column(db.String(150))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

class LogEntry(db.Model):
    """System logs"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    level = db.Column(db.String(20))  # INFO, WARNING, ERROR
    message = db.Column(db.Text)
    ip_address = db.Column(db.String(50))

# ===========================
# Helper Functions
# ===========================

def load_config():
    """Load portal configuration"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return get_default_config()

def save_config(config):
    """Save portal configuration"""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def get_default_config():
    """Default configuration"""
    return {
        "portal_name": "WiFi Portal",
        "ssid": "PublicHotspot",
        "github_portal_url": "https://mb43.github.io/wifiportal",
        "interface": "wlan0",
        "domain": "wifi.portal",
        "ports": {
            "redirect": 8080,
            "admin": 8443
        },
        "session": {
            "timeout": 3600,
            "bandwidth_limit": 0
        },
        "auth": {
            "password": {
                "enabled": True
            },
            "google": {
                "enabled": False,
                "client_id": "",
                "client_secret": ""
            },
            "facebook": {
                "enabled": False,
                "app_id": "",
                "app_secret": ""
            },
            "email": {
                "enabled": False,
                "smtp_host": "",
                "smtp_port": 587,
                "smtp_user": "",
                "smtp_password": "",
                "from_address": ""
            },
            "ldap": {
                "enabled": False,
                "host": "",
                "port": 389,
                "base_dn": "",
                "user_dn_template": "",
                "use_ssl": False
            }
        }
    }

def log_event(level, message, ip_address=None):
    """Log an event to database"""
    try:
        log = LogEntry(level=level, message=message, ip_address=ip_address)
        db.session.add(log)
        db.session.commit()
    except:
        pass  # Don't let logging errors break the app

def get_client_ip():
    """Get client IP from request"""
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    elif request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

def get_mac_address(ip):
    """Get MAC address from IP using ARP table"""
    try:
        result = subprocess.check_output(['arp', '-n', ip], text=True)
        for line in result.split('\n'):
            if ip in line:
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    except:
        pass
    return 'unknown'

def grant_internet_access(ip_address):
    """Add iptables rule to allow internet access"""
    try:
        # Check if rule already exists
        check_cmd = f"iptables -C FORWARD -s {ip_address} -j ACCEPT 2>/dev/null"
        result = subprocess.run(check_cmd, shell=True)

        if result.returncode != 0:
            # Rule doesn't exist, add it
            cmd = f"iptables -I FORWARD 1 -s {ip_address} -j ACCEPT"
            subprocess.run(cmd, shell=True, check=True)
            log_event('INFO', f'Granted internet access to {ip_address}', ip_address)
            return True
    except Exception as e:
        log_event('ERROR', f'Failed to grant access: {str(e)}', ip_address)
        return False
    return True

def revoke_internet_access(ip_address):
    """Remove iptables rule to revoke internet access"""
    try:
        cmd = f"iptables -D FORWARD -s {ip_address} -j ACCEPT"
        subprocess.run(cmd, shell=True, check=True)
        log_event('INFO', f'Revoked internet access from {ip_address}', ip_address)
        return True
    except:
        return False

def generate_session_token(username, ip):
    """Generate JWT session token"""
    payload = {
        'username': username,
        'ip': ip,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# ===========================
# Authentication Methods
# ===========================

def authenticate_password(username, password):
    """Authenticate with username/password"""
    user = AuthUser.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        return {'success': True, 'username': username, 'email': user.email}

    # Demo users (for testing)
    demo_users = {
        'demo': 'demo123',
        'admin': 'admin123',
        'user': 'password'
    }
    if username in demo_users and demo_users[username] == password:
        return {'success': True, 'username': username, 'email': f'{username}@demo.local'}

    return {'success': False, 'error': 'Invalid credentials'}

def authenticate_google(access_token):
    """Authenticate with Google OAuth"""
    try:
        # Verify token with Google
        url = f'https://oauth2.googleapis.com/tokeninfo?access_token={access_token}'
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'username': data.get('email', '').split('@')[0],
                'email': data.get('email', '')
            }
    except Exception as e:
        log_event('ERROR', f'Google auth error: {str(e)}')

    return {'success': False, 'error': 'Google authentication failed'}

def authenticate_facebook(access_token):
    """Authenticate with Facebook OAuth"""
    try:
        # Verify token with Facebook
        url = f'https://graph.facebook.com/me?fields=id,name,email&access_token={access_token}'
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'username': data.get('name', ''),
                'email': data.get('email', '')
            }
    except Exception as e:
        log_event('ERROR', f'Facebook auth error: {str(e)}')

    return {'success': False, 'error': 'Facebook authentication failed'}

def authenticate_email(email, code):
    """Authenticate with email verification code"""
    # This would normally verify a code sent via email
    # For now, accept any 6-digit code for demo
    if len(code) == 6 and code.isdigit():
        return {
            'success': True,
            'username': email.split('@')[0],
            'email': email
        }
    return {'success': False, 'error': 'Invalid verification code'}

def authenticate_ldap(username, password):
    """Authenticate with LDAP/Active Directory"""
    config = load_config()
    ldap_config = config['auth']['ldap']

    if not ldap_config['enabled']:
        return {'success': False, 'error': 'LDAP not enabled'}

    try:
        server = Server(ldap_config['host'], port=ldap_config['port'], get_info=ALL)

        # Format user DN
        if ldap_config.get('user_dn_template'):
            user_dn = ldap_config['user_dn_template'].format(username=username)
        else:
            user_dn = f"cn={username},{ldap_config['base_dn']}"

        # Attempt bind
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)

        if conn.bind():
            # Get user email from LDAP
            conn.search(user_dn, '(objectclass=person)', attributes=['mail'])
            email = ''
            if conn.entries:
                email = str(conn.entries[0].mail) if hasattr(conn.entries[0], 'mail') else ''

            conn.unbind()
            return {
                'success': True,
                'username': username,
                'email': email or f'{username}@{ldap_config["host"]}'
            }
    except Exception as e:
        log_event('ERROR', f'LDAP auth error: {str(e)}')

    return {'success': False, 'error': 'LDAP authentication failed'}

# ===========================
# API Endpoints
# ===========================

@app.route('/authenticate', methods=['POST'])
def authenticate():
    """Main authentication endpoint"""
    data = request.get_json() or {}
    auth_method = data.get('method', 'password')
    client_ip = get_client_ip()

    # Check if already authenticated
    existing_user = User.query.filter_by(ip_address=client_ip, active=True).first()
    if existing_user:
        return jsonify({'success': True, 'message': 'Already authenticated'})

    # Authenticate based on method
    result = None

    if auth_method == 'password':
        result = authenticate_password(data.get('username', ''), data.get('password', ''))

    elif auth_method == 'google':
        result = authenticate_google(data.get('accessToken', ''))

    elif auth_method == 'facebook':
        result = authenticate_facebook(data.get('accessToken', ''))

    elif auth_method == 'email':
        result = authenticate_email(data.get('email', ''), data.get('code', ''))

    elif auth_method == 'ldap':
        result = authenticate_ldap(data.get('username', ''), data.get('password', ''))

    else:
        return jsonify({'success': False, 'error': 'Invalid authentication method'})

    if not result or not result.get('success'):
        log_event('WARNING', f'Failed auth attempt: {auth_method}', client_ip)
        return jsonify(result)

    # Create user session
    try:
        mac = get_mac_address(client_ip)
        token = generate_session_token(result['username'], client_ip)

        user = User(
            username=result['username'],
            email=result.get('email', ''),
            ip_address=client_ip,
            mac_address=mac,
            auth_method=auth_method,
            session_token=token,
            active=True
        )

        db.session.add(user)
        db.session.commit()

        # Grant internet access
        if grant_internet_access(client_ip):
            log_event('INFO', f'User authenticated: {result["username"]} via {auth_method}', client_ip)
            return jsonify({
                'success': True,
                'token': token,
                'username': result['username']
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to grant access'})

    except Exception as e:
        db.session.rollback()
        log_event('ERROR', f'Session creation error: {str(e)}', client_ip)
        return jsonify({'success': False, 'error': 'Internal server error'})

@app.route('/config', methods=['GET', 'POST'])
def config():
    """Get or update portal configuration"""
    if request.method == 'GET':
        return jsonify(load_config())

    elif request.method == 'POST':
        try:
            new_config = request.get_json()
            save_config(new_config)
            log_event('INFO', 'Configuration updated', get_client_ip())
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

@app.route('/users', methods=['GET'])
def get_users():
    """Get list of connected users"""
    users = User.query.filter_by(active=True).all()

    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'ip_address': u.ip_address,
        'mac_address': u.mac_address,
        'auth_method': u.auth_method,
        'connected_at': u.connected_at.isoformat(),
        'last_seen': u.last_seen.isoformat(),
        'bytes_uploaded': u.bytes_uploaded,
        'bytes_downloaded': u.bytes_downloaded,
        'duration': int((datetime.utcnow() - u.connected_at).total_seconds())
    } for u in users])

@app.route('/users/disconnect', methods=['POST'])
def disconnect_user():
    """Disconnect a user"""
    data = request.get_json() or {}
    user_id = data.get('id')

    if not user_id:
        return jsonify({'success': False, 'error': 'User ID required'})

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'})

    # Revoke access
    revoke_internet_access(user.ip_address)

    # Mark as inactive
    user.active = False
    db.session.commit()

    log_event('INFO', f'User disconnected: {user.username}', user.ip_address)

    return jsonify({'success': True})

@app.route('/monitoring', methods=['GET'])
def monitoring():
    """Get system monitoring data"""
    try:
        # CPU usage
        cpu = 0
        with open('/proc/loadavg', 'r') as f:
            cpu = float(f.read().split()[0]) * 100 / os.cpu_count()

        # Memory usage
        mem_info = {}
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) > 1:
                    mem_info[parts[0].rstrip(':')] = int(parts[1])

        mem_total = mem_info.get('MemTotal', 1)
        mem_free = mem_info.get('MemFree', 0) + mem_info.get('Buffers', 0) + mem_info.get('Cached', 0)
        mem_used_percent = ((mem_total - mem_free) / mem_total) * 100

        # Disk usage
        stat = os.statvfs('/')
        disk_total = stat.f_blocks * stat.f_frsize
        disk_free = stat.f_bavail * stat.f_frsize
        disk_used_percent = ((disk_total - disk_free) / disk_total) * 100

        # Network stats (simplified)
        connected_users = User.query.filter_by(active=True).count()

        return jsonify({
            'cpu': round(min(cpu, 100), 1),
            'memory': round(mem_used_percent, 1),
            'disk': round(disk_used_percent, 1),
            'network': {
                'connected_users': connected_users,
                'bandwidth_usage': 0
            }
        })
    except Exception as e:
        log_event('ERROR', f'Monitoring error: {str(e)}')
        return jsonify({'cpu': 0, 'memory': 0, 'disk': 0, 'network': {'connected_users': 0, 'bandwidth_usage': 0}})

@app.route('/logs', methods=['GET'])
def get_logs():
    """Get system logs"""
    limit = request.args.get('limit', 100, type=int)
    logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(limit).all()

    return jsonify([{
        'id': log.id,
        'timestamp': log.timestamp.isoformat(),
        'level': log.level,
        'message': log.message,
        'ip_address': log.ip_address
    } for log in logs])

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})

# ===========================
# Session Management
# ===========================

def cleanup_expired_sessions():
    """Remove expired user sessions"""
    config = load_config()
    timeout = config['session']['timeout']

    cutoff_time = datetime.utcnow() - timedelta(seconds=timeout)
    expired_users = User.query.filter(
        User.active == True,
        User.last_seen < cutoff_time
    ).all()

    for user in expired_users:
        revoke_internet_access(user.ip_address)
        user.active = False
        log_event('INFO', f'Session expired: {user.username}', user.ip_address)

    if expired_users:
        db.session.commit()

# ===========================
# Initialization
# ===========================

def init_database():
    """Initialize database and create tables"""
    with app.app_context():
        db.create_all()

        # Create demo admin user if none exists
        if not AuthUser.query.filter_by(username='admin').first():
            admin = AuthUser(
                username='admin',
                password_hash=generate_password_hash('admin123'),
                email='admin@portal.local',
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print('✅ Created demo admin user: admin/admin123')

def init_config():
    """Initialize configuration file if it doesn't exist"""
    if not os.path.exists(CONFIG_FILE):
        save_config(get_default_config())
        print('✅ Created default configuration')

# ===========================
# Main
# ===========================

if __name__ == '__main__':
    print('🌐 Initializing Captive Portal API...')

    init_config()
    init_database()

    print('✅ API server starting on port 5000')
    print('📝 Endpoints:')
    print('   POST /authenticate - Authenticate users')
    print('   GET  /config - Get configuration')
    print('   POST /config - Update configuration')
    print('   GET  /users - List connected users')
    print('   POST /users/disconnect - Disconnect user')
    print('   GET  /monitoring - System monitoring')
    print('   GET  /logs - View logs')
    print('   GET  /health - Health check')

    # Run cleanup every 5 minutes
    import threading
    def periodic_cleanup():
        while True:
            time.sleep(300)  # 5 minutes
            cleanup_expired_sessions()

    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()

    # Start Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)
