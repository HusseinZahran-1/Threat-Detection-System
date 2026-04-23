import hashlib
import hmac
import secrets
import os  # Missing import added
import time  # Missing import added
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import bcrypt
from cryptography.fernet import Fernet
import base64
import json
import re

class SecurityManager:
    def __init__(self, app=None):
        self.app = app
        self.jwt_secret = os.getenv('JWT_SECRET', 'your-super-secret-key-change-in-production')
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        if app:
            self.setup_security(app)
    
    def setup_security(self, app):
        """Setup security middleware and configurations"""
        # JWT configuration
        app.config['JWT_SECRET_KEY'] = self.jwt_secret
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
        app.config['JWT_ALGORITHM'] = 'HS256'
        
        # Rate limiting
        self.limiter = Limiter(
            get_remote_address,
            app=app,
            default_limits=["1000 per day", "200 per hour"],
            storage_uri="memory://",
        )
        
        # Security headers
        @app.after_request
        def set_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'"
            return response
    
    def hash_password(self, password):
        """Hash a password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password, hashed):
        """Verify a password against its hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def generate_api_key(self, user_id):
        """Generate a secure API key"""
        random_part = secrets.token_urlsafe(32)
        user_part = hashlib.sha256(user_id.encode()).hexdigest()[:16]
        api_key = f"td_{user_part}_{random_part}"
        
        # Store the hash of the API key (not the key itself)
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        return api_key, api_key_hash
    
    def verify_api_key(self, api_key, stored_hash):
        """Verify an API key"""
        return hashlib.sha256(api_key.encode()).hexdigest() == stored_hash

class DataEncryptor:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
    
    def encrypt_sensitive_data(self, data):
        """Encrypt sensitive data before storage"""
        if isinstance(data, dict):
            data = json.dumps(data)
        
        encrypted_data = self.cipher_suite.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt_data(self, encrypted_data):
        """Decrypt sensitive data"""
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data)
            decrypted_data = self.cipher_suite.decrypt(decoded_data)
            return decrypted_data.decode()
        except Exception as e:
            print(f"❌ Decryption error: {e}")
            return None
    
    def encrypt_field(self, field_value):
        """Encrypt a single field"""
        if field_value is None:
            return None
        return self.encrypt_sensitive_data(str(field_value))
    
    def decrypt_field(self, encrypted_field):
        """Decrypt a single field"""
        if encrypted_field is None:
            return None
        return self.decrypt_data(encrypted_field)

class InputValidator:
    def __init__(self):
        self.suspicious_patterns = [
            r'<script>', r'javascript:', r'onload=', r'onerror=',
            r'union.*select', r'select.*from', r'insert.*into',
            r'drop.*table', r'or.*1=1', r'--\s',
            r'\.\./', r'\.\.\\',  # Path traversal
            r'\\x[0-9a-f]{2}',  # Hex encoding
        ]
    
    def sanitize_input(self, input_data):
        """Sanitize user input to prevent injection attacks"""
        if isinstance(input_data, dict):
            return {key: self.sanitize_input(value) for key, value in input_data.items()}
        elif isinstance(input_data, list):
            return [self.sanitize_input(item) for item in input_data]
        elif isinstance(input_data, str):
            # Remove suspicious patterns
            for pattern in self.suspicious_patterns:
                input_data = re.sub(pattern, '', input_data, flags=re.IGNORECASE)
            
            # Escape special characters
            input_data = input_data.replace('<', '&lt;').replace('>', '&gt;')
            input_data = input_data.replace('"', '&quot;').replace("'", '&#x27;')
            
            return input_data
        else:
            return input_data
    
    def validate_ip_address(self, ip_address):
        """Validate IP address format"""
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def validate_port(self, port):
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
    
    def validate_timestamp(self, timestamp_str):
        """Validate ISO timestamp format"""
        try:
            datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return True
        except ValueError:
            return False

def rate_limit_by_ip(func):
    """Custom rate limiting decorator based on IP and endpoint"""
    from flask import request, jsonify
    from functools import wraps
    import time
    
    # Store request timestamps per IP and endpoint
    request_history = {}
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        endpoint = request.endpoint or 'unknown'
        ip_address = get_remote_address()
        
        # Different limits for different endpoints
        limits = {
            'analyze_threats': {"requests": 50, "window": 60},  # 50 per minute
            'get_dashboard_data': {"requests": 100, "window": 60}, 
            'get_threat_intelligence': {"requests": 30, "window": 60},
            'generate_report': {"requests": 10, "window": 60},
            'login': {"requests": 5, "window": 60}  # Stricter limits for login
        }
        
        limit_config = limits.get(endpoint, {"requests": 100, "window": 3600})  # Default: 100 per hour
        
        current_time = time.time()
        key = f"{ip_address}:{endpoint}"
        
        # Initialize or clean old requests for this IP/endpoint
        if key not in request_history:
            request_history[key] = []
        
        # Remove requests outside the time window
        request_history[key] = [
            req_time for req_time in request_history[key] 
            if current_time - req_time < limit_config["window"]
        ]
        
        # Check if rate limit exceeded
        if len(request_history[key]) >= limit_config["requests"]:
            return jsonify({
                "error": "Rate limit exceeded",
                "message": f"Too many requests. Limit is {limit_config['requests']} per {limit_config['window']} seconds",
                "retry_after": int(request_history[key][0] + limit_config["window"] - current_time)
            }), 429
        
        # Add current request
        request_history[key].append(current_time)
        
        # Call the original function
        return func(*args, **kwargs)
    
    return wrapper
    
    # In production, this would write to a secure audit log
    print(f"🔐 AUDIT: {log_entry}")
    
    return log_entry

def generate_secure_token(length=32):
    """Generate a cryptographically secure token"""
    return secrets.token_urlsafe(length)

def validate_jwt_token(token):
    """Validate JWT token"""
    try:
        payload = jwt.decode(token, os.getenv('JWT_SECRET', 'secret'), algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

class ThreatPrevention:
    def __init__(self):
        self.blocked_ips = set()
        self.suspicious_activities = {}
    
    def check_ip_block(self, ip_address):
        """Check if IP is blocked"""
        return ip_address in self.blocked_ips
    
    def block_ip(self, ip_address, reason="Suspicious activity", duration_hours=24):
        """Block an IP address"""
        self.blocked_ips.add(ip_address)
        
        # Schedule unblocking
        import threading
        def unblock_ip():
            time.sleep(duration_hours * 3600)
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                print(f"🔓 Unblocked IP: {ip_address}")
        
        threading.Thread(target=unblock_ip).start()
        
        audit_log("IP_BLOCKED", "system", {
            'ip_address': ip_address,
            'reason': reason,
            'duration_hours': duration_hours
        })
        
        print(f"🔒 Blocked IP: {ip_address} - {reason}")
    
    def track_suspicious_activity(self, ip_address, activity_type, score):
        """Track suspicious activity for an IP"""
        if ip_address not in self.suspicious_activities:
            self.suspicious_activities[ip_address] = []
        
        self.suspicious_activities[ip_address].append({
            'timestamp': datetime.now().isoformat(),
            'activity_type': activity_type,
            'score': score
        })
        
        # Keep only recent activities
        self.suspicious_activities[ip_address] = self.suspicious_activities[ip_address][-50:]
        
        # Check if IP should be blocked
        recent_score = sum(act['score'] for act in self.suspicious_activities[ip_address][-10:])
        if recent_score > 5.0:  # Threshold for blocking
            self.block_ip(ip_address, "High suspicious activity score")
    
    def get_ip_risk_score(self, ip_address):
        """Calculate risk score for an IP"""
        if ip_address not in self.suspicious_activities:
            return 0
        
        recent_activities = self.suspicious_activities[ip_address][-20:]
        return sum(act['score'] for act in recent_activities)

# Global instances
security_manager = SecurityManager()
data_encryptor = DataEncryptor()
input_validator = InputValidator()
threat_prevention = ThreatPrevention()