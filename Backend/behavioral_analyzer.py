import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
import hashlib

class BehavioralAnalyzer:
    def __init__(self):
        self.user_profiles = {}
        self.group_profiles = {}
        self.anomaly_threshold = 0.8
        self.learning_period = timedelta(days=7)
        self.max_history = 1000
        
        # Behavioral patterns
        self.normal_patterns = self.load_normal_patterns()
        self.suspicious_sequences = self.load_suspicious_sequences()
    
    def analyze_user_behavior(self, user_id, current_activity):
        """Analyze user behavior for anomalies"""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = self.create_user_profile(user_id)
        
        profile = self.user_profiles[user_id]
        
        # Extract behavioral features
        features = self.extract_behavioral_features(current_activity)
        
        # Update profile with new activity
        self.update_user_profile(profile, features)
        
        # Calculate anomaly score
        anomaly_score = self.calculate_anomaly_score(profile, features)
        
        # Check for suspicious sequences
        sequence_score = self.check_suspicious_sequences(profile, current_activity)
        
        # Combined behavioral risk score
        behavioral_score = max(anomaly_score, sequence_score)
        
        return behavioral_score
    
    def create_user_profile(self, user_id):
        """Create a new user behavior profile"""
        return {
            'user_id': user_id,
            'created_at': datetime.now(),
            'activity_count': 0,
            'recent_activities': deque(maxlen=100),
            'behavior_baseline': {
                'working_hours': set(range(9, 18)),  # 9 AM - 6 PM
                'common_ports': set(),
                'typical_payload_sizes': [],
                'access_patterns': defaultdict(int),
                'request_frequency': 0
            },
            'anomaly_scores': [],
            'risk_level': 'Low'
        }
    
    def extract_behavioral_features(self, activity):
        """Extract behavioral features from activity"""
        timestamp = datetime.fromisoformat(activity.get('timestamp', datetime.now().isoformat()))
        
        return {
            'hour_of_day': timestamp.hour,
            'day_of_week': timestamp.weekday(),
            'port': activity.get('port', 0),
            'protocol': activity.get('protocol', 'Unknown'),
            'payload_size': activity.get('payload_size', 0),
            'source_ip': activity.get('source_ip', 'Unknown'),
            'request_type': self.classify_request_type(activity),
            'geolocation': self.estimate_geolocation(activity.get('source_ip', '')),
            'user_agent_pattern': self.analyze_user_agent(activity.get('raw_data', ''))
        }
    
    def update_user_profile(self, profile, features):
        """Update user profile with new activity"""
        profile['activity_count'] += 1
        profile['recent_activities'].append({
            'timestamp': datetime.now(),
            'features': features
        })
        
        # Update baseline statistics
        baseline = profile['behavior_baseline']
        
        # Update common ports
        if features['port'] > 0:
            baseline['common_ports'].add(features['port'])
            # Keep only recent ports (last 50)
            if len(baseline['common_ports']) > 50:
                baseline['common_ports'] = set(list(baseline['common_ports'])[-50:])
        
        # Update payload size statistics
        baseline['typical_payload_sizes'].append(features['payload_size'])
        if len(baseline['typical_payload_sizes']) > 100:
            baseline['typical_payload_sizes'] = baseline['typical_payload_sizes'][-100:]
        
        # Update access patterns
        baseline['access_patterns'][features['request_type']] += 1
        
        # Update request frequency (requests per hour)
        if len(profile['recent_activities']) >= 2:
            recent_times = [act['timestamp'] for act in list(profile['recent_activities'])[-10:]]
            if len(recent_times) >= 2:
                time_diff = (recent_times[-1] - recent_times[0]).total_seconds() / 3600
                baseline['request_frequency'] = len(recent_times) / max(time_diff, 0.1)
    
    def calculate_anomaly_score(self, profile, features):
        """Calculate behavioral anomaly score"""
        baseline = profile['behavior_baseline']
        anomaly_factors = []
        
        # Time-based anomalies
        if features['hour_of_day'] not in baseline['working_hours']:
            anomaly_factors.append(0.3)  # After-hours activity
        
        # Port usage anomalies
        if features['port'] > 0 and features['port'] not in baseline['common_ports']:
            anomaly_factors.append(0.4)  # Unusual port
        
        # Payload size anomalies
        if baseline['typical_payload_sizes']:
            avg_payload = np.mean(baseline['typical_payload_sizes'])
            std_payload = np.std(baseline['typical_payload_sizes'])
            if std_payload > 0:
                payload_zscore = abs(features['payload_size'] - avg_payload) / std_payload
                if payload_zscore > 3:  # 3 standard deviations
                    anomaly_factors.append(min(payload_zscore * 0.1, 0.5))
        
        # Request frequency anomalies
        current_freq = baseline['request_frequency']
        if current_freq > 100:  # Very high frequency
            anomaly_factors.append(0.6)
        elif current_freq > 50:  # High frequency
            anomaly_factors.append(0.3)
        
        # Protocol anomalies
        if features['protocol'] == 'Unknown':
            anomaly_factors.append(0.2)
        
        # Calculate overall anomaly score
        if anomaly_factors:
            anomaly_score = sum(anomaly_factors) / len(anomaly_factors)
        else:
            anomaly_score = 0
        
        # Update anomaly history
        profile['anomaly_scores'].append(anomaly_score)
        if len(profile['anomaly_scores']) > 100:
            profile['anomaly_scores'] = profile['anomaly_scores'][-100:]
        
        # Update risk level
        profile['risk_level'] = self.calculate_risk_level(profile)
        
        return min(anomaly_score, 1.0)
    
    def check_suspicious_sequences(self, profile, activity):
        """Check for suspicious activity sequences"""
        sequence_score = 0
        
        # Check for port scanning patterns
        recent_ports = [
            act['features']['port'] 
            for act in list(profile['recent_activities'])[-20:] 
            if act['features']['port'] > 0
        ]
        
        unique_ports = len(set(recent_ports))
        if unique_ports > 10 and len(recent_ports) > 15:
            sequence_score = max(sequence_score, 0.7)  # Port scanning
        
        # Check for brute force patterns
        recent_auth_attempts = [
            act for act in list(profile['recent_activities'])[-30:]
            if self.is_authentication_attempt(act['features'])
        ]
        
        if len(recent_auth_attempts) > 10:
            sequence_score = max(sequence_score, 0.8)  # Brute force
        
        # Check for data exfiltration patterns
        large_transfers = [
            act for act in list(profile['recent_activities'])[-50:]
            if act['features']['payload_size'] > 10000
        ]
        
        if len(large_transfers) > 5:
            sequence_score = max(sequence_score, 0.6)  # Data exfiltration
        
        return sequence_score
    
    def classify_request_type(self, activity):
        """Classify the type of request"""
        raw_data = activity.get('raw_data', '').lower()
        
        if any(keyword in raw_data for keyword in ['login', 'auth', 'password']):
            return 'authentication'
        elif any(keyword in raw_data for keyword in ['select', 'insert', 'update', 'delete']):
            return 'database'
        elif any(keyword in raw_data for keyword in ['get', 'post', 'put', 'delete']):
            return 'api'
        elif any(keyword in raw_data for keyword in ['upload', 'download', 'file']):
            return 'file_transfer'
        else:
            return 'other'
    
    def is_authentication_attempt(self, features):
        """Check if activity is an authentication attempt"""
        return features['request_type'] == 'authentication'
    
    def estimate_geolocation(self, ip_address):
        """Simple geolocation estimation (in real implementation, use GeoIP database)"""
        if ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return 'internal'
        elif ip_address == 'Unknown':
            return 'unknown'
        else:
            return 'external'
    
    def analyze_user_agent(self, raw_data):
        """Analyze user agent patterns"""
        # Simple user agent detection
        if 'curl' in raw_data.lower():
            return 'script'
        elif 'python' in raw_data.lower():
            return 'script'
        elif 'mozilla' in raw_data.lower():
            return 'browser'
        else:
            return 'unknown'
    
    def calculate_risk_level(self, profile):
        """Calculate overall user risk level"""
        if not profile['anomaly_scores']:
            return 'Low'
        
        avg_anomaly = np.mean(profile['anomaly_scores'][-20:])
        
        if avg_anomaly > 0.7:
            return 'Critical'
        elif avg_anomaly > 0.5:
            return 'High'
        elif avg_anomaly > 0.3:
            return 'Medium'
        else:
            return 'Low'
    
    def load_normal_patterns(self):
        """Load normal behavioral patterns"""
        return {
            'working_hours': set(range(6, 22)),  # 6 AM - 10 PM
            'common_services': {80, 443, 22, 21, 25},
            'typical_payload_ranges': {
                'web': (500, 5000),
                'api': (100, 2000),
                'database': (50, 1000)
            }
        }
    
    def load_suspicious_sequences(self):
        """Load known suspicious activity sequences"""
        return {
            'port_scanning': {
                'description': 'Rapid connection to multiple ports',
                'threshold': 10,  # Unique ports in short time
                'score': 0.8
            },
            'brute_force': {
                'description': 'Multiple authentication attempts',
                'threshold': 5,  # Failed auth attempts
                'score': 0.9
            },
            'data_exfiltration': {
                'description': 'Large outbound data transfers',
                'threshold': 3,  # Large transfers in short time
                'score': 0.7
            }
        }
    
    def get_user_risk_assessment(self, user_id):
        """Get comprehensive risk assessment for a user"""
        if user_id not in self.user_profiles:
            return {'error': 'User profile not found'}
        
        profile = self.user_profiles[user_id]
        
        return {
            'user_id': user_id,
            'risk_level': profile['risk_level'],
            'activity_count': profile['activity_count'],
            'recent_anomaly_score': np.mean(profile['anomaly_scores'][-10:]) if profile['anomaly_scores'] else 0,
            'behavior_baseline': {
                'common_ports_count': len(profile['behavior_baseline']['common_ports']),
                'avg_payload_size': np.mean(profile['behavior_baseline']['typical_payload_sizes']) if profile['behavior_baseline']['typical_payload_sizes'] else 0,
                'request_frequency': profile['behavior_baseline']['request_frequency']
            },
            'profile_age_days': (datetime.now() - profile['created_at']).days
        }
    
    def cleanup_old_profiles(self, max_age_days=30):
        """Clean up old user profiles"""
        current_time = datetime.now()
        users_to_remove = []
        
        for user_id, profile in self.user_profiles.items():
            profile_age = current_time - profile['created_at']
            if profile_age.days > max_age_days:
                users_to_remove.append(user_id)
        
        for user_id in users_to_remove:
            del self.user_profiles[user_id]
        
        print(f"🧹 Cleaned up {len(users_to_remove)} old user profiles")