import pandas as pd
import numpy as np
from datetime import datetime
import re

class DataPreprocessor:
    def __init__(self):
        self.suspicious_keywords = [
            'union', 'select', 'drop', 'insert', 'delete', 'update', 'exec', 
            'xp_', '--', 'or 1=1', 'script', 'javascript', 'onerror', 'alert',
            'eval', 'document.cookie', 'base64_decode', 'cmd.exe', '/bin/bash'
        ]
        
        self.sql_patterns = ['union', 'select', 'drop', 'insert', 'delete', '--', 'or 1=1']
        self.xss_patterns = ['<script>', 'javascript:', 'onerror=', 'alert(', 'document.cookie']
    
    def extract_features(self, log_data):
        """Extract features from log data for ML model"""
        features = {}
        
        # Basic network features
        features['source_ip'] = log_data.get('source_ip', 'Unknown')
        features['port'] = int(log_data.get('port', 0))
        features['protocol'] = log_data.get('protocol', 'Unknown')
        features['payload_size'] = int(log_data.get('payload_size', 0))
        features['timestamp'] = log_data.get('timestamp', datetime.now().isoformat())
        features['raw_data'] = log_data.get('raw_data', '')
        
        # Security-specific features
        features['suspicious_keywords'] = self.count_suspicious_keywords(features['raw_data'])
        features['request_frequency'] = int(log_data.get('request_frequency', 0))
        features['unique_ports_scanned'] = int(log_data.get('unique_ports_scanned', 0))
        features['auth_attempts'] = int(log_data.get('auth_attempts', 0))
        features['flag_anomalies'] = self.detect_flag_anomalies(log_data.get('flags', ''))
        features['protocol_encoded'] = self.encode_protocol(features['protocol'])
        features['sql_patterns'] = self.count_sql_patterns(features['raw_data'])
        features['xss_patterns'] = self.count_xss_patterns(features['raw_data'])
        
        return features
    
    def count_suspicious_keywords(self, text):
        """Count suspicious keywords in text"""
        if not text:
            return 0
        text_lower = text.lower()
        return sum(1 for keyword in self.suspicious_keywords if keyword in text_lower)
    
    def count_sql_patterns(self, text):
        """Count SQL injection patterns"""
        if not text:
            return 0
        text_lower = text.lower()
        return sum(1 for pattern in self.sql_patterns if pattern in text_lower)
    
    def count_xss_patterns(self, text):
        """Count XSS patterns"""
        if not text:
            return 0
        text_lower = text.lower()
        return sum(1 for pattern in self.xss_patterns if pattern in text_lower)
    
    def detect_flag_anomalies(self, flags):
        """Detect anomalous TCP flags"""
        if not flags:
            return 0
        
        flag_combinations = [
            ('SYN', 'FIN'),  # SYN-FIN attack
            ('RST', 'PSH'),  # RST-PSH anomaly
            ('URG', 'ACK')   # URG-ACK anomaly
        ]
        
        anomalies = 0
        for combo in flag_combinations:
            if all(flag in flags for flag in combo):
                anomalies += 1
        
        return anomalies
    
    def encode_protocol(self, protocol):
        """Encode protocol as numerical value"""
        protocol_mapping = {
            'HTTP': 1,
            'HTTPS': 2,
            'FTP': 3,
            'SSH': 4,
            'DNS': 5,
            'Unknown': 0
        }
        return protocol_mapping.get(protocol, 0)
    
    def create_feature_dataframe(self, data_list):
        """Create feature dataframe for ML model prediction"""
        features_list = []
        
        for data in data_list:
            features = self.extract_features(data)
            
            # Create feature vector for ML model (8 features as required)
            feature_vector = [
                float(features.get('suspicious_keywords', 0)),
                float(features.get('port', 0)),
                float(features.get('payload_size', 0)),
                float(features.get('request_frequency', 0)),
                float(features.get('unique_ports_scanned', 0)),
                float(features.get('auth_attempts', 0)),
                float(features.get('protocol_encoded', 0)),
                float(features.get('flag_anomalies', 0))
            ]
            
            features_list.append(feature_vector)
        
        # Create column names
        column_names = [
            'suspicious_keywords', 'port', 'payload_size', 'request_frequency',
            'unique_ports_scanned', 'auth_attempts', 'protocol_encoded', 'flag_anomalies'
        ]
        
        return pd.DataFrame(features_list, columns=column_names)

def create_feature_dataframe(data_list):
    """Wrapper function for compatibility"""
    preprocessor = DataPreprocessor()
    return preprocessor.create_feature_dataframe(data_list)