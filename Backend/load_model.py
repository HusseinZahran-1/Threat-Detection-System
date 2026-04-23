import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import os
from preprocess import create_feature_dataframe

# Threat type mapping
THREAT_TYPES = {
    0: 'SQL Injection Attempt',
    1: 'DDoS Attack Pattern',
    2: 'Malware Communication',
    3: 'Port Scanning',
    4: 'Brute Force Attack',
    5: 'Cross-Site Scripting (XSS)',
    6: 'Unauthorized Access Attempt',
    7: 'Data Exfiltration'
}

def load_model():
    """Load the trained model from disk"""
    model_path = 'Ai_Model/model.pkl'
    
    try:
        if os.path.exists(model_path):
            model = joblib.load(model_path)
            print(f"✓ Model loaded successfully from {model_path}")
            return model
        else:
            print(f"✗ Model file not found at {model_path}")
            print("ℹ Using fallback rule-based detection")
            return None
    except Exception as e:
        print(f"✗ Error loading model: {str(e)}")
        print("ℹ Using fallback rule-based detection")
        return None

def predict_threats(data_list):
    """
    Make predictions on preprocessed data
    
    Args:
        data_list: List of preprocessed feature dictionaries
    
    Returns:
        List of prediction results
    """
    model = load_model()
    
    if model is not None:
        return predict_with_model(model, data_list)
    else:
        return predict_with_rules(data_list)

def predict_with_model(model, data_list):
    """Make predictions using the trained ML model"""
    results = []
    
    try:
        # Convert data to DataFrame
        df = create_feature_dataframe(data_list)
        
        print(f"✓ Model expecting {model.n_features_in_} features")
        print(f"✓ Data providing {df.shape[1]} features")
        
        # Make predictions
        predictions = model.predict(df)
        probabilities = model.predict_proba(df)
        
        for idx, (prediction, proba, features) in enumerate(zip(predictions, probabilities, data_list)):
            result = {
                'prediction': int(prediction),
                'confidence': float(max(proba)),
                'timestamp': features.get('timestamp', datetime.now().isoformat()),
                'source_ip': features.get('source_ip', 'Unknown'),
                'raw_data': features.get('raw_data', ''),
                'model_used': True
            }
            
            if prediction == 1:  # Threat detected
                result['threat_type'] = determine_threat_type(features)
                result['threat_indicators'] = get_threat_indicators(features)
            else:
                result['threat_type'] = 'No Threat'
                result['threat_indicators'] = []
            
            results.append(result)
        
        print(f"✓ Successfully processed {len(results)} predictions using ML model")
        return results
    
    except Exception as e:
        print(f"✗ Error in model prediction: {str(e)}")
        print("ℹ Falling back to rule-based detection")
        return predict_with_rules(data_list)

def predict_with_rules(data_list):
    """Fallback rule-based threat detection"""
    results = []
    
    for features in data_list:
        threat_score = 0
        threat_indicators = []
        
        # Rule 1: Suspicious keywords
        suspicious_count = features.get('suspicious_keywords', 0)
        if suspicious_count > 0:
            threat_score += suspicious_count * 0.15
            threat_indicators.append(f"Suspicious keywords: {suspicious_count}")
        
        # Rule 2: Unusual port numbers
        port = features.get('port', 0)
        if port in [1433, 3306, 5432, 27017, 6379]:  # Database ports
            threat_score += 0.2
            threat_indicators.append(f"Database port access: {port}")
        elif port > 10000:  # High port numbers
            threat_score += 0.1
            threat_indicators.append(f"High port number: {port}")
        
        # Rule 3: Large payload size
        payload_size = features.get('payload_size', 0)
        if payload_size > 5000:
            threat_score += 0.15
            threat_indicators.append(f"Large payload: {payload_size} bytes")
        
        # Rule 4: TCP flag anomalies
        flags = features.get('flags', '')
        if 'SYN' in flags and 'FIN' in flags:  # SYN-FIN attack
            threat_score += 0.3
            threat_indicators.append("Anomalous TCP flags: SYN-FIN")
        elif 'RST' in flags and 'PSH' in flags:
            threat_score += 0.2
            threat_indicators.append("Anomalous TCP flags: RST-PSH")
        
        # Rule 5: Protocol-based rules
        protocol = features.get('protocol', '')
        if protocol == 'Unknown':
            threat_score += 0.1
            threat_indicators.append("Unknown protocol")
        
        # Rule 6: Check for SQL injection patterns
        raw_data = features.get('raw_data', '').lower()
        sql_keywords = ['union', 'select', 'drop', 'insert', 'delete', '--', 'or 1=1']
        sql_matches = sum(1 for keyword in sql_keywords if keyword in raw_data)
        if sql_matches >= 2:
            threat_score += 0.4
            threat_indicators.append("SQL injection pattern detected")
        
        # Rule 7: Check for XSS patterns
        xss_keywords = ['<script>', 'javascript:', 'onerror=', 'alert(']
        xss_matches = sum(1 for keyword in xss_keywords if keyword in raw_data)
        if xss_matches > 0:
            threat_score += 0.35
            threat_indicators.append("XSS pattern detected")
        
        # Rule 8: High request frequency (DDoS)
        request_frequency = features.get('request_frequency', 0)
        if request_frequency > 100:
            threat_score += 0.5
            threat_indicators.append(f"High request frequency: {request_frequency}/s")
        
        # Rule 9: Port scanning
        unique_ports = features.get('unique_ports_scanned', 0)
        if unique_ports > 10:
            threat_score += 0.4
            threat_indicators.append(f"Multiple ports scanned: {unique_ports}")
        
        # Normalize threat score to confidence (0-1)
        confidence = min(threat_score, 1.0)
        is_threat = confidence > 0.5
        
        result = {
            'prediction': 1 if is_threat else 0,
            'confidence': confidence,
            'timestamp': features.get('timestamp', datetime.now().isoformat()),
            'source_ip': features.get('source_ip', 'Unknown'),
            'raw_data': features.get('raw_data', ''),
            'threat_indicators': threat_indicators,
            'model_used': False
        }
        
        if is_threat:
            result['threat_type'] = determine_threat_type(features)
        else:
            result['threat_type'] = 'No Threat'
        
        results.append(result)
    
    return results

def determine_threat_type(features):
    """Determine the specific type of threat based on features"""
    raw_data = features.get('raw_data', '').lower()
    port = features.get('port', 0)
    payload_size = features.get('payload_size', 0)
    request_frequency = features.get('request_frequency', 0)
    unique_ports = features.get('unique_ports_scanned', 0)
    auth_attempts = features.get('auth_attempts', 0)
    
    # SQL Injection detection
    sql_keywords = ['union', 'select', 'drop', 'insert', 'delete', '--', 'or 1=1', 'exec(', 'xp_']
    sql_matches = sum(1 for keyword in sql_keywords if keyword in raw_data)
    if sql_matches >= 2:
        return THREAT_TYPES[0]
    
    # XSS detection
    xss_keywords = ['<script>', 'javascript:', 'onerror=', 'alert(', 'document.cookie', 'eval(']
    xss_matches = sum(1 for keyword in xss_keywords if keyword in raw_data)
    if xss_matches > 0:
        return THREAT_TYPES[5]
    
    # DDoS detection
    if request_frequency > 100:
        return THREAT_TYPES[1]
    
    # Port scanning detection
    if unique_ports > 10:
        return THREAT_TYPES[3]
    
    # Brute force detection
    if auth_attempts > 5:
        return THREAT_TYPES[4]
    
    # Malware communication patterns
    suspicious_domains = ['c2.', 'command.', 'malware.', 'botnet.']
    if any(domain in raw_data for domain in suspicious_domains):
        return THREAT_TYPES[2]
    
    # Data exfiltration
    if payload_size > 10000 and 'OUTBOUND' in str(features.get('traffic_direction', '')):
        return THREAT_TYPES[7]
    
    # Unauthorized access attempts
    if port in [22, 23, 3389, 5900] and auth_attempts > 0:
        return THREAT_TYPES[6]
    
    return THREAT_TYPES[6]  # Default to Unauthorized Access Attempt

def get_threat_indicators(features):
    """Get threat indicators for a given feature set"""
    indicators = []
    
    raw_data = features.get('raw_data', '').lower()
    
    # Check SQL patterns
    sql_keywords = ['union', 'select', 'drop', 'insert', 'delete', '--', 'or 1=1']
    sql_matches = sum(1 for keyword in sql_keywords if keyword in raw_data)
    if sql_matches > 0:
        indicators.append(f"SQL patterns: {sql_matches}")
    
    # Check XSS patterns
    xss_keywords = ['<script>', 'javascript:', 'onerror=', 'alert(']
    xss_matches = sum(1 for keyword in xss_keywords if keyword in raw_data)
    if xss_matches > 0:
        indicators.append(f"XSS patterns: {xss_matches}")
    
    # Check for high frequency
    if features.get('request_frequency', 0) > 100:
        indicators.append("High request frequency")
    
    # Check for port scanning
    if features.get('unique_ports_scanned', 0) > 10:
        indicators.append("Multiple ports scanned")
    
    return indicators