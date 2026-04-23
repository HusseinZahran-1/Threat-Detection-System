# enhanced_detector.py
import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import logging
from datetime import datetime

class EnhancedThreatDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_path = 'Ai_Model/model.pkl'
        self.backup_model_path = 'Ai_Model/backup_model.pkl'
        
        # Create model directory if it doesn't exist
        os.makedirs('Ai_Model', exist_ok=True)
        
        self.load_or_create_model()
    
    def load_or_create_model(self):
        """Load existing model or create a new one"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print("✅ AI model loaded successfully")
                self.is_trained = True
            else:
                self.create_fallback_model()
                print("✅ Fallback model created successfully")
                
        except Exception as e:
            print(f"❌ Model loading error: {e}")
            self.create_fallback_model()
            print("✅ Fallback models created")
    
    def create_fallback_model(self):
        """Create a basic fallback model"""
        try:
            # Create a simple Random Forest classifier
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            
            # Train with some basic synthetic data
            X_train = np.random.rand(100, 10)  # 100 samples, 10 features
            y_train = np.random.randint(0, 2, 100)  # Binary classification
            
            self.scaler.fit(X_train)
            X_train_scaled = self.scaler.transform(X_train)
            self.model.fit(X_train_scaled, y_train)
            self.is_trained = True
            
            # Save the model
            with open(self.backup_model_path, 'wb') as f:
                pickle.dump(self.model, f)
                
        except Exception as e:
            print(f"❌ Fallback model creation failed: {e}")
            self.is_trained = False
    
    def comprehensive_analysis(self, processed_data, mode='standard'):
        """Perform comprehensive threat analysis"""
        if not self.is_trained:
            return self._generate_fallback_results(processed_data)
        
        try:
            results = []
            for data in processed_data:
                # Extract features for prediction
                features = self._extract_features(data)
                
                if features is not None:
                    # Scale features
                    features_scaled = self.scaler.transform([features])
                    
                    # Predict
                    prediction = self.model.predict(features_scaled)[0]
                    confidence = self.model.predict_proba(features_scaled)[0][1]
                    
                    result = {
                        'prediction': int(prediction),
                        'confidence': float(confidence),
                        'threat_level': self._get_threat_level(confidence),
                        'features_used': len(features),
                        'analysis_mode': mode,
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    result = self._generate_fallback_single_result(data)
                
                results.append(result)
            
            return results
            
        except Exception as e:
            print(f"❌ Analysis error: {e}")
            return self._generate_fallback_results(processed_data)
    
    def _extract_features(self, data):
        """Extract features from log data"""
        try:
            features = []
            
            # Extract basic numerical features
            if isinstance(data, dict):
                # String length features
                for key in ['message', 'log_entry', 'data']:
                    if key in data:
                        features.append(len(str(data[key])))
                
                # Numeric features
                for key in ['severity', 'length', 'size']:
                    if key in data:
                        features.append(float(data[key]))
                
                # IP-based features (simplified)
                for key in ['source_ip', 'dest_ip']:
                    if key in data and data[key]:
                        ip_str = str(data[key])
                        features.append(sum(ord(c) for c in ip_str) / 1000)
            
            # Ensure we have at least 10 features
            while len(features) < 10:
                features.append(0.0)
            
            return features[:10]  # Return first 10 features
            
        except Exception as e:
            print(f"❌ Feature extraction error: {e}")
            return [0.0] * 10
    
    def _get_threat_level(self, confidence):
        """Convert confidence score to threat level"""
        if confidence > 0.8:
            return "HIGH"
        elif confidence > 0.6:
            return "MEDIUM"
        elif confidence > 0.4:
            return "LOW"
        else:
            return "INFO"
    
    def _generate_fallback_results(self, processed_data):
        """Generate fallback results when model fails"""
        return [self._generate_fallback_single_result(data) for data in processed_data]
    
    def _generate_fallback_single_result(self, data):
        """Generate a single fallback result"""
        return {
            'prediction': 0,  # Assume no threat
            'confidence': 0.3,
            'threat_level': "LOW",
            'features_used': 0,
            'analysis_mode': 'fallback',
            'timestamp': datetime.now().isoformat(),
            'fallback_reason': 'Model not available'
        }
    
    def extract_threat_patterns(self, analysis_results):
        """Extract threat patterns from analysis results"""
        patterns = []
        
        for result in analysis_results:
            if result.get('prediction', 0) == 1:  # If threat detected
                pattern = {
                    'confidence': result.get('confidence', 0),
                    'threat_level': result.get('threat_level', 'LOW'),
                    'timestamp': result.get('timestamp'),
                    'features_count': result.get('features_used', 0)
                }
                patterns.append(pattern)
        
        return patterns
    
    def retrain_model(self, new_data, labels):
        """Retrain model with new data"""
        try:
            if len(new_data) > 0:
                X = np.array([self._extract_features(data) for data in new_data])
                y = np.array(labels)
                
                if len(X) > 0 and len(y) > 0:
                    X_scaled = self.scaler.fit_transform(X)
                    self.model.fit(X_scaled, y)
                    self.is_trained = True
                    
                    # Save the updated model
                    with open(self.model_path, 'wb') as f:
                        pickle.dump(self.model, f)
                    
                    print("✅ Model retrained and saved successfully")
                    return True
                    
        except Exception as e:
            print(f"❌ Model retraining failed: {e}")
        
        return False