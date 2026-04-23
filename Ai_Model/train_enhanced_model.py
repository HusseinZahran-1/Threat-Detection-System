import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import xgboost as xgb
from sklearn.datasets import make_classification
import joblib
import os
from datetime import datetime

class ModelTrainer:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_names = [
            'suspicious_keywords', 'port', 'payload_size', 'request_frequency',
            'unique_ports_scanned', 'auth_attempts', 'protocol_encoded', 'flag_anomalies',
            'sql_patterns', 'xss_patterns', 'ddos_score', 'scan_score', 
            'malware_score', 'data_exfil_score', 'behavioral_score'
        ]
        
    def generate_training_data(self, n_samples=10000):
        """Generate realistic training data for threat detection"""
        print("📊 Generating training data...")
        
        # Create synthetic dataset with realistic threat patterns
        X, y = make_classification(
            n_samples=n_samples,
            n_features=15,
            n_informative=12,
            n_redundant=3,
            n_clusters_per_class=2,
            flip_y=0.02,
            random_state=42
        )
        
        # Transform features to realistic ranges for network security
        X = self._transform_features(X)
        
        # Add realistic threat patterns
        X, y = self._add_threat_patterns(X, y)
        
        return X, y
    
    def _transform_features(self, X):
        """Transform features to realistic network security ranges"""
        # Feature 0: suspicious_keywords (0-10)
        X[:, 0] = np.abs(X[:, 0] * 10)
        
        # Feature 1: port (1-65535, but mostly common ports)
        X[:, 1] = self._generate_ports(X[:, 1])
        
        # Feature 2: payload_size (50-50000 bytes)
        X[:, 2] = np.abs(X[:, 2] * 50000) + 50
        
        # Feature 3: request_frequency (0-500 requests/sec)
        X[:, 3] = np.abs(X[:, 3] * 500)
        
        # Feature 4: unique_ports_scanned (0-100)
        X[:, 4] = np.abs(X[:, 4] * 100)
        
        # Feature 5: auth_attempts (0-20)
        X[:, 5] = np.abs(X[:, 5] * 20)
        
        # Feature 6: protocol_encoded (0-5)
        X[:, 6] = np.abs(X[:, 6] * 5)
        
        # Feature 7: flag_anomalies (0-3)
        X[:, 7] = np.abs(X[:, 7] * 3)
        
        # Feature 8: sql_patterns (0-5)
        X[:, 8] = np.abs(X[:, 8] * 5)
        
        # Feature 9: xss_patterns (0-5)
        X[:, 9] = np.abs(X[:, 9] * 5)
        
        # Feature 10: ddos_score (0-1)
        X[:, 10] = np.abs(X[:, 10])
        
        # Feature 11: scan_score (0-1)
        X[:, 11] = np.abs(X[:, 11])
        
        # Feature 12: malware_score (0-1)
        X[:, 12] = np.abs(X[:, 12])
        
        # Feature 13: data_exfil_score (0-1)
        X[:, 13] = np.abs(X[:, 13])
        
        # Feature 14: behavioral_score (0-1)
        X[:, 14] = np.abs(X[:, 14])
        
        return X
    
    def _generate_ports(self, feature_values):
        """Generate realistic port numbers"""
        ports = []
        common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 587, 3306, 5432, 27017]
        
        for val in feature_values:
            if abs(val) < 0.3:  # 30% chance for common ports
                port = np.random.choice(common_ports)
            elif abs(val) < 0.6:  # 30% chance for registered ports
                port = np.random.randint(1024, 49152)
            else:  # 40% chance for dynamic ports
                port = np.random.randint(49152, 65536)
            ports.append(port)
        
        return np.array(ports)
    
    def _add_threat_patterns(self, X, y):
        """Add realistic threat patterns to the dataset"""
        n_samples = len(X)
        
        # SQL Injection patterns
        sql_indices = np.random.choice(np.where(y == 1)[0], size=int(n_samples * 0.15), replace=False)
        X[sql_indices, 8] += np.random.uniform(2, 5, len(sql_indices))  # High SQL patterns
        X[sql_indices, 0] += np.random.uniform(3, 6, len(sql_indices))  # Suspicious keywords
        
        # DDoS patterns
        ddos_indices = np.random.choice(np.where(y == 1)[0], size=int(n_samples * 0.10), replace=False)
        X[ddos_indices, 3] += np.random.uniform(200, 400, len(ddos_indices))  # High frequency
        X[ddos_indices, 10] += np.random.uniform(0.6, 0.9, len(ddos_indices))  # High DDoS score
        
        # Port Scanning patterns
        scan_indices = np.random.choice(np.where(y == 1)[0], size=int(n_samples * 0.12), replace=False)
        X[scan_indices, 4] += np.random.uniform(20, 80, len(scan_indices))  # Many ports scanned
        X[scan_indices, 11] += np.random.uniform(0.5, 0.8, len(scan_indices))  # High scan score
        
        # Brute Force patterns
        brute_indices = np.random.choice(np.where(y == 1)[0], size=int(n_samples * 0.08), replace=False)
        X[brute_indices, 5] += np.random.uniform(8, 15, len(brute_indices))  # Many auth attempts
        
        # XSS patterns
        xss_indices = np.random.choice(np.where(y == 1)[0], size=int(n_samples * 0.10), replace=False)
        X[xss_indices, 9] += np.random.uniform(2, 4, len(xss_indices))  # XSS patterns
        X[xss_indices, 0] += np.random.uniform(2, 4, len(xss_indices))  # Suspicious keywords
        
        # Ensure values are within bounds
        X = np.clip(X, 0, None)
        
        return X, y
    
    def train_models(self, X, y):
        """Train multiple machine learning models"""
        print("🤖 Training machine learning models...")
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        self.scalers['standard'] = scaler
        
        # Train Random Forest
        print("🌲 Training Random Forest...")
        rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
        rf_model.fit(X_train_scaled, y_train)
        self.models['random_forest'] = rf_model
        
        # Train XGBoost
        print("🚀 Training XGBoost...")
        xgb_model = xgb.XGBClassifier(
            n_estimators=150,
            max_depth=10,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            eval_metric='logloss',
            n_jobs=-1
        )
        xgb_model.fit(X_train_scaled, y_train)
        self.models['xgboost'] = xgb_model
        
        # Create Ensemble Model
        print("🤝 Creating Ensemble Model...")
        ensemble_model = VotingClassifier(
            estimators=[
                ('rf', rf_model),
                ('xgb', xgb_model)
            ],
            voting='soft',
            n_jobs=-1
        )
        ensemble_model.fit(X_train_scaled, y_train)
        self.models['ensemble'] = ensemble_model
        
        # Evaluate models
        self.evaluate_models(X_test_scaled, y_test)
        
        return X_test_scaled, y_test
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate all trained models"""
        print("\n📈 Model Evaluation Results:")
        print("=" * 50)
        
        for name, model in self.models.items():
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            print(f"\n{name.upper():<15} Accuracy: {accuracy:.4f}")
            
            # Cross-validation scores
            if name != 'ensemble':  # Ensemble is expensive for CV
                cv_scores = cross_val_score(model, X_test, y_test, cv=5, scoring='accuracy')
                print(f"{'CV Accuracy':<15} Mean: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
            
            # Detailed classification report for the best model
            if accuracy > 0.85:
                print("\nDetailed Classification Report:")
                print(classification_report(y_test, y_pred, target_names=['Normal', 'Threat']))
    
    def save_models(self, directory='Ai_Model'):
        """Save trained models and scalers"""
        print("\n💾 Saving models...")
        
        # Create directory if it doesn't exist
        os.makedirs(directory, exist_ok=True)
        
        # Save models
        for name, model in self.models.items():
            filename = os.path.join(directory, f'{name}_model.pkl')
            joblib.dump(model, filename)
            print(f"✅ Saved {name} model: {filename}")
        
        # Save scalers
        for name, scaler in self.scalers.items():
            filename = os.path.join(directory, f'{name}_scaler.pkl')
            joblib.dump(scaler, filename)
            print(f"✅ Saved {name} scaler: {filename}")
        
        # Save feature names
        feature_info = {
            'feature_names': self.feature_names,
            'training_date': datetime.now().isoformat(),
            'num_features': len(self.feature_names)
        }
        
        feature_filename = os.path.join(directory, 'feature_info.pkl')
        joblib.dump(feature_info, feature_filename)
        print(f"✅ Saved feature info: {feature_filename}")
        
        # Create a simple test to verify models work
        self._create_verification_test(directory)
    
    def _create_verification_test(self, directory):
        """Create a verification test to ensure models work correctly"""
        test_data = {
            'sample_features': [3, 80, 1500, 5, 1, 0, 1, 0, 2, 0, 0.1, 0.0, 0.0, 0.0, 0.1],  # SQL Injection
            'expected_threat': 1,
            'description': 'SQL Injection pattern test'
        }
        
        test_filename = os.path.join(directory, 'model_test.pkl')
        joblib.dump(test_data, test_filename)
        print(f"✅ Created model test: {test_filename}")
    
    def verify_models(self, directory='Ai_Model'):
        """Verify that saved models work correctly"""
        print("\n🔍 Verifying saved models...")
        
        try:
            # Load the test data
            test_filename = os.path.join(directory, 'model_test.pkl')
            test_data = joblib.load(test_filename)
            
            # Load the ensemble model
            model_filename = os.path.join(directory, 'ensemble_model.pkl')
            model = joblib.load(model_filename)
            
            # Load the scaler
            scaler_filename = os.path.join(directory, 'standard_scaler.pkl')
            scaler = joblib.load(scaler_filename)
            
            # Prepare test features
            features = np.array([test_data['sample_features']])
            features_scaled = scaler.transform(features)
            
            # Make prediction
            prediction = model.predict(features_scaled)[0]
            probability = model.predict_proba(features_scaled)[0]
            
            print(f"✅ Model verification successful!")
            print(f"📊 Test: {test_data['description']}")
            print(f"🎯 Prediction: {prediction} (expected: {test_data['expected_threat']})")
            print(f"📈 Probabilities: Normal: {probability[0]:.3f}, Threat: {probability[1]:.3f}")
            
            return prediction == test_data['expected_threat']
            
        except Exception as e:
            print(f"❌ Model verification failed: {e}")
            return False

def main():
    """Main training function"""
    print("🚀 Starting Enhanced Threat Detection Model Training")
    print("=" * 60)
    
    # Initialize trainer
    trainer = ModelTrainer()
    
    # Generate training data
    X, y = trainer.generate_training_data(n_samples=15000)
    
    print(f"📊 Dataset Info:")
    print(f"   Samples: {X.shape[0]}")
    print(f"   Features: {X.shape[1]}")
    print(f"   Threats: {np.sum(y)} ({np.sum(y)/len(y)*100:.1f}%)")
    print(f"   Normal: {len(y) - np.sum(y)} ({(len(y) - np.sum(y))/len(y)*100:.1f}%)")
    
    # Train models
    X_test, y_test = trainer.train_models(X, y)
    
    # Save models
    trainer.save_models()
    
    # Verify models
    success = trainer.verify_models()
    
    if success:
        print("\n🎉 Model training completed successfully!")
        print("🤖 Your AI models are ready for threat detection!")
    else:
        print("\n⚠️  Model training completed with warnings.")
        print("🔧 Please check the model files before deployment.")

if __name__ == "__main__":
    main()