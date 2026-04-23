import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.datasets import make_classification
import os

def create_and_save_model():
    """Create and save a trained ML model with 8 features"""
    print("Creating threat detection model...")
    
    # Create training data with 8 features
    n_samples = 3000
    n_features = 8
    
    X, y = make_classification(
        n_samples=n_samples,
        n_features=n_features,
        n_informative=6,
        n_redundant=2,
        n_clusters_per_class=1,
        flip_y=0.03,
        random_state=42
    )
    
    # Scale features to realistic ranges
    X[:, 0] = np.abs(X[:, 0] * 5)                    # suspicious_keywords
    X[:, 1] = np.clip(np.abs(X[:, 1] * 1000) + 80, 80, 65535)  # port
    X[:, 2] = np.abs(X[:, 2] * 10000) + 100          # payload_size
    X[:, 3] = np.abs(X[:, 3] * 200)                  # request_frequency
    X[:, 4] = np.abs(X[:, 4] * 20)                   # unique_ports_scanned
    X[:, 5] = np.abs(X[:, 5] * 10)                   # auth_attempts
    X[:, 6] = np.abs(X[:, 6] * 3)                    # protocol_encoded
    X[:, 7] = np.abs(X[:, 7] * 2)                    # flag_anomalies
    
    # Create and train the model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight='balanced'
    )
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train model
    model.fit(X_train, y_train)
    
    # Evaluate model
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    
    print(f"✓ Model training completed:")
    print(f"  - Training accuracy: {train_score:.4f}")
    print(f"  - Test accuracy: {test_score:.4f}")
    print(f"  - Features: {n_features}")
    print(f"  - Samples: {n_samples}")
    
    # Create directory if it doesn't exist
    os.makedirs('Ai_Model', exist_ok=True)
    
    # Save the model
    model_filename = 'Ai_Model/model.pkl'
    joblib.dump(model, model_filename)
    
    if os.path.exists(model_filename):
        file_size = os.path.getsize(model_filename) / 1024
        print(f"✓ Model saved successfully as '{model_filename}'")
        print(f"✓ File size: {file_size:.2f} KB")
        return True
    
    return False

if __name__ == "__main__":
    create_and_save_model()