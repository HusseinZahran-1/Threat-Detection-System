import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

class ModelEvaluator:
    def __init__(self, model_path='Ai_Model/model.pkl', scaler_path='Ai_Model/standard_scaler.pkl'):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        
        self.load_model()
    
    def load_model(self):
        """Load the trained model and scaler"""
        try:
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            print("✅ Model and scaler loaded successfully")
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            raise
    
    def generate_test_data(self, n_samples=2000):
        """Generate test data for evaluation"""
        from sklearn.datasets import make_classification
        
        X, y = make_classification(
            n_samples=n_samples,
            n_features=15,
            n_informative=12,
            n_redundant=3,
            n_clusters_per_class=2,
            flip_y=0.02,
            random_state=42
        )
        
        # Transform to realistic ranges (same as training)
        X = self._transform_test_features(X)
        
        return X, y
    
    def _transform_test_features(self, X):
        """Transform test features to match training data ranges"""
        # Apply same transformations as training
        X[:, 0] = np.abs(X[:, 0] * 10)  # suspicious_keywords
        X[:, 1] = np.abs(X[:, 1] * 65535)  # port
        X[:, 2] = np.abs(X[:, 2] * 50000) + 50  # payload_size
        X[:, 3] = np.abs(X[:, 3] * 500)  # request_frequency
        X[:, 4] = np.abs(X[:, 4] * 100)  # unique_ports_scanned
        X[:, 5] = np.abs(X[:, 5] * 20)  # auth_attempts
        X[:, 6] = np.abs(X[:, 6] * 5)  # protocol_encoded
        X[:, 7] = np.abs(X[:, 7] * 3)  # flag_anomalies
        X[:, 8] = np.abs(X[:, 8] * 5)  # sql_patterns
        X[:, 9] = np.abs(X[:, 9] * 5)  # xss_patterns
        X[:, 10] = np.abs(X[:, 10])  # ddos_score
        X[:, 11] = np.abs(X[:, 11])  # scan_score
        X[:, 12] = np.abs(X[:, 12])  # malware_score
        X[:, 13] = np.abs(X[:, 13])  # data_exfil_score
        X[:, 14] = np.abs(X[:, 14])  # behavioral_score
        
        return X
    
    def comprehensive_evaluation(self):
        """Perform comprehensive model evaluation"""
        print("📊 Starting Comprehensive Model Evaluation")
        print("=" * 60)
        
        # Generate test data
        X_test, y_test = self.generate_test_data()
        X_test_scaled = self.scaler.transform(X_test)
        
        # Make predictions
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)
        
        # Calculate metrics
        accuracy = np.mean(y_pred == y_test)
        auc_score = roc_auc_score(y_test, y_pred_proba[:, 1])
        
        print(f"📈 Basic Metrics:")
        print(f"   Accuracy: {accuracy:.4f}")
        print(f"   AUC Score: {auc_score:.4f}")
        print(f"   Test Samples: {len(y_test)}")
        print(f"   Threat Rate: {np.mean(y_test):.3f}")
        
        # Detailed classification report
        print(f"\n📋 Detailed Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Threat']))
        
        # Confusion matrix
        self._plot_confusion_matrix(y_test, y_pred)
        
        # ROC curve
        self._plot_roc_curve(y_test, y_pred_proba[:, 1])
        
        # Feature importance (if available)
        self._analyze_feature_importance()
        
        # Performance by threat type
        self._analyze_threat_types(X_test, y_test, y_pred)
        
        return {
            'accuracy': accuracy,
            'auc_score': auc_score,
            'confusion_matrix': confusion_matrix(y_test, y_pred),
            'classification_report': classification_report(y_test, y_pred, output_dict=True)
        }
    
    def _plot_confusion_matrix(self, y_true, y_pred):
        """Plot confusion matrix"""
        cm = confusion_matrix(y_true, y_pred)
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Normal', 'Threat'],
                    yticklabels=['Normal', 'Threat'])
        plt.title('Confusion Matrix')
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.tight_layout()
        plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print("✅ Confusion matrix saved: confusion_matrix.png")
    
    def _plot_roc_curve(self, y_true, y_pred_proba):
        """Plot ROC curve"""
        fpr, tpr, thresholds = roc_curve(y_true, y_pred_proba)
        auc_score = roc_auc_score(y_true, y_pred_proba)
        
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {auc_score:.3f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")
        plt.grid(True)
        plt.tight_layout()
        plt.savefig('roc_curve.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print("✅ ROC curve saved: roc_curve.png")
    
    def _analyze_feature_importance(self):
        """Analyze and plot feature importance"""
        try:
            if hasattr(self.model, 'feature_importances_'):
                # Get feature names
                feature_names = [
                    'suspicious_keywords', 'port', 'payload_size', 'request_frequency',
                    'unique_ports_scanned', 'auth_attempts', 'protocol_encoded', 'flag_anomalies',
                    'sql_patterns', 'xss_patterns', 'ddos_score', 'scan_score', 
                    'malware_score', 'data_exfil_score', 'behavioral_score'
                ]
                
                importances = self.model.feature_importances_
                indices = np.argsort(importances)[::-1]
                
                plt.figure(figsize=(10, 8))
                plt.title('Feature Importances')
                plt.bar(range(len(importances)), importances[indices])
                plt.xticks(range(len(importances)), [feature_names[i] for i in indices], rotation=45)
                plt.tight_layout()
                plt.savefig('feature_importance.png', dpi=300, bbox_inches='tight')
                plt.close()
                
                print("✅ Feature importance plot saved: feature_importance.png")
                
                # Print top features
                print(f"\n🔝 Top 5 Most Important Features:")
                for i in range(min(5, len(indices))):
                    print(f"   {i+1}. {feature_names[indices[i]]}: {importances[indices[i]]:.4f}")
                    
        except Exception as e:
            print(f"⚠️  Could not analyze feature importance: {e}")
    
    def _analyze_threat_types(self, X_test, y_test, y_pred):
        """Analyze performance by different threat types"""
        # This is a simplified analysis - in production you'd have actual threat types
        print(f"\n🎯 Performance Analysis by Pattern Type:")
        
        # Analyze high SQL patterns
        high_sql_mask = X_test[:, 8] > 2  # High SQL patterns
        if np.any(high_sql_mask):
            sql_accuracy = np.mean(y_pred[high_sql_mask] == y_test[high_sql_mask])
            print(f"   High SQL Patterns: {sql_accuracy:.3f} "
                  f"({np.sum(high_sql_mask)} samples)")
        
        # Analyze high frequency (DDoS)
        high_freq_mask = X_test[:, 3] > 100  # High frequency
        if np.any(high_freq_mask):
            freq_accuracy = np.mean(y_pred[high_freq_mask] == y_test[high_freq_mask])
            print(f"   High Frequency: {freq_accuracy:.3f} "
                  f"({np.sum(high_freq_mask)} samples)")
        
        # Analyze port scanning
        high_scan_mask = X_test[:, 4] > 10  # Many ports scanned
        if np.any(high_scan_mask):
            scan_accuracy = np.mean(y_pred[high_scan_mask] == y_test[high_scan_mask])
            print(f"   Port Scanning: {scan_accuracy:.3f} "
                  f"({np.sum(high_scan_mask)} samples)")
    
    def performance_report(self):
        """Generate a comprehensive performance report"""
        results = self.comprehensive_evaluation()
        
        report = {
            'evaluation_date': datetime.now().isoformat(),
            'model_info': {
                'model_type': type(self.model).__name__,
                'training_date': 'Generated',
                'features_used': 15
            },
            'performance_metrics': {
                'accuracy': results['accuracy'],
                'auc_score': results['auc_score'],
                'precision': results['classification_report']['1']['precision'],
                'recall': results['classification_report']['1']['recall'],
                'f1_score': results['classification_report']['1']['f1-score']
            },
            'confusion_matrix': results['confusion_matrix'].tolist()
        }
        
        # Save report
        import json
        with open('model_evaluation_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Evaluation report saved: model_evaluation_report.json")
        
        return report

def main():
    """Main evaluation function"""
    print("🔍 Starting Model Evaluation")
    print("=" * 50)
    
    try:
        evaluator = ModelEvaluator()
        report = evaluator.performance_report()
        
        print(f"\n🎉 Evaluation completed successfully!")
        print(f"📊 Final Model Performance:")
        print(f"   Accuracy: {report['performance_metrics']['accuracy']:.3f}")
        print(f"   AUC Score: {report['performance_metrics']['auc_score']:.3f}")
        print(f"   F1-Score: {report['performance_metrics']['f1_score']:.3f}")
        
    except Exception as e:
        print(f"❌ Evaluation failed: {e}")

if __name__ == "__main__":
    main()