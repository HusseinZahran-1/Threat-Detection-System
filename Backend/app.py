from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
import json
import os
import sys
from datetime import datetime, timedelta
import asyncio
import threading

# Enhanced imports
from enhanced_detector import EnhancedThreatDetector
from threat_intelligence import ThreatIntelligence
from behavioral_analyzer import BehavioralAnalyzer
from streaming_analyzer import StreamingAnalyzer
from security import DataEncryptor, rate_limit_by_ip
from threat_cache import ThreatCache
from monitoring import PerformanceMonitor, setup_metrics
from reporting import ReportGenerator
from DatabaseManager import DatabaseManager  # This should work now
from preprocess import DataPreprocessor

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET', 'your-super-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

CORS(app)
jwt = JWTManager(app)

# Enhanced rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://",
)

def start_background_tasks():
    """Start background monitoring tasks"""
    try:
        asyncio.run(streaming_analyzer.start_monitoring())
    except Exception as e:
        print(f"Background task error: {e}")

# Initialize enhanced components
try:
    db_manager = DatabaseManager()
    preprocessor = DataPreprocessor()
    threat_detector = EnhancedThreatDetector()
    threat_intel = ThreatIntelligence()
    behavioral_analyzer = BehavioralAnalyzer()
    data_encryptor = DataEncryptor()
    threat_cache = ThreatCache()
    performance_monitor = PerformanceMonitor()
    report_generator = ReportGenerator()
    
    # Start background tasks
    streaming_analyzer = StreamingAnalyzer()
    background_thread = threading.Thread(target=start_background_tasks)
    background_thread.daemon = True
    background_thread.start()
    
    print("🚀 Enhanced Threat Detection System Initialized")
    print("✅ All components loaded successfully")
    
except Exception as e:
    print(f"❌ Initialization error: {e}")
    print("⚠️  Continuing with fallback mode...")

# Metrics endpoint
setup_metrics(app)

@app.route('/')
def home():
    return jsonify({
        "message": "Enhanced Threat Detection API",
        "version": "2.0.0",
        "status": "active",
        "features": [
            "Multi-model AI detection",
            "Real-time threat intelligence",
            "Behavioral analysis",
            "Streaming analysis",
            "Advanced reporting",
            "Performance monitoring"
        ]
    })

@app.route('/api/analyze', methods=['POST'])
@jwt_required()
@limiter.limit("50 per minute")
def analyze_threats():
    """Enhanced threat analysis with multiple detection methods"""
    try:
        start_time = datetime.now()
        
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415
        
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Extract and validate data
        log_entries = data.get('logs', [])
        user_id = data.get('user_id', 'anonymous')
        analysis_mode = data.get('mode', 'standard')
        
        if not log_entries:
            return jsonify({"error": "No log entries provided"}), 400
        
        if not isinstance(log_entries, list):
            log_entries = [log_entries]
        
        print(f"🔍 Enhanced analysis of {len(log_entries)} logs for user: {user_id}")
        
        # Enhanced preprocessing
        processed_data = []
        threat_scores = []
        
        for log_entry in log_entries:
            # Basic feature extraction
            features = preprocessor.extract_features(log_entry)
            processed_data.append(features)
            
            # Behavioral analysis
            behavior_score = behavioral_analyzer.analyze_user_behavior(
                user_id, log_entry
            )
            threat_scores.append(behavior_score)
        
        # Multi-stage threat detection
        detection_results = threat_detector.comprehensive_analysis(
            processed_data, 
            mode=analysis_mode
        )
        
        # Threat intelligence enrichment
        enriched_results = []
        for result in detection_results:
            # Add threat intelligence if source_ip exists
            source_ip = result.get('source_ip')
            if source_ip and source_ip != 'Unknown':
                try:
                    intel_data = threat_intel.check_ip_reputation(source_ip)
                    result['threat_intelligence'] = intel_data
                except Exception as e:
                    print(f"❌ Threat intelligence error for IP {source_ip}: {e}")
                    result['threat_intelligence'] = {}
            
            # Add behavioral score
            result['behavioral_score'] = threat_scores.pop(0) if threat_scores else 0
            
            # Calculate combined threat score
            ml_confidence = result.get('confidence', 0)
            behavioral_score = result.get('behavioral_score', 0)
            intel_score = result.get('threat_intelligence', {}).get('reputation_score', 0)
            
            combined_score = (
                ml_confidence * 0.6 + 
                behavioral_score * 0.3 + 
                intel_score * 0.1
            )
            
            result['combined_confidence'] = combined_score
            result['prediction'] = 1 if combined_score > 0.7 else 0
            
            # Encrypt sensitive data
            if 'raw_data' in result:
                result['encrypted_data'] = data_encryptor.encrypt_sensitive_data(
                    result['raw_data']
                )
            
            enriched_results.append(result)
        
        # Cache frequent patterns
        threat_patterns = threat_detector.extract_threat_patterns(enriched_results)
        threat_cache.cache_threat_patterns(threat_patterns)
        
        # Save to database
        saved_ids = []
        for result in enriched_results:
            db_result = {
                'user_id': user_id,
                'log_data': json.dumps(log_entries),
                'analysis_mode': analysis_mode,
                'prediction': result.get('prediction', 0),
                'confidence': result.get('confidence', 0),
                'threat_level': result.get('threat_level', 'LOW'),
                'source_ip': result.get('source_ip'),
                'features_used': result.get('features_used', 0),
                'behavioral_score': result.get('behavioral_score', 0),
                'combined_confidence': result.get('combined_confidence', 0),
                'encrypted_data': result.get('encrypted_data'),
                'timestamp': result.get('timestamp', datetime.now().isoformat())
            }
            
            result_id = db_manager.save_enhanced_analysis_result(db_result)
            if result_id:
                saved_ids.append(result_id)
        
        # Performance monitoring
        analysis_time = (datetime.now() - start_time).total_seconds()
        performance_monitor.record_analysis_time(analysis_time)
        performance_monitor.record_threats_detected(
            sum(1 for r in enriched_results if r['prediction'] == 1)
        )
        
        # Prepare response
        threats_detected = sum(1 for r in enriched_results if r['prediction'] == 1)
        avg_confidence = sum(r['combined_confidence'] for r in enriched_results) / len(enriched_results) if enriched_results else 0
        
        response = {
            "status": "success",
            "version": "enhanced",
            "total_analyzed": len(enriched_results),
            "threats_detected": threats_detected,
            "average_confidence": round(avg_confidence, 4),
            "analysis_time_seconds": round(analysis_time, 4),
            "analysis_mode": analysis_mode,
            "results": enriched_results,
            "timestamp": datetime.now().isoformat(),
            "performance_metrics": performance_monitor.get_current_metrics()
        }
        
        print(f"✅ Enhanced analysis complete: {threats_detected} threats detected")
        return jsonify(response)
    
    except Exception as e:
        print(f"❌ Enhanced analysis error: {str(e)}")
        performance_monitor.record_error()
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_data():
    """Get comprehensive dashboard data"""
    try:
        # Real-time statistics
        stats = db_manager.get_enhanced_statistics()
        
        # Recent threats
        recent_threats = db_manager.get_recent_threats(limit=10)
        
        # Threat distribution
        threat_distribution = db_manager.get_threat_distribution()
        
        # System performance
        performance_data = performance_monitor.get_dashboard_metrics()
        
        # Threat intelligence summary
        intel_summary = threat_intel.get_global_threat_level()
        
        dashboard_data = {
            "statistics": stats,
            "recent_threats": recent_threats,
            "threat_distribution": threat_distribution,
            "performance": performance_data,
            "threat_intelligence": intel_summary,
            "last_updated": datetime.now().isoformat()
        }
        
        return jsonify({"status": "success", "data": dashboard_data})
    
    except Exception as e:
        return jsonify({"error": f"Dashboard error: {str(e)}"}), 500

@app.route('/api/intel/<ip_address>', methods=['GET'])
@jwt_required()
def get_threat_intelligence(ip_address):
    """Get detailed threat intelligence for an IP"""
    try:
        intel_data = threat_intel.check_ip_reputation(ip_address)
        return jsonify({"status": "success", "intelligence": intel_data})
    except Exception as e:
        return jsonify({"error": f"Intel lookup failed: {str(e)}"}), 500

@app.route('/api/report', methods=['POST'])
@jwt_required()
def generate_report():
    """Generate PDF threat report"""
    try:
        data = request.get_json()
        report_type = data.get('type', 'summary')
        
        # Get analysis data for report
        analysis_id = data.get('analysis_id')
        if analysis_id:
            report_data = db_manager.get_analysis_for_report(analysis_id)
        else:
            report_data = db_manager.get_recent_analysis_data()
        
        # Generate PDF report
        pdf_path = report_generator.generate_enhanced_report(report_data, report_type)
        
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
    
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Prometheus metrics endpoint"""
    return performance_monitor.generate_metrics()

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User authentication"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # Simple authentication (replace with proper auth)
        if username == 'admin' and password == 'password':
            access_token = create_access_token(identity=username)
            return jsonify({
                "status": "success",
                "access_token": access_token,
                "user": {"username": username, "role": "admin"}
            })
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    
    except Exception as e:
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

# Serve frontend files
@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('../Frontend', path)

@app.route('/')
def serve_index():
    return send_from_directory('../Frontend', 'index.html')

if __name__ == '__main__':
    print("🚀 Starting Enhanced Threat Detection API...")
    print("📊 Performance monitoring: Active")
    print("🔍 Real-time analysis: Active")
    print("🌐 API: http://localhost:5000")
    print("📈 Metrics: http://localhost:5000/api/metrics")
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)