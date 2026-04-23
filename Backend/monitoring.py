# monitoring.py
import time
import psutil
from datetime import datetime, timedelta
from collections import deque
import threading
from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
from prometheus_client.core import CollectorRegistry

class PerformanceMonitor:
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PerformanceMonitor, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not PerformanceMonitor._initialized:
            # Use a separate registry to avoid conflicts
            self.registry = CollectorRegistry()
            
            # Define metrics with unique names
            self.requests_total = Counter(
                'threat_detection_requests_total_v2',
                'Total number of threat detection requests',
                registry=self.registry
            )
            
            self.request_duration = Histogram(
                'threat_detection_request_duration_seconds_v2',
                'Request duration in seconds',
                registry=self.registry
            )
            
            self.threats_detected = Counter(
                'threats_detected_total_v2',
                'Total number of threats detected',
                registry=self.registry
            )
            
            self.errors_total = Counter(
                'threat_detection_errors_total_v2',
                'Total number of errors',
                registry=self.registry
            )
            
            self.system_cpu = Gauge(
                'system_cpu_usage_percent_v2',
                'System CPU usage percentage',
                registry=self.registry
            )
            
            self.system_memory = Gauge(
                'system_memory_usage_percent_v2',
                'System memory usage percentage',
                registry=self.registry
            )
            
            # Performance tracking
            self.analysis_times = deque(maxlen=100)
            self.threat_counts = deque(maxlen=100)
            self.error_counts = deque(maxlen=100)
            self.start_time = datetime.now()
            
            PerformanceMonitor._initialized = True
    
    def record_analysis_time(self, duration_seconds):
        """Record analysis time"""
        self.analysis_times.append(duration_seconds)
        self.request_duration.observe(duration_seconds)
    
    def record_threats_detected(self, count):
        """Record number of threats detected"""
        self.threat_counts.append(count)
        self.threats_detected.inc(count)
    
    def record_error(self):
        """Record an error"""
        self.error_counts.append(1)
        self.errors_total.inc()
    
    def record_request(self):
        """Record a request"""
        self.requests_total.inc()
    
    def get_current_metrics(self):
        """Get current performance metrics"""
        current_time = datetime.now()
        uptime = current_time - self.start_time
        
        analysis_times = list(self.analysis_times)
        threat_counts = list(self.threat_counts)
        error_counts = list(self.error_counts)
        
        return {
            'uptime_seconds': uptime.total_seconds(),
            'total_requests': len(analysis_times),
            'total_threats': sum(threat_counts),
            'total_errors': sum(error_counts),
            'avg_analysis_time': sum(analysis_times) / len(analysis_times) if analysis_times else 0,
            'current_cpu_usage': psutil.cpu_percent(),
            'current_memory_usage': psutil.virtual_memory().percent,
            'system_health': 'healthy' if sum(error_counts) < 10 else 'degraded'
        }
    
    def get_dashboard_metrics(self):
        """Get metrics for dashboard"""
        metrics = self.get_current_metrics()
        
        # Add historical data for charts
        metrics.update({
            'analysis_times_history': list(self.analysis_times)[-20:],  # Last 20 readings
            'threat_counts_history': list(self.threat_counts)[-20:],
            'error_counts_history': list(self.error_counts)[-20:],
            'timestamp': datetime.now().isoformat()
        })
        
        return metrics
    
    def generate_metrics(self):
        """Generate Prometheus metrics"""
        # Update system metrics
        self.system_cpu.set(psutil.cpu_percent())
        self.system_memory.set(psutil.virtual_memory().percent)
        
        return generate_latest(self.registry)

def setup_metrics(app):
    """Setup metrics endpoint"""
    monitor = PerformanceMonitor()
    
    @app.route('/metrics')
    def metrics():
        return monitor.generate_metrics(), 200, {'Content-Type': 'text/plain'}

# Global instance
performance_monitor = PerformanceMonitor()