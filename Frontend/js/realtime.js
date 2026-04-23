class RealtimeManager {
    constructor() {
        this.connections = new Map();
        this.eventCallbacks = new Map();
        this.init();
    }

    init() {
        this.setupEventSource();
        this.startHealthChecks();
    }

    setupEventSource() {
        // Simulate real-time events for demonstration
        setInterval(() => {
            this.emitRandomEvent();
        }, 10000); // Emit event every 10 seconds
    }

    emitRandomEvent() {
        const events = [
            {
                type: 'threat_detected',
                data: {
                    id: Date.now(),
                    type: 'Suspicious Activity',
                    severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
                    ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
                    timestamp: new Date().toISOString()
                }
            },
            {
                type: 'system_alert',
                data: {
                    component: ['CPU', 'Memory', 'Network', 'Storage'][Math.floor(Math.random() * 4)],
                    level: 'warning',
                    message: 'Resource usage above threshold',
                    timestamp: new Date().toISOString()
                }
            },
            {
                type: 'analysis_complete',
                data: {
                    jobId: 'job_' + Date.now(),
                    results: Math.floor(Math.random() * 10),
                    timestamp: new Date().toISOString()
                }
            }
        ];

        const randomEvent = events[Math.floor(Math.random() * events.length)];
        this.emit(randomEvent.type, randomEvent.data);
    }

    on(event, callback) {
        if (!this.eventCallbacks.has(event)) {
            this.eventCallbacks.set(event, []);
        }
        this.eventCallbacks.get(event).push(callback);
    }

    emit(event, data) {
        const callbacks = this.eventCallbacks.get(event) || [];
        callbacks.forEach(callback => {
            try {
                callback(data);
            } catch (error) {
                console.error('Error in event callback:', error);
            }
        });
    }

    startHealthChecks() {
        setInterval(() => {
            this.checkSystemHealth();
        }, 30000); // Check every 30 seconds
    }

    async checkSystemHealth() {
        try {
            const status = await API.getSystemStatus();
            this.emit('system_health', status);
        } catch (error) {
            console.error('Health check failed:', error);
            this.emit('system_health', { status: 'offline', error: error.message });
        }
    }

    // Method to simulate real-time threat updates
    simulateThreatUpdate() {
        const threats = [
            {
                id: Date.now(),
                type: 'New Threat Detected',
                severity: 'high',
                description: 'Zero-day vulnerability exploitation attempt',
                ip: `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
                timestamp: new Date().toISOString()
            }
        ];

        this.emit('threat_update', threats);
    }

    // Method to update dashboard metrics in real-time
    updateMetrics() {
        const metrics = {
            cpu: Math.floor(Math.random() * 100),
            memory: Math.floor(Math.random() * 100),
            network: Math.floor(Math.random() * 100),
            activeConnections: Math.floor(Math.random() * 1000),
            threatsBlocked: Math.floor(Math.random() * 50)
        };

        this.emit('metrics_update', metrics);
    }
}

// Initialize realtime manager
const realtimeManager = new RealtimeManager();