// Real-time monitoring functionality

class RealtimeMonitor {
    constructor() {
        this.isMonitoring = false;
        this.websocket = null;
        this.threats = [];
    }
    
    startMonitoring() {
        if (this.isMonitoring) {
            console.log('Monitoring already active');
            return;
        }
        
        this.isMonitoring = true;
        this.threats = [];
        
        // Simulate WebSocket connection
        this.simulateRealtimeData();
        
        // In a real implementation, this would connect to a WebSocket server
        // this.websocket = new WebSocket('wss://api.threatshield.ai/realtime');
        // this.websocket.onmessage = this.handleMessage.bind(this);
        // this.websocket.onopen = this.handleOpen.bind(this);
        // this.websocket.onclose = this.handleClose.bind(this);
        // this.websocket.onerror = this.handleError.bind(this);
        
        console.log('Real-time monitoring started');
    }
    
    stopMonitoring() {
        this.isMonitoring = false;
        
        if (this.websocket) {
            this.websocket.close();
            this.websocket = null;
        }
        
        console.log('Real-time monitoring stopped');
    }
    
    simulateRealtimeData() {
        if (!this.isMonitoring) return;
        
        // Simulate receiving threat data
        const threatTypes = ['Malware', 'Intrusion', 'Phishing', 'DDoS', 'Data Exfiltration'];
        const severityLevels = ['low', 'medium', 'high', 'critical'];
        
        setInterval(() => {
            if (Math.random() > 0.7) { // 30% chance of threat
                const threat = {
                    id: Date.now(),
                    type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
                    severity: severityLevels[Math.floor(Math.random() * severityLevels.length)],
                    timestamp: new Date().toISOString(),
                    source: `192.168.1.${Math.floor(Math.random() * 255)}`,
                    confidence: Math.floor(Math.random() * 30) + 70
                };
                
                this.threats.push(threat);
                this.onThreatDetected(threat);
            }
            
            // Update UI with current stats
            this.updateStats();
            
        }, 3000); // Simulate data every 3 seconds
    }
    
    onThreatDetected(threat) {
        // This would update the UI with the new threat
        console.log('Threat detected:', threat);
        
        // Show notification
        this.showThreatNotification(threat);
        
        // Update threat list
        this.updateThreatList();
    }
    
    showThreatNotification(threat) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `threat-notification ${threat.severity}`;
        notification.innerHTML = `
            <div class="notification-header">
                <span class="threat-icon">⚠️</span>
                <strong>${threat.type} Detected</strong>
                <button class="close-notification" onclick="this.parentElement.parentElement.remove()">×</button>
            </div>
            <div class="notification-body">
                <p>Severity: <span class="severity-${threat.severity}">${threat.severity}</span></p>
                <p>Source: ${threat.source}</p>
                <p>Confidence: ${threat.confidence}%</p>
            </div>
        `;
        
        // Add to notifications container
        const container = document.getElementById('notificationsContainer');
        if (container) {
            container.appendChild(notification);
            
            // Auto-remove after 10 seconds
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.remove();
                }
            }, 10000);
        }
    }
    
    updateThreatList() {
        // Update the threats list in the UI
        const threatsList = document.getElementById('threatsList');
        if (threatsList) {
            threatsList.innerHTML = this.threats
                .slice(-10) // Show last 10 threats
                .map(threat => `
                    <div class="threat-item ${threat.severity}">
                        <span class="threat-type">${threat.type}</span>
                        <span class="threat-severity ${threat.severity}">${threat.severity}</span>
                        <span class="threat-source">${threat.source}</span>
                        <span class="threat-time">${new Date(threat.timestamp).toLocaleTimeString()}</span>
                    </div>
                `)
                .join('');
        }
    }
    
    updateStats() {
        // Update real-time statistics
        const stats = {
            totalThreats: this.threats.length,
            criticalThreats: this.threats.filter(t => t.severity === 'critical').length,
            activeConnections: Math.floor(Math.random() * 1000) + 500,
            networkThroughput: (Math.random() * 1000).toFixed(2) + ' MB/s'
        };
        
        // Update UI elements
        Object.keys(stats).forEach(stat => {
            const element = document.getElementById(`realtime-${stat}`);
            if (element) {
                element.textContent = stats[stat];
            }
        });
    }
    
    handleMessage(event) {
        // Handle real WebSocket messages
        const data = JSON.parse(event.data);
        this.onThreatDetected(data);
    }
    
    handleOpen() {
        console.log('WebSocket connection established');
    }
    
    handleClose() {
        console.log('WebSocket connection closed');
        this.isMonitoring = false;
    }
    
    handleError(error) {
        console.error('WebSocket error:', error);
    }
}

// Global realtime monitor instance
window.realtimeMonitor = new RealtimeMonitor();

// Utility functions for real-time monitoring
function startRealtimeMonitoring() {
    window.realtimeMonitor.startMonitoring();
    alert('Real-time monitoring started. Threats will be displayed as they are detected.');
}

function stopRealtimeMonitoring() {
    window.realtimeMonitor.stopMonitoring();
    alert('Real-time monitoring stopped.');
}

// Initialize real-time monitoring when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on a page that should auto-start monitoring
    const shouldAutoStart = document.querySelector('[data-auto-start-monitoring]');
    if (shouldAutoStart) {
        startRealtimeMonitoring();
    }
});