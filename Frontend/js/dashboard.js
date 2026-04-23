// Dashboard functionality

// Global variables
let isRealtimeMonitoring = false;
let realtimeInterval = null;
let threatCount = 0;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    setupDashboardEventListeners();
    loadDashboardData();
});

function initializeDashboard() {
    console.log('Dashboard initialized');
    
    // Check authentication
    checkDashboardAuth();
    
    // Load user data
    loadUserData();
    
    // Initialize any charts or visualizations
    initializeCharts();
}

function setupDashboardEventListeners() {
    // Upload functionality
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    
    if (uploadArea && fileInput) {
        // Drag and drop functionality
        uploadArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        
        uploadArea.addEventListener('dragleave', function() {
            uploadArea.classList.remove('dragover');
        });
        
        uploadArea.addEventListener('drop', function(e) {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = e.dataTransfer.files;
            handleFiles(files);
        });
        
        // File input change
        fileInput.addEventListener('change', function() {
            handleFiles(this.files);
        });
        
        // Click to browse
        uploadArea.addEventListener('click', function() {
            fileInput.click();
        });
    }
    
    // Time filter for threat distribution
    const threatTimeFilter = document.getElementById('threatTimeFilter');
    if (threatTimeFilter) {
        threatTimeFilter.addEventListener('change', updateThreatDistribution);
    }
    
    // Mobile menu toggle
    const mobileMenuToggle = document.createElement('button');
    mobileMenuToggle.className = 'mobile-menu-toggle';
    mobileMenuToggle.innerHTML = '<i class="fas fa-bars"></i>';
    mobileMenuToggle.onclick = toggleMobileMenu;
    document.body.appendChild(mobileMenuToggle);
    
    const mobileOverlay = document.createElement('div');
    mobileOverlay.className = 'mobile-overlay';
    mobileOverlay.onclick = toggleMobileMenu;
    document.body.appendChild(mobileOverlay);
}

function checkDashboardAuth() {
    const authToken = localStorage.getItem('authToken');
    const userData = localStorage.getItem('userData');
    
    if (!authToken || !userData) {
        window.location.href = 'index.html';
        return;
    }
}

function loadUserData() {
    const userData = JSON.parse(localStorage.getItem('userData'));
    if (userData) {
        // Update user info in sidebar
        const userAvatar = document.querySelector('.user-avatar');
        const userName = document.querySelector('.user-details strong');
        const userRole = document.querySelector('.user-details span');
        
        if (userAvatar) {
            userAvatar.innerHTML = `<i class="fas fa-user"></i>`;
        }
        
        if (userName) {
            userName.textContent = `${userData.firstName} ${userData.lastName}`;
        }
        
        if (userRole) {
            userRole.textContent = userData.role.charAt(0).toUpperCase() + userData.role.slice(1);
        }
        
        // Update welcome message
        const welcomeSubtitle = document.querySelector('.subtitle');
        if (welcomeSubtitle) {
            welcomeSubtitle.textContent = `Welcome back, ${userData.firstName}. Here's your security overview.`;
        }
    }
}

function loadDashboardData() {
    // Simulate loading dashboard data
    setTimeout(() => {
        updateStats();
        updateRecentActivity();
        updateSystemHealth();
    }, 1000);
}

function initializeCharts() {
    // Initialize any dashboard charts
    console.log('Charts initialized');
}

function updateStats() {
    // Simulate updating stats with real data
    const stats = {
        threats: 12,
        safeFiles: 156,
        totalAnalysis: 189,
        accuracy: 98.2
    };
    
    // Update stat cards
    document.querySelectorAll('.stat-value')[0].textContent = stats.threats;
    document.querySelectorAll('.stat-value')[1].textContent = stats.safeFiles;
    document.querySelectorAll('.stat-value')[2].textContent = stats.totalAnalysis;
    document.querySelectorAll('.stat-value')[3].textContent = stats.accuracy + '%';
}

function updateRecentActivity() {
    // This would be populated from API data
    console.log('Recent activity updated');
}

function updateSystemHealth() {
    // Simulate system health metrics
    const metrics = [
        { label: 'AI Model', value: 95 },
        { label: 'Database', value: 98 },
        { label: 'API Services', value: 99 },
        { label: 'Real-time Processing', value: 92 }
    ];
    
    const metricBars = document.querySelectorAll('.metric-fill');
    metrics.forEach((metric, index) => {
        if (metricBars[index]) {
            metricBars[index].style.width = metric.value + '%';
        }
    });
}

function updateThreatDistribution() {
    const timeFilter = document.getElementById('threatTimeFilter').value;
    
    // Simulate different data based on time filter
    let distribution;
    switch (timeFilter) {
        case '24h':
            distribution = { malware: 35, intrusion: 40, phishing: 15, other: 10 };
            break;
        case '7d':
            distribution = { malware: 45, intrusion: 30, phishing: 15, other: 10 };
            break;
        case '30d':
            distribution = { malware: 50, intrusion: 25, phishing: 15, other: 10 };
            break;
        default:
            distribution = { malware: 45, intrusion: 30, phishing: 15, other: 10 };
    }
    
    // Update pie chart (simplified - in real app would use chart library)
    console.log('Threat distribution updated for:', timeFilter, distribution);
}

// File handling functionality (similar to main script but for dashboard)
let uploadedFiles = [];

function handleFiles(files) {
    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        if (isValidFileType(file)) {
            if (!isFileAlreadyAdded(file)) {
                uploadedFiles.push(file);
                addFileToList(file);
            }
        } else {
            showNotification(`File "${file.name}" is not a supported file type. Please upload CSV, JSON, TXT, or LOG files.`, 'error');
        }
    }
    updateAnalyzeButton();
}

function isValidFileType(file) {
    const validTypes = ['.csv', '.json', '.txt', '.log'];
    const fileName = file.name.toLowerCase();
    return validTypes.some(type => fileName.endsWith(type));
}

function isFileAlreadyAdded(file) {
    return uploadedFiles.some(f => f.name === file.name && f.size === file.size && f.lastModified === file.lastModified);
}

function addFileToList(file) {
    const fileList = document.getElementById('fileList');
    const fileItem = document.createElement('div');
    fileItem.className = 'file-item';
    fileItem.innerHTML = `
        <div class="file-info">
            <i class="fas fa-file-alt file-icon"></i>
            <span>${file.name}</span>
            <small>(${formatFileSize(file.size)})</small>
        </div>
        <div class="file-actions">
            <button class="btn-action remove" onclick="removeFile('${file.name}')">
                <i class="fas fa-times"></i>
                Remove
            </button>
        </div>
    `;
    fileList.appendChild(fileItem);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function removeFile(fileName) {
    uploadedFiles = uploadedFiles.filter(file => file.name !== fileName);
    const fileList = document.getElementById('fileList');
    fileList.innerHTML = '';
    uploadedFiles.forEach(file => addFileToList(file));
    updateAnalyzeButton();
}

function updateAnalyzeButton() {
    const analyzeBtn = document.getElementById('analyzeBtn');
    if (analyzeBtn) {
        analyzeBtn.disabled = uploadedFiles.length === 0;
    }
}

function resetUploadArea() {
    uploadedFiles = [];
    const fileList = document.getElementById('fileList');
    if (fileList) {
        fileList.innerHTML = '';
    }
    const fileInput = document.getElementById('fileInput');
    if (fileInput) {
        fileInput.value = '';
    }
    updateAnalyzeButton();
}

// Modal functionality
function showUploadModal() {
    document.getElementById('uploadModal').style.display = 'block';
    document.body.style.overflow = 'hidden';
}

function closeUploadModal() {
    document.getElementById('uploadModal').style.display = 'none';
    document.body.style.overflow = '';
    resetUploadArea();
}

function analyzeFiles() {
    if (uploadedFiles.length === 0) {
        showNotification('Please select at least one file to analyze.', 'warning');
        return;
    }
    
    // Show loading state
    const analyzeBtn = document.getElementById('analyzeBtn');
    const originalText = analyzeBtn.innerHTML;
    analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing Files...';
    analyzeBtn.disabled = true;
    
    // Simulate API call and processing
    setTimeout(() => {
        // Store files in localStorage for demo purposes
        localStorage.setItem('uploadedFiles', JSON.stringify(uploadedFiles.map(f => f.name)));
        
        // Show success notification
        showNotification(`Successfully analyzed ${uploadedFiles.length} file(s). Redirecting to results...`, 'success');
        
        // Redirect to results page after a delay
        setTimeout(() => {
            window.location.href = 'results.html';
        }, 2000);
    }, 3000);
}

// Real-time monitoring functionality
function startRealtimeMonitoring() {
    if (isRealtimeMonitoring) return;
    
    isRealtimeMonitoring = true;
    threatCount = 0;
    
    // Update UI
    const startBtn = document.getElementById('startMonitorBtn');
    const stopBtn = document.getElementById('stopMonitorBtn');
    const threatsFeed = document.getElementById('threatsFeed');
    
    if (startBtn) startBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;
    
    // Clear previous threats
    if (threatsFeed) {
        threatsFeed.innerHTML = '';
    }
    
    showNotification('Real-time threat monitoring started', 'success');
    
    // Start simulating threats
    realtimeInterval = setInterval(() => {
        simulateThreatDetection();
        updateMonitorStats();
    }, 3000);
}

function stopRealtimeMonitoring() {
    if (!isRealtimeMonitoring) return;
    
    isRealtimeMonitoring = false;
    clearInterval(realtimeInterval);
    
    // Update UI
    const startBtn = document.getElementById('startMonitorBtn');
    const stopBtn = document.getElementById('stopMonitorBtn');
    
    if (startBtn) startBtn.disabled = false;
    if (stopBtn) stopBtn.disabled = true;
    
    showNotification('Real-time threat monitoring stopped', 'info');
}

function simulateThreatDetection() {
    if (!isRealtimeMonitoring) return;
    
    const threatTypes = [
        { type: 'Malware', icon: 'fas fa-virus', severity: 'high' },
        { type: 'Intrusion', icon: 'fas fa-user-secret', severity: 'critical' },
        { type: 'Phishing', icon: 'fas fa-fish', severity: 'medium' },
        { type: 'DDoS', icon: 'fas fa-network-wired', severity: 'high' },
        { type: 'Data Exfiltration', icon: 'fas fa-database', severity: 'critical' }
    ];
    
    const randomThreat = threatTypes[Math.floor(Math.random() * threatTypes.length)];
    addThreatToFeed(randomThreat);
    threatCount++;
}

function addThreatToFeed(threat) {
    const threatsFeed = document.getElementById('threatsFeed');
    if (!threatsFeed) return;
    
    // Remove placeholder if it exists
    const placeholder = threatsFeed.querySelector('.feed-placeholder');
    if (placeholder) {
        placeholder.remove();
    }
    
    const threatItem = document.createElement('div');
    threatItem.className = `threat-item ${threat.severity}`;
    threatItem.innerHTML = `
        <div class="threat-icon">
            <i class="${threat.icon}"></i>
        </div>
        <div class="threat-details">
            <span class="threat-type">${threat.type} Detected</span>
            <span class="threat-source">Source: 192.168.1.${Math.floor(Math.random() * 255)}</span>
            <span class="threat-time">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="threat-confidence">${Math.floor(Math.random() * 30) + 70}%</div>
    `;
    
    threatsFeed.appendChild(threatItem);
    threatsFeed.scrollTop = threatsFeed.scrollHeight;
}

function updateMonitorStats() {
    if (!isRealtimeMonitoring) return;
    
    // Update stats
    const threatsDetected = document.getElementById('threatsDetected');
    const activeConnections = document.getElementById('activeConnections');
    const networkThroughput = document.getElementById('networkThroughput');
    const processingTime = document.getElementById('processingTime');
    
    if (threatsDetected) threatsDetected.textContent = threatCount;
    if (activeConnections) activeConnections.textContent = Math.floor(Math.random() * 500) + 500;
    if (networkThroughput) networkThroughput.textContent = (Math.random() * 100).toFixed(1) + ' MB/s';
    if (processingTime) processingTime.textContent = Math.floor(Math.random() * 50) + 10 + 'ms';
}

// Quick actions
function generateReport() {
    showNotification('Generating security report...', 'info');
    
    // Simulate report generation
    setTimeout(() => {
        showNotification('Security report generated successfully!', 'success');
    }, 2000);
}

function viewAlerts() {
    showNotification('Opening security alerts...', 'info');
    // In real app, this would navigate to alerts page
}

function manageTeam() {
    showNotification('Opening team management...', 'info');
    // In real app, this would navigate to team management
}

function systemSettings() {
    showNotification('Opening system settings...', 'info');
    // In real app, this would navigate to settings
}

// Mobile menu functionality
function toggleMobileMenu() {
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.querySelector('.mobile-overlay');
    
    sidebar.classList.toggle('mobile-open');
    overlay.classList.toggle('active');
    document.body.style.overflow = sidebar.classList.contains('mobile-open') ? 'hidden' : '';
}

function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.global-notification');
    existingNotifications.forEach(notification => {
        notification.remove();
    });
    
    const notification = document.createElement('div');
    notification.className = `global-notification ${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${getNotificationIcon(type)}"></i>
            <span>${message}</span>
        </div>
        <button class="notification-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

function getNotificationIcon(type) {
    const icons = {
        'success': 'check-circle',
        'error': 'exclamation-circle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

// Close modals when clicking outside
window.addEventListener('click', function(event) {
    const uploadModal = document.getElementById('uploadModal');
    if (event.target === uploadModal) {
        closeUploadModal();
    }
});

// Export functions for global access
window.showUploadModal = showUploadModal;
window.closeUploadModal = closeUploadModal;
window.analyzeFiles = analyzeFiles;
window.removeFile = removeFile;
window.startRealtimeMonitoring = startRealtimeMonitoring;
window.stopRealtimeMonitoring = stopRealtimeMonitoring;
window.generateReport = generateReport;
window.viewAlerts = viewAlerts;
window.manageTeam = manageTeam;
window.systemSettings = systemSettings;
window.toggleMobileMenu = toggleMobileMenu;