// Main script for index.html

// Global variables
let uploadedFiles = [];
let isRealtimeDemoRunning = false;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    startHeroAnimations();
});

function initializeApp() {
    console.log('ThreatShield AI initialized');
    
    // Check if user is logged in (demo purposes)
    const authToken = localStorage.getItem('authToken');
    if (authToken) {
        updateAuthUI(true);
    }
    
    // Initialize any tooltips or additional UI elements
    initializeTooltips();
}

function setupEventListeners() {
    // Mobile menu toggle
    const mobileMenuToggle = document.getElementById('mobileMenuToggle');
    const mobileOverlay = document.getElementById('mobileOverlay');
    const nav = document.querySelector('.nav');
    
    if (mobileMenuToggle) {
        mobileMenuToggle.addEventListener('click', function() {
            nav.classList.toggle('active');
            mobileOverlay.classList.toggle('active');
            document.body.style.overflow = nav.classList.contains('active') ? 'hidden' : '';
        });
    }
    
    if (mobileOverlay) {
        mobileOverlay.addEventListener('click', function() {
            nav.classList.remove('active');
            mobileOverlay.classList.remove('active');
            document.body.style.overflow = '';
        });
    }
    
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
    
    // Close modals with Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeAllModals();
        }
    });
}

function initializeTooltips() {
    // Initialize any tooltip functionality
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    
    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
    });
}

function showTooltip(e) {
    const tooltipText = e.target.getAttribute('data-tooltip');
    if (!tooltipText) return;
    
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = tooltipText;
    document.body.appendChild(tooltip);
    
    const rect = e.target.getBoundingClientRect();
    tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
    tooltip.style.top = rect.top - tooltip.offsetHeight - 10 + 'px';
}

function hideTooltip() {
    const tooltip = document.querySelector('.tooltip');
    if (tooltip) {
        tooltip.remove();
    }
}

function startHeroAnimations() {
    // Start any hero section animations
    const threatOrbs = document.querySelectorAll('.threat-orb');
    
    threatOrbs.forEach((orb, index) => {
        orb.style.animationDelay = (index * 0.5) + 's';
    });
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

function showLoginModal() {
    document.getElementById('loginModal').style.display = 'block';
    document.body.style.overflow = 'hidden';
}

function closeLoginModal() {
    document.getElementById('loginModal').style.display = 'none';
    document.body.style.overflow = '';
}

function closeAllModals() {
    closeUploadModal();
    closeLoginModal();
}

// File handling functionality
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

// Real-time demo functionality
function startRealtimeDemo() {
    if (isRealtimeDemoRunning) return;
    
    isRealtimeDemoRunning = true;
    showNotification('Starting real-time threat monitoring demo...', 'info');
    
    // Simulate real-time threat detection
    const threatTypes = [
        { type: 'Malware', icon: 'fas fa-virus', severity: 'high' },
        { type: 'Intrusion', icon: 'fas fa-user-secret', severity: 'critical' },
        { type: 'Phishing', icon: 'fas fa-fish', severity: 'medium' },
        { type: 'DDoS', icon: 'fas fa-network-wired', severity: 'high' }
    ];
    
    let threatCount = 0;
    const demoInterval = setInterval(() => {
        if (threatCount >= 5) {
            clearInterval(demoInterval);
            isRealtimeDemoRunning = false;
            showNotification('Real-time demo completed. 5 threats were simulated.', 'success');
            return;
        }
        
        const randomThreat = threatTypes[Math.floor(Math.random() * threatTypes.length)];
        simulateThreatDetection(randomThreat);
        threatCount++;
    }, 2000);
    
    // Auto-stop after 15 seconds
    setTimeout(() => {
        clearInterval(demoInterval);
        isRealtimeDemoRunning = false;
    }, 15000);
}

function simulateThreatDetection(threat) {
    // Create threat notification
    const notification = document.createElement('div');
    notification.className = `threat-notification ${threat.severity}`;
    notification.innerHTML = `
        <div class="notification-header">
            <i class="${threat.icon}"></i>
            <strong>${threat.type} Detected</strong>
            <span class="threat-time">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="notification-body">
            <p>Severity: <span class="severity-${threat.severity}">${threat.severity.toUpperCase()}</span></p>
            <p>Source IP: 192.168.1.${Math.floor(Math.random() * 255)}</p>
            <p>Confidence: ${Math.floor(Math.random() * 30) + 70}%</p>
        </div>
    `;
    
    // Add to page (temporary for demo)
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

// Notification system
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

// Auth UI updates
function updateAuthUI(isLoggedIn) {
    const loginBtn = document.getElementById('loginBtn');
    if (loginBtn) {
        if (isLoggedIn) {
            loginBtn.innerHTML = '<i class="fas fa-user"></i><span>Dashboard</span>';
            loginBtn.onclick = () => window.location.href = 'dashboard.html';
        } else {
            loginBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i><span>Login</span>';
            loginBtn.onclick = showLoginModal;
        }
    }
}

// Close modals when clicking outside
window.addEventListener('click', function(event) {
    const uploadModal = document.getElementById('uploadModal');
    const loginModal = document.getElementById('loginModal');
    
    if (event.target === uploadModal) {
        closeUploadModal();
    }
    if (event.target === loginModal) {
        closeLoginModal();
    }
});

// Export functions for global access
window.showUploadModal = showUploadModal;
window.closeUploadModal = closeUploadModal;
window.showLoginModal = showLoginModal;
window.closeLoginModal = closeLoginModal;
window.startRealtimeDemo = startRealtimeDemo;
window.analyzeFiles = analyzeFiles;
window.removeFile = removeFile;