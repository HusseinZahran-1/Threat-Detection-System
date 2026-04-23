// Results page functionality

// Global variables
let currentResults = [];
let filteredResults = [];
let selectedResults = new Set();
let currentPage = 1;
const resultsPerPage = 10;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeResults();
    setupResultsEventListeners();
    loadResultsData();
});

function initializeResults() {
    console.log('Results page initialized');
    
    // Check authentication
    checkResultsAuth();
    
    // Load user data
    loadUserData();
}

function setupResultsEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(filterResults, 300));
    }
    
    // Upload functionality
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    
    if (uploadArea && fileInput) {
        setupUploadFunctionality(uploadArea, fileInput);
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

function checkResultsAuth() {
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
    }
}

function loadResultsData() {
    // Show loading state
    showLoadingState();
    
    // Simulate API call to load results
    setTimeout(() => {
        // Generate sample data for demonstration
        currentResults = generateSampleResults();
        filteredResults = [...currentResults];
        
        // Render results
        renderResults();
        
        // Update summary cards
        updateSummaryCards();
        
        // Hide loading state
        hideLoadingState();
    }, 1500);
}

function generateSampleResults() {
    const sampleResults = [];
    const statuses = ['critical', 'warning', 'safe'];
    const threatTypes = {
        critical: ['Malware Infection', 'Data Breach', 'System Intrusion'],
        warning: ['Suspicious Activity', 'Unauthorized Access', 'Phishing Attempt'],
        safe: ['No Threats Found', 'Clean File', 'Verified Safe']
    };
    const fileNames = [
        'network_logs.csv', 'access_log.txt', 'system_logs.json',
        'security_events.log', 'firewall_logs.csv', 'user_activity.json',
        'server_logs.txt', 'application_logs.csv', 'database_logs.json'
    ];
    
    for (let i = 0; i < 56; i++) {
        const status = statuses[Math.floor(Math.random() * statuses.length)];
        const threatType = threatTypes[status][Math.floor(Math.random() * threatTypes[status].length)];
        
        sampleResults.push({
            id: i + 1,
            fileName: fileNames[Math.floor(Math.random() * fileNames.length)],
            analysisDate: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
            status: status,
            threatType: threatType,
            confidence: status === 'safe' ? Math.floor(Math.random() * 10) + 90 : Math.floor(Math.random() * 30) + 70,
            fileSize: Math.floor(Math.random() * 5000) + 100 + ' KB',
            details: {
                algorithm: ['Random Forest', 'XGBoost', 'Decision Tree', 'Ensemble'][Math.floor(Math.random() * 4)],
                patterns: Math.floor(Math.random() * 20) + 1,
                analysisTime: (Math.random() * 5 + 1).toFixed(1) + 's',
                riskScore: Math.floor(Math.random() * 100)
            }
        });
    }
    
    return sampleResults.sort((a, b) => new Date(b.analysisDate) - new Date(a.analysisDate));
}

function renderResults() {
    const tableBody = document.getElementById('resultsTableBody');
    if (!tableBody) return;
    
    // Calculate pagination
    const startIndex = (currentPage - 1) * resultsPerPage;
    const endIndex = startIndex + resultsPerPage;
    const pageResults = filteredResults.slice(startIndex, endIndex);
    
    tableBody.innerHTML = '';
    
    if (pageResults.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" class="no-results">
                    <i class="fas fa-search"></i>
                    <p>No results found</p>
                    <small>Try adjusting your search or filter criteria</small>
                </td>
            </tr>
        `;
        return;
    }
    
    pageResults.forEach(result => {
        const row = document.createElement('tr');
        row.className = `result-row ${result.status}`;
        row.innerHTML = `
            <td>
                <input type="checkbox" class="result-checkbox" value="${result.id}" 
                       ${selectedResults.has(result.id) ? 'checked' : ''}
                       onchange="toggleResultSelection(${result.id})">
            </td>
            <td>
                <div class="file-info">
                    <i class="fas fa-file-alt file-icon"></i>
                    <span>${result.fileName}</span>
                </div>
            </td>
            <td>${formatDate(result.analysisDate)}</td>
            <td>
                <span class="status-badge ${result.status}">
                    <i class="fas ${getStatusIcon(result.status)}"></i>
                    ${result.status.charAt(0).toUpperCase() + result.status.slice(1)}
                </span>
            </td>
            <td>${result.threatType}</td>
            <td>
                <div class="confidence-indicator">
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: ${result.confidence}%"></div>
                    </div>
                    <span class="confidence-value">${result.confidence}%</span>
                </div>
            </td>
            <td>${result.fileSize}</td>
            <td>
                <div class="action-buttons">
                    <button class="btn-action view" onclick="viewResultDetails(${result.id})" 
                            title="View Details">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn-action export" onclick="exportResult(${result.id})" 
                            title="Export Result">
                        <i class="fas fa-download"></i>
                    </button>
                    <button class="btn-action delete" onclick="deleteResult(${result.id})" 
                            title="Delete Result">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        tableBody.appendChild(row);
    });
    
    updatePagination();
    updateSelectedCount();
}

function formatDate(date) {
    return new Date(date).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function getStatusIcon(status) {
    const icons = {
        critical: 'fa-exclamation-triangle',
        warning: 'fa-exclamation-circle',
        safe: 'fa-check-circle'
    };
    return icons[status] || 'fa-info-circle';
}

function updateSummaryCards() {
    const criticalCount = currentResults.filter(r => r.status === 'critical').length;
    const warningCount = currentResults.filter(r => r.status === 'warning').length;
    const safeCount = currentResults.filter(r => r.status === 'safe').length;
    const totalCount = currentResults.length;
    
    // Update summary cards
    document.querySelectorAll('.summary-value')[0].textContent = criticalCount;
    document.querySelectorAll('.summary-value')[1].textContent = warningCount;
    document.querySelectorAll('.summary-value')[2].textContent = safeCount;
    document.querySelectorAll('.summary-value')[3].textContent = totalCount;
}

function filterResults() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const filterValue = document.getElementById('resultsFilter').value;
    
    filteredResults = currentResults.filter(result => {
        // Search filter
        const matchesSearch = result.fileName.toLowerCase().includes(searchTerm) ||
                            result.threatType.toLowerCase().includes(searchTerm);
        
        // Status filter
        let matchesFilter = true;
        switch (filterValue) {
            case 'critical':
                matchesFilter = result.status === 'critical';
                break;
            case 'warning':
                matchesFilter = result.status === 'warning';
                break;
            case 'safe':
                matchesFilter = result.status === 'safe';
                break;
            case 'today':
                const today = new Date();
                const resultDate = new Date(result.analysisDate);
                matchesFilter = resultDate.toDateString() === today.toDateString();
                break;
            case 'week':
                const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
                matchesFilter = new Date(result.analysisDate) >= weekAgo;
                break;
        }
        
        return matchesSearch && matchesFilter;
    });
    
    currentPage = 1;
    renderResults();
}

function sortResults() {
    const sortValue = document.getElementById('resultsSort').value;
    
    filteredResults.sort((a, b) => {
        switch (sortValue) {
            case 'newest':
                return new Date(b.analysisDate) - new Date(a.analysisDate);
            case 'oldest':
                return new Date(a.analysisDate) - new Date(b.analysisDate);
            case 'severity':
                const severityOrder = { critical: 3, warning: 2, safe: 1 };
                return severityOrder[b.status] - severityOrder[a.status];
            case 'filename':
                return a.fileName.localeCompare(b.fileName);
            default:
                return 0;
        }
    });
    
    renderResults();
}

function toggleSelectAll() {
    const selectAll = document.getElementById('selectAll');
    const checkboxes = document.querySelectorAll('.result-checkbox');
    
    if (selectAll.checked) {
        checkboxes.forEach(checkbox => {
            checkbox.checked = true;
            selectedResults.add(parseInt(checkbox.value));
        });
    } else {
        checkboxes.forEach(checkbox => {
            checkbox.checked = false;
        });
        selectedResults.clear();
    }
    
    updateSelectedCount();
}

function toggleResultSelection(resultId) {
    if (selectedResults.has(resultId)) {
        selectedResults.delete(resultId);
    } else {
        selectedResults.add(resultId);
    }
    
    updateSelectedCount();
    
    // Update select all checkbox
    const selectAll = document.getElementById('selectAll');
    const checkboxes = document.querySelectorAll('.result-checkbox');
    const allChecked = Array.from(checkboxes).every(checkbox => checkbox.checked);
    selectAll.checked = allChecked;
}

function updateSelectedCount() {
    const selectedCount = document.getElementById('selectedCount');
    if (selectedCount) {
        selectedCount.textContent = `${selectedResults.size} item${selectedResults.size !== 1 ? 's' : ''} selected`;
    }
}

function updatePagination() {
    const totalPages = Math.ceil(filteredResults.length / resultsPerPage);
    const pageInfo = document.querySelector('.page-info');
    
    if (pageInfo) {
        pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
    }
    
    // Update button states
    const prevButton = document.querySelector('.pagination .btn:first-child');
    const nextButton = document.querySelector('.pagination .btn:last-child');
    
    if (prevButton) prevButton.disabled = currentPage === 1;
    if (nextButton) nextButton.disabled = currentPage === totalPages;
}

function previousPage() {
    if (currentPage > 1) {
        currentPage--;
        renderResults();
    }
}

function nextPage() {
    const totalPages = Math.ceil(filteredResults.length / resultsPerPage);
    if (currentPage < totalPages) {
        currentPage++;
        renderResults();
    }
}

function refreshResults() {
    showNotification('Refreshing results...', 'info');
    loadResultsData();
}

function viewResultDetails(resultId) {
    const result = currentResults.find(r => r.id === resultId);
    if (!result) return;
    
    const detailContent = document.getElementById('detailContent');
    detailContent.innerHTML = `
        <div class="detail-header">
            <div class="file-details">
                <h4>${result.fileName}</h4>
                <p>Analyzed: ${formatDate(result.analysisDate)} | Size: ${result.fileSize}</p>
            </div>
            <div class="threat-level">
                <span class="status-badge ${result.status}">
                    <i class="fas ${getStatusIcon(result.status)}"></i>
                    ${result.status.charAt(0).toUpperCase() + result.status.slice(1)}
                </span>
            </div>
        </div>
        
        <div class="detail-grid">
            <div class="detail-section">
                <h5>
                    <i class="fas fa-info-circle"></i>
                    Threat Information
                </h5>
                <div class="info-item">
                    <label>Threat Type:</label>
                    <span>${result.threatType}</span>
                </div>
                <div class="info-item">
                    <label>Confidence Level:</label>
                    <span class="confidence-value">${result.confidence}%</span>
                </div>
                <div class="info-item">
                    <label>Risk Score:</label>
                    <span class="risk-score">${result.details.riskScore}/100</span>
                </div>
            </div>
            
            <div class="detail-section">
                <h5>
                    <i class="fas fa-cogs"></i>
                    Detection Details
                </h5>
                <div class="info-item">
                    <label>Algorithm Used:</label>
                    <span>${result.details.algorithm}</span>
                </div>
                <div class="info-item">
                    <label>Patterns Detected:</label>
                    <span>${result.details.patterns} suspicious patterns</span>
                </div>
                <div class="info-item">
                    <label>Analysis Time:</label>
                    <span>${result.details.analysisTime}</span>
                </div>
            </div>
        </div>
        
        ${result.status !== 'safe' ? `
        <div class="threat-indicators">
            <h5>
                <i class="fas fa-exclamation-triangle"></i>
                Threat Indicators
            </h5>
            <div class="indicators-list">
                <div class="indicator ${result.status}">
                    <span class="indicator-dot"></span>
                    <span>${getThreatIndicator(result)}</span>
                </div>
                <div class="indicator warning">
                    <span class="indicator-dot"></span>
                    <span>Unusual network traffic patterns detected</span>
                </div>
                <div class="indicator warning">
                    <span class="indicator-dot"></span>
                    <span>Suspicious file transfer activity</span>
                </div>
            </div>
        </div>
        
        <div class="recommendations">
            <h5>
                <i class="fas fa-lightbulb"></i>
                Recommended Actions
            </h5>
            <ul>
                <li>Block identified malicious IP addresses</li>
                <li>Scan affected systems for malware</li>
                <li>Review and update firewall rules</li>
                <li>Notify security team for further investigation</li>
                <li>Update security protocols and monitoring rules</li>
            </ul>
        </div>
        ` : `
        <div class="safe-result">
            <div class="safe-icon">
                <i class="fas fa-shield-alt"></i>
            </div>
            <h5>No Threats Detected</h5>
            <p>This file has been thoroughly analyzed and no security threats were found. The analysis indicates normal, expected behavior.</p>
        </div>
        `}
    `;
    
    document.getElementById('detailModal').style.display = 'block';
    document.body.style.overflow = 'hidden';
}

function getThreatIndicator(result) {
    if (result.status === 'critical') {
        return 'Critical security threat requiring immediate attention';
    } else if (result.status === 'warning') {
        return 'Suspicious activity that requires investigation';
    }
    return 'No significant threats detected';
}

function closeDetailModal() {
    document.getElementById('detailModal').style.display = 'none';
    document.body.style.overflow = '';
}

function exportResult(resultId) {
    const result = currentResults.find(r => r.id === resultId);
    if (!result) return;
    
    showNotification(`Exporting analysis result for ${result.fileName}...`, 'info');
    
    // Simulate export process
    setTimeout(() => {
        showNotification(`Analysis report for ${result.fileName} exported successfully!`, 'success');
    }, 2000);
}

function exportAllResults() {
    if (selectedResults.size === 0) {
        showNotification('Please select results to export', 'warning');
        return;
    }
    
    showNotification(`Exporting ${selectedResults.size} analysis results...`, 'info');
    
    // Simulate export process
    setTimeout(() => {
        showNotification(`Successfully exported ${selectedResults.size} analysis reports!`, 'success');
    }, 3000);
}

function exportSingleResult() {
    // This would export the currently viewed result
    showNotification('Exporting detailed analysis report...', 'info');
    
    setTimeout(() => {
        showNotification('Detailed analysis report exported successfully!', 'success');
        closeDetailModal();
    }, 2000);
}

function deleteResult(resultId) {
    if (!confirm('Are you sure you want to delete this analysis result? This action cannot be undone.')) {
        return;
    }
    
    // Remove from current results
    currentResults = currentResults.filter(r => r.id !== resultId);
    filteredResults = filteredResults.filter(r => r.id !== resultId);
    selectedResults.delete(resultId);
    
    // Re-render results
    renderResults();
    updateSummaryCards();
    
    showNotification('Analysis result deleted successfully', 'success');
}

function showLoadingState() {
    const tableBody = document.getElementById('resultsTableBody');
    if (tableBody) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" class="loading-state">
                    <i class="fas fa-spinner fa-spin"></i>
                    <p>Loading analysis results...</p>
                </td>
            </tr>
        `;
    }
}

function hideLoadingState() {
    // Loading state is automatically removed when results are rendered
}

// Upload functionality (similar to dashboard)
let uploadedFiles = [];

function setupUploadFunctionality(uploadArea, fileInput) {
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
        // Show success notification
        showNotification(`Successfully analyzed ${uploadedFiles.length} file(s). Updating results...`, 'success');
        
        // Close modal and refresh results
        closeUploadModal();
        refreshResults();
    }, 3000);
}

// Utility functions
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
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

function toggleMobileMenu() {
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.querySelector('.mobile-overlay');
    
    sidebar.classList.toggle('mobile-open');
    overlay.classList.toggle('active');
    document.body.style.overflow = sidebar.classList.contains('mobile-open') ? 'hidden' : '';
}

// Close modals when clicking outside
window.addEventListener('click', function(event) {
    const uploadModal = document.getElementById('uploadModal');
    const detailModal = document.getElementById('detailModal');
    
    if (event.target === uploadModal) {
        closeUploadModal();
    }
    if (event.target === detailModal) {
        closeDetailModal();
    }
});

// Export functions for global access
window.showUploadModal = showUploadModal;
window.closeUploadModal = closeUploadModal;
window.analyzeFiles = analyzeFiles;
window.removeFile = removeFile;
window.filterResults = filterResults;
window.sortResults = sortResults;
window.toggleSelectAll = toggleSelectAll;
window.toggleResultSelection = toggleResultSelection;
window.previousPage = previousPage;
window.nextPage = nextPage;
window.refreshResults = refreshResults;
window.viewResultDetails = viewResultDetails;
window.closeDetailModal = closeDetailModal;
window.exportResult = exportResult;
window.exportAllResults = exportAllResults;
window.exportSingleResult = exportSingleResult;
window.deleteResult = deleteResult;
window.toggleMobileMenu = toggleMobileMenu;