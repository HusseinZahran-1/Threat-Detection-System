// Authentication functionality

// Global variables
let passwordStrength = 0;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeAuth();
    setupAuthEventListeners();
});

function initializeAuth() {
    console.log('Auth system initialized');
    
    // Check if user is already logged in
    checkAuthStatus();
    
    // Initialize password strength checker
    initializePasswordStrength();
}

function setupAuthEventListeners() {
    // Login form submission
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // Register form submission
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
    
    // Password strength real-time checking
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', updatePasswordStrength);
    }
    
    // Email validation
    const emailInput = document.getElementById('email');
    if (emailInput) {
        emailInput.addEventListener('blur', validateEmail);
    }
    
    // Confirm password validation
    const confirmPasswordInput = document.getElementById('confirmPassword');
    if (confirmPasswordInput) {
        confirmPasswordInput.addEventListener('input', validateConfirmPassword);
    }
    
    // Social auth buttons
    const socialButtons = document.querySelectorAll('.btn-social');
    socialButtons.forEach(button => {
        button.addEventListener('click', handleSocialAuth);
    });
}

function checkAuthStatus() {
    const authToken = localStorage.getItem('authToken');
    const userData = localStorage.getItem('userData');
    
    if (authToken && userData) {
        // User is logged in, redirect to dashboard if on auth pages
        if (window.location.pathname.includes('register.html') || 
            window.location.pathname.includes('index.html')) {
            window.location.href = 'dashboard.html';
        }
    } else {
        // User is not logged in
        if (window.location.pathname.includes('dashboard.html') || 
            window.location.pathname.includes('results.html')) {
            window.location.href = 'index.html';
        }
    }
}

function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    const rememberMe = document.getElementById('rememberMe').checked;
    
    // Validation
    if (!validateLoginForm(email, password)) {
        return;
    }
    
    // Show loading state
    const submitBtn = e.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing In...';
    submitBtn.classList.add('btn-loading');
    submitBtn.disabled = true;
    
    // Simulate API call
    setTimeout(() => {
        // For demo purposes, always succeed
        const userData = {
            id: 1,
            email: email,
            firstName: 'John',
            lastName: 'Smith',
            company: 'Demo Corp',
            role: 'administrator'
        };
        
        // Store auth data
        localStorage.setItem('authToken', 'demo-token-' + Date.now());
        localStorage.setItem('userData', JSON.stringify(userData));
        localStorage.setItem('rememberMe', rememberMe.toString());
        
        // Show success notification
        showNotification('Successfully signed in! Redirecting to dashboard...', 'success');
        
        // Redirect to dashboard
        setTimeout(() => {
            window.location.href = 'dashboard.html';
        }, 1500);
        
    }, 2000);
}

function handleRegister(e) {
    e.preventDefault();
    
    const firstName = document.getElementById('firstName').value;
    const lastName = document.getElementById('lastName').value;
    const email = document.getElementById('email').value;
    const company = document.getElementById('company').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const terms = document.getElementById('terms').checked;
    const newsletter = document.getElementById('newsletter').checked;
    
    // Validation
    if (!validateRegisterForm(firstName, lastName, email, password, confirmPassword, terms)) {
        return;
    }
    
    // Show loading state
    const submitBtn = document.getElementById('registerBtn');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating Account...';
    submitBtn.classList.add('btn-loading');
    submitBtn.disabled = true;
    
    // Simulate API call
    setTimeout(() => {
        // For demo purposes, always succeed
        const userData = {
            id: Math.floor(Math.random() * 1000),
            email: email,
            firstName: firstName,
            lastName: lastName,
            company: company,
            role: 'user',
            newsletter: newsletter
        };
        
        // Store auth data
        localStorage.setItem('authToken', 'demo-token-' + Date.now());
        localStorage.setItem('userData', JSON.stringify(userData));
        
        // Show success notification
        showNotification('Account created successfully! Welcome to ThreatShield AI.', 'success');
        
        // Redirect to dashboard
        setTimeout(() => {
            window.location.href = 'dashboard.html';
        }, 2000);
        
    }, 3000);
}

function validateLoginForm(email, password) {
    let isValid = true;
    
    // Reset previous errors
    clearLoginErrors();
    
    // Email validation
    if (!email) {
        showLoginError('loginEmail', 'Email is required');
        isValid = false;
    } else if (!isValidEmail(email)) {
        showLoginError('loginEmail', 'Please enter a valid email address');
        isValid = false;
    }
    
    // Password validation
    if (!password) {
        showLoginError('loginPassword', 'Password is required');
        isValid = false;
    } else if (password.length < 6) {
        showLoginError('loginPassword', 'Password must be at least 6 characters');
        isValid = false;
    }
    
    return isValid;
}

function validateRegisterForm(firstName, lastName, email, password, confirmPassword, terms) {
    let isValid = true;
    
    // Reset previous errors
    clearRegisterErrors();
    
    // First name validation
    if (!firstName) {
        showRegisterError('firstName', 'First name is required');
        isValid = false;
    }
    
    // Last name validation
    if (!lastName) {
        showRegisterError('lastName', 'Last name is required');
        isValid = false;
    }
    
    // Email validation
    if (!email) {
        showRegisterError('email', 'Email is required');
        isValid = false;
    } else if (!isValidEmail(email)) {
        showRegisterError('email', 'Please enter a valid email address');
        isValid = false;
    }
    
    // Password validation
    if (!password) {
        showRegisterError('password', 'Password is required');
        isValid = false;
    } else if (password.length < 8) {
        showRegisterError('password', 'Password must be at least 8 characters');
        isValid = false;
    } else if (passwordStrength < 3) {
        showRegisterError('password', 'Please choose a stronger password');
        isValid = false;
    }
    
    // Confirm password validation
    if (!confirmPassword) {
        showRegisterError('confirmPassword', 'Please confirm your password');
        isValid = false;
    } else if (password !== confirmPassword) {
        showRegisterError('confirmPassword', 'Passwords do not match');
        isValid = false;
    }
    
    // Terms validation
    if (!terms) {
        showRegisterError('terms', 'You must agree to the terms and conditions');
        isValid = false;
    }
    
    return isValid;
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function showLoginError(fieldId, message) {
    const field = document.getElementById(fieldId);
    const feedback = document.createElement('div');
    feedback.className = 'input-feedback error';
    feedback.textContent = message;
    feedback.id = fieldId + 'Feedback';
    
    field.parentNode.appendChild(feedback);
    field.style.borderColor = 'var(--danger-color)';
}

function showRegisterError(fieldId, message) {
    let feedbackElement = document.getElementById(fieldId + 'Feedback');
    
    if (!feedbackElement) {
        const field = document.getElementById(fieldId);
        feedbackElement = document.createElement('div');
        feedbackElement.className = 'input-feedback error';
        feedbackElement.id = fieldId + 'Feedback';
        
        if (fieldId === 'terms') {
            field.parentNode.appendChild(feedbackElement);
        } else {
            field.parentNode.appendChild(feedbackElement);
        }
    }
    
    feedbackElement.textContent = message;
    
    if (fieldId !== 'terms') {
        const field = document.getElementById(fieldId);
        field.style.borderColor = 'var(--danger-color)';
    }
}

function clearLoginErrors() {
    const feedbacks = document.querySelectorAll('#loginForm .input-feedback');
    feedbacks.forEach(feedback => feedback.remove());
    
    const inputs = document.querySelectorAll('#loginForm input');
    inputs.forEach(input => {
        input.style.borderColor = 'var(--border-color)';
    });
}

function clearRegisterErrors() {
    const feedbacks = document.querySelectorAll('#registerForm .input-feedback');
    feedbacks.forEach(feedback => feedback.remove());
    
    const inputs = document.querySelectorAll('#registerForm input');
    inputs.forEach(input => {
        input.style.borderColor = 'var(--border-color)';
    });
}

function initializePasswordStrength() {
    const passwordInput = document.getElementById('password');
    if (!passwordInput) return;
    
    // Initialize requirement indicators
    updateRequirementIndicator('reqLength', false);
    updateRequirementIndicator('reqUppercase', false);
    updateRequirementIndicator('reqLowercase', false);
    updateRequirementIndicator('reqNumber', false);
    updateRequirementIndicator('reqSpecial', false);
}

function updatePasswordStrength() {
    const password = document.getElementById('password').value;
    const strengthFill = document.getElementById('strengthFill');
    const strengthText = document.getElementById('strengthText');
    
    let strength = 0;
    let color = 'var(--danger-color)';
    let text = 'Very Weak';
    
    // Check requirements
    const hasLength = password.length >= 8;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);
    
    // Update requirement indicators
    updateRequirementIndicator('reqLength', hasLength);
    updateRequirementIndicator('reqUppercase', hasUppercase);
    updateRequirementIndicator('reqLowercase', hasLowercase);
    updateRequirementIndicator('reqNumber', hasNumber);
    updateRequirementIndicator('reqSpecial', hasSpecial);
    
    // Calculate strength
    if (hasLength) strength += 20;
    if (hasUppercase) strength += 20;
    if (hasLowercase) strength += 20;
    if (hasNumber) strength += 20;
    if (hasSpecial) strength += 20;
    
    // Update strength meter
    passwordStrength = Math.floor(strength / 20); // 0-5 scale
    
    if (strength >= 80) {
        color = 'var(--success-color)';
        text = 'Very Strong';
    } else if (strength >= 60) {
        color = 'var(--success-color)';
        text = 'Strong';
    } else if (strength >= 40) {
        color = 'var(--warning-color)';
        text = 'Medium';
    } else if (strength >= 20) {
        color = 'var(--warning-color)';
        text = 'Weak';
    }
    
    if (strengthFill) {
        strengthFill.style.width = strength + '%';
        strengthFill.style.backgroundColor = color;
    }
    
    if (strengthText) {
        strengthText.textContent = text;
        strengthText.style.color = color;
    }
}

function updateRequirementIndicator(elementId, isValid) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    if (isValid) {
        element.classList.add('valid');
        element.querySelector('i').className = 'fas fa-check-circle';
    } else {
        element.classList.remove('valid');
        element.querySelector('i').className = 'fas fa-circle';
    }
}

function validateEmail() {
    const email = document.getElementById('email').value;
    const feedback = document.getElementById('emailFeedback');
    
    if (!feedback) return;
    
    if (!email) {
        feedback.textContent = '';
        feedback.className = 'input-feedback';
    } else if (!isValidEmail(email)) {
        feedback.textContent = 'Please enter a valid email address';
        feedback.className = 'input-feedback error';
    } else {
        feedback.textContent = 'Email address is valid';
        feedback.className = 'input-feedback valid';
    }
}

function validateConfirmPassword() {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const feedback = document.getElementById('confirmPasswordFeedback');
    
    if (!feedback) return;
    
    if (!confirmPassword) {
        feedback.textContent = '';
        feedback.className = 'input-feedback';
    } else if (password !== confirmPassword) {
        feedback.textContent = 'Passwords do not match';
        feedback.className = 'input-feedback error';
    } else {
        feedback.textContent = 'Passwords match';
        feedback.className = 'input-feedback valid';
    }
}

function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    const toggleButton = field.parentNode.querySelector('.password-toggle');
    const icon = toggleButton.querySelector('i');
    
    if (field.type === 'password') {
        field.type = 'text';
        icon.className = 'fas fa-eye-slash';
        toggleButton.setAttribute('aria-label', 'Hide password');
    } else {
        field.type = 'password';
        icon.className = 'fas fa-eye';
        toggleButton.setAttribute('aria-label', 'Show password');
    }
}

function handleSocialAuth(e) {
    const provider = e.target.classList.contains('btn-google') ? 'google' :
                    e.target.classList.contains('btn-microsoft') ? 'microsoft' : 'github';
    
    // Show loading state
    const originalText = e.target.innerHTML;
    e.target.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Connecting...';
    e.target.disabled = true;
    
    // Simulate social auth
    setTimeout(() => {
        showNotification(`Connecting with ${provider}... (Demo mode)`, 'info');
        
        // Reset button
        e.target.innerHTML = originalText;
        e.target.disabled = false;
        
        // In a real app, this would redirect to OAuth flow
    }, 1500);
}

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        // Clear auth data
        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');
        
        // Show notification
        showNotification('You have been successfully logged out.', 'info');
        
        // Redirect to home page
        setTimeout(() => {
            window.location.href = 'index.html';
        }, 1000);
    }
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

// Export functions for global access
window.togglePassword = togglePassword;
window.logout = logout;