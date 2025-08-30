// Custom JavaScript for Employee Leave Management System

document.addEventListener('DOMContentLoaded', function() {
    
    // Auto-hide flash messages after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
    
    // Add loading spinner to form submissions
    const forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('input[type="submit"], button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                const originalText = submitBtn.value || submitBtn.textContent;
                if (submitBtn.tagName === 'INPUT') {
                    submitBtn.value = 'Processing...';
                } else {
                    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
                }
                
                // Re-enable after 3 seconds in case of errors
                setTimeout(function() {
                    submitBtn.disabled = false;
                    if (submitBtn.tagName === 'INPUT') {
                        submitBtn.value = originalText;
                    } else {
                        submitBtn.textContent = originalText;
                    }
                }, 3000);
            }
        });
    });
    
    // Confirmation dialogs for destructive actions
    const deleteLinks = document.querySelectorAll('a[onclick*="confirm"]');
    deleteLinks.forEach(function(link) {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const message = link.getAttribute('onclick').match(/confirm\('([^']+)'/)[1];
            if (confirm(message)) {
                window.location.href = link.href;
            }
        });
        // Remove inline onclick
        link.removeAttribute('onclick');
    });
    
    // Date validation for leave request forms
    const startDateInput = document.getElementById('start_date');
    const endDateInput = document.getElementById('end_date');
    
    if (startDateInput && endDateInput) {
        function validateDates() {
            const startDate = new Date(startDateInput.value);
            const endDate = new Date(endDateInput.value);
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            
            // Check if start date is in the past
            if (startDate < today) {
                startDateInput.setCustomValidity('Start date cannot be in the past');
            } else {
                startDateInput.setCustomValidity('');
            }
            
            // Check if end date is before start date
            if (endDate < startDate) {
                endDateInput.setCustomValidity('End date cannot be before start date');
            } else {
                endDateInput.setCustomValidity('');
            }
            
            // Calculate and display days
            if (startDate && endDate && endDate >= startDate) {
                const diffTime = Math.abs(endDate - startDate);
                const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;
                
                let daysDisplay = document.getElementById('days-display');
                if (!daysDisplay) {
                    daysDisplay = document.createElement('small');
                    daysDisplay.id = 'days-display';
                    daysDisplay.className = 'text-info mt-1 d-block';
                    endDateInput.parentNode.appendChild(daysDisplay);
                }
                daysDisplay.innerHTML = `<i class="bi bi-info-circle"></i> Total days: ${diffDays}`;
            }
        }
        
        startDateInput.addEventListener('change', validateDates);
        endDateInput.addEventListener('change', validateDates);
        
        // Set minimum date to today
        const today = new Date().toISOString().split('T')[0];
        startDateInput.setAttribute('min', today);
        endDateInput.setAttribute('min', today);
    }
    
    // Search functionality for tables
    const searchInputs = document.querySelectorAll('input[placeholder*="Search"]');
    searchInputs.forEach(function(input) {
        input.addEventListener('keyup', function() {
            const filter = input.value.toLowerCase();
            const table = input.closest('.card').querySelector('table tbody');
            if (table) {
                const rows = table.querySelectorAll('tr');
                rows.forEach(function(row) {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(filter) ? '' : 'none';
                });
            }
        });
    });
    
    // Tooltip initialization for Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Auto-refresh data every 30 seconds for dashboard pages
    if (window.location.pathname.includes('dashboard')) {
        setInterval(function() {
            // Only refresh if user is active (has interacted in last 5 minutes)
            if (Date.now() - window.lastActivity < 300000) {
                // Add subtle indication of refresh
                const refreshIndicator = document.createElement('div');
                refreshIndicator.className = 'position-fixed top-0 end-0 p-3';
                refreshIndicator.innerHTML = '<div class="toast show" role="alert"><div class="toast-body"><i class="bi bi-arrow-clockwise"></i> Refreshing data...</div></div>';
                document.body.appendChild(refreshIndicator);
                
                setTimeout(function() {
                    refreshIndicator.remove();
                }, 2000);
                
                // In a real application, you would make an AJAX call here
                // For now, we'll just reload the page
                // window.location.reload();
            }
        }, 30000);
    }
    
    // Track user activity
    window.lastActivity = Date.now();
    document.addEventListener('mousedown', function() {
        window.lastActivity = Date.now();
    });
    document.addEventListener('keydown', function() {
        window.lastActivity = Date.now();
    });
    
    // Form field character counter
    const textareas = document.querySelectorAll('textarea[maxlength]');
    textareas.forEach(function(textarea) {
        const maxLength = textarea.getAttribute('maxlength');
        const counter = document.createElement('small');
        counter.className = 'text-muted';
        textarea.parentNode.appendChild(counter);
        
        function updateCounter() {
            const remaining = maxLength - textarea.value.length;
            counter.textContent = `${textarea.value.length}/${maxLength} characters`;
            if (remaining < 50) {
                counter.className = 'text-warning';
            } else {
                counter.className = 'text-muted';
            }
        }
        
        textarea.addEventListener('input', updateCounter);
        updateCounter();
    });
    
    // Enhance select dropdowns with search (if using a library like Choices.js)
    // This would require including the Choices.js library
    /*
    const selectElements = document.querySelectorAll('select.searchable');
    selectElements.forEach(function(select) {
        new Choices(select, {
            searchEnabled: true,
            itemSelectText: '',
            shouldSort: false
        });
    });
    */
    
    // Quick keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Alt + N for new leave request (on employee dashboard)
        if (e.altKey && e.key === 'n' && window.location.pathname.includes('employee')) {
            const newButton = document.querySelector('a[href*="apply-leave"]');
            if (newButton) {
                newButton.click();
            }
        }
        
        // Alt + D for dashboard
        if (e.altKey && e.key === 'd') {
            const dashboardLink = document.querySelector('a[href*="dashboard"]');
            if (dashboardLink) {
                dashboardLink.click();
            }
        }
        
        // Escape to close modals
        if (e.key === 'Escape') {
            const openModals = document.querySelectorAll('.modal.show');
            openModals.forEach(function(modal) {
                const bsModal = bootstrap.Modal.getInstance(modal);
                if (bsModal) {
                    bsModal.hide();
                }
            });
        }
    });
    
    // Add visual feedback for long-running operations
    function showLoadingOverlay(message = 'Loading...') {
        const overlay = document.createElement('div');
        overlay.id = 'loading-overlay';
        overlay.className = 'position-fixed top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center';
        overlay.style.backgroundColor = 'rgba(0,0,0,0.5)';
        overlay.style.zIndex = '9999';
        overlay.innerHTML = `
            <div class="bg-white p-4 rounded text-center">
                <div class="spinner-border text-primary mb-3"></div>
                <div>${message}</div>
            </div>
        `;
        document.body.appendChild(overlay);
    }
    
    function hideLoadingOverlay() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.remove();
        }
    }
    
    // Export functions for use in other scripts
    window.ELMS = {
        showLoadingOverlay: showLoadingOverlay,
        hideLoadingOverlay: hideLoadingOverlay
    };
    
    console.log('ELMS JavaScript initialized successfully');
});
