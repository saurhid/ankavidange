// Toggle sidebar
const sidebarToggle = document.getElementById('sidebar-toggle');
const wrapper = document.getElementById('wrapper');

if (sidebarToggle) {
    sidebarToggle.addEventListener('click', function(e) {
        e.preventDefault();
        wrapper.classList.toggle('toggled');
        localStorage.setItem('sidebarCollapsed', wrapper.classList.contains('toggled'));
    });
}

// Restore sidebar state on page load
document.addEventListener('DOMContentLoaded', function() {
    const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    if (isCollapsed) {
        wrapper.classList.add('toggled');
    }
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// Auto-dismiss alerts
setTimeout(function() {
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function(alert) {
        const bsAlert = new bootstrap.Alert(alert);
        bsAlert.close();
    });
}, 5000);

// Confirm before performing destructive actions
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('confirm-action')) {
        if (!confirm('Êtes-vous sûr de vouloir effectuer cette action ? Cette action est irréversible.')) {
            e.preventDefault();
        }
    }
});

// Search functionality for tables
document.addEventListener('DOMContentLoaded', function() {
    const searchInputs = document.querySelectorAll('.table-search');
    
    searchInputs.forEach(function(input) {
        input.addEventListener('keyup', function() {
            const tableId = this.dataset.table;
            const table = document.getElementById(tableId);
            const filter = this.value.toLowerCase();
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const cells = row.getElementsByTagName('td');
                let found = false;
                
                for (let j = 0; j < cells.length; j++) {
                    const cell = cells[j];
                    if (cell) {
                        const textValue = cell.textContent || cell.innerText;
                        if (textValue.toLowerCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }
                
                row.style.display = found ? '' : 'none';
            }
        });
    });
});

// Initialize date pickers
if (typeof flatpickr !== 'undefined') {
    document.querySelectorAll('.datepicker').forEach(function(element) {
        flatpickr(element, {
            dateFormat: 'Y-m-d',
            allowInput: true,
            locale: 'fr',
            disableMobile: true
        });
    });
    
    document.querySelectorAll('.datetimepicker').forEach(function(element) {
        flatpickr(element, {
            enableTime: true,
            dateFormat: 'Y-m-d H:i',
            allowInput: true,
            locale: 'fr',
            disableMobile: true
        });
    });
}

// Initialize select2 if available
if (typeof $ !== 'undefined' && $.fn.select2) {
    $('.select2').select2({
        theme: 'bootstrap-5',
        width: '100%'
    });
}

// Toggle password visibility
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const icon = document.querySelector(`[data-target="#${inputId}"] i`);
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

// Initialize charts if Chart.js is available
if (typeof Chart !== 'undefined') {
    document.addEventListener('DOMContentLoaded', function() {
        const chartElements = document.querySelectorAll('.chart-container');
        
        chartElements.forEach(function(chartElement) {
            const canvas = chartElement.querySelector('canvas');
            if (!canvas) return;
            
            const ctx = canvas.getContext('2d');
            const chartData = JSON.parse(chartElement.dataset.chartData || '{}');
            
            if (Object.keys(chartData).length === 0) return;
            
            new Chart(ctx, {
                type: chartData.type || 'bar',
                data: chartData.data || {},
                options: chartData.options || {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        });
    });
}
