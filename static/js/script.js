/**
 * Phishing URL Detection System - Client Scripts
 * Handles Chart.js visualization, UI animations, and UX enhancements.
 */

document.addEventListener('DOMContentLoaded', () => {
    initMobileNav();
    initDashboardCharts();
    initFormScanAnimations();
});

/**
 * Mobile Navigation Menu Toggle
 */
function initMobileNav() {
    const toggleBtn = document.getElementById('mobileMenuBtn');
    const navMenu = document.getElementById('navMenu');

    if (toggleBtn && navMenu) {
        function closeNav() {
            navMenu.classList.remove('show');
            toggleBtn.setAttribute('aria-expanded', 'false');
            const icon = toggleBtn.querySelector('i');
            if (icon) {
                icon.classList.remove('fa-xmark');
                icon.classList.add('fa-bars');
            }
        }

        toggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = navMenu.classList.toggle('show');
            toggleBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
            const icon = toggleBtn.querySelector('i');
            if (icon) {
                if (isOpen) {
                    icon.classList.remove('fa-bars');
                    icon.classList.add('fa-xmark');
                } else {
                    icon.classList.remove('fa-xmark');
                    icon.classList.add('fa-bars');
                }
            }
        });

        // Close menu when tapping any nav link
        navMenu.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', () => {
                closeNav();
            });
        });

        // Close menu when clicking outside
        document.addEventListener('click', (e) => {
            if (navMenu.classList.contains('show') && !navMenu.contains(e.target) && !toggleBtn.contains(e.target)) {
                closeNav();
            }
        });

        // Close menu on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && navMenu.classList.contains('show')) {
                closeNav();
            }
        });

        // Reset if window resizes to desktop width
        window.addEventListener('resize', () => {
            if (window.innerWidth > 768 && navMenu.classList.contains('show')) {
                closeNav();
            }
        });
    }
}

/**
 * Initialize Dashboard Chart.js Visualizations
 */
function initDashboardCharts() {
    const classChartCanvas = document.getElementById('classificationChart');
    const riskChartCanvas = document.getElementById('riskDistributionChart');

    if (!classChartCanvas && !riskChartCanvas) {
        return;
    }

    const data = window.DASHBOARD_DATA || {
        total: 0,
        phishing: 0,
        safe: 0,
        high: 0,
        medium: 0,
        low: 0
    };

    // Global Chart.js dark theme defaults
    if (window.Chart) {
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = "'Inter', sans-serif";
    }

    // 1. Classification Donut Chart (Safe vs Phishing)
    if (classChartCanvas && window.Chart) {
        const hasData = (data.safe + data.phishing) > 0;
        const ctx = classChartCanvas.getContext('2d');

        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: hasData ? ['Safe URLs', 'Phishing URLs'] : ['No Scans Logged'],
                datasets: [{
                    data: hasData ? [data.safe, data.phishing] : [1],
                    backgroundColor: hasData 
                        ? ['#10b981', '#ef4444'] 
                        : ['rgba(56, 80, 130, 0.4)'],
                    borderColor: '#0d1424',
                    borderWidth: 3,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 16,
                            usePointStyle: true,
                            font: { size: 12, weight: 600 }
                        }
                    },
                    tooltip: {
                        enabled: hasData,
                        backgroundColor: '#11192e',
                        titleColor: '#f1f5f9',
                        bodyColor: '#94a3b8',
                        borderColor: 'rgba(56, 80, 130, 0.6)',
                        borderWidth: 1,
                        padding: 12
                    }
                },
                cutout: '72%'
            }
        });
    }

    // 2. Risk Level Distribution Bar Chart (Low, Med, High)
    if (riskChartCanvas && window.Chart) {
        const ctx = riskChartCanvas.getContext('2d');
        const hasData = (data.low + data.medium + data.high) > 0;

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Low Risk (0–30)', 'Med Risk (31–70)', 'High Risk (71–100)'],
                datasets: [{
                    label: 'Analyzed URLs',
                    data: hasData ? [data.low, data.medium, data.high] : [0, 0, 0],
                    backgroundColor: [
                        'rgba(16, 185, 129, 0.8)',
                        'rgba(245, 158, 11, 0.8)',
                        'rgba(239, 68, 68, 0.8)'
                    ],
                    borderColor: [
                        '#10b981',
                        '#f59e0b',
                        '#ef4444'
                    ],
                    borderWidth: 1.5,
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0,
                            color: '#64748b'
                        },
                        grid: {
                            color: 'rgba(56, 80, 130, 0.15)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#94a3b8',
                            font: { size: 11, weight: 500 }
                        },
                        grid: {
                            display: false
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: '#11192e',
                        titleColor: '#f1f5f9',
                        bodyColor: '#94a3b8',
                        borderColor: 'rgba(56, 80, 130, 0.6)',
                        borderWidth: 1,
                        padding: 10
                    }
                }
            }
        });
    }
}

/**
 * Loading State / Scanning Spinner Animation on Forms
 */
function initFormScanAnimations() {
    const scanForms = [
        document.getElementById('quickScanForm'),
        document.getElementById('fullAnalyzerForm')
    ];

    scanForms.forEach(form => {
        if (!form) return;
        form.addEventListener('submit', (e) => {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                const originalHtml = submitBtn.innerHTML;
                submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Analyzing Features...</span>';
                submitBtn.style.opacity = '0.85';
            }
        });
    });
}
