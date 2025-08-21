window.addEventListener('DOMContentLoaded', () => {

  // === User Profile Dropdown Toggle ===
  const userProfile = document.getElementById('userProfile');
  if (userProfile) {
    userProfile.addEventListener('click', function (event) {
      this.classList.toggle('active');
      event.stopPropagation();
    });
    window.addEventListener('click', function (event) {
      if (!userProfile.contains(event.target)) {
        userProfile.classList.remove('active');
      }
    });
  }

  // === Sidebar Submenu Toggles ===
  const masterDataToggle = document.getElementById('masterDataToggle');
  if (masterDataToggle) {
    masterDataToggle.addEventListener('click', function (event) {
      event.preventDefault();
      this.classList.toggle('expanded');
    });
  }

  const reportsToggle = document.getElementById('reportsToggle');
  if (reportsToggle) {
    reportsToggle.addEventListener('click', function (event) {
      event.preventDefault();
      this.classList.toggle('expanded');
    });
  }

  // === Hamburger menu toggle ===
  const dashboardHamburger = document.getElementById('hamburger');
  const dashboardSidebar = document.getElementById('sidebar');
  if (dashboardHamburger && dashboardSidebar) {
    dashboardHamburger.addEventListener('click', function () {
      dashboardSidebar.classList.toggle('active');
    });
    document.addEventListener('click', function (event) {
      if (dashboardSidebar.classList.contains('active') &&
          !dashboardSidebar.contains(event.target) &&
          !dashboardHamburger.contains(event.target)) {
        dashboardSidebar.classList.remove('active');
      }
    });
  }

  // === Search Filter Function (targets dashboard cards) ===
  const searchInput = document.getElementById('navbarSearchInput');
  if (searchInput) {
    searchInput.addEventListener('keyup', function () {
      const query = this.value.toLowerCase().trim();
      const cards = document.querySelectorAll('.dashboard-grid .card');
      cards.forEach(card => {
        const title = card.querySelector('.card-title')?.innerText.toLowerCase();
        card.style.display = title?.includes(query) ? '' : 'none';
      });
    });
  }

  // === Global Color Mapping (Revised) ===
  // This must be defined BEFORE animationOptions
  const COLOR_MAP = {
    // Primary Action/Highlight Colors
    primary: '#007ACC',            // A vibrant, reliable blue
    secondary: '#FF8C00',          // A warm, engaging orange

    // Status/Categorization Colors
    success: '#4CAF50',            // Classic green for success/positive
    warning: '#FFC107',            // Bright yellow for warning/pending
    danger: '#DC3545',             // Clear red for critical/urgent
    info: '#17A2B8',               // Standard teal for informational/time-based

    // Neutral/Supporting Colors
    neutralDark: '#34495E',        // Deep, modern charcoal for text/background elements
    neutralLight: '#ECF0F1',       // Soft, light gray for backgrounds/borders
    textDark: '#2C3E50',           // Darker text for readability
    textLight: '#7F8C8D',          // Lighter gray for secondary text

    // Lighter Tones for Backgrounds/Fills
    primaryLight: 'rgba(0, 122, 204, 0.15)',  // Light primary for fills
    infoLight: 'rgba(23, 162, 184, 0.15)',    // Light info for fills

    // Gradient Set for diverse categories or multi-series charts
    gradientSet: [
      '#007ACC', // Vibrant Blue
      '#673AB7', // Deep Purple
      '#FF8C00', // Engaging Orange
      '#00BCD4', // Cyan/Teal
      '#8BC34A', // Lime Green
      '#FF5722', // Deep Orange/Red
      '#9C27B0', // Magenta/Violet
      '#FFD700'  // Gold (for highlights or specific categories)
    ],

    // Specific Use Case Colors (adjust as needed based on your data)
    terminalRegionBase: '#4A6572' // A muted blue-gray for terminal/region base tone
  };

  // === Chart Animation and Styling Config ===
  const animationOptions = {
    animation: {
      duration: 1200, // Slightly reduced duration for quicker feedback
      easing: 'easeOutQuart', // Smoother, more natural easing curve
      onComplete: function (animation) {
        console.log('Chart animation completed!');
      }
    },
    responsive: true,
    maintainAspectRatio: false, // Allow charts to fill container without strict aspect ratio
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          boxWidth: 15,
          padding: 20,
          font: {
            size: 14,
            family: 'Roboto, sans-serif',
          },
          color: COLOR_MAP.textDark,
        },
      },
      tooltip: {
        enabled: true,
        backgroundColor: COLOR_MAP.neutralDark,
        titleFont: {
          size: 14,
          weight: 'bold',
          family: 'Roboto, sans-serif',
        },
        bodyFont: {
          size: 12,
          family: 'Roboto, sans-serif',
        },
        padding: 12,
        caretPadding: 10,
        cornerRadius: 8,
        displayColors: true,
        borderColor: COLOR_MAP.primary,
        borderWidth: 1,
      },
    },
    hover: {
      mode: 'nearest',
      intersect: true,
      animationDuration: 400,
    },
    scales: {
      x: {
        ticks: {
          color: COLOR_MAP.textLight,
          font: {
            family: 'Roboto, sans-serif',
          }
        },
        grid: {
          color: COLOR_MAP.neutralLight,
          borderColor: COLOR_MAP.neutralLight,
        }
      },
      y: {
        ticks: {
          color: COLOR_MAP.textLight,
          font: {
            family: 'Roboto, sans-serif',
          }
        },
        grid: {
          color: COLOR_MAP.neutralLight,
          borderColor: COLOR_MAP.neutralLight,
        }
      }
    }
  };

  // === Initialize Charts ===
  // Helper function to safely destroy existing chart
  function destroyExistingChart(canvasId) {
    const chartInstance = Chart.getChart(canvasId);
    if (chartInstance) {
      chartInstance.destroy();
    }
  }

  const ticketReportChart = document.getElementById('ticketReportChart');
  if (ticketReportChart) {
    destroyExistingChart('ticketReportChart');
    const statusLabels = STATUS_DATA.map(item => item.status.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()));
    const statusCounts = STATUS_DATA.map(item => item.count);
    new Chart(ticketReportChart, {
      type: 'bar',
      data: {
        labels: statusLabels,
        datasets: [{
          label: 'Tickets',
          data: statusCounts,
          backgroundColor: [COLOR_MAP.primary, COLOR_MAP.warning, COLOR_MAP.success, COLOR_MAP.danger],
          borderRadius: 5,
          barThickness: 40
        }]
      },
      options: {
        ...animationOptions,
        scales: {
          y: {
            beginAtZero: true,
            ticks: { stepSize: 1 },
            grid: { drawBorder: false }
          },
          x: {
            grid: { display: false }
          }
        }
      }
    });
  }

  const monthlyTrendChart = document.getElementById('monthlyTrendChart');
  if (monthlyTrendChart) {
    destroyExistingChart('monthlyTrendChart');
    const monthlyLabels = MONTHLY_DATA.map(item => item.month);
    const monthlyCounts = MONTHLY_DATA.map(item => item.count);
    new Chart(monthlyTrendChart, {
      type: 'line',
      data: {
        labels: monthlyLabels,
        datasets: [{
          label: 'Tickets',
          data: monthlyCounts,
          borderColor: COLOR_MAP.primary,
          backgroundColor: COLOR_MAP.primaryLight,
          tension: 0.3,
          fill: true,
          pointBackgroundColor: COLOR_MAP.primary
        }]
      },
      options: {
        ...animationOptions,
        scales: {
          y: {
            beginAtZero: true
          }
        }
      }
    });
  }

  const terminalChart = document.getElementById('terminalChart');
  if (terminalChart) {
    destroyExistingChart('terminalChart');
    const terminalLabels = TERMINAL_DATA.map(item => item.terminal || 'Unnamed');
    const terminalCounts = TERMINAL_DATA.map(item => item.count);
    new Chart(terminalChart, {
      type: 'bar',
      data: {
        labels: terminalLabels,
        datasets: [{
          label: 'Tickets',
          data: terminalCounts,
          backgroundColor: COLOR_MAP.gradientSet,
          borderRadius: 5,
          barThickness: 35
        }]
      },
      options: {
        ...animationOptions,
        scales: {
          y: {
            beginAtZero: true
          },
          x: {
            grid: { display: false }
          }
        }
      }
    });
  }

  // === Region-wise Ticket Volume ===
  const regionChart = document.getElementById('regionChart');
  if (regionChart) {
    destroyExistingChart('regionChart');
    const regionLabels = REGION_DATA.map(item => item.region || 'Unnamed');
    const regionCounts = REGION_DATA.map(item => item.count);
    new Chart(regionChart, {
      type: 'bar',
      data: {
        labels: regionLabels,
        datasets: [{
          label: 'Tickets',
          data: regionCounts,
          backgroundColor: COLOR_MAP.gradientSet,
          borderRadius: 5,
          barThickness: 35
        }]
      },
      options: animationOptions
    });
  }

  const priorityChart = document.getElementById('priorityChart');
  if (priorityChart) {
    destroyExistingChart('priorityChart');
    console.log(PRIORITY_DATA);
    const priorityLabels = PRIORITY_DATA.map(item => item.priority.replace(/\b\w/g, l => l.toUpperCase()));
    const priorityCounts = PRIORITY_DATA.map(item => item.count);
    new Chart(priorityChart, {
      type: 'pie',
      data: {
        labels: priorityLabels,
        datasets: [{
          data: priorityCounts,
          backgroundColor: [COLOR_MAP.danger, COLOR_MAP.warning, COLOR_MAP.success, COLOR_MAP.primary],
          borderColor: '#fff',
          borderWidth: 2
        }]
      },
      options: animationOptions
    });
  }

  const statusChart = document.getElementById('statusChart');
  if (statusChart) {
    destroyExistingChart('statusChart');
    const statusLabels = STATUS_DATA.map(item => item.status.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()));
    const statusCounts = STATUS_DATA.map(item => item.count);
    new Chart(statusChart, {
      type: 'pie',
      data: {
        labels: statusLabels,
        datasets: [{
          data: statusCounts,
          backgroundColor: [COLOR_MAP.success, COLOR_MAP.warning, COLOR_MAP.primary, COLOR_MAP.neutralDark],
          borderColor: '#fff',
          borderWidth: 2
        }]
      },
      options: animationOptions
    });
  }

  const timeTrendChart = document.getElementById('timeTrendChart');
  if (timeTrendChart) {
    destroyExistingChart('timeTrendChart');
    new Chart(timeTrendChart, {
      type: 'line',
      data: {
        labels: ['Day', 'Week', 'Month', 'Year'],
        datasets: [{
          label: 'Ticket Volume',
          data: [TIME_DATA.day, TIME_DATA.week, TIME_DATA.month, TIME_DATA.year],
          borderColor: COLOR_MAP.info,
          backgroundColor: COLOR_MAP.infoLight,
          fill: true,
          tension: 0.4,
          pointBackgroundColor: COLOR_MAP.info
        }]
      },
      options: animationOptions
    });
  }

  const categoryChart = document.getElementById('categoryChart');
  if (categoryChart) {
    destroyExistingChart('categoryChart');
    new Chart(categoryChart, {
      type: 'bar',
      data: {
        labels: CATEGORY_DATA.map(c => c.category),
        datasets: [{
          label: 'Tickets',
          data: CATEGORY_DATA.map(c => c.count),
          backgroundColor: COLOR_MAP.gradientSet[1],
          borderRadius: 4,
          barThickness: 30
        }]
      },
      options: animationOptions
    });
  }

  const categoryTimeChart = document.getElementById('categoryTimeChart');
  if (categoryTimeChart) {
    destroyExistingChart('categoryTimeChart');
    const categoryLabels = CATEGORY_TIME_DATA.map(item => item.category);
    const categoryCounts = CATEGORY_TIME_DATA.map(item => item.daily_count);
    new Chart(categoryTimeChart, {
      type: 'bar',
      data: {
        labels: categoryLabels,
        datasets: [{
          label: 'Tickets by Category',
          data: categoryCounts,
          backgroundColor: COLOR_MAP.gradientSet[2],
          borderRadius: 4,
          barThickness: 30
        }]
      },
      options: animationOptions
    });
  }

  const overviewChart = document.getElementById('overviewChart');
  if (typeof OVERVIEW_DATA !== 'undefined' && overviewChart) {
    const overviewLabels = OVERVIEW_DATA.map(item => item.label);
    const overviewCounts = OVERVIEW_DATA.map(item => item.count);

    destroyExistingChart('overviewChart');

    new Chart(overviewChart, {
      type: 'bar',
      data: {
        labels: overviewLabels,
        datasets: [{
          label: 'Ticket Counts',
          data: overviewCounts,
          backgroundColor: [
            COLOR_MAP.gradientSet[0],
            COLOR_MAP.gradientSet[1],
            COLOR_MAP.gradientSet[2],
            COLOR_MAP.gradientSet[3]
          ],
          borderRadius: 5,
          barThickness: 40
        }]
      },
      options: animationOptions
    });
  }

  const customerChart = document.getElementById('customerChart');
  if (customerChart) {
    destroyExistingChart('customerChart');
    new Chart(customerChart, {
      type: 'bar',
      data: {
        labels: CUSTOMER_DATA.map(c => c.customer),
        datasets: [{
          label: 'Tickets',
          data: CUSTOMER_DATA.map(c => c.count),
          backgroundColor: COLOR_MAP.secondary,
          borderRadius: 4,
          barThickness: 30
        }]
      },
      options: animationOptions
    });
  }

  console.log("ticketing_dashboard.js executed successfully. Chart.js available:", typeof Chart !== "undefined");

});