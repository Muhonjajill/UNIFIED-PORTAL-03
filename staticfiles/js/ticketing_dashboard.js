const chartInstances = {};

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


  // === Chart Animation and Styling Config ===
  const animationOptions = {
    animation: {
      duration: 1600, 
      easing: 'easeInOutQuad', 
      onComplete: function () {
        // Animation complete callback (from the first config)
        console.log('Chart animation completed!');
        // You can add additional effects here when animation is complete
      }
    },
    responsive: true,
    plugins: {
      legend: {
        display: true,
        position: 'bottom',
        labels: {
          boxWidth: 15,
          padding: 20,
          font: {
            size: 14, 
          },
        },
      },
      tooltip: {
        enabled: true,
        backgroundColor: '#333',
        titleFont: { size: 14 }, 
        bodyFont: { size: 12 },
        padding: 10,
        caretPadding: 12,
      },
    },
  };



  // === Initialize Charts ===
  // Helper function to safely destroy existing chart
  function destroyExistingChart(canvasId) {
    const chartInstance = Chart.getChart(canvasId);
    if (chartInstance) {
      chartInstance.destroy();
      delete chartInstances[canvasId];
    }
  }


  const ticketReportChart = document.getElementById('ticketReportChart');
  if (ticketReportChart) {
    destroyExistingChart('ticketReportChart'); 

    const statusLabels = STATUS_DATA.map(item => item.status.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()));
    const statusCounts = STATUS_DATA.map(item => item.count);
    chartInstances[ticketReportChart.id] = new Chart(ticketReportChart, {
      type: 'bar',
      data: {
        labels: statusLabels,
        datasets: [{
          label: 'Tickets',
          data: statusCounts,
          backgroundColor: ['#007bff', '#ffc107', '#28a745'],
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
    chartInstances[monthlyTrendChart.id] = new Chart(monthlyTrendChart, {
      type: 'line',
      data: {
        labels: monthlyLabels,
        datasets: [{
          label: 'Tickets',
          data: monthlyCounts,
          borderColor: '#007bff',
          backgroundColor: 'rgba(0, 123, 255, 0.1)',
          tension: 0.3,
          fill: true,
          pointBackgroundColor: '#007bff'
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
    chartInstances[terminalChart.id] = new Chart(terminalChart, {
      type: 'bar',
      data: {
        labels: terminalLabels,
        datasets: [{
          label: 'Tickets',
          data: terminalCounts,
          backgroundColor: ['#6c757d', '#17a2b8', '#ffc107'],
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
    destroyExistingChart('regionChart');  // Destroy any existing chart instance

    const regionLabels = REGION_DATA.map(item => item.region || 'Unnamed');  // Update as per your model field
    const regionCounts = REGION_DATA.map(item => item.count);

    chartInstances[regionChart.id] = new Chart(regionChart, {
      type: 'bar',
      data: {
        labels: regionLabels,
        datasets: [{
          label: 'Tickets',
          data: regionCounts,
          backgroundColor: '#007bff', 
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

  const priorityLabels = PRIORITY_DATA.map(item => item.priority.replace(/\b\w/g, l => l.toUpperCase()));
  const priorityCounts = PRIORITY_DATA.map(item => item.count);

  chartInstances[priorityChart.id] = new Chart(priorityChart, {
    type: 'doughnut',
    data: {
      labels: priorityLabels,
      datasets: [{
        data: priorityCounts,
        backgroundColor: ['#007bff', '#ffc107', '#28a745', '#dc3545'],
        borderWidth: 2,
        borderColor: '#fff',
        hoverOffset: 12,
      }]
    },
    options: {
      ...animationOptions,
      cutout: '60%',
      plugins: {
        ...animationOptions.plugins,
        datalabels: {
          color: '#fff',
          font: { weight: 'bold', size: 12 },
          formatter: (value, context) => {
            const total = context.chart._metasets[0].total;
            return ((value / total) * 100).toFixed(1) + '%';
          }
        },
        tooltip: {
          callbacks: {
            label: function (context) {
              const label = context.label || '';
              const value = context.parsed;
              const total = context.chart._metasets[context.datasetIndex].total;
              const percent = ((value / total) * 100).toFixed(1);
              return `${label}: ${value} (${percent}%)`;
            }
          }
        }
      }
    },
    plugins: [ChartDataLabels]
  });
}


 const statusChart = document.getElementById('statusChart');
if (statusChart) {
  destroyExistingChart('statusChart');

  const statusLabels = STATUS_DATA.map(item => item.status.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()));
  const statusCounts = STATUS_DATA.map(item => item.count);

  chartInstances[statusChart.id] = new Chart(statusChart, {
    type: 'doughnut',
    data: {
      labels: statusLabels,
      datasets: [{
        data: statusCounts,
        backgroundColor: ['#28a745', '#ffc107', '#007bff', '#6c757d'],
        borderWidth: 2,
        borderColor: '#fff',
        hoverOffset: 12,
      }]
    },
    options: {
      ...animationOptions,
      cutout: '60%',
      plugins: {
        ...animationOptions.plugins,
        datalabels: {
          color: '#fff',
          font: { weight: 'bold', size: 12 },
          formatter: (value, context) => {
            const total = context.chart._metasets[0].total;
            return ((value / total) * 100).toFixed(1) + '%';
          }
        },
        tooltip: {
          callbacks: {
            label: function (context) {
              const label = context.label || '';
              const value = context.parsed;
              const total = context.chart._metasets[context.datasetIndex].total;
              const percent = ((value / total) * 100).toFixed(1);
              return `${label}: ${value} (${percent}%)`;
            }
          }
        }
      }
    },
    plugins: [ChartDataLabels]
  });
}


  const timeTrendChart = document.getElementById('timeTrendChart');
  if (timeTrendChart) {
    destroyExistingChart('timeTrendChart');

    chartInstances[timeTrendChart.id] = new Chart(timeTrendChart, {
      type: 'line',
      data: {
        labels: ['Day', 'Week', 'Month', 'Year'],
        datasets: [{
          label: 'Ticket Volume',
          data: [TIME_DATA.day, TIME_DATA.week, TIME_DATA.month, TIME_DATA.year],
          borderColor: '#17a2b8',
          backgroundColor: 'rgba(23, 162, 184, 0.1)',
          fill: true,
          tension: 0.4,
          pointBackgroundColor: '#17a2b8'
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

    chartInstances[categoryTimeChart.id] = new Chart(categoryTimeChart, {
      type: 'bar',
      data: {
        labels: categoryLabels,
        datasets: [{
          label: 'Tickets by Category',
          data: categoryCounts,
          backgroundColor: '#6f42c1',
          borderRadius: 4,
          barThickness: 30
        }]
      },
      options: animationOptions
    });
  }

  const overviewChart = document.getElementById('overviewChart');
  const overviewLabels = OVERVIEW_DATA.map(item => item.label);
  const overviewCounts = OVERVIEW_DATA.map(item => item.count);
  if (overviewChart){
    destroyExistingChart('overviewChart');
  chartInstances[overviewChart.id] = new Chart(overviewChart, {
    type: 'bar',
    data: {
      labels: overviewLabels,
      datasets: [{
        label: 'Ticket Counts',
        data: overviewCounts,
        backgroundColor: ['#007bff', '#ffc107', '#28a745', '#dc3545'],
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

    chartInstances[customerChart.id] = new Chart(customerChart, {
      type: 'bar',
      data: {
        labels: CUSTOMER_DATA.map(c => c.customer),
        datasets: [{
          label: 'Tickets',
          data: CUSTOMER_DATA.map(c => c.count),
          backgroundColor: '#fd7e14',
          borderRadius: 4,
          barThickness: 30
        }]
      },
      options: animationOptions
    });
  }

  console.log("ticketing_dashboard.js executed successfully. Chart.js available:", typeof Chart !== "undefined");
});
