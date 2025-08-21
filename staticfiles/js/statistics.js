$(document).ready(function() {

    // Declare chart instances outside of updateCharts function
    let dayChart, weekdayChart, hourChart, monthChart, yearChart, statusChart, terminalChart, categoryChart, monthlyChart;

    // Initialize the chart rendering with the default data
    updateCharts(data);

    // Function to destroy existing chart if it exists
    function destroyChart(chartInstance) {
        if (chartInstance) {
            chartInstance.destroy();
        }
    }

    // Function to create gradient color
    function createGradient(ctx, chartArea, colorStart, colorEnd) {
        if (!chartArea) return; // Ensure chartArea exists before applying gradient

        let gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
        gradient.addColorStop(0, colorStart);
        gradient.addColorStop(1, colorEnd);
        return gradient;
    }

    function updateCharts(data) {
        const ctxDay = document.getElementById('ticketsPerDayChart').getContext('2d');
        const ctxWeekday = document.getElementById('ticketsPerWeekdayChart').getContext('2d');
        const ctxHour = document.getElementById('ticketsPerHourChart').getContext('2d');
        const ctxMonth = document.getElementById('ticketsPerMonthChart').getContext('2d');
        const ctxYear = document.getElementById('ticketsPerYearChart').getContext('2d');
        const ctxStatus = document.getElementById('ticketStatusChart').getContext('2d');
        const ctxTerminal = document.getElementById('ticketsPerTerminalChart').getContext('2d');
        const ctxCategory = document.getElementById('ticketsByCategoryChart').getContext('2d');
        const ctxMonthly = document.getElementById('monthlyTicketTrendsChart').getContext('2d');

        // Destroy the previous charts if they exist
        destroyChart(dayChart);
        destroyChart(weekdayChart);
        destroyChart(hourChart);
        destroyChart(monthChart);
        destroyChart(yearChart);
        destroyChart(statusChart);
        destroyChart(terminalChart);
        destroyChart(categoryChart);
        destroyChart(monthlyChart);

        // Per day chart with gradient animation
        dayChart = new Chart(ctxDay, {
            type: 'bar',
            data: {
                labels: data.days,
                datasets: [{
                    label: 'Tickets per Day',
                    data: data.ticketsPerDay,
                    backgroundColor: function(context) {
                        const chartArea = context.chart.chartArea;
                        return createGradient(ctxDay, chartArea, '#007bff', '#00b0ff');
                    },
                }]
            },
            options: {
                responsive: true,
                animation: {
                    duration: 1000, 
                    easing: 'easeOutQuart',
                },
                plugins: {
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(0, 123, 255, 0.8)',
                    }
                },
                events: ['resize', 'afterUpdate'], // Ensure chart area is updated
                onResize: function(chart) {
                    chart.update();
                }
            }
        });

        // Per weekday chart with gradient animation
        weekdayChart = new Chart(ctxWeekday, {
            type: 'bar',
            data: {
                labels: data.weekdays,
                datasets: [{
                    label: 'Tickets per Weekday',
                    data: data.ticketsPerWeekday,
                    backgroundColor: function(context) {
                        const chartArea = context.chart.chartArea;
                        return createGradient(ctxWeekday, chartArea, '#28a745', '#32e52f');
                    },
                }]
            },
            options: {
                responsive: true,
                animation: {
                    duration: 1000,
                    easing: 'easeOutQuart',
                },
                plugins: {
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(40, 167, 69, 0.8)',
                    }
                },
                events: ['resize', 'afterUpdate'],
                onResize: function(chart) {
                    chart.update();
                }
            }
        });

        // Per hour chart with gradient animation
        hourChart = new Chart(ctxHour, {
            type: 'bar',
            data: {
                labels: data.hours,
                datasets: [{
                    label: 'Tickets per Hour',
                    data: data.ticketsPerHour,
                    backgroundColor: function(context) {
                        const chartArea = context.chart.chartArea;
                        return createGradient(ctxHour, chartArea, '#ffc107', '#ffcc00');
                    },
                }]
            },
            options: {
                responsive: true,
                animation: {
                    duration: 1000,
                    easing: 'easeOutQuart',
                },
                plugins: {
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(255, 193, 7, 0.8)',
                    }
                },
                events: ['resize', 'afterUpdate'],
                onResize: function(chart) {
                    chart.update();
                }
            }
        });

        // Per month chart with gradient animation
        monthChart = new Chart(ctxMonth, {
            type: 'bar',
            data: {
                labels: data.months,
                datasets: [{
                    label: 'Tickets per Month',
                    data: data.ticketsPerMonth,
                    backgroundColor: function(context) {
                        const chartArea = context.chart.chartArea;
                        return createGradient(ctxMonth, chartArea, '#dc3545', '#e02f3a');
                    },
                }]
            },
            options: {
                responsive: true,
                animation: {
                    duration: 1000,
                    easing: 'easeOutQuart',
                },
                plugins: {
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(220, 53, 69, 0.8)',
                    }
                },
                events: ['resize', 'afterUpdate'],
                onResize: function(chart) {
                    chart.update();
                }
            }
        });

        // Per year chart with gradient animation
        yearChart = new Chart(ctxYear, {
            type: 'bar',
            data: {
                labels: data.years,
                datasets: [{
                    label: 'Tickets per Year',
                    data: data.ticketsPerYear,
                    backgroundColor: function(context) {
                        const chartArea = context.chart.chartArea;
                        return createGradient(ctxYear, chartArea, '#17a2b8', '#20c1d7');
                    },
                }]
            },
            options: {
                responsive: true,
                animation: {
                    duration: 1000,
                    easing: 'easeOutQuart',
                },
                plugins: {
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(23, 162, 184, 0.8)',
                    }
                },
                events: ['resize', 'afterUpdate'],
                onResize: function(chart) {
                    chart.update();
                }
            }
        });

        // Ticket statuses chart (Pie chart) with hover animations
        statusChart = new Chart(ctxStatus, {
            type: 'pie',
            data: {
                labels: data.ticketStatuses.labels, // Get status labels from data
                datasets: [{
                    label: 'Ticket Statuses',
                    data: data.ticketStatuses.data, // Get status counts from data
                    backgroundColor: ['#007bff', '#28a745', '#ffc107', '#dc3545'],
                }]
            },
            options: {
                responsive: true,
                animation: {
                    animateRotate: true,
                    animateScale: true,
                    duration: 1000,
                },
                plugins: {
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(0, 123, 255, 0.8)',
                    },
                    // Custom Plugin to display the numbers/percentages below the chart
                    datalabels: {
                        display: true,
                        color: '#fff',
                        formatter: (value, context) => {
                            const total = context.chart._metasets[0].data.reduce((acc, val) => acc + val, 0);
                            const percentage = ((value / total) * 100).toFixed(2);  // Calculate percentage
                            return `${value} (${percentage}%)`;  // Format as number and percentage
                        },
                        font: {
                            weight: 'bold',
                            size: 14
                        },
                        anchor: 'end',
                        align: 'center',
                        offset: 10
                    }
                },
                events: ['resize', 'afterUpdate'],
                onResize: function(chart) {
                    chart.update();
                }
            }
        });

        // Tickets per Terminal Chart
        terminalChart = new Chart(ctxTerminal, {
            type: 'bar',
            data: {
                //labels: data.terminals.map(terminal => terminal.branch_name),
                labels: data.ticketsPerTerminal.map(entry => entry.branch_name),
                datasets: [{
                    label: 'Tickets per Terminal',
                   // data: data.ticketsPerTerminal,
                   data: data.ticketsPerTerminal.map(entry => entry.count),
                    backgroundColor: function(context) {
                        const chartArea = context.chart.chartArea;
                        return createGradient(ctxTerminal, chartArea, '#007bff', '#00b0ff');
                    },
                }]
            },
            options: {
                responsive: true,
                animation: { duration: 1000, easing: 'easeOutQuart' },
            }
        });

        // Tickets by Category (Radar Chart)
        categoryChart = new Chart(ctxCategory, {
            type: 'radar',
            data: {
                labels: data.ticketCategories.labels,
                datasets: [{
                    label: 'Tickets by Category',
                    data: data.ticketCategories.data,
                    backgroundColor: 'rgba(0, 123, 255, 0.3)', 
                    borderColor: '#007bff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                scale: { ticks: { beginAtZero: true } }
            }
        });

        // Monthly Ticket Trends (Line Chart)
        monthlyChart = new Chart(ctxMonthly, {
            type: 'line',
            data: {
                labels: data.months,
                datasets: [{
                    label: 'Monthly Ticket Trends',
                    data: data.ticketsPerMonth,
                    fill: true,
                    backgroundColor: '#007bff',
                    borderColor: '#0056b3',
                    borderWidth: 2,
                }]
            },
            options: {
                responsive: true,
                animation: { duration: 1000, easing: 'easeOutQuart' },
                plugins: { tooltip: { backgroundColor: 'rgba(0, 123, 255, 0.8)' } }
            }
        });

    }

    function updateTicketStatusBreakdown(labels, data) {
        const total = data.reduce((acc, value) => acc + value, 0);
        let breakdownHTML = '';
        labels.forEach((label, index) => {
            const count = data[index];
            const percentage = ((count / total) * 100).toFixed(2);
            breakdownHTML += `<p><strong>${label}:</strong> ${count} tickets (${percentage}%)</p>`;
        });
        document.getElementById('ticket-status-breakdown').innerHTML = breakdownHTML;
    }

    // Call the function to display the breakdown
    updateTicketStatusBreakdown(data.ticketStatuses.labels, data.ticketStatuses.data);
    
    // Populate Dropdowns
    function populateDropdown(id, items, idKey, nameKey) {
        const dropdown = document.getElementById(id);
        dropdown.innerHTML = "";
        items.forEach(item => {
            const opt = document.createElement("option");
            opt.value = item[idKey];
            opt.text = item[nameKey];
            dropdown.appendChild(opt);
        });
    }

    // Apply the initial data
    populateDropdown("customer-filter", data.customers, "id", "name");
    populateDropdown("region-filter", data.regions, "id", "name");
    populateDropdown("terminal-filter", data.terminals, "id", "branch_name");

    // Handle filter changes and update charts dynamically
    $('#time-period, #customer-filter, #terminal-filter, #region-filter').change(function() {
        console.log("Filter changed");
        const timePeriod = $('#time-period').val();
        const customer = $('#customer-filter').val();
        const terminal = $('#terminal-filter').val();
        const region = $('#region-filter').val();

        $.ajax({
            url: '/statistics/',
            type: 'GET',
            data: {
                'time-period': timePeriod,
                'customer': customer,
                'terminal': terminal,
                'region': region,
            },
            success: function(response) {
                console.log("Server response:", response);
                if (response) {
                    try {
                        console.log("New Data:", response);
                        updateCharts(response); 
                    } catch (error) {
                        console.error("Error while updating charts:", error);
                    }
                } else {
                    console.error("No data received from server.");
                }
            },
            error: function(xhr, status, error) {
                console.error("AJAX error:", status, error);
            }
        });
    });

});
