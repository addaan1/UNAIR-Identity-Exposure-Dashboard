/* ========================================================================== 
   UNAIR Identity Exposure Intelligence Dashboard
   Light UI interactions and Chart.js renderer
   ========================================================================== */

const UNAIR_PALETTE = {
  blue: '#174B89',
  blueDark: '#0B315F',
  blueSoft: '#EAF2FB',
  gold: '#FFC50B',
  navy: '#051B2C',
  slate: '#64748B',
  border: '#D8E1EC',
  red: '#DC2626',
  orange: '#EA580C',
  amber: '#D97706',
  green: '#16A34A',
  teal: '#0F766E',
  violet: '#7C3AED',
  sky: '#0284C7',
};

const CHART_COLORS = [
  UNAIR_PALETTE.blue,
  UNAIR_PALETTE.gold,
  UNAIR_PALETTE.sky,
  UNAIR_PALETTE.green,
  UNAIR_PALETTE.violet,
  UNAIR_PALETTE.orange,
  UNAIR_PALETTE.teal,
  '#6B7280',
  '#2563EB',
  '#A16207',
];

const SEVERITY_COLORS = [
  UNAIR_PALETTE.red,
  UNAIR_PALETTE.orange,
  UNAIR_PALETTE.amber,
  UNAIR_PALETTE.green,
];

function initSidebar() {
  const toggle = document.getElementById('sidebarToggle');
  const isMobile = () => window.matchMedia('(max-width: 760px)').matches;

  if (!toggle) return;

  if (localStorage.getItem('unairSidebarCollapsed') === 'true' && !isMobile()) {
    document.body.classList.add('sidebar-collapsed');
  }

  toggle.addEventListener('click', () => {
    if (isMobile()) {
      document.body.classList.toggle('sidebar-open');
      return;
    }
    document.body.classList.toggle('sidebar-collapsed');
    localStorage.setItem(
      'unairSidebarCollapsed',
      document.body.classList.contains('sidebar-collapsed') ? 'true' : 'false'
    );
  });

  document.addEventListener('click', (event) => {
    if (!isMobile() || !document.body.classList.contains('sidebar-open')) return;
    const sidebar = document.getElementById('appSidebar');
    if (!sidebar || sidebar.contains(event.target) || toggle.contains(event.target)) return;
    document.body.classList.remove('sidebar-open');
  });
}

function configureChartDefaults() {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.font.family = "Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";
  Chart.defaults.font.size = 11.5;
  Chart.defaults.color = '#4B5563';
  Chart.defaults.plugins.legend.labels.usePointStyle = true;
  Chart.defaults.plugins.legend.labels.boxWidth = 8;
  Chart.defaults.plugins.legend.labels.padding = 14;
  Chart.defaults.plugins.legend.labels.font = { weight: '600' };
  Chart.defaults.plugins.tooltip.backgroundColor = '#051B2C';
  Chart.defaults.plugins.tooltip.titleColor = '#FFFFFF';
  Chart.defaults.plugins.tooltip.bodyColor = '#E5E7EB';
  Chart.defaults.plugins.tooltip.borderColor = '#FFC50B';
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.cornerRadius = 10;
  Chart.defaults.plugins.tooltip.padding = 12;
  Chart.defaults.animation.duration = 650;
  Chart.defaults.animation.easing = 'easeOutQuart';
}

const gridOptions = {
  color: '#E5ECF4',
  drawBorder: false,
};

function renderBarChart(el, labels, values, label, options = {}) {
  return new Chart(el, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label,
        data: values,
        backgroundColor: options.multiColor ? CHART_COLORS : UNAIR_PALETTE.blue,
        borderRadius: 7,
        maxBarThickness: options.maxBarThickness || 28,
        barPercentage: 0.7,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: options.horizontal ? 'y' : 'x',
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: options.horizontal ? gridOptions : { display: false }, beginAtZero: true },
        y: { grid: options.horizontal ? { display: false } : gridOptions, beginAtZero: true },
      },
    },
  });
}

async function renderAllCharts() {
  if (typeof Chart === 'undefined') return;
  configureChartDefaults();

  const hasAnyChart = document.querySelector('canvas[id^="chart"]');
  if (!hasAnyChart) return;

  try {
    const response = await fetch('/api/chart-data/');
    if (!response.ok) throw new Error('Failed to fetch chart API');
    const data = await response.json();

    const goalsEl = document.getElementById('chartGoals');
    if (goalsEl && data.goals) {
      new Chart(goalsEl, {
        type: 'bar',
        data: {
          labels: data.goals.labels,
          datasets: [
            {
              label: 'Capaian Aktual (%)',
              data: data.goals.actual_values,
              backgroundColor: UNAIR_PALETTE.blue,
              borderRadius: 7,
              barPercentage: 0.65,
            },
            {
              label: 'Target (%)',
              data: data.goals.target_values,
              backgroundColor: '#FCD34D',
              borderColor: UNAIR_PALETTE.gold,
              borderWidth: 1,
              borderRadius: 7,
              barPercentage: 0.65,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: { legend: { position: 'bottom' } },
          scales: {
            x: { max: 100, grid: gridOptions, ticks: { callback: v => `${v}%` } },
            y: { grid: { display: false }, ticks: { color: UNAIR_PALETTE.navy, font: { weight: '600' } } },
          },
        },
      });
    }

    const facultyEl = document.getElementById('chartFaculty');
    if (facultyEl && data.faculty) {
      renderBarChart(facultyEl, data.faculty.labels, data.faculty.values, 'Insiden Exposure', { horizontal: true, multiColor: true, maxBarThickness: 24 });
    }

    const riskEl = document.getElementById('chartRiskLevel');
    if (riskEl && data.risk_level) {
      new Chart(riskEl, {
        type: 'doughnut',
        data: {
          labels: data.risk_level.labels,
          datasets: [{ data: data.risk_level.values, backgroundColor: SEVERITY_COLORS, borderColor: '#FFFFFF', borderWidth: 4, hoverOffset: 5 }],
        },
        options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { position: 'right' } } },
      });
    }

    const timelineEl = document.getElementById('chartTimeline');
    if (timelineEl && data.timeline) {
      new Chart(timelineEl, {
        type: 'line',
        data: {
          labels: data.timeline.labels,
          datasets: [{
            label: 'Deteksi Bulanan',
            data: data.timeline.values,
            borderColor: UNAIR_PALETTE.blue,
            borderWidth: 2.5,
            backgroundColor: (context) => {
              const ctx = context.chart.ctx;
              const gradient = ctx.createLinearGradient(0, 0, 0, 220);
              gradient.addColorStop(0, 'rgba(23, 75, 137, 0.22)');
              gradient.addColorStop(1, 'rgba(23, 75, 137, 0)');
              return gradient;
            },
            fill: true,
            tension: 0.35,
            pointBackgroundColor: '#FFFFFF',
            pointBorderColor: UNAIR_PALETTE.blue,
            pointBorderWidth: 2,
            pointRadius: 4,
            pointHoverRadius: 6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { x: { grid: { display: false } }, y: { grid: gridOptions, beginAtZero: true } },
        },
      });
    }

    const acctEl = document.getElementById('chartAccountType');
    if (acctEl && data.account_type) {
      new Chart(acctEl, {
        type: 'doughnut',
        data: { labels: data.account_type.labels, datasets: [{ data: data.account_type.values, backgroundColor: CHART_COLORS, borderColor: '#FFFFFF', borderWidth: 4, hoverOffset: 5 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { position: 'right' } } },
      });
    }

    const rolesEl = document.getElementById('chartFacultyRoles');
    if (rolesEl && data.faculty_roles) {
      new Chart(rolesEl, {
        type: 'bar',
        data: {
          labels: data.faculty_roles.labels,
          datasets: [
            { label: 'Mahasiswa', data: data.faculty_roles.students, backgroundColor: UNAIR_PALETTE.blue, borderRadius: 4 },
            { label: 'Dosen', data: data.faculty_roles.lecturers, backgroundColor: UNAIR_PALETTE.gold, borderRadius: 4 },
            { label: 'Staf', data: data.faculty_roles.staff, backgroundColor: UNAIR_PALETTE.green, borderRadius: 4 },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: { legend: { position: 'bottom' } },
          scales: { x: { stacked: true, grid: gridOptions }, y: { stacked: true, grid: { display: false } } },
        },
      });
    }

    const typesEl = document.getElementById('chartExposureTypes');
    if (typesEl && data.exposure_types) {
      new Chart(typesEl, {
        type: 'polarArea',
        data: { labels: data.exposure_types.labels, datasets: [{ data: data.exposure_types.values, backgroundColor: CHART_COLORS.map(c => `${c}B8`), borderColor: '#FFFFFF', borderWidth: 2 }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right' } }, scales: { r: { grid: { color: '#E5ECF4' }, ticks: { display: false } } } },
      });
    }

    const domainEl = document.getElementById('chartTopDomains');
    if (domainEl && data.top_domains) {
      renderBarChart(domainEl, data.top_domains.labels, data.top_domains.values, 'Insiden Domain', { horizontal: true, maxBarThickness: 26 });
    }

    const remediationEl = document.getElementById('chartRemediation');
    if (remediationEl && data.remediation) {
      new Chart(remediationEl, {
        type: 'doughnut',
        data: { labels: data.remediation.labels, datasets: [{ data: data.remediation.values, backgroundColor: [UNAIR_PALETTE.gold, UNAIR_PALETTE.blue, UNAIR_PALETTE.sky, UNAIR_PALETTE.green, UNAIR_PALETTE.teal, UNAIR_PALETTE.red], borderColor: '#FFFFFF', borderWidth: 4, hoverOffset: 5 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { position: 'right' } } },
      });
    }
  } catch (error) {
    console.warn('Chart rendering skipped:', error.message);
  }
}

function initIncidentDrilldown() {
  const buttons = document.querySelectorAll('.incident-toggle[data-target]');
  buttons.forEach((button) => {
    button.addEventListener('click', () => {
      const target = document.getElementById(button.dataset.target);
      if (!target) return;
      const willOpen = target.hasAttribute('hidden');
      target.toggleAttribute('hidden', !willOpen);
      button.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
      button.textContent = willOpen ? 'Tutup insiden' : 'Lihat insiden';
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initSidebar();
  initIncidentDrilldown();
  renderAllCharts();
});
