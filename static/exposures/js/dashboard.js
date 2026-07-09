/* ═══════════════════════════════════════════════════════════════════════════
   UNAIR IDENTITY EXPOSURE INTELLIGENCE — CHART.JS EXECUTIVE DARK RENDERER
   Precision Height Management & Premium Dark Cyber Palette
   ═══════════════════════════════════════════════════════════════════════════ */

const CYBER_PALETTE = {
  gold:      '#FFC50B',
  goldSoft:  '#FDE047',
  cyan:      '#0EA5E9',
  sky:       '#38BDF8',
  blue:      '#3B82F6',
  indigo:    '#6366F1',
  emerald:   '#10B981',
  teal:      '#14B8A6',
  amber:     '#F59E0B',
  orange:    '#F97316',
  red:       '#EF4444',
  purple:    '#8B5CF6',
  pink:      '#EC4899',
};

const CHART_COLORS = [
  CYBER_PALETTE.cyan,
  CYBER_PALETTE.gold,
  CYBER_PALETTE.indigo,
  CYBER_PALETTE.emerald,
  CYBER_PALETTE.purple,
  CYBER_PALETTE.orange,
  CYBER_PALETTE.pink,
  CYBER_PALETTE.teal,
  CYBER_PALETTE.sky,
  CYBER_PALETTE.amber,
];

const SEVERITY_COLORS = [
  CYBER_PALETTE.red,
  CYBER_PALETTE.orange,
  CYBER_PALETTE.gold,
  CYBER_PALETTE.emerald
];

function configureChartDefaults() {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.font.family = "'Plus Jakarta Sans', system-ui, sans-serif";
  Chart.defaults.font.size = 11.5;
  Chart.defaults.color = '#94A3B8';
  Chart.defaults.plugins.legend.labels.usePointStyle = true;
  Chart.defaults.plugins.legend.labels.boxWidth = 8;
  Chart.defaults.plugins.legend.labels.padding = 14;
  Chart.defaults.plugins.legend.labels.font = { weight: '600' };
  
  Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(13, 23, 42, 0.95)';
  Chart.defaults.plugins.tooltip.titleColor = '#F8FAFC';
  Chart.defaults.plugins.tooltip.bodyColor = '#E2E8F0';
  Chart.defaults.plugins.tooltip.borderColor = 'rgba(255, 197, 11, 0.35)';
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.cornerRadius = 10;
  Chart.defaults.plugins.tooltip.padding = 12;
  Chart.defaults.animation.duration = 750;
  Chart.defaults.animation.easing = 'easeOutQuart';
}

async function renderAllCharts() {
  if (typeof Chart === 'undefined') return;
  configureChartDefaults();

  const hasOverview = document.getElementById('chartGoals') || document.getElementById('chartFaculty');
  const hasDomain = document.getElementById('chartTopDomains');
  const hasRemediation = document.getElementById('chartRemediation');

  if (!hasOverview && !hasDomain && !hasRemediation) return;

  try {
    const response = await fetch('/api/chart-data/');
    if (!response.ok) throw new Error('Failed to fetch chart API');
    const data = await response.json();

    // ── 1. GOALS & TARGET SLA CHART (Compact & Crisp Bar) ──
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
              backgroundColor: CYBER_PALETTE.cyan,
              borderRadius: 6,
              barPercentage: 0.65,
            },
            {
              label: 'Target SLA 2026 (%)',
              data: data.goals.target_values,
              backgroundColor: 'rgba(255, 197, 11, 0.35)',
              borderColor: CYBER_PALETTE.gold,
              borderWidth: 1.5,
              borderRadius: 6,
              barPercentage: 0.65,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: { position: 'bottom' },
          },
          scales: {
            x: {
              max: 100,
              grid: { color: 'rgba(255,255,255,0.05)' },
              ticks: { callback: v => v + '%' },
            },
            y: {
              grid: { display: false },
              ticks: { color: '#F8FAFC', font: { weight: '600' } },
            },
          },
        },
      });
    }

    // ── 2. FACULTY EXPOSURE BAR CHART ──
    const facultyEl = document.getElementById('chartFaculty');
    if (facultyEl && data.faculty) {
      new Chart(facultyEl, {
        type: 'bar',
        data: {
          labels: data.faculty.labels,
          datasets: [{
            label: 'Insiden Exposure',
            data: data.faculty.values,
            backgroundColor: CHART_COLORS,
            borderRadius: 6,
            maxBarThickness: 24,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: 'rgba(255,255,255,0.05)' } },
            y: { grid: { display: false }, ticks: { color: '#E2E8F0' } },
          },
        },
      });
    }

    // ── 3. RISK LEVEL DISTRIBUISON DOUGHNUT (STRICT COMPACT CUTOUT) ──
    const riskEl = document.getElementById('chartRiskLevel');
    if (riskEl && data.risk_level) {
      new Chart(riskEl, {
        type: 'doughnut',
        data: {
          labels: data.risk_level.labels,
          datasets: [{
            data: data.risk_level.values,
            backgroundColor: SEVERITY_COLORS,
            borderColor: '#0D172A',
            borderWidth: 3,
            hoverOffset: 6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: { position: 'right' },
          },
        },
      });
    }

    // ── 4. TIMELINE AREA TREND CHART ──
    const timelineEl = document.getElementById('chartTimeline');
    if (timelineEl && data.timeline) {
      new Chart(timelineEl, {
        type: 'line',
        data: {
          labels: data.timeline.labels,
          datasets: [{
            label: 'Deteksi Bulanan',
            data: data.timeline.values,
            borderColor: CYBER_PALETTE.cyan,
            borderWidth: 2.5,
            backgroundColor: (context) => {
              const ctx = context.chart.ctx;
              const gradient = ctx.createLinearGradient(0, 0, 0, 240);
              gradient.addColorStop(0, 'rgba(14, 165, 233, 0.35)');
              gradient.addColorStop(1, 'rgba(14, 165, 233, 0.0)');
              return gradient;
            },
            fill: true,
            tension: 0.35,
            pointBackgroundColor: CYBER_PALETTE.cyan,
            pointBorderColor: '#070D18',
            pointBorderWidth: 2,
            pointRadius: 4,
            pointHoverRadius: 7,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: 'rgba(255,255,255,0.05)' } },
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
          },
        },
      });
    }

    // ── 5. ACCOUNT TYPE DOUGHNUT ──
    const acctEl = document.getElementById('chartAccountType');
    if (acctEl && data.account_type) {
      new Chart(acctEl, {
        type: 'doughnut',
        data: {
          labels: data.account_type.labels,
          datasets: [{
            data: data.account_type.values,
            backgroundColor: [CYBER_PALETTE.blue, CYBER_PALETTE.purple, CYBER_PALETTE.pink, CYBER_PALETTE.gold, CYBER_PALETTE.emerald],
            borderColor: '#0D172A',
            borderWidth: 3,
            hoverOffset: 6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: { position: 'right' },
          },
        },
      });
    }

    // ── 6. STACKED FACULTY ROLES ──
    const rolesEl = document.getElementById('chartFacultyRoles');
    if (rolesEl && data.faculty_roles) {
      new Chart(rolesEl, {
        type: 'bar',
        data: {
          labels: data.faculty_roles.labels,
          datasets: [
            { label: 'Mahasiswa', data: data.faculty_roles.students, backgroundColor: CYBER_PALETTE.cyan, borderRadius: 4 },
            { label: 'Dosen', data: data.faculty_roles.lecturers, backgroundColor: CYBER_PALETTE.purple, borderRadius: 4 },
            { label: 'Staf', data: data.faculty_roles.staff, backgroundColor: CYBER_PALETTE.gold, borderRadius: 4 },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: { legend: { position: 'bottom' } },
          scales: {
            x: { stacked: true, grid: { color: 'rgba(255,255,255,0.05)' } },
            y: { stacked: true, grid: { display: false } },
          },
        },
      });
    }

    // ── 7. EXPOSURE TYPES POLAR AREA ──
    const typesEl = document.getElementById('chartExposureTypes');
    if (typesEl && data.exposure_types) {
      new Chart(typesEl, {
        type: 'polarArea',
        data: {
          labels: data.exposure_types.labels,
          datasets: [{
            data: data.exposure_types.values,
            backgroundColor: CHART_COLORS.map(c => c + 'AA'),
            borderColor: '#0D172A',
            borderWidth: 2,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'right' } },
          scales: {
            r: {
              grid: { color: 'rgba(255,255,255,0.08)' },
              ticks: { display: false },
            },
          },
        },
      });
    }

    // ── 8. TOP DOMAINS (DOMAIN RISK PAGE) ──
    if (hasDomain && data.top_domains) {
      new Chart(hasDomain, {
        type: 'bar',
        data: {
          labels: data.top_domains.labels,
          datasets: [{
            label: 'Insiden Domain',
            data: data.top_domains.values,
            backgroundColor: CYBER_PALETTE.cyan,
            borderRadius: 6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: 'rgba(255,255,255,0.05)' } },
            y: { grid: { display: false } },
          },
        },
      });
    }

    // ── 9. REMEDIATION STATUS DOUGHNUT (REMEDIATION PAGE) ──
    if (hasRemediation && data.remediation) {
      new Chart(hasRemediation, {
        type: 'doughnut',
        data: {
          labels: data.remediation.labels,
          datasets: [{
            data: data.remediation.values,
            backgroundColor: [CYBER_PALETTE.gold, CYBER_PALETTE.cyan, CYBER_PALETTE.blue, CYBER_PALETTE.emerald, CYBER_PALETTE.teal, CYBER_PALETTE.red],
            borderColor: '#0D172A',
            borderWidth: 3,
            hoverOffset: 6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: { position: 'right' },
          },
        },
      });
    }

  } catch (err) {
    console.warn('Chart render error:', err);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  if (typeof Chart !== 'undefined') {
    renderAllCharts();
  } else {
    window.addEventListener('load', renderAllCharts);
  }
});
