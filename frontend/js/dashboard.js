/**
 * CyberGuard - Security Analytics Dashboard Controller
 * Zero-Knowledge Architecture: Renders only non-invertible aggregate metrics.
 */

let classificationChart = null;
let lengthChart = null;
let weaknessChart = null;

document.addEventListener('DOMContentLoaded', () => {
  loadDashboardData();
  // Optional auto-refresh every 30 seconds
  setInterval(loadDashboardData, 30000);
});

function loadDashboardData() {
  fetch('/api/dashboard/stats')
    .then(res => res.json())
    .then(data => {
      renderSummaryCards(data);
      renderCharts(data);
      renderTelemetryTable(data.recent_scans || []);
    })
    .catch(err => {
      // Graceful error handling
    });
}

function renderSummaryCards(data) {
  const total = data.total_analyses || 0;
  const avg = data.average_score || 0;
  const dist = data.classification_distribution || {};

  const strongCount = (dist['STRONG'] || 0) + (dist['VERY STRONG'] || 0);
  const strongPct = total > 0 ? Math.round((strongCount / total) * 100) : 0;

  const totalEl = document.getElementById('stat-total');
  const avgEl = document.getElementById('stat-avg');
  const pctEl = document.getElementById('stat-strong-pct');

  if (totalEl) totalEl.textContent = total.toLocaleString();
  if (avgEl) avgEl.textContent = `${avg} / 100`;
  if (pctEl) pctEl.textContent = `${strongPct}%`;
}

function renderCharts(data) {
  if (typeof Chart === 'undefined') return;

  const dist = data.classification_distribution || {};
  const lenDist = data.length_distribution || {};
  const weakDist = data.weakness_frequency || {};

  // Chart 1: Classification Doughnut
  const ctxClass = document.getElementById('chart-classification');
  if (ctxClass) {
    if (classificationChart) classificationChart.destroy();
    classificationChart = new Chart(ctxClass, {
      type: 'doughnut',
      data: {
        labels: ['VERY WEAK', 'WEAK', 'MODERATE', 'STRONG', 'VERY STRONG'],
        datasets: [{
          data: [
            dist['VERY WEAK'] || 0,
            dist['WEAK'] || 0,
            dist['MODERATE'] || 0,
            dist['STRONG'] || 0,
            dist['VERY STRONG'] || 0
          ],
          backgroundColor: [
            '#ef4444',
            '#f97316',
            '#eab308',
            '#10b981',
            '#06b6d4'
          ],
          borderWidth: 1,
          borderColor: '#131c31'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#94a3b8', font: { size: 11 } }
          }
        }
      }
    });
  }

  // Chart 2: Length Buckets Bar Chart
  const ctxLen = document.getElementById('chart-length');
  if (ctxLen) {
    if (lengthChart) lengthChart.destroy();
    lengthChart = new Chart(ctxLen, {
      type: 'bar',
      data: {
        labels: Object.keys(lenDist),
        datasets: [{
          label: 'Passwords Evaluated',
          data: Object.values(lenDist),
          backgroundColor: '#3b82f6',
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: '#94a3b8' }, grid: { display: false } },
          y: { ticks: { color: '#94a3b8', stepSize: 1 }, grid: { color: '#233558' } }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }

  // Chart 3: Weakness Frequencies (Horizontal Bar)
  const ctxWeak = document.getElementById('chart-weaknesses');
  if (ctxWeak) {
    if (weaknessChart) weaknessChart.destroy();
    const categories = Object.keys(weakDist);
    const counts = Object.values(weakDist);

    weaknessChart = new Chart(ctxWeak, {
      type: 'bar',
      indexAxis: 'y',
      data: {
        labels: categories.length > 0 ? categories : ['No Weaknesses Yet'],
        datasets: [{
          label: 'Times Detected',
          data: counts.length > 0 ? counts : [0],
          backgroundColor: '#f59e0b',
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: '#94a3b8', stepSize: 1 }, grid: { color: '#233558' } },
          y: { ticks: { color: '#94a3b8' }, grid: { display: false } }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }
}

function renderTelemetryTable(scans) {
  const tbody = document.getElementById('telemetry-table-body');
  if (!tbody) return;

  if (scans.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No evaluations recorded yet.</td></tr>';
    return;
  }

  tbody.innerHTML = scans.map(s => {
    let badgeClass = 'badge-very-weak';
    if (s.classification === 'WEAK') badgeClass = 'badge-weak';
    else if (s.classification === 'MODERATE') badgeClass = 'badge-moderate';
    else if (s.classification === 'STRONG') badgeClass = 'badge-strong';
    else if (s.classification === 'VERY STRONG') badgeClass = 'badge-very-strong';

    const formattedDate = new Date(s.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    return `
      <tr>
        <td style="font-family: var(--font-mono); color: var(--accent-cyan);">#${s.id}</td>
        <td style="font-weight: 700;">${s.score}</td>
        <td><span class="classification-badge ${badgeClass}" style="font-size: 0.72rem;">${s.classification}</span></td>
        <td>${s.length} chars</td>
        <td>${s.entropy} bits</td>
        <td style="color: var(--text-dim);">${formattedDate || s.timestamp}</td>
      </tr>
    `;
  }).join('');
}
