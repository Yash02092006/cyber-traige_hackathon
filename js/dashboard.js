/**
 * CYBER TRIAGE TOOL - SIH1744
 * Dashboard Engine
 * Dynamically computes investigation metrics, risk severity meters,
 * priority watchlist, and timeline previews from CyberTriageStore.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  if (!window.CyberTriageStore) {
    console.error('CyberTriageStore not loaded.');
    return;
  }

  function renderDashboard() {
    const stats = window.CyberTriageStore.getDashboardStatistics();
    const evidenceList = window.CyberTriageStore.getAllEvidence();
    const timelineList = window.CyberTriageStore.getAllTimelineEvents();

    // 1. Dynamic Metric Cards
    const elTotal = document.getElementById('statTotalEvidence');
    const elSuspicious = document.getElementById('statSuspiciousEvidence');
    const elIocs = document.getElementById('statTotalIocs');
    const elCritical = document.getElementById('statCriticalFindings');

    if (elTotal) elTotal.textContent = stats.totalEvidence;
    if (elSuspicious) elSuspicious.textContent = stats.suspiciousEvidence;
    if (elIocs) elIocs.textContent = stats.totalIocs;
    if (elCritical) elCritical.textContent = stats.criticalFindings;

    const elBreakdown = document.getElementById('statEvidenceBreakdown');
    if (elBreakdown) {
      const types = Object.keys(stats.typeDistribution).map(t => `${t}: ${stats.typeDistribution[t]}`).join(' &bull; ');
      elBreakdown.innerHTML = types;
    }

    // 2. Risk Severity Distribution
    const dist = stats.riskDistribution;
    const total = stats.totalEvidence || 1;

    const pctCritical = ((dist.CRITICAL / total) * 100).toFixed(1);
    const pctHigh = ((dist.HIGH / total) * 100).toFixed(1);
    const pctMedium = ((dist.MEDIUM / total) * 100).toFixed(1);
    const pctLow = ((dist.LOW / total) * 100).toFixed(1);

    const barCrit = document.getElementById('riskBarCritical');
    const barHigh = document.getElementById('riskBarHigh');
    const barMed = document.getElementById('riskBarMedium');
    const barLow = document.getElementById('riskBarLow');

    if (barCrit) barCrit.style.width = `${pctCritical}%`;
    if (barHigh) barHigh.style.width = `${pctHigh}%`;
    if (barMed) barMed.style.width = `${pctMedium}%`;
    if (barLow) barLow.style.width = `${pctLow}%`;

    const countCrit = document.getElementById('distCriticalCount');
    const countHigh = document.getElementById('distHighCount');
    const countMed = document.getElementById('distMediumCount');
    const countLow = document.getElementById('distLowCount');

    if (countCrit) countCrit.textContent = dist.CRITICAL;
    if (countHigh) countHigh.textContent = dist.HIGH;
    if (countMed) countMed.textContent = dist.MEDIUM;
    if (countLow) countLow.textContent = dist.LOW;

    // 3. Priority Evidence Watchlist Table
    const tableBody = document.getElementById('priorityEvidenceTableBody');
    if (tableBody) {
      tableBody.innerHTML = '';
      const priorityItems = evidenceList
        .filter(e => e.riskScore >= 60)
        .sort((a, b) => b.riskScore - a.riskScore)
        .slice(0, 8);

      if (priorityItems.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 20px; color: var(--text-muted);">No critical items detected.</td></tr>`;
      } else {
        priorityItems.forEach(item => {
          const tr = document.createElement('tr');
          const badgeClass = `badge-${item.riskTier.toLowerCase()}`;

          tr.innerHTML = `
            <td class="font-mono" style="font-weight: 700; color: var(--color-accent-red);">${item.id}</td>
            <td><span class="badge badge-type font-mono">${item.type}</span></td>
            <td style="font-weight: 600; color: var(--text-white);">${item.name}</td>
            <td class="font-mono" style="color: var(--text-muted); font-size: 0.72rem; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${item.source}</td>
            <td class="font-mono" style="color: var(--text-secondary);">${item.timestamp.split(' ')[1] || item.timestamp}</td>
            <td>
              <span class="badge ${badgeClass} font-mono">${item.riskScore} / 100</span>
            </td>
            <td>
              <button type="button" class="table-action-btn font-mono" data-id="${item.id}">INSPECT</button>
            </td>
          `;

          // Row click opens modal
          tr.addEventListener('click', (e) => {
            if (window.openEvidenceModal) {
              window.openEvidenceModal(item.id);
            }
          });

          // Inspect button click
          const inspectBtn = tr.querySelector('.table-action-btn');
          inspectBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (window.openEvidenceModal) {
              window.openEvidenceModal(item.id);
            }
          });

          tableBody.appendChild(tr);
        });
      }
    }

    // 4. Recent Timeline Preview
    const timelineContainer = document.getElementById('dashboardTimelinePreview');
    if (timelineContainer) {
      timelineContainer.innerHTML = '';
      const recentEvents = timelineList.slice(0, 5);

      recentEvents.forEach(evt => {
        const itemEl = document.createElement('div');
        itemEl.className = 'font-mono';
        itemEl.style.cssText = 'background: var(--bg-panel); border: 1px solid var(--border-subtle); padding: 10px 12px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: border-color 0.15s;';
        
        const sevClass = `badge-${evt.severity.toLowerCase()}`;
        itemEl.innerHTML = `
          <div style="display: flex; align-items: center; gap: 10px;">
            <span style="color: var(--color-accent-red); font-weight: 700;">${evt.time}</span>
            <span style="color: var(--text-white); font-size: 0.8rem;">${evt.title}</span>
          </div>
          <div style="display: flex; align-items: center; gap: 6px;">
            <span class="badge ${sevClass}">${evt.severity}</span>
            <span style="color: var(--text-muted); font-size: 0.68rem;">&rarr;</span>
          </div>
        `;

        itemEl.addEventListener('mouseenter', () => itemEl.style.borderColor = 'var(--color-accent-red)');
        itemEl.addEventListener('mouseleave', () => itemEl.style.borderColor = 'var(--border-subtle)');
        itemEl.addEventListener('click', () => {
          if (evt.relatedEvidenceId && window.openEvidenceModal) {
            window.openEvidenceModal(evt.relatedEvidenceId);
          } else {
            window.location.href = 'timeline.html';
          }
        });

        timelineContainer.appendChild(itemEl);
      });
    }
  }

  // Initial render
  renderDashboard();

  // Listen for newly acquired evidence updates
  window.addEventListener('evidence:updated', () => {
    renderDashboard();
  });

  // Refresh button
  const refreshBtn = document.getElementById('refreshStatsBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      renderDashboard();
      if (window.showAppToast) {
        window.showAppToast('DASHBOARD TELEMETRY REFRESHED');
      }
    });
  }
});
