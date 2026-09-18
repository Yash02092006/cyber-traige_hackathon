/**
 * CYBER TRIAGE TOOL - SIH1744
 * Indicator of Compromise (IOC) Engine
 * Dynamic table rendering, search, filtering, right-side drawer inspection,
 * and CSV export connected to REST API.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // DOM Elements
  const tableBody = document.getElementById('iocTableBody');
  const searchInput = document.getElementById('iocSearchInput');
  const typeFilter = document.getElementById('iocTypeFilter');
  const riskFilter = document.getElementById('iocRiskFilter');
  const counterEl = document.getElementById('iocCounter');
  const exportCsvBtn = document.getElementById('exportIocCsvBtn');

  // Summary Cards
  const elCrit = document.getElementById('iocCountCritical');
  const elHigh = document.getElementById('iocCountHigh');
  const elNet = document.getElementById('iocCountNet');
  const elHash = document.getElementById('iocCountHashes');

  let currentLoadedIocs = [];

  async function renderTable() {
    if (!tableBody) return;

    const query = (searchInput ? searchInput.value : '').trim();
    const typeVal = typeFilter ? typeFilter.value : 'ALL';
    const riskVal = riskFilter ? riskFilter.value : 'ALL';

    let iocs = [];

    // 1. Fetch from FastAPI Backend
    if (window.CyberTriageAPI) {
      try {
        iocs = await window.CyberTriageAPI.getIOCs(1, {
          ioc_type: typeVal,
          risk: riskVal,
          search: query
        });
      } catch (err) {
        console.warn('[ioc.js] API fetch failed, trying local fallback:', err);
      }
    }

    // 2. Client-side fallback if offline
    if ((!iocs || iocs.length === 0) && window.CyberTriageStore) {
      const allIocs = window.CyberTriageStore.getAllIOCs();
      iocs = allIocs.filter(item => {
        const itemType = item.type || item.ioc_type || 'IP';
        const itemRisk = item.risk || item.threat_level || 'MEDIUM';

        if (typeVal !== 'ALL' && itemType !== typeVal) return false;
        if (riskVal !== 'ALL' && itemRisk !== riskVal) return false;

        if (query) {
          const q = query.toLowerCase();
          const matchVal = (item.value || item.ioc || '').toLowerCase().includes(q);
          const matchCtx = (item.context || item.description || '').toLowerCase().includes(q);
          if (!matchVal && !matchCtx) return false;
        }
        return true;
      });
    }

    currentLoadedIocs = iocs || [];

    // 3. Compute Summary Card Counts
    if (elCrit || elHigh || elNet || elHash) {
      let critCount = 0, highCount = 0, netCount = 0, hashCount = 0;
      const allSource = (window.CyberTriageStore ? window.CyberTriageStore.getAllIOCs() : currentLoadedIocs) || [];

      allSource.forEach(item => {
        const threat = (item.risk || item.threat_level || '').toUpperCase();
        const type = (item.type || item.ioc_type || '').toUpperCase();
        if (threat === 'CRITICAL') critCount++;
        else if (threat === 'HIGH') highCount++;

        if (type === 'IP' || type === 'DOMAIN' || type === 'URL') netCount++;
        if (type === 'HASH' || type === 'MD5' || type === 'SHA256') hashCount++;
      });

      if (elCrit) elCrit.textContent = critCount;
      if (elHigh) elHigh.textContent = highCount;
      if (elNet) elNet.textContent = netCount;
      if (elHash) elHash.textContent = hashCount;
    }

    // 4. Render Table Rows
    tableBody.innerHTML = '';

    if (counterEl) {
      counterEl.textContent = `SHOWING ${currentLoadedIocs.length} INDICATORS`;
    }

    if (currentLoadedIocs.length === 0) {
      const emptyRow = document.createElement('tr');
      emptyRow.innerHTML = `
        <td colspan="6" style="text-align: center; padding: 36px; color: var(--text-muted);" class="font-mono">
          NO MATCHING INDICATORS OF COMPROMISE FOUND.
        </td>
      `;
      tableBody.appendChild(emptyRow);
      return;
    }

    currentLoadedIocs.forEach(item => {
      const tr = document.createElement('tr');
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('role', 'button');

      const val = item.value || item.ioc || '';
      const type = item.type || item.ioc_type || 'IP';
      const threat = (item.risk || item.threat_level || 'MEDIUM').toUpperCase();
      const badgeClass = `badge-${threat.toLowerCase()}`;
      const context = item.context || item.description || 'Observed threat artifact';
      const relIds = item.related_evidence_ids || item.relatedEvidenceIds || [];
      const relCount = relIds.length;

      tr.innerHTML = `
        <td class="font-mono" style="font-weight: 600; color: var(--text-white); max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          <span style="color: var(--color-accent-amber); margin-right: 6px;">&bull;</span>
          <span title="${val}">${val}</span>
        </td>
        <td><span class="badge badge-type font-mono">${type}</span></td>
        <td><span class="badge ${badgeClass} font-mono">${threat}</span></td>
        <td style="font-size: 0.74rem; color: var(--text-secondary); max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${context}">${context}</td>
        <td>
          <span class="chip-btn font-mono" style="font-size: 0.68rem;">
            ${relCount > 0 ? `${relCount} Associated Artifacts` : 'Direct Detection'}
          </span>
        </td>
        <td style="text-align: right;">
          <button type="button" class="table-action-btn font-mono">Inspect</button>
        </td>
      `;

      // Row click opens right drawer
      tr.addEventListener('click', () => {
        if (window.openIocDrawer) {
          window.openIocDrawer(item);
        }
      });

      // Inspect button click
      const inspectBtn = tr.querySelector('.table-action-btn');
      if (inspectBtn) {
        inspectBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          if (window.openIocDrawer) {
            window.openIocDrawer(item);
          }
        });
      }

      tableBody.appendChild(tr);
    });
  }

  // Filter Listeners
  if (searchInput) {
    let debounceTimer = null;
    searchInput.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(renderTable, 250);
    });
  }

  if (typeFilter) typeFilter.addEventListener('change', renderTable);
  if (riskFilter) riskFilter.addEventListener('change', renderTable);

  // CSV Export
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', () => {
      if (currentLoadedIocs.length === 0) {
        if (window.showAppToast) window.showAppToast('NO IOCs TO EXPORT');
        return;
      }

      const headers = ['Value', 'Type', 'ThreatLevel', 'Context', 'RelatedEvidence'];
      const rows = currentLoadedIocs.map(item => [
        `"${item.value || item.ioc || ''}"`,
        `"${item.type || item.ioc_type || ''}"`,
        `"${item.risk || item.threat_level || ''}"`,
        `"${(item.context || item.description || '').replace(/"/g, '""')}"`,
        `"${(item.related_evidence_ids || item.relatedEvidenceIds || []).join(';')}"`
      ]);

      const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement('a');
      link.setAttribute('href', encodedUri);
      link.setAttribute('download', `cyber_triage_iocs_${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      if (window.showAppToast) {
        window.showAppToast(`EXPORTED ${currentLoadedIocs.length} IOCs TO CSV`);
      }
    });
  }

  // Initial Load
  renderTable();
});
