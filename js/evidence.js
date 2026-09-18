/**
 * CYBER TRIAGE TOOL - SIH1744
 * Evidence Explorer Engine
 * Dynamic table rendering, multi-column search, multi-vector filtering,
 * custom sorting, right-side detail drawer triggers, and CSV export connected to REST API.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // DOM Elements
  const tableBody = document.getElementById('evidenceTableBody');
  const searchInput = document.getElementById('evidenceSearchInput');
  const clearSearchBtn = document.getElementById('clearSearchBtn');
  const filterType = document.getElementById('filterType');
  const filterRisk = document.getElementById('filterRisk');
  const filterStatus = document.getElementById('filterStatus');
  const sortSelector = document.getElementById('sortSelector');
  const counterEl = document.getElementById('evidenceRecordCounter');
  const exportCsvBtn = document.getElementById('exportEvidenceCsvBtn');
  const triggerAcqBtn = document.getElementById('triggerAcquisitionBtn');

  let currentSort = 'risk-desc';
  let currentLoadedRecords = [];

  async function renderTable() {
    if (!tableBody) return;

    const query = (searchInput ? searchInput.value : '').trim();
    const typeVal = filterType ? filterType.value : 'ALL';
    const riskVal = filterRisk ? filterRisk.value : 'ALL';
    const statusVal = filterStatus ? filterStatus.value : 'ALL';

    let records = [];

    // 1. Fetch from FastAPI Backend
    if (window.CyberTriageAPI) {
      try {
        records = await window.CyberTriageAPI.getEvidence({
          case_id: 1,
          evidence_type: typeVal,
          risk: riskVal,
          status: statusVal,
          search: query,
          sort: currentSort
        });
      } catch (err) {
        console.warn('[evidence.js] API fetch failed, trying local fallback:', err);
      }
    }

    // 2. Client-side fallback if offline
    if ((!records || records.length === 0) && query === '' && typeVal === 'ALL' && riskVal === 'ALL' && statusVal === 'ALL' && window.CyberTriageStore) {
      records = window.CyberTriageStore.getAllEvidence();
    } else if (!records && window.CyberTriageStore) {
      // Offline fallback with manual filtering
      const allRecords = window.CyberTriageStore.getAllEvidence();
      records = allRecords.filter(item => {
        if (typeVal !== 'ALL' && item.type !== typeVal) return false;
        if (riskVal !== 'ALL' && (item.riskTier || item.risk_tier) !== riskVal) return false;
        if (statusVal !== 'ALL' && item.status !== statusVal) return false;
        if (query) {
          const q = query.toLowerCase();
          const matchId = (item.id || '').toLowerCase().includes(q);
          const matchName = (item.name || item.filename || '').toLowerCase().includes(q);
          const matchSource = (item.source || '').toLowerCase().includes(q);
          const matchDesc = (item.description || '').toLowerCase().includes(q);
          const matchSha = (item.sha256 || '').toLowerCase().includes(q);
          if (!matchId && !matchName && !matchSource && !matchDesc && !matchSha) return false;
        }
        return true;
      });
    }

    currentLoadedRecords = records || [];

    // 3. Render DOM Rows
    tableBody.innerHTML = '';

    if (counterEl) {
      counterEl.textContent = `SHOWING ${currentLoadedRecords.length} ARTIFACTS`;
    }

    if (currentLoadedRecords.length === 0) {
      const emptyRow = document.createElement('tr');
      emptyRow.innerHTML = `
        <td colspan="8" style="text-align: center; padding: 36px; color: var(--text-muted);" class="font-mono">
          NO MATCHING EVIDENCE FOUND. TRY ADJUSTING SEARCH FILTERS OR KEYWORDS.
        </td>
      `;
      tableBody.appendChild(emptyRow);
      return;
    }

    currentLoadedRecords.forEach(item => {
      const tr = document.createElement('tr');
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('role', 'button');
      tr.setAttribute('aria-label', `View details for evidence ${item.id}`);

      const tier = (item.risk_tier || item.riskTier || 'LOW').toLowerCase();
      const riskBadgeClass = `badge-${tier}`;
      const score = item.risk_score ?? item.riskScore ?? 0;
      const name = item.filename || item.name || 'Unknown Artifact';
      const type = item.evidence_type || item.type || 'File';
      const src = item.source || item.original_path || 'N/A';
      const time = item.timestamp || (item.collected_at ? item.collected_at.replace('T', ' ').substring(0, 19) : 'N/A');
      const statusColor = item.status === 'Flagged' ? 'color: var(--color-accent-red); font-weight:700;' : 'color: var(--text-secondary);';

      tr.innerHTML = `
        <td class="font-mono" style="font-weight: 700; color: var(--color-accent-red);">${item.id}</td>
        <td><span class="badge badge-type font-mono">${type}</span></td>
        <td style="font-weight: 600; color: var(--text-white); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${name}">${name}</td>
        <td class="font-mono" style="color: var(--text-muted); font-size: 0.72rem; max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${src}">${src}</td>
        <td class="font-mono" style="color: var(--text-secondary); white-space: nowrap; font-size: 0.72rem;">${time}</td>
        <td class="font-mono" style="${statusColor}; font-size: 0.72rem;">${item.status || 'Analyzed'}</td>
        <td>
          <span class="badge ${riskBadgeClass} font-mono">${score} / 100</span>
        </td>
        <td style="text-align: right;">
          <button type="button" class="table-action-btn font-mono" data-id="${item.id}" aria-label="Inspect ${item.id}">Inspect</button>
        </td>
      `;

      // Row click opens right drawer
      tr.addEventListener('click', () => {
        if (window.openEvidenceDrawer) {
          window.openEvidenceDrawer(item.id);
        }
      });

      // Keyboard accessibility
      tr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          if (window.openEvidenceDrawer) window.openEvidenceDrawer(item.id);
        }
      });

      // Inspect action button
      const inspectBtn = tr.querySelector('.table-action-btn');
      if (inspectBtn) {
        inspectBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          if (window.openEvidenceDrawer) window.openEvidenceDrawer(item.id);
        });
      }

      tableBody.appendChild(tr);
    });
  }

  // Event Listeners for Filters
  if (searchInput) {
    let debounceTimer = null;
    searchInput.addEventListener('input', () => {
      if (clearSearchBtn) {
        clearSearchBtn.style.display = searchInput.value ? 'inline-block' : 'none';
      }
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(renderTable, 250);
    });
  }

  if (clearSearchBtn) {
    clearSearchBtn.addEventListener('click', () => {
      searchInput.value = '';
      clearSearchBtn.style.display = 'none';
      renderTable();
    });
  }

  if (filterType) filterType.addEventListener('change', renderTable);
  if (filterRisk) filterRisk.addEventListener('change', renderTable);
  if (filterStatus) filterStatus.addEventListener('change', renderTable);

  if (sortSelector) {
    sortSelector.addEventListener('change', (e) => {
      currentSort = e.target.value;
      renderTable();
    });
  }

  // CSV Export
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', () => {
      if (currentLoadedRecords.length === 0) {
        if (window.showAppToast) window.showAppToast('NO RECORDS TO EXPORT');
        return;
      }

      const headers = ['ID', 'Type', 'Name', 'Source', 'Timestamp', 'Status', 'RiskScore', 'RiskTier', 'SHA256', 'User', 'MITRE'];
      const rows = currentLoadedRecords.map(item => [
        `"${item.id}"`,
        `"${item.evidence_type || item.type || ''}"`,
        `"${(item.filename || item.name || '').replace(/"/g, '""')}"`,
        `"${(item.source || '').replace(/"/g, '""')}"`,
        `"${item.timestamp || item.collected_at || ''}"`,
        `"${item.status || ''}"`,
        item.risk_score ?? item.riskScore ?? 0,
        `"${item.risk_tier || item.riskTier || ''}"`,
        `"${item.sha256 || 'N/A'}"`,
        `"${(item.user || 'N/A').replace(/"/g, '""')}"`,
        `"${(item.mitre_attack || item.mitreAttack || 'N/A').replace(/"/g, '""')}"`
      ]);

      const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement('a');
      link.setAttribute('href', encodedUri);
      link.setAttribute('download', `cyber_triage_evidence_${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      if (window.showAppToast) {
        window.showAppToast(`EXPORTED ${currentLoadedRecords.length} FORENSIC RECORDS TO CSV`);
      }
    });
  }

  // Quick Ingest Button
  if (triggerAcqBtn) {
    triggerAcqBtn.addEventListener('click', () => window.openAcquisitionModal && window.openAcquisitionModal());
  }

  // Listen for newly ingested evidence
  window.addEventListener('evidence:updated', () => {
    renderTable();
  });

  // Initial Load
  renderTable().then(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const inspectParam = urlParams.get('inspect') || urlParams.get('id');
    if (inspectParam && window.openEvidenceDrawer) {
      setTimeout(() => window.openEvidenceDrawer(inspectParam), 200);
    }
  });
});
