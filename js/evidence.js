/**
 * CYBER TRIAGE TOOL - SIH1744
 * Evidence Explorer Engine
 * Dynamic table rendering, multi-column search, multi-vector filtering,
 * custom sorting, detail modal triggers, and CSV export.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  if (!window.CyberTriageStore) {
    console.error('CyberTriageStore not found.');
    return;
  }

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
  const openAcqDemoBtn = document.getElementById('openAcquireDemoBtn');

  let currentSort = 'risk-desc';

  function renderTable() {
    if (!tableBody) return;
    const allRecords = window.CyberTriageStore.getAllEvidence();

    const query = (searchInput ? searchInput.value : '').trim().toLowerCase();
    const typeVal = filterType ? filterType.value : 'ALL';
    const riskVal = filterRisk ? filterRisk.value : 'ALL';
    const statusVal = filterStatus ? filterStatus.value : 'ALL';

    // 1. Filtering
    let filtered = allRecords.filter(item => {
      // Type filter
      if (typeVal !== 'ALL' && item.type !== typeVal) return false;

      // Risk filter
      if (riskVal !== 'ALL' && item.riskTier !== riskVal) return false;

      // Status filter
      if (statusVal !== 'ALL' && item.status !== statusVal) return false;

      // Search query filter
      if (query) {
        const matchId = (item.id || '').toLowerCase().includes(query);
        const matchName = (item.name || '').toLowerCase().includes(query);
        const matchSource = (item.source || '').toLowerCase().includes(query);
        const matchDesc = (item.description || '').toLowerCase().includes(query);
        const matchSha = (item.sha256 || '').toLowerCase().includes(query);
        const matchUser = (item.user || '').toLowerCase().includes(query);
        if (!matchId && !matchName && !matchSource && !matchDesc && !matchSha && !matchUser) {
          return false;
        }
      }

      return true;
    });

    // 2. Sorting
    filtered.sort((a, b) => {
      switch (currentSort) {
        case 'risk-desc':
          return b.riskScore - a.riskScore;
        case 'risk-asc':
          return a.riskScore - b.riskScore;
        case 'time-desc':
          return b.timestamp.localeCompare(a.timestamp);
        case 'time-asc':
          return a.timestamp.localeCompare(b.timestamp);
        case 'id-asc':
          return a.id.localeCompare(b.id);
        case 'name-asc':
          return a.name.localeCompare(b.name);
        default:
          return b.riskScore - a.riskScore;
      }
    });

    // 3. Render DOM Rows
    tableBody.innerHTML = '';

    if (counterEl) {
      counterEl.textContent = `SHOWING ${filtered.length} OF ${allRecords.length} FORENSIC RECORDS`;
    }

    if (filtered.length === 0) {
      const emptyRow = document.createElement('tr');
      emptyRow.innerHTML = `
        <td colspan="8" style="text-align: center; padding: 36px; color: var(--text-muted);" class="font-mono">
          NO MATCHING EVIDENCE FOUND. TRY ADJUSTING SEARCH FILTERS OR KEYWORDS.
        </td>
      `;
      tableBody.appendChild(emptyRow);
      return;
    }

    filtered.forEach(item => {
      const tr = document.createElement('tr');
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('role', 'button');
      tr.setAttribute('aria-label', `View details for evidence ${item.id}`);

      const riskBadgeClass = `badge-${(item.riskTier || 'LOW').toLowerCase()}`;
      const statusColor = item.status === 'Flagged' ? 'color: var(--color-accent-red); font-weight:700;' : 'color: var(--text-secondary);';

      tr.innerHTML = `
        <td class="font-mono" style="font-weight: 700; color: var(--color-accent-red);">${item.id}</td>
        <td><span class="badge badge-type font-mono">${item.type}</span></td>
        <td style="font-weight: 600; color: var(--text-white); max-width: 260px;">${item.name}</td>
        <td class="font-mono" style="color: var(--text-muted); font-size: 0.72rem; max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.source}">${item.source}</td>
        <td class="font-mono" style="color: var(--text-secondary); white-space: nowrap;">${item.timestamp}</td>
        <td class="font-mono" style="${statusColor}; font-size: 0.72rem;">${item.status}</td>
        <td>
          <span class="badge ${riskBadgeClass} font-mono">${item.riskScore} / 100</span>
        </td>
        <td>
          <button type="button" class="table-action-btn font-mono" data-id="${item.id}" aria-label="Inspect ${item.id}">INSPECT</button>
        </td>
      `;

      // Row click opens modal
      tr.addEventListener('click', () => {
        if (window.openEvidenceModal) {
          window.openEvidenceModal(item.id);
        }
      });

      // Keyboard accessible row enter
      tr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          if (window.openEvidenceModal) window.openEvidenceModal(item.id);
        }
      });

      // Inspect action button
      const inspectBtn = tr.querySelector('.table-action-btn');
      inspectBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (window.openEvidenceModal) window.openEvidenceModal(item.id);
      });

      tableBody.appendChild(tr);
    });
  }

  // Event Listeners for Filters
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      if (clearSearchBtn) {
        clearSearchBtn.style.display = searchInput.value ? 'inline-block' : 'none';
      }
      renderTable();
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

  // Column Header Sort Click
  const sortableHeaders = document.querySelectorAll('#evidenceTable th.sortable');
  sortableHeaders.forEach(th => {
    th.addEventListener('click', () => {
      const sortType = th.getAttribute('data-sort');
      if (sortType === 'risk') {
        currentSort = (currentSort === 'risk-desc') ? 'risk-asc' : 'risk-desc';
      } else if (sortType === 'time') {
        currentSort = (currentSort === 'time-desc') ? 'time-asc' : 'time-desc';
      } else if (sortType === 'id') {
        currentSort = (currentSort === 'id-asc') ? 'id-desc' : 'id-asc';
      } else if (sortType === 'name') {
        currentSort = (currentSort === 'name-asc') ? 'name-desc' : 'name-asc';
      } else if (sortType === 'type') {
        currentSort = 'name-asc';
      }
      if (sortSelector) sortSelector.value = currentSort;
      renderTable();
    });
  });

  // CSV Export functionality
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', () => {
      const records = window.CyberTriageStore.getAllEvidence();
      let csv = 'ID,Type,Name,Source,Timestamp,Status,RiskScore,RiskTier,SHA256,Description\n';
      records.forEach(r => {
        const cleanName = `"${(r.name || '').replace(/"/g, '""')}"`;
        const cleanSource = `"${(r.source || '').replace(/"/g, '""')}"`;
        const cleanDesc = `"${(r.description || '').replace(/"/g, '""')}"`;
        csv += `${r.id},${r.type},${cleanName},${cleanSource},${r.timestamp},${r.status},${r.riskScore},${r.riskTier},${r.sha256 || 'N/A'},${cleanDesc}\n`;
      });

      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', `cyber_triage_evidence_${Date.now()}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      if (window.showAppToast) window.showAppToast('EVIDENCE CATALOG EXPORTED TO CSV');
    });
  }

  // Open Acquisition Demo Modal
  if (triggerAcqBtn) {
    triggerAcqBtn.addEventListener('click', () => {
      if (window.openAcquisitionModal) window.openAcquisitionModal();
    });
  }
  if (openAcqDemoBtn) {
    openAcqDemoBtn.addEventListener('click', () => {
      if (window.openAcquisitionModal) window.openAcquisitionModal();
    });
  }

  // Listen for storage updates
  window.addEventListener('evidence:updated', () => {
    renderTable();
  });

  // Initial table render
  renderTable();
});
