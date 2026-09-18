/**
 * CYBER TRIAGE TOOL - SIH1744
 * Indicator of Compromise (IOC) Engine
 * Dynamic table rendering, search, filtering, related evidence correlation modal,
 * and CSV export.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  if (!window.CyberTriageStore) {
    console.error('CyberTriageStore not found.');
    return;
  }

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

  // Modal Elements
  const iocModal = document.getElementById('iocRelatedModal');
  const iocModalTitle = document.getElementById('iocModalValue');
  const iocModalBody = document.getElementById('iocModalBody');
  const closeIocModalBtn = document.getElementById('closeIocModalBtn');
  const dismissIocModalBtn = document.getElementById('dismissIocModalBtn');

  const closeIocModal = () => iocModal.classList.remove('open');
  if (closeIocModalBtn) closeIocModalBtn.addEventListener('click', closeIocModal);
  if (dismissIocModalBtn) dismissIocModalBtn.addEventListener('click', closeIocModal);
  if (iocModal) {
    iocModal.addEventListener('click', (e) => {
      if (e.target === iocModal) closeIocModal();
    });
  }

  function openIocEvidenceModal(iocObj) {
    if (!iocModal || !iocModalBody) return;

    iocModalTitle.textContent = iocObj.ioc;

    // Find all evidence records containing this IOC in their relatedIocs or matching properties
    const allEvidence = window.CyberTriageStore.getAllEvidence();
    const relatedEvidence = allEvidence.filter(ev => {
      if (iocObj.relatedEvidenceIds && iocObj.relatedEvidenceIds.includes(ev.id)) return true;
      if (ev.relatedIocs && ev.relatedIocs.includes(iocObj.ioc)) return true;
      if (ev.sha256 === iocObj.ioc) return true;
      if (ev.destinationIp === iocObj.ioc) return true;
      if (ev.name === iocObj.ioc) return true;
      return false;
    });

    let evidenceHtml = '';
    if (relatedEvidence.length === 0) {
      evidenceHtml = `
        <div style="padding: 24px; text-align: center; color: var(--text-muted);">
          No direct evidence records explicitly mapped to this IOC.
        </div>
      `;
    } else {
      evidenceHtml = `
        <div style="display: flex; flex-direction: column; gap: 10px;">
          <span style="font-size: 0.72rem; color: var(--text-muted); letter-spacing: 0.08em;">
            FOUND ${relatedEvidence.length} ASSOCIATED FORENSIC ARTIFACTS:
          </span>
          ${relatedEvidence.map(ev => {
            const riskClass = `badge-${(ev.riskTier || 'LOW').toLowerCase()}`;
            return `
              <div style="background: var(--bg-panel); border: 1px solid var(--border-subtle); padding: 12px; display: flex; justify-content: space-between; align-items: center; gap: 12px; cursor: pointer; transition: border-color 0.15s;" class="ioc-ev-card" onclick="window.openEvidenceModal('${ev.id}')">
                <div style="display: flex; flex-direction: column; gap: 3px;">
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="color: var(--color-accent-red); font-weight: 700;">${ev.id}</span>
                    <span class="badge badge-type">${ev.type}</span>
                    <strong style="color: var(--text-white); font-size: 0.85rem;">${ev.name}</strong>
                  </div>
                  <span style="color: var(--text-muted); font-size: 0.72rem;">${ev.source}</span>
                </div>
                <div style="display: flex; align-items: center; gap: 10px; flex-shrink: 0;">
                  <span class="badge ${riskClass}">${ev.riskScore} PTS</span>
                  <button type="button" class="table-action-btn font-mono">INSPECT &rarr;</button>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      `;
    }

    iocModalBody.innerHTML = `
      <!-- IOC Metadata Summary -->
      <div class="meta-field-group">
        <div class="meta-field">
          <span class="meta-label">IOC VALUE:</span>
          <span class="meta-val font-mono" style="color: #ff3333;">${iocObj.ioc}</span>
        </div>
        <div class="meta-field">
          <span class="meta-label">TYPE / CATEGORY:</span>
          <span class="meta-val">${iocObj.type}</span>
        </div>
        <div class="meta-field">
          <span class="meta-label">TOTAL OCCURRENCES:</span>
          <span class="meta-val">${iocObj.occurrences} Times Observed</span>
        </div>
        <div class="meta-field">
          <span class="meta-label">THREAT STATUS:</span>
          <span class="meta-val" style="color: #fbbf24;">${iocObj.status}</span>
        </div>
        <div class="meta-field">
          <span class="meta-label">FIRST SEEN (UTC):</span>
          <span class="meta-val">${iocObj.firstSeen}</span>
        </div>
        <div class="meta-field">
          <span class="meta-label">LAST SEEN (UTC):</span>
          <span class="meta-val">${iocObj.lastSeen}</span>
        </div>
      </div>

      <!-- Associated Evidence List -->
      ${evidenceHtml}
    `;

    iocModal.classList.add('open');
  }

  function renderIOCs() {
    if (!tableBody) return;
    const allIocs = window.CyberTriageStore.getAllIOCs();

    // Update Top Summary Counts
    if (elCrit) elCrit.textContent = allIocs.filter(i => i.risk === 'CRITICAL').length;
    if (elHigh) elHigh.textContent = allIocs.filter(i => i.risk === 'HIGH').length;
    if (elNet) elNet.textContent = allIocs.filter(i => i.type.includes('IP') || i.type.includes('Domain')).length;
    if (elHash) elHash.textContent = allIocs.filter(i => i.type.includes('Hash')).length;

    const query = (searchInput ? searchInput.value : '').trim().toLowerCase();
    const typeVal = typeFilter ? typeFilter.value : 'ALL';
    const riskVal = riskFilter ? riskFilter.value : 'ALL';

    // Filter
    const filtered = allIocs.filter(item => {
      if (typeVal !== 'ALL' && !item.type.toLowerCase().includes(typeVal.toLowerCase())) return false;
      if (riskVal !== 'ALL' && item.risk !== riskVal) return false;

      if (query) {
        const matchVal = (item.ioc || '').toLowerCase().includes(query);
        const matchType = (item.type || '').toLowerCase().includes(query);
        const matchStatus = (item.status || '').toLowerCase().includes(query);
        const matchCountry = (item.country || '').toLowerCase().includes(query);
        const matchAsn = (item.asn || '').toLowerCase().includes(query);
        if (!matchVal && !matchType && !matchStatus && !matchCountry && !matchAsn) return false;
      }
      return true;
    });

    if (counterEl) {
      counterEl.textContent = `SHOWING ${filtered.length} OF ${allIocs.length} CORRELATED IOCs`;
    }

    tableBody.innerHTML = '';
    if (filtered.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="8" style="text-align: center; padding: 30px; color: var(--text-muted);" class="font-mono">
            NO MATCHING INDICATORS OF COMPROMISE FOUND.
          </td>
        </tr>
      `;
      return;
    }

    filtered.forEach(item => {
      const tr = document.createElement('tr');
      const riskClass = `badge-${item.risk.toLowerCase()}`;

      tr.innerHTML = `
        <td class="font-mono" style="font-weight: 700; color: var(--text-white); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.ioc}">
          ${item.ioc}
        </td>
        <td><span class="badge badge-type font-mono">${item.type}</span></td>
        <td class="font-mono" style="color: var(--text-secondary); text-align: center;">${item.occurrences}</td>
        <td class="font-mono" style="color: var(--text-muted); font-size: 0.72rem; white-space: nowrap;">${item.firstSeen.split(' ')[1] || item.firstSeen}</td>
        <td class="font-mono" style="color: var(--text-muted); font-size: 0.72rem; white-space: nowrap;">${item.lastSeen.split(' ')[1] || item.lastSeen}</td>
        <td><span class="badge ${riskClass} font-mono">${item.risk}</span></td>
        <td class="font-mono" style="color: #fbbf24; font-size: 0.72rem;">${item.status}</td>
        <td>
          <button type="button" class="table-action-btn font-mono" aria-label="View evidence for ${item.ioc}">VIEW EVIDENCE</button>
        </td>
      `;

      tr.addEventListener('click', () => openIocEvidenceModal(item));
      const btn = tr.querySelector('.table-action-btn');
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        openIocEvidenceModal(item);
      });

      tableBody.appendChild(tr);
    });
  }

  // Filters & Search
  if (searchInput) searchInput.addEventListener('input', renderIOCs);
  if (typeFilter) typeFilter.addEventListener('change', renderIOCs);
  if (riskFilter) riskFilter.addEventListener('change', renderIOCs);

  // CSV Export
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', () => {
      const allIocs = window.CyberTriageStore.getAllIOCs();
      let csv = 'Indicator,Type,Occurrences,FirstSeen,LastSeen,Risk,Status,ASN,Country\n';
      allIocs.forEach(i => {
        csv += `"${i.ioc}","${i.type}",${i.occurrences},"${i.firstSeen}","${i.lastSeen}","${i.risk}","${i.status}","${i.asn || ''}","${i.country || ''}"\n`;
      });
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', `cyber_triage_iocs_${Date.now()}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      if (window.showAppToast) window.showAppToast('IOC THREAT FEED EXPORTED TO CSV');
    });
  }

  // Initial render
  renderIOCs();
});
