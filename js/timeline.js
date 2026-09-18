/**
 * CYBER TRIAGE TOOL - SIH1744
 * Correlated Attack Timeline Engine
 * Dynamic rendering of chronological forensic events, severity filtering,
 * category filtering, search, and deep evidence inspection links.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  if (!window.CyberTriageStore) {
    console.error('CyberTriageStore not found.');
    return;
  }

  const container = document.getElementById('timelineStreamContainer');
  const searchInput = document.getElementById('timelineSearchInput');
  const severityFilter = document.getElementById('timelineSeverityFilter');
  const typeFilter = document.getElementById('timelineTypeFilter');
  const exportBtn = document.getElementById('exportTimelineJsonBtn');

  function renderTimeline() {
    if (!container) return;
    const events = window.CyberTriageStore.getAllTimelineEvents();

    const query = (searchInput ? searchInput.value : '').trim().toLowerCase();
    const sevVal = severityFilter ? severityFilter.value : 'ALL';
    const typeVal = typeFilter ? typeFilter.value : 'ALL';

    const filtered = events.filter(evt => {
      if (sevVal !== 'ALL' && evt.severity !== sevVal) return false;
      if (typeVal !== 'ALL' && evt.eventType !== typeVal) return false;

      if (query) {
        const matchTitle = (evt.title || '').toLowerCase().includes(query);
        const matchDesc = (evt.description || '').toLowerCase().includes(query);
        const matchMitre = (evt.mitre || '').toLowerCase().includes(query);
        const matchTime = (evt.time || '').toLowerCase().includes(query);
        const matchEvd = (evt.relatedEvidenceId || '').toLowerCase().includes(query);
        if (!matchTitle && !matchDesc && !matchMitre && !matchTime && !matchEvd) return false;
      }
      return true;
    });

    container.innerHTML = '';

    if (filtered.length === 0) {
      container.innerHTML = `
        <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); padding: 36px; text-align: center; color: var(--text-muted);">
          NO MATCHING FORENSIC TIMELINE EVENTS FOUND FOR CURRENT FILTERS.
        </div>
      `;
      return;
    }

    filtered.forEach(evt => {
      const card = document.createElement('article');
      card.className = 'timeline-card';
      card.setAttribute('tabindex', '0');
      card.setAttribute('role', 'article');
      card.setAttribute('aria-label', `${evt.time} ${evt.title}`);

      const sevClass = `badge-${evt.severity.toLowerCase()}`;

      card.innerHTML = `
        <div class="timeline-node-marker ${evt.severity}" aria-hidden="true"></div>
        <div class="timeline-meta-row font-mono">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="timeline-timestamp">${evt.time} UTC</span>
            <span style="color: var(--text-dark-muted);">&bull;</span>
            <span style="color: var(--text-muted); font-size: 0.72rem;">${evt.date}</span>
            <span class="badge badge-type">${evt.eventType}</span>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            ${evt.mitre ? `<span class="badge badge-mitre">${evt.mitre}</span>` : ''}
            <span class="badge ${sevClass}">${evt.severity}</span>
          </div>
        </div>

        <div class="timeline-title">${evt.title}</div>
        <div class="timeline-desc font-sans">${evt.description}</div>

        ${evt.relatedEvidenceId ? `
          <div style="display: flex; align-items: center; gap: 8px; margin-top: 4px;">
            <span style="font-size: 0.68rem; color: var(--text-muted);">CORRELATED EVIDENCE:</span>
            <button type="button" class="chip-btn font-mono" onclick="window.openEvidenceModal('${evt.relatedEvidenceId}')">
              &rarr; ${evt.relatedEvidenceId}
            </button>
          </div>
        ` : ''}
      `;

      card.addEventListener('click', () => {
        if (evt.relatedEvidenceId && window.openEvidenceModal) {
          window.openEvidenceModal(evt.relatedEvidenceId);
        }
      });

      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          if (evt.relatedEvidenceId && window.openEvidenceModal) {
            window.openEvidenceModal(evt.relatedEvidenceId);
          }
        }
      });

      container.appendChild(card);
    });
  }

  // Filters & Search listeners
  if (searchInput) searchInput.addEventListener('input', renderTimeline);
  if (severityFilter) severityFilter.addEventListener('change', renderTimeline);
  if (typeFilter) typeFilter.addEventListener('change', renderTimeline);

  // Export JSON
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      const events = window.CyberTriageStore.getAllTimelineEvents();
      const jsonStr = JSON.stringify(events, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', `cyber_triage_timeline_${Date.now()}.json`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      if (window.showAppToast) window.showAppToast('TIMELINE EVENTS EXPORTED AS JSON');
    });
  }

  // Initial render
  renderTimeline();
});
