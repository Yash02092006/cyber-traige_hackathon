/**
 * CYBER TRIAGE TOOL - SIH1744
 * Correlated Attack Timeline Engine
 * Dynamic rendering of chronological forensic events, severity filtering,
 * category filtering, search, and deep evidence inspection links connected to REST API.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  const container = document.getElementById('timelineStreamContainer');
  const searchInput = document.getElementById('timelineSearchInput');
  const severityFilter = document.getElementById('timelineSeverityFilter');
  const typeFilter = document.getElementById('timelineTypeFilter');
  const exportBtn = document.getElementById('exportTimelineJsonBtn');
  const counterEl = document.getElementById('timelineCounter');

  let currentLoadedEvents = [];

  async function renderTimeline() {
    if (!container) return;

    const query = (searchInput ? searchInput.value : '').trim();
    const sevVal = severityFilter ? severityFilter.value : 'ALL';
    const typeVal = typeFilter ? typeFilter.value : 'ALL';

    let events = [];

    // 1. Fetch from FastAPI Backend
    if (window.CyberTriageAPI) {
      try {
        events = await window.CyberTriageAPI.getTimeline(1, {
          severity: sevVal,
          event_type: typeVal,
          search: query
        });
      } catch (err) {
        console.warn('[timeline.js] API fetch failed, trying local fallback:', err);
      }
    }

    // 2. Fallback to client-side store if offline
    if ((!events || events.length === 0) && window.CyberTriageStore) {
      const allEvents = window.CyberTriageStore.getAllTimelineEvents();
      events = allEvents.filter(evt => {
        const itemSev = (evt.severity || 'LOW').toUpperCase();
        const itemType = evt.event_type || evt.eventType || '';
        if (sevVal !== 'ALL' && itemSev !== sevVal) return false;
        if (typeVal !== 'ALL' && !itemType.toLowerCase().includes(typeVal.toLowerCase())) return false;

        if (query) {
          const q = query.toLowerCase();
          const matchTitle = (evt.title || '').toLowerCase().includes(q);
          const matchDesc = (evt.description || '').toLowerCase().includes(q);
          const matchMitre = (evt.mitre || '').toLowerCase().includes(q);
          const matchEvd = (evt.related_evidence_id || evt.relatedEvidenceId || '').toLowerCase().includes(q);
          if (!matchTitle && !matchDesc && !matchMitre && !matchEvd) return false;
        }
        return true;
      });
    }

    currentLoadedEvents = events || [];
    container.innerHTML = '';

    if (counterEl) {
      counterEl.textContent = `SHOWING ${currentLoadedEvents.length} EVENTS`;
    }

    if (currentLoadedEvents.length === 0) {
      container.innerHTML = `
        <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); padding: 36px; text-align: center; color: var(--text-muted); border-radius: 4px;">
          NO MATCHING FORENSIC TIMELINE EVENTS FOUND FOR CURRENT FILTERS.
        </div>
      `;
      return;
    }

    currentLoadedEvents.forEach(evt => {
      const card = document.createElement('article');
      const severity = (evt.severity || 'LOW').toUpperCase();
      const sevLower = severity.toLowerCase();
      card.className = `timeline-event-card ${sevLower}`;
      card.setAttribute('tabindex', '0');
      card.setAttribute('role', 'button');

      const timeVal = evt.time || (evt.timestamp && evt.timestamp.includes(' ') ? evt.timestamp.split(' ')[1] : evt.timestamp) || '09:42:00';
      const dateVal = evt.date || (evt.timestamp && evt.timestamp.includes(' ') ? evt.timestamp.split(' ')[0] : '2024-10-14');
      const eventType = evt.event_type || evt.eventType || 'System';
      const sevClass = `badge-${sevLower}`;
      const relId = evt.evidence_id || evt.relatedEvidenceId;

      card.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 6px; width: 100%;">
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="color: var(--color-accent-red); font-weight: 700; font-size: 0.8rem;">${timeVal} UTC</span>
              <span style="color: var(--text-dark-muted);">&bull;</span>
              <span style="color: var(--text-muted); font-size: 0.72rem;">${dateVal}</span>
              <span class="badge badge-type font-mono">${eventType}</span>
            </div>
            <div style="display: flex; align-items: center; gap: 6px;">
              ${evt.mitre ? `<span class="badge badge-mitre font-mono">${evt.mitre}</span>` : ''}
              <span class="badge ${sevClass} font-mono">${severity}</span>
            </div>
          </div>

          <div style="color: var(--text-white); font-weight: 600; font-size: 0.86rem; margin-top: 2px;">
            ${evt.title}
          </div>

          <p style="color: var(--text-secondary); font-family: var(--font-sans); font-size: 0.78rem; line-height: 1.45; margin: 0;">
            ${evt.description || ''}
          </p>

          ${relId ? `
            <div style="display: flex; align-items: center; gap: 6px; margin-top: 4px;">
              <span style="font-size: 0.65rem; color: var(--text-muted);">LINKED ARTIFACT:</span>
              <button type="button" class="chip-btn font-mono" onclick="event.stopPropagation(); window.openEvidenceDrawer('${relId}')">
                &rarr; ${relId}
              </button>
            </div>
          ` : ''}
        </div>
      `;

      card.addEventListener('click', () => {
        if (relId && window.openEvidenceDrawer) {
          window.openEvidenceDrawer(relId);
        }
      });

      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          if (relId && window.openEvidenceDrawer) window.openEvidenceDrawer(relId);
        }
      });

      container.appendChild(card);
    });
  }

  // Filters & Search listeners
  if (searchInput) {
    let debounceTimer = null;
    searchInput.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(renderTimeline, 250);
    });
  }

  if (severityFilter) severityFilter.addEventListener('change', renderTimeline);
  if (typeFilter) typeFilter.addEventListener('change', renderTimeline);

  // Export JSON
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      if (currentLoadedEvents.length === 0) {
        if (window.showAppToast) window.showAppToast('NO TIMELINE EVENTS TO EXPORT');
        return;
      }
      const jsonStr = JSON.stringify(currentLoadedEvents, null, 2);
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
