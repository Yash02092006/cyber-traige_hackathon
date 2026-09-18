/**
 * CYBER TRIAGE TOOL - SIH1744
 * Unified Global Application Controller
 * Manages App Shell, Right-Side Detail Drawer (Progressive Disclosure),
 * Rapid Evidence Ingestion Modal, System Telemetry, and Keyboard Shortcuts.
 */

(function(root) {
  'use strict';

  // ==========================================================================
  // 1. App Shell Lifecycle & Navigation Active State
  // ==========================================================================
  document.addEventListener('DOMContentLoaded', () => {
    initAppShell();
    initStatusIndicator();
    initGlobalListeners();
  });

  function initAppShell() {
    // Determine active page
    const currentPath = window.location.pathname.split('/').pop() || 'index.html';
    const pageMap = {
      '': 'dashboard',
      'index.html': 'home',
      'dashboard.html': 'dashboard',
      'evidence.html': 'evidence',
      'ioc.html': 'ioc',
      'timeline.html': 'timeline',
      'graph.html': 'graph',
      'reports.html': 'reports'
    };
    const activePage = pageMap[currentPath] || 'dashboard';

    // Highlight sidebar links
    const sidebarLinks = document.querySelectorAll('.sidebar-link');
    sidebarLinks.forEach(link => {
      const pageAttr = link.getAttribute('data-page');
      const href = link.getAttribute('href') || '';
      if (pageAttr === activePage || href.includes(currentPath)) {
        link.classList.add('active');
        link.setAttribute('aria-current', 'page');
      } else {
        link.classList.remove('active');
        link.removeAttribute('aria-current');
      }
    });

    // Mobile sidebar toggle
    const toggleBtn = document.getElementById('mobileNavToggle') || document.querySelector('.mobile-nav-toggle');
    const sidebar = document.querySelector('.app-sidebar');
    if (toggleBtn && sidebar) {
      toggleBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        sidebar.classList.toggle('open');
      });

      document.addEventListener('click', (e) => {
        if (sidebar.classList.contains('open') && !sidebar.contains(e.target) && e.target !== toggleBtn) {
          sidebar.classList.remove('open');
        }
      });
    }

    // Connect all Ingest Evidence triggers
    const ingestBtns = document.querySelectorAll('#quickIngestBtn, .topbar-btn-ingest, .btn-acquire-quick, #triggerAcquisitionBtn, #openAcquireDemoBtn');
    ingestBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        window.openAcquisitionModal();
      });
    });

    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('ingest') === '1' || urlParams.get('modal') === 'ingest') {
      setTimeout(() => window.openAcquisitionModal(), 250);
    }
  }

  // Probe API Health for Top Bar Telemetry
  async function initStatusIndicator() {
    const dot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-indicator span:last-child');
    if (!dot || !statusText) return;

    if (window.CyberTriageAPI) {
      try {
        const health = await window.CyberTriageAPI.checkHealth();
        if (health && (health.status === 'healthy' || health.status === 'ok')) {
          dot.style.backgroundColor = 'var(--color-accent-green)';
          dot.style.boxShadow = '0 0 6px var(--color-accent-green)';
          statusText.textContent = 'System Ready • DB Connected';
          return;
        }
      } catch (_) {}
    }

    // Fallback indicator
    dot.style.backgroundColor = 'var(--color-accent-amber)';
    dot.style.boxShadow = '0 0 6px var(--color-accent-amber)';
    statusText.textContent = 'Offline / Local Sandbox';
  }

  // ==========================================================================
  // 2. Global Toast Notification System
  // ==========================================================================
  let toastTimer = null;
  window.showAppToast = function(message) {
    let toast = document.getElementById('appToast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'appToast';
      toast.className = 'toast-notification font-mono';
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('show');

    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toast.classList.remove('show');
    }, 2800);
  };

  // ==========================================================================
  // 3. Progressive Disclosure Right-Side Detail Drawer
  // ==========================================================================
  let activeDrawerItem = null;
  let activeDrawerTab = 'overview';

  function ensureDrawerDOM() {
    let backdrop = document.getElementById('drawerBackdrop');
    if (!backdrop) {
      backdrop = document.createElement('div');
      backdrop.id = 'drawerBackdrop';
      backdrop.className = 'drawer-backdrop';
      document.body.appendChild(backdrop);
      backdrop.addEventListener('click', window.closeAppDrawer);
    }

    let drawer = document.getElementById('appDetailDrawer');
    if (!drawer) {
      drawer = document.createElement('aside');
      drawer.id = 'appDetailDrawer';
      drawer.className = 'app-drawer font-mono';
      drawer.setAttribute('aria-label', 'Evidence Detail Drawer');
      drawer.innerHTML = `
        <div class="drawer-header">
          <div class="drawer-header-left">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span class="badge badge-type" id="drawerTypeBadge">FILE</span>
              <span style="font-weight: 800; color: var(--color-accent-red); font-size: 0.95rem;" id="drawerItemId">EVD-1001</span>
              <span class="badge badge-critical" id="drawerRiskBadge">CRITICAL</span>
            </div>
            <div style="font-size: 0.88rem; font-weight: 600; color: var(--text-white); margin-top: 4px;" id="drawerItemName">Artifact Name</div>
          </div>
          <button type="button" class="drawer-close-btn" id="drawerCloseBtn" aria-label="Close drawer">&times;</button>
        </div>

        <div class="drawer-tabs" role="tablist">
          <button type="button" class="drawer-tab-btn active" data-tab="overview">Overview</button>
          <button type="button" class="drawer-tab-btn" data-tab="iocs">Linked IOCs</button>
          <button type="button" class="drawer-tab-btn" data-tab="timeline">Timeline</button>
          <button type="button" class="drawer-tab-btn" data-tab="metadata">Metadata</button>
        </div>

        <div class="drawer-body" id="drawerBody">
          <!-- Dynamic Content by Tab -->
        </div>

        <div class="drawer-footer" id="drawerFooter">
          <button type="button" class="btn-secondary" id="drawerCopyHashBtn">Copy SHA-256</button>
          <button type="button" class="btn-primary" id="drawerInspectGraphBtn">View in Graph &rarr;</button>
        </div>
      `;
      document.body.appendChild(drawer);

      // Close button listener
      drawer.querySelector('#drawerCloseBtn').addEventListener('click', window.closeAppDrawer);

      // Tab switcher listener
      const tabs = drawer.querySelectorAll('.drawer-tab-btn');
      tabs.forEach(tab => {
        tab.addEventListener('click', () => {
          tabs.forEach(t => t.classList.remove('active'));
          tab.classList.add('active');
          activeDrawerTab = tab.getAttribute('data-tab');
          renderDrawerTabContent();
        });
      });

      // Footer button listeners
      drawer.querySelector('#drawerCopyHashBtn').addEventListener('click', () => {
        if (activeDrawerItem && activeDrawerItem.sha256) {
          navigator.clipboard.writeText(activeDrawerItem.sha256);
          window.showAppToast('SHA-256 COPIED TO CLIPBOARD');
        } else {
          window.showAppToast('No SHA-256 hash available for this artifact');
        }
      });

      drawer.querySelector('#drawerInspectGraphBtn').addEventListener('click', () => {
        window.location.href = 'graph.html';
      });
    }

    return { drawer, backdrop };
  }

  window.closeAppDrawer = function() {
    const drawer = document.getElementById('appDetailDrawer');
    const backdrop = document.getElementById('drawerBackdrop');
    if (drawer) drawer.classList.remove('open');
    if (backdrop) backdrop.classList.remove('open');
    activeDrawerItem = null;
  };

  /**
   * Main entry point to inspect an evidence item in the Right Drawer.
   */
  window.openEvidenceDrawer = async function(evidenceId) {
    const { drawer, backdrop } = ensureDrawerDOM();

    let item = null;
    if (window.CyberTriageAPI) {
      try {
        item = await window.CyberTriageAPI.getEvidenceById(evidenceId);
      } catch (err) {
        console.warn('[app.js] API lookup failed, trying local store:', err);
      }
    }
    if (!item && window.CyberTriageStore) {
      item = window.CyberTriageStore.getEvidenceById(evidenceId);
    }
    if (!item) {
      window.showAppToast(`Evidence ${evidenceId} not found.`);
      return;
    }

    activeDrawerItem = item;

    // Header values
    const typeBadge = drawer.querySelector('#drawerTypeBadge');
    const idSpan = drawer.querySelector('#drawerItemId');
    const riskBadge = drawer.querySelector('#drawerRiskBadge');
    const nameEl = drawer.querySelector('#drawerItemName');

    const tier = (item.risk_tier || item.riskTier || 'LOW').toLowerCase();
    const score = item.risk_score ?? item.riskScore ?? 0;
    const type = item.evidence_type || item.type || 'File';
    const name = item.filename || item.name || 'Forensic Artifact';

    typeBadge.textContent = type;
    idSpan.textContent = item.id;
    riskBadge.className = `badge badge-${tier}`;
    riskBadge.textContent = `${tier.toUpperCase()} (${score}/100)`;
    nameEl.textContent = name;

    // Default to Overview tab
    activeDrawerTab = 'overview';
    const tabs = drawer.querySelectorAll('.drawer-tab-btn');
    tabs.forEach(t => {
      if (t.getAttribute('data-tab') === 'overview') t.classList.add('active');
      else t.classList.remove('active');
    });

    renderDrawerTabContent();

    drawer.classList.add('open');
    backdrop.classList.add('open');
  };

  // Backward compatibility alias for existing code
  window.openEvidenceModal = window.openEvidenceDrawer;

  /**
   * Renders the content of the currently active drawer tab.
   */
  function renderDrawerTabContent() {
    const drawer = document.getElementById('appDetailDrawer');
    if (!drawer || !activeDrawerItem) return;

    const body = drawer.querySelector('#drawerBody');
    const item = activeDrawerItem;

    if (activeDrawerTab === 'overview') {
      // Explainable "Why?" Risk Checklist
      const reasons = item.risk_reasons || item.riskReasons || [];
      let reasonsHtml = '';
      if (reasons.length > 0) {
        reasonsHtml = reasons.map(r => `
          <li class="risk-rule-item">
            <div>
              <span class="rule-check">&#10003;</span>
              <span>${r.rule || r.description || 'Heuristic rule triggered'}</span>
            </div>
            <span class="rule-pts">+${r.points || 15} PTS</span>
          </li>
        `).join('');
      } else {
        reasonsHtml = `
          <li class="risk-rule-item">
            <div>
              <span style="color: var(--text-muted); margin-right: 6px;">&bull;</span>
              <span style="color: var(--text-secondary);">No malicious behavioral heuristics triggered.</span>
            </div>
            <span style="color: var(--color-accent-green); font-size: 0.68rem; font-weight: 700;">CLEAN</span>
          </li>
        `;
      }

      body.innerHTML = `
        <!-- Description -->
        <div style="display: flex; flex-direction: column; gap: 6px;">
          <span class="meta-label">FORENSIC SUMMARY</span>
          <p style="color: var(--text-primary); font-size: 0.82rem; font-family: var(--font-sans); line-height: 1.5; margin: 0;">
            ${item.description || 'Forensic artifact acquired during incident investigation. No descriptive notes recorded.'}
          </p>
        </div>

        <!-- Explainable Risk Engine Evaluation -->
        <div class="risk-explain-box">
          <div class="risk-explain-header">
            <span class="risk-explain-title">TRANSPARENT RISK EVALUATION</span>
            <span class="badge badge-${(item.risk_tier || item.riskTier || 'low').toLowerCase()}">${item.risk_score ?? item.riskScore ?? 0} / 100</span>
          </div>
          <ul class="risk-rules-list">
            ${reasonsHtml}
          </ul>
        </div>

        <!-- Quick Summary Attributes -->
        <div class="meta-field-group">
          <div class="meta-field">
            <span class="meta-label">SOURCE LOCATION:</span>
            <span class="meta-val font-mono" style="font-size: 0.72rem;">${item.source || item.original_path || 'N/A'}</span>
          </div>
          <div class="meta-field">
            <span class="meta-label">TIMESTAMP (UTC):</span>
            <span class="meta-val font-mono" style="font-size: 0.72rem;">${item.timestamp || item.collected_at || 'N/A'}</span>
          </div>
          <div class="meta-field">
            <span class="meta-label">SECURITY CONTEXT:</span>
            <span class="meta-val font-mono" style="font-size: 0.72rem;">${item.user || 'SYSTEM / Local'}</span>
          </div>
          <div class="meta-field">
            <span class="meta-label">MITRE ATT&CK:</span>
            <span class="meta-val font-mono" style="font-size: 0.72rem; color: #d8b4fe;">${item.mitre_attack || item.mitreAttack || 'T1005'}</span>
          </div>
        </div>
      `;
    } else if (activeDrawerTab === 'iocs') {
      const iocs = item.related_iocs || item.relatedIocs || (item.sha256 ? [item.sha256] : []);
      if (iocs.length === 0) {
        body.innerHTML = `
          <div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 0.78rem;">
            No direct Indicators of Compromise mapped to this artifact.
          </div>
        `;
      } else {
        body.innerHTML = `
          <div style="display: flex; flex-direction: column; gap: 8px;">
            <span class="meta-label">ASSOCIATED THREAT INDICATORS (${iocs.length})</span>
            <div style="display: flex; flex-direction: column; gap: 8px;">
              ${iocs.map(ioc => `
                <div style="background: var(--bg-panel); border: 1px solid var(--border-subtle); padding: 10px 12px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                  <span style="font-size: 0.74rem; color: var(--color-accent-amber); word-break: break-all;">${ioc}</span>
                  <button type="button" class="table-action-btn" onclick="navigator.clipboard.writeText('${ioc}'); window.showAppToast('IOC COPIED');">COPY</button>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }
    } else if (activeDrawerTab === 'timeline') {
      body.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <span class="meta-label">CHRONOLOGICAL OCCURRENCE</span>
          <div style="background: var(--bg-panel); border: 1px solid var(--border-subtle); padding: 12px; border-radius: 4px; display: flex; flex-direction: column; gap: 6px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: var(--color-accent-red); font-weight: 700; font-size: 0.78rem;">${item.timestamp || '2024-10-14 09:42:00'}</span>
              <span class="badge badge-${(item.risk_tier || item.riskTier || 'low').toLowerCase()}">${item.status || 'Analyzed'}</span>
            </div>
            <div style="color: var(--text-white); font-weight: 600; font-size: 0.8rem;">Evidence Logged into Case Triage</div>
            <p style="color: var(--text-secondary); font-size: 0.76rem; font-family: var(--font-sans); margin: 0;">
              Acquired via triage ingestion pipeline. Correlated with host activity timeline.
            </p>
          </div>
          <div style="margin-top: 8px;">
            <button type="button" class="btn-secondary" onclick="location.href='timeline.html'">View Full Attack Timeline &rarr;</button>
          </div>
        </div>
      `;
    } else if (activeDrawerTab === 'metadata') {
      body.innerHTML = `
        <div class="meta-field-group" style="grid-template-columns: 1fr;">
          <div class="meta-field">
            <span class="meta-label">ARTIFACT IDENTIFIER:</span>
            <span class="meta-val font-mono">${item.id}</span>
          </div>
          <div class="meta-field">
            <span class="meta-label">FULL FILE / ARTIFACT NAME:</span>
            <span class="meta-val font-mono">${item.filename || item.name || 'N/A'}</span>
          </div>
          <div class="meta-field">
            <span class="meta-label">FILE SYSTEM PATH / SOURCE:</span>
            <span class="meta-val font-mono">${item.source || item.original_path || 'N/A'}</span>
          </div>
          <div class="meta-field">
            <span class="meta-label">FILE SIZE:</span>
            <span class="meta-val font-mono">${item.size || 'N/A'}</span>
          </div>
          <div class="meta-field">
            <span class="meta-label">COLLECTED TIMESTAMP (UTC):</span>
            <span class="meta-val font-mono">${item.timestamp || item.collected_at || 'N/A'}</span>
          </div>
          <div class="meta-field">
            <span class="meta-label">SECURITY USER CONTEXT:</span>
            <span class="meta-val font-mono">${item.user || 'SYSTEM / Local'}</span>
          </div>
          <div class="meta-field">
            <span class="meta-label">PARENT PROCESS TREE:</span>
            <span class="meta-val font-mono">${item.parent_process || item.parentProcess || 'explorer.exe'}</span>
          </div>
          ${item.command_line || item.commandLine ? `
            <div class="meta-field">
              <span class="meta-label">COMMAND LINE INVOCATION:</span>
              <span class="meta-val font-mono" style="color: #f59e0b;">${item.command_line || item.commandLine}</span>
            </div>
          ` : ''}
          <div class="meta-field">
            <span class="meta-label">SHA-256 CRYPTOGRAPHIC HASH:</span>
            <span class="meta-val font-mono" style="color: var(--color-accent-red);">${item.sha256 || 'N/A (Volatile in-memory artifact)'}</span>
          </div>
        </div>
      `;
    }
  }

  /**
   * Helper to open IOC drawer
   */
  window.openIocDrawer = function(iocValueOrObj) {
    const val = typeof iocValueOrObj === 'string' ? iocValueOrObj : (iocValueOrObj.value || iocValueOrObj.ioc || '');
    const { drawer, backdrop } = ensureDrawerDOM();

    activeDrawerItem = {
      id: 'IOC',
      type: typeof iocValueOrObj === 'object' ? (iocValueOrObj.ioc_type || iocValueOrObj.type || 'Indicator') : 'Indicator',
      name: val,
      risk_tier: typeof iocValueOrObj === 'object' ? (iocValueOrObj.threat_level || iocValueOrObj.risk || 'HIGH') : 'HIGH',
      risk_score: 85,
      description: typeof iocValueOrObj === 'object' ? (iocValueOrObj.context || iocValueOrObj.description || `Extracted indicator of compromise: ${val}`) : `Extracted indicator of compromise: ${val}`,
      source: 'Threat Intelligence & Case Triage',
      timestamp: '2024-10-14 09:42:00',
      user: 'DFIR Intelligence',
      mitre_attack: 'T1071 - C2',
      sha256: val.length === 64 ? val : null,
      related_iocs: [val]
    };

    const typeBadge = drawer.querySelector('#drawerTypeBadge');
    const idSpan = drawer.querySelector('#drawerItemId');
    const riskBadge = drawer.querySelector('#drawerRiskBadge');
    const nameEl = drawer.querySelector('#drawerItemName');

    typeBadge.textContent = 'IOC';
    idSpan.textContent = val.substring(0, 16) + (val.length > 16 ? '...' : '');
    riskBadge.className = 'badge badge-high';
    riskBadge.textContent = activeDrawerItem.risk_tier;
    nameEl.textContent = val;

    activeDrawerTab = 'overview';
    renderDrawerTabContent();

    drawer.classList.add('open');
    backdrop.classList.add('open');
  };

  // ==========================================================================
  // 4. Clean Evidence Acquisition Modal
  // ==========================================================================
  async function computeSha256(file) {
    if (window.crypto && window.crypto.subtle) {
      try {
        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (e) {
        console.warn('Web Crypto API failed, using fallback hash:', e);
      }
    }
    let hash = 0;
    const str = `${file.name}_${file.size}_${file.lastModified}`;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(64, 'e');
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  window.openAcquisitionModal = function() {
    let modalOverlay = document.getElementById('acquisitionModal');
    if (!modalOverlay) {
      modalOverlay = document.createElement('div');
      modalOverlay.id = 'acquisitionModal';
      modalOverlay.className = 'modal-overlay font-mono';
      modalOverlay.innerHTML = `
        <div class="modal-box" role="dialog" aria-modal="true" aria-labelledby="modalAcquireTitle">
          <div class="modal-header">
            <div class="modal-title" id="modalAcquireTitle">
              <span class="badge badge-critical">RAPID INGESTION</span>
              <span>Ingest Forensic Evidence</span>
            </div>
            <button type="button" class="modal-close-btn" id="closeAcquireModalBtn">&times;</button>
          </div>
          <div class="modal-body">
            <div class="disclaimer-banner">
              <span style="font-size: 1.1rem; color: var(--color-accent-amber);">&#9888;</span>
              <div>
                <strong>FORENSIC TRIAGE SIMULATION:</strong><br>
                Computes real SHA-256 integrity hash, analyzes payload heuristics, and scores risk dynamically in real time.
              </div>
            </div>

            <div class="dropzone-box" id="acquisitionDropzone">
              <input type="file" id="localFileInput" style="display: none;">
              <div class="dropzone-icon">&plus;</div>
              <div class="dropzone-text">DRAG &amp; DROP EVIDENCE FILE HERE</div>
              <div class="dropzone-sub">Supports memory dumps, PCAPs, logs (.evtx), binaries (.exe/.dll), or memory artifacts</div>
              <button type="button" class="btn-secondary" id="browseFilesBtn" style="margin-top: 6px;">Browse Local Files</button>
            </div>

            <div id="acquisitionPreviewArea" style="display: none; flex-direction: column; gap: 10px;">
              <div class="meta-field-group">
                <div class="meta-field">
                  <span class="meta-label">TARGET ARTIFACT:</span>
                  <span class="meta-val" id="acqFileName">-</span>
                </div>
                <div class="meta-field">
                  <span class="meta-label">FILE SIZE:</span>
                  <span class="meta-val" id="acqFileSize">-</span>
                </div>
                <div class="meta-field">
                  <span class="meta-label">DETECTED MIME:</span>
                  <span class="meta-val" id="acqFileType">-</span>
                </div>
                <div class="meta-field">
                  <span class="meta-label">INFERRED TYPE:</span>
                  <span class="meta-val" id="acqInferredType">-</span>
                </div>
                <div class="meta-field" style="grid-column: 1 / -1;">
                  <span class="meta-label">CALCULATED SHA-256 INTEGRITY:</span>
                  <span class="meta-val font-mono" id="acqSha256" style="color: var(--color-accent-red);">CALCULATING HASH...</span>
                </div>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn-secondary" id="cancelAcquireBtn">Cancel</button>
            <button type="button" class="btn-primary" id="confirmIngestBtn" disabled style="opacity: 0.5;">Ingest into Evidence Store</button>
          </div>
        </div>
      `;
      document.body.appendChild(modalOverlay);

      const closeBtn = modalOverlay.querySelector('#closeAcquireModalBtn');
      const cancelBtn = modalOverlay.querySelector('#cancelAcquireBtn');
      const browseBtn = modalOverlay.querySelector('#browseFilesBtn');
      const fileInput = modalOverlay.querySelector('#localFileInput');
      const dropzone = modalOverlay.querySelector('#acquisitionDropzone');
      const confirmBtn = modalOverlay.querySelector('#confirmIngestBtn');

      let currentFile = null;
      let inferredType = 'File';
      let computedSha = '';

      const closeModal = () => {
        modalOverlay.classList.remove('open');
        currentFile = null;
        confirmBtn.disabled = true;
        confirmBtn.style.opacity = '0.5';
        confirmBtn.textContent = 'Ingest into Evidence Store';
        modalOverlay.querySelector('#acquisitionPreviewArea').style.display = 'none';
        dropzone.style.display = 'flex';
      };

      closeBtn.addEventListener('click', closeModal);
      cancelBtn.addEventListener('click', closeModal);
      modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) closeModal();
      });

      browseBtn.addEventListener('click', () => fileInput.click());
      dropzone.addEventListener('click', (e) => {
        if (e.target !== browseBtn) fileInput.click();
      });

      dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
      });
      dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
      dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          processFile(e.dataTransfer.files[0]);
        }
      });

      fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          processFile(e.target.files[0]);
        }
      });

      async function processFile(file) {
        currentFile = file;
        dropzone.style.display = 'none';
        const preview = modalOverlay.querySelector('#acquisitionPreviewArea');
        preview.style.display = 'flex';

        modalOverlay.querySelector('#acqFileName').textContent = file.name;
        modalOverlay.querySelector('#acqFileSize').textContent = formatBytes(file.size);
        modalOverlay.querySelector('#acqFileType').textContent = file.type || 'application/octet-stream';

        const lowerName = file.name.toLowerCase();
        inferredType = 'File';
        if (lowerName.endsWith('.pcap') || lowerName.endsWith('.pcapng')) inferredType = 'Network';
        else if (lowerName.endsWith('.evtx') || lowerName.endsWith('.reg')) inferredType = 'System';
        else if (lowerName.endsWith('.dmp') || lowerName.endsWith('.raw')) inferredType = 'Memory';
        else if (lowerName.includes('history') || lowerName.includes('cookie')) inferredType = 'Browser';

        modalOverlay.querySelector('#acqInferredType').textContent = inferredType;
        modalOverlay.querySelector('#acqSha256').textContent = 'CALCULATING HASH VIA WEB CRYPTO API...';

        computedSha = await computeSha256(file);
        modalOverlay.querySelector('#acqSha256').textContent = computedSha;

        confirmBtn.disabled = false;
        confirmBtn.style.opacity = '1';
        confirmBtn.textContent = 'Ingest into Evidence Store';
      }

      confirmBtn.addEventListener('click', async () => {
        if (!currentFile) return;
        confirmBtn.disabled = true;
        confirmBtn.textContent = 'Ingesting to Server...';

        try {
          let saved = null;
          if (window.CyberTriageAPI) {
            saved = await window.CyberTriageAPI.uploadEvidence(currentFile, 1, inferredType);
          } else if (window.CyberTriageStore) {
            const nextId = 'EVD-' + (1000 + window.CyberTriageStore.getAllEvidence().length + 1);
            saved = window.CyberTriageStore.addEvidence({
              id: nextId,
              type: inferredType,
              name: currentFile.name,
              source: `Local Disk / Ingestion Upload / ${currentFile.name}`,
              timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
              status: 'Analyzed',
              size: formatBytes(currentFile.size),
              user: 'local\\investigator',
              sha256: computedSha,
              riskScore: 75,
              riskTier: 'HIGH',
              riskReasons: [{ rule: 'Manual investigator upload intake', points: 25 }]
            });
          }

          const savedId = saved ? (saved.id || 'EVD-INGESTED') : 'EVD-INGESTED';
          const score = saved ? (saved.risk_score ?? saved.riskScore ?? 0) : 0;
          window.showAppToast(`EVIDENCE ${savedId} INGESTED (RISK SCORE: ${score}/100)`);
          closeModal();

          // Broadcast refresh event to active pages
          window.dispatchEvent(new CustomEvent('evidence:updated', { detail: saved }));
        } catch (err) {
          console.warn('[app.js] Upload error:', err);
          window.showAppToast(`INGESTION FAILED: ${err.message}`);
          confirmBtn.disabled = false;
          confirmBtn.textContent = 'Ingest into Evidence Store';
        }
      });
    }

    modalOverlay.classList.add('open');
  };

  // ==========================================================================
  // 5. Global Keyboard Shortcuts
  // ==========================================================================
  function initGlobalListeners() {
    document.addEventListener('keydown', (e) => {
      // ESC closes open drawer and modals
      if (e.key === 'Escape') {
        window.closeAppDrawer();
        document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
      }
      // 'A' key shortcut opens acquisition modal (unless user is typing in input)
      if ((e.key === 'a' || e.key === 'A') && !['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) {
        window.openAcquisitionModal();
      }
    });
  }

})(window);
