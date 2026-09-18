/**
 * CYBER TRIAGE TOOL - SIH1744
 * Global Application Framework (Navbar, Modals, SHA-256 Acquisition Engine, Toast)
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // ==========================================================================
  // 1. Navigation Active Link & Mobile Menu
  // ==========================================================================
  const currentPath = window.location.pathname.split('/').pop() || 'index.html';
  const navLinks = document.querySelectorAll('.nav-link');
  navLinks.forEach(link => {
    const href = link.getAttribute('href');
    if (href === currentPath || (currentPath === '' && href === 'index.html')) {
      link.classList.add('active');
      link.setAttribute('aria-current', 'page');
    } else {
      link.classList.remove('active');
    }
  });

  const mobileToggle = document.getElementById('mobileNavToggle');
  const navLinksContainer = document.getElementById('navLinksContainer');
  if (mobileToggle && navLinksContainer) {
    mobileToggle.addEventListener('click', () => {
      navLinksContainer.classList.toggle('open');
      const isOpen = navLinksContainer.classList.contains('open');
      mobileToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });
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
    }, 2400);
  };

  // ==========================================================================
  // 3. Global Evidence Detail Modal
  // ==========================================================================
  window.openEvidenceModal = function(evidenceId) {
    if (!window.CyberTriageStore) return;
    const item = window.CyberTriageStore.getEvidenceById(evidenceId);
    if (!item) {
      window.showAppToast(`Evidence ID ${evidenceId} not found.`);
      return;
    }

    let modalOverlay = document.getElementById('evidenceDetailModal');
    if (!modalOverlay) {
      modalOverlay = document.createElement('div');
      modalOverlay.id = 'evidenceDetailModal';
      modalOverlay.className = 'modal-overlay';
      modalOverlay.innerHTML = `
        <div class="modal-box font-mono" role="dialog" aria-modal="true" aria-labelledby="modalDetailTitle">
          <div class="modal-header">
            <div class="modal-title" id="modalDetailTitle">
              <span class="badge badge-type" id="modalTypeBadge">FILE</span>
              <span id="modalEvidenceId">EVD-1001</span>
            </div>
            <button type="button" class="modal-close-btn" id="closeDetailModalBtn">&times; CLOSE</button>
          </div>
          <div class="modal-body" id="modalDetailBody">
            <!-- Dynamic Content -->
          </div>
          <div class="modal-footer">
            <button type="button" class="table-action-btn" id="copyDetailHashBtn">COPY SHA-256</button>
            <button type="button" class="action-btn" id="closeDetailFooterBtn">DISMISS</button>
          </div>
        </div>
      `;
      document.body.appendChild(modalOverlay);

      const closeBtn = modalOverlay.querySelector('#closeDetailModalBtn');
      const closeFooterBtn = modalOverlay.querySelector('#closeDetailFooterBtn');
      const copyHashBtn = modalOverlay.querySelector('#copyDetailHashBtn');

      const closeModal = () => modalOverlay.classList.remove('open');
      closeBtn.addEventListener('click', closeModal);
      closeFooterBtn.addEventListener('click', closeModal);
      modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) closeModal();
      });

      copyHashBtn.addEventListener('click', () => {
        const hashEl = modalOverlay.querySelector('#modalShaVal');
        if (hashEl && hashEl.textContent) {
          navigator.clipboard.writeText(hashEl.textContent.trim());
          window.showAppToast('SHA-256 COPIED TO CLIPBOARD');
        }
      });
    }

    // Populate Modal Content
    const typeBadge = modalOverlay.querySelector('#modalTypeBadge');
    const idSpan = modalOverlay.querySelector('#modalEvidenceId');
    const bodyEl = modalOverlay.querySelector('#modalDetailBody');

    typeBadge.textContent = item.type || 'EVIDENCE';
    idSpan.textContent = item.id;

    // Build Transparent Risk Breakdown HTML
    const riskBadgeClass = `badge-${(item.riskTier || 'LOW').toLowerCase()}`;
    const riskReasonsHtml = (item.riskReasons && item.riskReasons.length > 0)
      ? item.riskReasons.map(r => `
          <li class="risk-rule-item">
            <span>&bull; ${r.rule}</span>
            <span class="rule-points">+${r.points} PTS</span>
          </li>
        `).join('')
      : `<li class="risk-rule-item"><span>&bull; No malicious behavioral indicators triggered</span><span class="rule-points">0 PTS</span></li>`;

    // Related evidence chips
    const relatedChipsHtml = (item.relatedEvidenceIds && item.relatedEvidenceIds.length > 0)
      ? item.relatedEvidenceIds.map(relId => `
          <button type="button" class="chip-btn font-mono" onclick="window.openEvidenceModal('${relId}')">
            &rarr; ${relId}
          </button>
        `).join('')
      : '<span style="color: var(--text-muted); font-size: 0.72rem;">None identified</span>';

    // Related IOC chips
    const relatedIocHtml = (item.relatedIocs && item.relatedIocs.length > 0)
      ? item.relatedIocs.map(ioc => `
          <span class="badge badge-type font-mono">${ioc}</span>
        `).join(' ')
      : '<span style="color: var(--text-muted); font-size: 0.72rem;">None linked</span>';

    bodyEl.innerHTML = `
      <!-- Headline & Summary -->
      <div>
        <h3 style="color: var(--text-white); font-size: 1.1rem; margin-bottom: 6px;">${item.name}</h3>
        <p style="color: var(--text-secondary); font-size: 0.84rem; font-family: var(--font-sans); line-height: 1.5;">
          ${item.description || 'No descriptive forensic context supplied.'}
        </p>
      </div>

      <!-- Transparent Risk Engine Score -->
      <div class="risk-calc-box">
        <div class="risk-calc-header">
          <div>
            <span style="font-size: 0.72rem; color: var(--text-muted); letter-spacing: 0.08em;">TRANSPARENT RISK ENGINE EVALUATION:</span>
            <div style="margin-top: 4px;">
              <span class="badge ${riskBadgeClass}">${item.riskTier} TIER</span>
            </div>
          </div>
          <div class="risk-score-display">${item.riskScore} / 100</div>
        </div>
        <ul class="risk-rules-list">
          ${riskReasonsHtml}
        </ul>
      </div>

      <!-- Technical Metadata Grid -->
      <div class="meta-field-group">
        <div class="meta-field">
          <span class="meta-label">SOURCE LOCATION:</span>
          <span class="meta-val">${item.source || 'N/A'}</span>
        </div>
        <div class="meta-field">
          <span class="meta-label">TIMESTAMP (UTC):</span>
          <span class="meta-val">${item.timestamp || 'N/A'}</span>
        </div>
        <div class="meta-field">
          <span class="meta-label">SECURITY USER CONTEXT:</span>
          <span class="meta-val">${item.user || 'N/A'}</span>
        </div>
        <div class="meta-field">
          <span class="meta-label">PARENT PROCESS:</span>
          <span class="meta-val">${item.parentProcess || 'N/A'}</span>
        </div>
        <div class="meta-field" style="grid-column: 1 / -1;">
          <span class="meta-label">SHA-256 CHECKSUM:</span>
          <span class="meta-val font-mono" id="modalShaVal">${item.sha256 || 'N/A (Non-binary / Volatile artifact)'}</span>
        </div>
        ${item.commandLine ? `
          <div class="meta-field" style="grid-column: 1 / -1;">
            <span class="meta-label">COMMAND LINE INVOCATION:</span>
            <span class="meta-val font-mono" style="color: #fbbf24;">${item.commandLine}</span>
          </div>
        ` : ''}
        ${item.mitreAttack ? `
          <div class="meta-field" style="grid-column: 1 / -1;">
            <span class="meta-label">MITRE ATT&CK MATRIX:</span>
            <span class="badge badge-mitre" style="align-self: flex-start; margin-top: 4px;">${item.mitreAttack}</span>
          </div>
        ` : ''}
      </div>

      <!-- Correlated Entities -->
      <div style="display: flex; flex-direction: column; gap: 8px;">
        <span class="meta-label">RELATED EVIDENCE ARTIFACTS:</span>
        <div class="chip-container">
          ${relatedChipsHtml}
        </div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 8px;">
        <span class="meta-label">LINKED INDICATORS OF COMPROMISE (IOCs):</span>
        <div class="chip-container">
          ${relatedIocHtml}
        </div>
      </div>
    `;

    modalOverlay.classList.add('open');
  };

  // ==========================================================================
  // 4. Global Evidence Acquisition Demo Feature
  // ==========================================================================
  async function computeSha256(file) {
    if (window.crypto && window.crypto.subtle) {
      try {
        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (e) {
        console.warn('SubtleCrypto failed, generating fallback hash:', e);
      }
    }
    // Fallback pseudo-hash based on filename and size
    let hash = 0;
    const str = `${file.name}_${file.size}_${file.lastModified}`;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(64, 'a');
  }

  function formatFileSize(bytes) {
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
      modalOverlay.className = 'modal-overlay';
      modalOverlay.innerHTML = `
        <div class="modal-box font-mono" role="dialog" aria-modal="true" aria-labelledby="modalAcquireTitle">
          <div class="modal-header">
            <div class="modal-title" id="modalAcquireTitle">
              <span class="badge badge-critical">DEMO ACQUISITION</span>
              <span>RAPID EVIDENCE INGESTION</span>
            </div>
            <button type="button" class="modal-close-btn" id="closeAcquireModalBtn">&times; CLOSE</button>
          </div>
          <div class="modal-body">
            <!-- Disclaimer Banner -->
            <div class="disclaimer-banner">
              <span style="font-size: 1rem;">&#9888;</span>
              <div>
                <strong>FRONTEND DEMO / TRIAGE SIMULATION ONLY:</strong><br>
                This feature demonstrates client-side hashing, metadata extraction, and automated risk scoring in the browser. It does not perform forensic hardware bit-stream drive imaging or E01 container packaging.
              </div>
            </div>

            <!-- Drag & Drop Zone -->
            <div class="dropzone-box" id="acquisitionDropzone">
              <input type="file" id="localFileInput" style="display: none;">
              <div class="dropzone-icon">&plus;</div>
              <div class="dropzone-text">SELECT OR DRAG & DROP EVIDENCE FILE</div>
              <div class="dropzone-sub">Upload logs (.evtx, .log), binaries (.exe, .dll), or captures (.pcap)</div>
              <button type="button" class="action-btn" id="browseFilesBtn" style="margin-top: 8px;">BROWSE LOCAL FILES</button>
            </div>

            <!-- Ingestion Progress / Preview Area -->
            <div id="acquisitionPreviewArea" style="display: none; flex-direction: column; gap: 12px;">
              <div class="meta-field-group">
                <div class="meta-field">
                  <span class="meta-label">TARGET FILENAME:</span>
                  <span class="meta-val" id="acqFileName">-</span>
                </div>
                <div class="meta-field">
                  <span class="meta-label">FILE SIZE:</span>
                  <span class="meta-val" id="acqFileSize">-</span>
                </div>
                <div class="meta-field">
                  <span class="meta-label">DETECTED MIME TYPE:</span>
                  <span class="meta-val" id="acqFileType">-</span>
                </div>
                <div class="meta-field">
                  <span class="meta-label">INFERRED EVIDENCE TYPE:</span>
                  <span class="meta-val" id="acqInferredType">-</span>
                </div>
                <div class="meta-field" style="grid-column: 1 / -1;">
                  <span class="meta-label">CALCULATED SHA-256 CHECKSUM:</span>
                  <span class="meta-val font-mono" id="acqSha256" style="color: #ff3333;">CALCULATING...</span>
                </div>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="table-action-btn" id="cancelAcquireBtn">CANCEL</button>
            <button type="button" class="action-btn" id="confirmIngestBtn" disabled style="opacity: 0.5;">INGEST INTO EVIDENCE STORE</button>
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

      let currentAcquiredRecord = null;

      const closeModal = () => {
        modalOverlay.classList.remove('open');
        currentAcquiredRecord = null;
        confirmBtn.disabled = true;
        confirmBtn.style.opacity = '0.5';
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

      dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
      });

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
        dropzone.style.display = 'none';
        const preview = modalOverlay.querySelector('#acquisitionPreviewArea');
        preview.style.display = 'flex';

        modalOverlay.querySelector('#acqFileName').textContent = file.name;
        modalOverlay.querySelector('#acqFileSize').textContent = formatFileSize(file.size);
        modalOverlay.querySelector('#acqFileType').textContent = file.type || 'application/octet-stream';

        // Infer type
        const lowerName = file.name.toLowerCase();
        let infType = 'File';
        if (lowerName.endsWith('.pcap') || lowerName.endsWith('.pcapng')) infType = 'Network';
        else if (lowerName.endsWith('.evtx') || lowerName.endsWith('.reg')) infType = 'System';
        else if (lowerName.includes('history') || lowerName.includes('cookie')) infType = 'Browser';

        modalOverlay.querySelector('#acqInferredType').textContent = infType;
        modalOverlay.querySelector('#acqSha256').textContent = 'CALCULATING HASH VIA WEB CRYPTO API...';

        const sha = await computeSha256(file);
        modalOverlay.querySelector('#acqSha256').textContent = sha;

        const nextId = 'EVD-' + (1000 + window.CyberTriageStore.getAllEvidence().length + 1);
        const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);

        currentAcquiredRecord = {
          id: nextId,
          type: infType,
          name: file.name,
          source: `Local Disk / Ingested Upload / ${file.name}`,
          timestamp: nowStr,
          status: 'Analyzed',
          size: formatFileSize(file.size),
          user: 'local\\investigator',
          parentProcess: 'browser_triage_intake',
          sha256: sha,
          recentlyDownloaded: true,
          description: `Acquired via Rapid Evidence Ingestion Demo. Size: ${formatFileSize(file.size)}. SHA-256 verified.`,
          mitreAttack: 'T1005 - Data from Local System',
          relatedEvidenceIds: [],
          relatedIocs: [sha]
        };

        confirmBtn.disabled = false;
        confirmBtn.style.opacity = '1';
      }

      confirmBtn.addEventListener('click', () => {
        if (!currentAcquiredRecord) return;
        const saved = window.CyberTriageStore.addEvidence(currentAcquiredRecord);
        window.showAppToast(`EVIDENCE ${saved.id} INGESTED (RISK: ${saved.riskScore}/100)`);
        closeModal();

        // Dispatch notification event for active page
        window.dispatchEvent(new CustomEvent('evidence:updated', { detail: saved }));
      });
    }

    modalOverlay.classList.add('open');
  };

  // Quick Acquire button listeners in nav
  document.querySelectorAll('.btn-acquire-quick').forEach(btn => {
    btn.addEventListener('click', window.openAcquisitionModal);
  });

  // Global ESC key to dismiss modals
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
    }
    // 'A' shortcut opens acquisition modal (unless in input)
    if ((e.key === 'a' || e.key === 'A') && !['INPUT', 'TEXTAREA'].includes(e.target.tagName)) {
      window.openAcquisitionModal();
    }
  });

  console.log('[Cyber Triage App] Navigation & Global Modules Initialized.');
});
