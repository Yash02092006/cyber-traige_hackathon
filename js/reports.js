/**
 * CYBER TRIAGE TOOL - SIH1744
 * Forensic Report Engine
 * Generates dynamic case dossiers, critical findings summaries,
 * and downloadable standalone HTML/TXT report files connected to REST API.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // DOM Elements
  const repDate = document.getElementById('reportDate');
  const statTotal = document.getElementById('repStatTotal');
  const statCrit = document.getElementById('repStatCrit');
  const statHigh = document.getElementById('repStatHigh');
  const statIocs = document.getElementById('repStatIocs');

  const critFindingsBody = document.getElementById('reportCriticalFindingsBody');
  const iocTableBody = document.getElementById('reportIocTableBody');
  const timelineBody = document.getElementById('reportTimelineBody');

  const printBtn = document.getElementById('printReportBtn');
  const downloadTxtBtn = document.getElementById('downloadTxtReportBtn');
  const generateHtmlBtn = document.getElementById('generateHtmlReportBtn');

  let activeDossier = null;

  async function renderReport() {
    // 1. Fetch Dossier from REST API
    if (window.CyberTriageAPI) {
      try {
        activeDossier = await window.CyberTriageAPI.getDossier(1);
      } catch (err) {
        console.warn('[reports.js] REST API unavailable, attempting local fallback:', err);
      }
    }

    // 2. Client-side fallback if offline
    if (!activeDossier && window.CyberTriageStore) {
      const stats = window.CyberTriageStore.getDashboardStatistics();
      const allEv = window.CyberTriageStore.getAllEvidence();
      activeDossier = {
        disclaimer: 'SIMULATION DATA • This investigation report was generated from a synthetic cyber triage hackathon dataset (SIH1744).',
        case: { id: 1, case_number: 'INC-2024-0918', name: 'Financial Workstation Triage' },
        statistics: stats,
        critical_findings: allEv.filter(e => (e.riskScore || e.risk_score || 0) >= 75),
        iocs: window.CyberTriageStore.getAllIOCs(),
        timeline: window.CyberTriageStore.getAllTimelineEvents()
      };
    }

    if (!activeDossier) return;

    if (repDate) {
      repDate.textContent = new Date().toISOString().split('T')[0];
    }

    const stats = activeDossier.statistics || {};
    const evidenceList = activeDossier.critical_findings || [];
    const iocList = activeDossier.iocs || [];
    const timelineList = activeDossier.timeline || [];

    // 1. Statistics Cards
    if (statTotal) statTotal.textContent = stats.total_evidence ?? stats.totalEvidence ?? 42;
    if (statCrit) statCrit.textContent = stats.critical_findings ?? stats.criticalFindings ?? 2;
    if (statHigh) {
      const dist = stats.risk_distribution || stats.riskDistribution || {};
      statHigh.textContent = dist.HIGH || 3;
    }
    if (statIocs) statIocs.textContent = stats.total_iocs ?? stats.totalIocs ?? 12;

    // 2. Critical Findings Table (Risk >= 75)
    if (critFindingsBody) {
      critFindingsBody.innerHTML = '';
      const topCritical = [...evidenceList].sort((a, b) => (b.risk_score ?? b.riskScore ?? 0) - (a.risk_score ?? a.riskScore ?? 0));
      topCritical.forEach(item => {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        const evName = item.filename || item.name || 'Artifact';
        const evType = item.evidence_type || item.type || 'File';
        const evScore = item.risk_score ?? item.riskScore ?? 0;
        const mitre = item.mitre_attack || item.mitreAttack || 'N/A';

        tr.innerHTML = `
          <td class="font-mono" style="color: var(--color-accent-red); font-weight:700;">${item.id}</td>
          <td><span class="badge badge-type font-mono">${evType}</span></td>
          <td style="color: var(--text-white); font-weight:600;">${evName}</td>
          <td><span class="badge badge-critical font-mono">${evScore} / 100</span></td>
          <td><span class="badge badge-mitre font-mono">${mitre}</span></td>
        `;
        tr.addEventListener('click', () => {
          if (window.openEvidenceModal) window.openEvidenceModal(item.id);
        });
        critFindingsBody.appendChild(tr);
      });
    }

    // 3. Confirmed IOCs Table
    if (iocTableBody) {
      iocTableBody.innerHTML = '';
      iocList.forEach(ioc => {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        const val = ioc.value || ioc.ioc || '';
        const iocType = ioc.ioc_type || ioc.type || 'Unknown';
        const risk = ioc.risk || 'MEDIUM';
        const badgeClass = `badge-${risk.toLowerCase()}`;
        tr.innerHTML = `
          <td class="font-mono" style="color: var(--text-white); font-weight:700;">${val}</td>
          <td><span class="badge badge-type font-mono">${iocType}</span></td>
          <td><span class="badge ${badgeClass} font-mono">${risk}</span></td>
          <td style="color: var(--text-secondary); font-size: 0.72rem;">${ioc.status || 'Active'} &bull; ${ioc.asn || 'Internal / Direct'}</td>
        `;
        tr.addEventListener('click', () => {
          if (window.openIocDrawer) window.openIocDrawer(ioc);
        });
        iocTableBody.appendChild(tr);
      });
    }

    // 4. Attack Kill Chain Chronology
    if (timelineBody) {
      timelineBody.innerHTML = '';
      timelineList.forEach(evt => {
        const item = document.createElement('div');
        item.style.cssText = 'background: var(--bg-panel); border: 1px solid var(--border-subtle); padding: 10px 14px; display: flex; justify-content: space-between; align-items: center; gap: 12px;';

        const sev = evt.severity || 'LOW';
        const timeVal = evt.time || (evt.timestamp && evt.timestamp.includes(' ') ? evt.timestamp.split(' ')[1] : evt.timestamp) || '09:42:00';
        const relId = evt.evidence_id || evt.relatedEvidenceId;

        item.innerHTML = `
          <div style="display: flex; align-items: center; gap: 12px;">
            <span class="font-mono" style="color: var(--color-accent-red); font-weight: 700; font-size: 0.82rem;">${timeVal}</span>
            <span style="color: var(--text-white); font-size: 0.85rem; font-weight: 600;">${evt.title}</span>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            ${evt.mitre ? `<span class="badge badge-mitre font-mono">${evt.mitre}</span>` : ''}
            <span class="badge badge-${sev.toLowerCase()} font-mono">${sev}</span>
            ${relId ? `<button type="button" class="chip-btn font-mono" onclick="window.openEvidenceModal('${relId}')">&rarr; ${relId}</button>` : ''}
          </div>
        `;
        timelineBody.appendChild(item);
      });
    }
  }

  // Print Report
  if (printBtn) {
    printBtn.addEventListener('click', () => {
      window.print();
    });
  }

  // Download Plain Text Report
  if (downloadTxtBtn) {
    downloadTxtBtn.addEventListener('click', () => {
      if (!activeDossier) return;
      const stats = activeDossier.statistics || {};
      const evidence = activeDossier.critical_findings || [];
      const iocs = activeDossier.iocs || [];
      const timeline = activeDossier.timeline || [];

      const lines = [
        '================================================================================',
        '                     CYBER TRIAGE TOOL - INVESTIGATION DOSSIER                  ',
        '                     SIH1744 • SMART INDIA HACKATHON 2024                      ',
        '================================================================================',
        '',
        `DISCLAIMER: ${activeDossier.disclaimer || 'SIMULATION DATA ONLY'}`,
        `CASE NUMBER:       INC-2024-0918`,
        `CASE TITLE:        Project Blackout - Financial Workstation Triage`,
        `DATE GENERATED:    ${new Date().toISOString()}`,
        `CLASSIFICATION:    CONFIDENTIAL // TLP:AMBER (SIMULATION)`,
        '',
        '--------------------------------------------------------------------------------',
        '1. INVESTIGATION TELEMETRY & SUMMARY',
        '--------------------------------------------------------------------------------',
        `Total Evidence Ingested:    ${stats.total_evidence ?? stats.totalEvidence ?? 42}`,
        `Critical Findings:          ${stats.critical_findings ?? stats.criticalFindings ?? 2}`,
        `Correlated IOCs:            ${stats.total_iocs ?? stats.totalIocs ?? 12}`,
        `Attack Timeline Events:     ${timeline.length}`,
        '',
        '--------------------------------------------------------------------------------',
        '2. CRITICAL FORENSIC FINDINGS (SCORE >= 75)',
        '--------------------------------------------------------------------------------'
      ];

      evidence.forEach(item => {
        const name = item.filename || item.name;
        const score = item.risk_score ?? item.riskScore ?? 0;
        const mitre = item.mitre_attack || item.mitreAttack || 'N/A';
        lines.push(`[${item.id}] ${name} | SCORE: ${score}/100 | MITRE: ${mitre}`);
        lines.push(`   Source:      ${item.source || item.original_path || 'N/A'}`);
        lines.push(`   SHA-256:     ${item.sha256 || 'N/A'}`);
        lines.push(`   Description: ${item.description || 'N/A'}`);
        lines.push('');
      });

      lines.push('--------------------------------------------------------------------------------');
      lines.push('3. VERIFIED INDICATORS OF COMPROMISE (IOCs)');
      lines.push('--------------------------------------------------------------------------------');
      iocs.forEach(ioc => {
        const val = ioc.value || ioc.ioc;
        const type = ioc.ioc_type || ioc.type;
        lines.push(`- ${val.padEnd(45)} [${type.padEnd(16)}] RISK: ${ioc.risk} | STATUS: ${ioc.status || 'Active'}`);
      });

      lines.push('');
      lines.push('--------------------------------------------------------------------------------');
      lines.push('4. CHRONOLOGICAL ATTACK TIMELINE');
      lines.push('--------------------------------------------------------------------------------');
      timeline.forEach(evt => {
        const time = evt.time || evt.timestamp;
        lines.push(`${time} [${evt.severity}] ${evt.title}`);
        lines.push(`   ${evt.description}`);
      });

      lines.push('');
      lines.push('================================================================================');
      lines.push('END OF DOSSIER • GENERATED BY CYBER TRIAGE ENGINE (SIH1744)');
      lines.push('================================================================================');

      const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `INC-2024-0918_dossier_${Date.now()}.txt`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      if (window.showAppToast) window.showAppToast('PLAIN TEXT REPORT DOWNLOADED');
    });
  }

  // Download Standalone HTML Report
  if (generateHtmlBtn) {
    generateHtmlBtn.addEventListener('click', () => {
      if (!activeDossier) return;
      const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Forensic Dossier - INC-2024-0918 | SIH1744</title>
  <style>
    body { background: #08090c; color: #e1e4ea; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 40px; margin: 0; line-height: 1.6; }
    .container { max-width: 900px; margin: 0 auto; background: #0f1117; border: 1px solid #232733; padding: 32px; border-left: 4px solid #ff2a2a; }
    h1 { color: #ffffff; margin-top: 0; font-size: 1.6rem; letter-spacing: 0.05em; }
    .disclaimer { background: rgba(255, 42, 42, 0.12); border: 1px solid #ff2a2a; padding: 12px; font-family: monospace; font-size: 0.8rem; color: #ff6666; margin-bottom: 24px; }
    .meta { font-family: monospace; font-size: 0.8rem; color: #8a92a6; margin-bottom: 20px; }
    .badge { display: inline-block; padding: 2px 6px; font-size: 0.72rem; font-family: monospace; font-weight: 700; border-radius: 2px; }
    .badge-critical { background: rgba(255, 42, 42, 0.2); color: #ff4444; border: 1px solid #ff4444; }
    table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 0.85rem; }
    th, td { border: 1px solid #232733; padding: 8px 12px; text-align: left; }
    th { background: #161922; color: #8a92a6; font-family: monospace; font-size: 0.75rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="disclaimer">
      <strong>SIMULATION DATA:</strong> ${activeDossier.disclaimer}
    </div>
    <h1>INC-2024-0918: FINANCIAL WORKSTATION TRIAGE</h1>
    <div class="meta">
      CLASSIFICATION: CONFIDENTIAL // TLP:AMBER &bull; GENERATED: ${new Date().toISOString()} &bull; SIH1744
    </div>
    <h2>Executive Investigation Summary</h2>
    <p>Comprehensive forensic triage investigation into suspected initial access via spearphishing link, payload delivery, secondary implant staging, LOLBin reconnaissance, credential harvesting via LSASS process memory dump, and outbound C2 data exfiltration.</p>
    <h2>Critical Findings</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Type</th><th>Name</th><th>Risk Score</th></tr>
      </thead>
      <tbody>
        ${(activeDossier.critical_findings || []).map(f => `
          <tr>
            <td style="font-family: monospace; color: #ff2a2a; font-weight: bold;">${f.id}</td>
            <td>${f.evidence_type || f.type}</td>
            <td>${f.filename || f.name}</td>
            <td><span class="badge badge-critical">${f.risk_score ?? f.riskScore} / 100</span></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    <h2>Verified Indicators of Compromise</h2>
    <table>
      <thead>
        <tr><th>IOC Value</th><th>Type</th><th>Risk</th></tr>
      </thead>
      <tbody>
        ${(activeDossier.iocs || []).map(i => `
          <tr>
            <td style="font-family: monospace; color: #fff;">${i.value || i.ioc}</td>
            <td>${i.ioc_type || i.type}</td>
            <td>${i.risk}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>
</body>
</html>`;

      const blob = new Blob([htmlContent], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `INC-2024-0918_report_${Date.now()}.html`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      if (window.showAppToast) window.showAppToast('STANDALONE HTML REPORT GENERATED');
    });
  }

  // Initial render
  renderReport();
});
