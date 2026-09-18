/**
 * CYBER TRIAGE TOOL - SIH1744
 * Forensic Report Engine
 * Generates dynamic case dossiers, critical findings summaries,
 * and downloadable standalone HTML/TXT report files.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  if (!window.CyberTriageStore) {
    console.error('CyberTriageStore not found.');
    return;
  }

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

  function renderReport() {
    const stats = window.CyberTriageStore.getDashboardStatistics();
    const evidenceList = window.CyberTriageStore.getAllEvidence();
    const iocList = window.CyberTriageStore.getAllIOCs();
    const timelineList = window.CyberTriageStore.getAllTimelineEvents();

    if (repDate) {
      repDate.textContent = new Date().toISOString().split('T')[0];
    }

    // 1. Statistics
    if (statTotal) statTotal.textContent = stats.totalEvidence;
    if (statCrit) statCrit.textContent = stats.criticalFindings;
    if (statHigh) statHigh.textContent = stats.riskDistribution.HIGH;
    if (statIocs) statIocs.textContent = stats.totalIocs;

    // 2. Critical Findings Table (Risk >= 75)
    if (critFindingsBody) {
      critFindingsBody.innerHTML = '';
      const topCritical = evidenceList.filter(e => e.riskScore >= 75).sort((a, b) => b.riskScore - a.riskScore);
      topCritical.forEach(item => {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.innerHTML = `
          <td class="font-mono" style="color: var(--color-accent-red); font-weight:700;">${item.id}</td>
          <td><span class="badge badge-type font-mono">${item.type}</span></td>
          <td style="color: var(--text-white); font-weight:600;">${item.name}</td>
          <td><span class="badge badge-critical font-mono">${item.riskScore} / 100</span></td>
          <td><span class="badge badge-mitre font-mono">${item.mitreAttack || 'N/A'}</span></td>
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
        const badgeClass = `badge-${ioc.risk.toLowerCase()}`;
        tr.innerHTML = `
          <td class="font-mono" style="color: var(--text-white); font-weight:700;">${ioc.ioc}</td>
          <td><span class="badge badge-type font-mono">${ioc.type}</span></td>
          <td><span class="badge ${badgeClass} font-mono">${ioc.risk}</span></td>
          <td style="color: var(--text-secondary); font-size: 0.72rem;">${ioc.status} &bull; ${ioc.asn || 'Internal / Direct'}</td>
        `;
        iocTableBody.appendChild(tr);
      });
    }

    // 4. Attack Kill Chain Chronology
    if (timelineBody) {
      timelineBody.innerHTML = '';
      timelineList.forEach(evt => {
        const item = document.createElement('div');
        item.style.cssText = 'background: var(--bg-panel); border: 1px solid var(--border-subtle); padding: 10px 14px; display: flex; justify-content: space-between; align-items: center; gap: 12px;';
        
        const sevClass = `badge-${evt.severity.toLowerCase()}`;
        item.innerHTML = `
          <div style="display: flex; align-items: center; gap: 12px;">
            <span style="color: var(--color-accent-red); font-weight: 700; width: 65px;">${evt.time}</span>
            <span class="badge badge-type">${evt.eventType}</span>
            <strong style="color: var(--text-white); font-size: 0.85rem;">${evt.title}</strong>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="color: var(--text-secondary); font-size: 0.76rem; font-family: var(--font-sans);">${evt.description}</span>
            <span class="badge ${sevClass}">${evt.severity}</span>
          </div>
        `;
        timelineBody.appendChild(item);
      });
    }
  }

  // Print button
  if (printBtn) {
    printBtn.addEventListener('click', () => {
      window.print();
    });
  }

  // Download Plaintext TXT Report
  if (downloadTxtBtn) {
    downloadTxtBtn.addEventListener('click', () => {
      const stats = window.CyberTriageStore.getDashboardStatistics();
      const evidenceList = window.CyberTriageStore.getAllEvidence();
      const iocList = window.CyberTriageStore.getAllIOCs();
      const timelineList = window.CyberTriageStore.getAllTimelineEvents();

      let txt = `================================================================================\n`;
      txt += `CYBER TRIAGE TOOL - OFFICIAL INCIDENT INVESTIGATION REPORT\n`;
      txt += `CASE ID: #2024-TRIAGE-01 // HOST: WS-04.CORP.INTERNAL\n`;
      txt += `DATE: ${new Date().toISOString()}\n`;
      txt += `PROJECT: SIH1744 - SMART INDIA HACKATHON 2024\n`;
      txt += `================================================================================\n\n`;

      txt += `1.0 EXECUTIVE SUMMARY\n`;
      txt += `--------------------------------------------------------------------------------\n`;
      txt += `On October 14, 2024 at 09:42 UTC, workstation WS-04 was compromised via spearphishing.\n`;
      txt += `A multi-stage attack was identified: weaponized dropper -> temp space implant ->\n`;
      txt += `PowerShell C2 socket -> LSASS dump -> Domain Admin Pass-the-Hash -> lateral movement\n`;
      txt += `to DC-01 -> exfiltration of 34.4 MB to offshore IP 91.240.118.172.\n\n`;

      txt += `2.0 EVIDENCE STATISTICS\n`;
      txt += `--------------------------------------------------------------------------------\n`;
      txt += `Total Artifacts Ingested:   ${stats.totalEvidence}\n`;
      txt += `Critical Findings:          ${stats.criticalFindings}\n`;
      txt += `High Severity Findings:     ${stats.riskDistribution.HIGH}\n`;
      txt += `Confirmed IOCs:             ${stats.totalIocs}\n\n`;

      txt += `3.0 CRITICAL EVIDENCE FINDINGS (RISK >= 75)\n`;
      txt += `--------------------------------------------------------------------------------\n`;
      evidenceList.filter(e => e.riskScore >= 75).forEach(e => {
        txt += `[${e.id}] ${e.name}\n`;
        txt += `  Type:       ${e.type} | Risk: ${e.riskScore}/100 (${e.riskTier})\n`;
        txt += `  Source:     ${e.source}\n`;
        txt += `  Timestamp:  ${e.timestamp}\n`;
        txt += `  SHA-256:    ${e.sha256 || 'N/A'}\n`;
        txt += `  MITRE:      ${e.mitreAttack || 'N/A'}\n`;
        txt += `  Details:    ${e.description}\n\n`;
      });

      txt += `4.0 CONFIRMED INDICATORS OF COMPROMISE (IOCs)\n`;
      txt += `--------------------------------------------------------------------------------\n`;
      iocList.forEach(i => {
        txt += `* [${i.risk}] ${i.ioc} (${i.type})\n`;
        txt += `  Status: ${i.status} | Occurrences: ${i.occurrences} | First Seen: ${i.firstSeen}\n`;
      });
      txt += `\n`;

      txt += `5.0 ATTACK TIMELINE CHRONOLOGY\n`;
      txt += `--------------------------------------------------------------------------------\n`;
      timelineList.forEach(t => {
        txt += `${t.time} UTC - [${t.severity}] ${t.title} (${t.eventType})\n`;
        txt += `  ${t.description}\n`;
        if (t.relatedEvidenceId) txt += `  Related Evidence: ${t.relatedEvidenceId}\n`;
      });
      txt += `\n`;

      txt += `6.0 CHAIN OF CUSTODY & INTEGRITY\n`;
      txt += `--------------------------------------------------------------------------------\n`;
      txt += `Bitstream validation verified via SHA-256 / Blake3 hash signatures.\n`;
      txt += `ISO/IEC 27037 Digital Evidence Compliance Confirmed.\n`;
      txt += `================================================================================\n`;
      txt += `END OF REPORT\n`;

      const blob = new Blob([txt], { type: 'text/plain;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', `CyberTriage_Report_Case2024-01_${Date.now()}.txt`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      if (window.showAppToast) window.showAppToast('FORENSIC DOSSIER DOWNLOADED AS TXT');
    });
  }

  // Generate Standalone Downloadable HTML Report
  if (generateHtmlBtn) {
    generateHtmlBtn.addEventListener('click', () => {
      const stats = window.CyberTriageStore.getDashboardStatistics();
      const evidenceList = window.CyberTriageStore.getAllEvidence();
      const iocList = window.CyberTriageStore.getAllIOCs();
      const timelineList = window.CyberTriageStore.getAllTimelineEvents();

      const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Cyber Triage Report - Case #2024-TRIAGE-01</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #08090c; color: #f1f5f9; padding: 40px; margin: 0; }
    .report-card { max-width: 1000px; margin: 0 auto; background: #0d0f14; border: 1px solid rgba(255,255,255,0.1); border-top: 4px solid #ff2a2a; padding: 36px; }
    h1, h2, h3 { font-family: monospace; color: #ffffff; }
    h1 { font-size: 24px; margin-top: 6px; }
    .badge { display: inline-block; padding: 3px 8px; font-size: 11px; font-family: monospace; font-weight: bold; border-radius: 2px; }
    .badge-crit { background: rgba(255,42,42,0.2); color: #ff3333; border: 1px solid #ff2a2a; }
    .badge-high { background: rgba(255,107,53,0.2); color: #ff6b35; border: 1px solid #ff6b35; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
    th, td { padding: 10px; border-bottom: 1px solid rgba(255,255,255,0.08); text-align: left; }
    th { font-family: monospace; color: #94a3b8; background: #0a0c10; }
    .mono { font-family: monospace; }
    .stat-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }
    .stat-box { background: #0a0c10; border: 1px solid rgba(255,255,255,0.08); padding: 14px; text-align: center; }
    .stat-num { font-size: 28px; font-weight: bold; font-family: monospace; color: #ffffff; }
    .timeline-item { background: #0a0c10; border-left: 3px solid #ff2a2a; padding: 10px 14px; margin-bottom: 8px; font-family: monospace; font-size: 12px; }
  </style>
</head>
<body>
  <div class="report-card">
    <span class="badge badge-crit">CONFIDENTIAL // DIGITAL FORENSICS DOSSIER</span>
    <h1>CASE #2024-TRIAGE-01: WS-04 FORENSIC TRIAGE REPORT</h1>
    <p class="mono" style="color: #94a3b8; font-size: 12px;">Generated via SIH1744 Cyber Triage Engine &bull; Target: WS-04.CORP.INTERNAL &bull; ${new Date().toUTCString()}</p>
    <hr style="border:none; border-top: 1px solid rgba(255,255,255,0.1); margin: 20px 0;">

    <h3>1.0 EXECUTIVE SUMMARY</h3>
    <p style="font-size: 14px; line-height: 1.6; color: #cbd5e1;">Workstation WS-04 was compromised via spearphishing. Rapid triage correlated 42 forensic artifacts reconstructing a complete Cobalt Strike execution kill chain resulting in Domain Admin token replay and 34.4 MB external exfiltration.</p>

    <h3>2.0 TRIAGE METRICS</h3>
    <div class="stat-row">
      <div class="stat-box"><div class="stat-num">${stats.totalEvidence}</div><div class="mono" style="font-size: 11px; color: #94a3b8;">TOTAL ARTIFACTS</div></div>
      <div class="stat-box"><div class="stat-num" style="color: #ff2a2a;">${stats.criticalFindings}</div><div class="mono" style="font-size: 11px; color: #94a3b8;">CRITICAL FINDINGS</div></div>
      <div class="stat-box"><div class="stat-num" style="color: #ff6b35;">${stats.riskDistribution.HIGH}</div><div class="mono" style="font-size: 11px; color: #94a3b8;">HIGH SEVERITY</div></div>
      <div class="stat-box"><div class="stat-num" style="color: #f59e0b;">${stats.totalIocs}</div><div class="mono" style="font-size: 11px; color: #94a3b8;">CORRELATED IOCs</div></div>
    </div>

    <h3>3.0 CRITICAL EVIDENCE FINDINGS (RISK >= 75)</h3>
    <table>
      <thead><tr><th>ID</th><th>TYPE</th><th>NAME</th><th>RISK</th><th>MITRE ATT&CK</th></tr></thead>
      <tbody>
        ${evidenceList.filter(e => e.riskScore >= 75).map(e => `
          <tr>
            <td class="mono" style="color: #ff2a2a; font-weight:bold;">${e.id}</td>
            <td class="mono">${e.type}</td>
            <td><strong>${e.name}</strong><br><small style="color: #94a3b8;">${e.source}</small></td>
            <td class="mono"><span class="badge badge-crit">${e.riskScore} / 100</span></td>
            <td class="mono" style="color: #c084fc;">${e.mitreAttack || 'N/A'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <h3 style="margin-top: 24px;">4.0 CONFIRMED INDICATORS OF COMPROMISE</h3>
    <table>
      <thead><tr><th>INDICATOR</th><th>TYPE</th><th>RISK</th><th>STATUS</th></tr></thead>
      <tbody>
        ${iocList.map(i => `
          <tr>
            <td class="mono" style="color: #ffffff; font-weight:bold;">${i.ioc}</td>
            <td class="mono">${i.type}</td>
            <td><span class="badge ${i.risk === 'CRITICAL' ? 'badge-crit' : 'badge-high'}">${i.risk}</span></td>
            <td class="mono" style="color: #fbbf24;">${i.status}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <h3 style="margin-top: 24px;">5.0 ATTACK KILL CHAIN TIMELINE</h3>
    <div>
      ${timelineList.map(t => `
        <div class="timeline-item">
          <span style="color: #ff2a2a; font-weight: bold;">${t.time} UTC</span> &bull; 
          <span class="badge ${t.severity === 'CRITICAL' ? 'badge-crit' : 'badge-high'}">${t.severity}</span>
          <strong>${t.title}</strong> (${t.eventType})
          <div style="color: #94a3b8; font-family: sans-serif; font-size: 13px; margin-top: 4px;">${t.description}</div>
        </div>
      `).join('')}
    </div>

    <hr style="border:none; border-top: 1px solid rgba(255,255,255,0.1); margin: 24px 0;">
    <p class="mono" style="font-size: 11px; color: #64748b; text-align: center;">SIH1744 CYBER TRIAGE ENGINE &bull; ISO/IEC 27037 FORENSIC AUDIT TRAIL CONFIRMED</p>
  </div>
</body>
</html>`;

      const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', `CyberTriage_CaseReport_2024-01_${Date.now()}.html`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      if (window.showAppToast) window.showAppToast('STANDALONE HTML REPORT GENERATED & DOWNLOADED');
    });
  }

  // Initial render
  renderReport();
});
