/**
 * CYBER TRIAGE TOOL - SIH1744
 * Centralized Asynchronous REST API Client
 * Connects frontend UI to FastAPI backend endpoints with graceful offline fallback.
 */

(function(root) {
  'use strict';

  const API_BASE = '/api';

  class CyberTriageAPIClient {
    constructor() {
      this.baseUrl = API_BASE;
      this.isConnected = false;
      this.lastError = null;
    }

    /**
     * Checks whether the FastAPI backend is operational.
     */
    async checkHealth() {
      try {
        const res = await fetch(`${this.baseUrl}/health`, { method: 'GET' });
        if (res.ok) {
          const data = await res.json();
          this.isConnected = true;
          return data;
        }
      } catch (err) {
        this.isConnected = false;
      }
      return null;
    }

    /**
     * Generic fetch wrapper with error handling.
     */
    async request(endpoint, options = {}) {
      const url = `${this.baseUrl}${endpoint}`;
      try {
        const response = await fetch(url, {
          headers: {
            'Accept': 'application/json',
            ...(options.headers || {})
          },
          ...options
        });

        if (!response.ok) {
          let errorDetail = `HTTP ${response.status}: ${response.statusText}`;
          try {
            const errData = await response.json();
            if (errData && errData.detail) {
              errorDetail = typeof errData.detail === 'string' ? errData.detail : JSON.stringify(errData.detail);
            }
          } catch (_) {}
          throw new Error(errorDetail);
        }

        this.isConnected = true;
        return await response.json();
      } catch (err) {
        console.warn(`[CyberTriageAPI] Request to ${endpoint} failed:`, err.message);
        this.lastError = err.message;
        throw err;
      }
    }

    // ========================================================================
    // Cases & Dashboard
    // ========================================================================
    async getCases() {
      try {
        return await this.request('/cases');
      } catch (err) {
        return [{ id: 1, case_number: 'INC-2024-0918', name: 'Financial Workstation Triage', status: 'ACTIVE_INVESTIGATION' }];
      }
    }

    async getCase(id = 1) {
      try {
        return await this.request(`/cases/${id}`);
      } catch (err) {
        return { id: 1, case_number: 'INC-2024-0918', name: 'Financial Workstation Triage', status: 'ACTIVE_INVESTIGATION' };
      }
    }

    async getStatistics(caseId = 1) {
      try {
        const stats = await this.request(`/cases/${caseId}/statistics`);
        this.isConnected = true;
        return stats;
      } catch (err) {
        if (window.CyberTriageStore) {
          console.info('[CyberTriageAPI] Falling back to local store for statistics.');
          return window.CyberTriageStore.getDashboardStatistics();
        }
        throw err;
      }
    }

    // ========================================================================
    // Evidence Management
    // ========================================================================
    async getEvidence(filters = {}) {
      try {
        const params = new URLSearchParams();
        if (filters.case_id) params.append('case_id', filters.case_id);
        if (filters.evidence_type && filters.evidence_type !== 'ALL') params.append('evidence_type', filters.evidence_type);
        if (filters.risk && filters.risk !== 'ALL') params.append('risk', filters.risk);
        if (filters.status && filters.status !== 'ALL') params.append('status', filters.status);
        if (filters.search) params.append('search', filters.search);
        if (filters.sort) params.append('sort', filters.sort);
        if (filters.limit) params.append('limit', filters.limit);
        if (filters.skip) params.append('skip', filters.skip);

        const queryStr = params.toString() ? `?${params.toString()}` : '';
        const data = await this.request(`/evidence${queryStr}`);
        return data;
      } catch (err) {
        if (window.CyberTriageStore) {
          console.info('[CyberTriageAPI] Falling back to local store for evidence list.');
          return window.CyberTriageStore.getAllEvidence();
        }
        throw err;
      }
    }

    async getEvidenceById(id) {
      try {
        return await this.request(`/evidence/${encodeURIComponent(id)}`);
      } catch (err) {
        if (window.CyberTriageStore) {
          return window.CyberTriageStore.getEvidenceById(id);
        }
        throw err;
      }
    }

    async uploadEvidence(file, caseId = 1, evidenceType = null) {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('case_id', caseId.toString());
      if (evidenceType) {
        formData.append('evidence_type', evidenceType);
      }

      const url = `${this.baseUrl}/evidence/upload`;
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Accept': 'application/json'
        },
        body: formData
      });

      if (!response.ok) {
        let errorMsg = `Upload failed with HTTP ${response.status}`;
        try {
          const errJson = await response.json();
          if (errJson && errJson.detail) errorMsg = errJson.detail;
        } catch (_) {}
        throw new Error(errorMsg);
      }

      const created = await response.json();
      // Sync with local store if available
      if (window.CyberTriageStore) {
        window.CyberTriageStore.addEvidence(created);
      }
      return created;
    }

    async deleteEvidence(id) {
      return await this.request(`/evidence/${encodeURIComponent(id)}`, { method: 'DELETE' });
    }

    // ========================================================================
    // Indicators of Compromise (IOCs)
    // ========================================================================
    async getIOCs(caseId = 1, filters = {}) {
      try {
        const params = new URLSearchParams();
        if (filters.ioc_type && filters.ioc_type !== 'ALL') params.append('ioc_type', filters.ioc_type);
        if (filters.risk && filters.risk !== 'ALL') params.append('risk', filters.risk);
        if (filters.search) params.append('search', filters.search);

        const queryStr = params.toString() ? `?${params.toString()}` : '';
        const endpoint = caseId ? `/cases/${caseId}/iocs${queryStr}` : `/iocs${queryStr}`;
        return await this.request(endpoint);
      } catch (err) {
        if (window.CyberTriageStore) {
          console.info('[CyberTriageAPI] Falling back to local store for IOCs.');
          return window.CyberTriageStore.getAllIOCs();
        }
        throw err;
      }
    }

    async getIOCById(id) {
      return await this.request(`/iocs/${id}`);
    }

    // ========================================================================
    // Timeline
    // ========================================================================
    async getTimeline(caseId = 1, filters = {}) {
      try {
        const params = new URLSearchParams();
        if (filters.severity && filters.severity !== 'ALL') params.append('severity', filters.severity);
        if (filters.event_type && filters.event_type !== 'ALL') params.append('event_type', filters.event_type);
        if (filters.search) params.append('search', filters.search);

        const queryStr = params.toString() ? `?${params.toString()}` : '';
        return await this.request(`/cases/${caseId}/timeline${queryStr}`);
      } catch (err) {
        if (window.CyberTriageStore) {
          console.info('[CyberTriageAPI] Falling back to local store for timeline.');
          return window.CyberTriageStore.getAllTimelineEvents();
        }
        throw err;
      }
    }

    // ========================================================================
    // Graph
    // ========================================================================
    async getGraph(caseId = 1) {
      try {
        return await this.request(`/cases/${caseId}/graph`);
      } catch (err) {
        if (window.CyberTriageStore) {
          console.info('[CyberTriageAPI] Falling back to local store for graph.');
          return window.CyberTriageStore.getGraphData();
        }
        throw err;
      }
    }

    // ========================================================================
    // Reports & Case Dossier
    // ========================================================================
    async getReports(caseId = 1) {
      return await this.request(`/cases/${caseId}/reports`);
    }

    async getDossier(caseId = 1) {
      try {
        return await this.request(`/cases/${caseId}/dossier`);
      } catch (err) {
        console.info('[CyberTriageAPI] Falling back for dossier.');
        const stats = window.CyberTriageStore ? window.CyberTriageStore.getDashboardStatistics() : {};
        const evidence = window.CyberTriageStore ? window.CyberTriageStore.getAllEvidence() : [];
        const iocs = window.CyberTriageStore ? window.CyberTriageStore.getAllIOCs() : [];
        const timeline = window.CyberTriageStore ? window.CyberTriageStore.getAllTimelineEvents() : [];
        return {
          disclaimer: 'SIMULATION DATA • Generated from synthetic triage dataset.',
          case: { case_number: 'INC-2024-0918', name: 'Financial Workstation Triage' },
          statistics: stats,
          critical_findings: evidence.filter(e => (e.riskScore || e.risk_score || 0) >= 75),
          iocs: iocs,
          timeline: timeline
        };
      }
    }

    async generateReport(caseId = 1, payload = {}) {
      return await this.request(`/cases/${caseId}/reports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    }
  }

  // Export singleton instance to window
  root.CyberTriageAPI = new CyberTriageAPIClient();

  // Quick background health probe
  document.addEventListener('DOMContentLoaded', () => {
    root.CyberTriageAPI.checkHealth().then(status => {
      if (status) {
        console.log(`[CyberTriageAPI] Connected to FastAPI Backend (${status.service} v${status.version})`);
        const pulse = document.querySelector('.case-pulse');
        if (pulse) {
          pulse.title = "Backend: CONNECTED (FastAPI + SQLite)";
        }
      } else {
        console.log('[CyberTriageAPI] Backend offline or running in standalone simulation mode.');
      }
    });
  });

})(typeof self !== 'undefined' ? self : this);
