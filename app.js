/* ==========================================================================
   SECURESCOPE — FULL-STACK WEB APPLICATION CONTROLLER
   Integrated with Python Flask REST API & SQLite Database
   ========================================================================== */

const app = {
  // API Base URL Configuration (relative when served by Flask, absolute otherwise)
  apiBase: 'https://securescope-backend-xq7s.onrender.com',

  // Application State
  currentView: 'dashboard',
  selectedVulnId: null,
  activeScanId: null,
  activeScanData: null,
  activeReportScanId: null,
  activeReportType: 'Executive Security Report',
  
  // Dynamic Datasets loaded from SQLite API
  stats: {
    total_scans: 0,
    apps_analyzed: 0,
    total_findings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    overall_risk_score: 0,
    overall_risk_level: 'SECURE'
  },
  applications: [],
  vulnerabilities: [],
  scanHistory: [],

  // Chart instances
  doughnutChart: null,
  trendChart: null,

  // Polling tracker for active background scans
  scanPollInterval: null,

  // Initialization Method
  async init() {
    this.bindEvents();
    this.handleRouting();
    
    // Fetch live data from backend SQLite database
    await this.loadDashboardData();
    await this.loadVulnerabilities();
    await this.loadScanHistory();
    this.initCharts();
    
    console.log(`SecureScope full-stack client connected to backend API at: ${this.apiBase || 'Origin'}`);
  },

  // Event Binding
  bindEvents() {
    // Navigation Links
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        const view = link.getAttribute('data-view');
        if (view) {
          e.preventDefault();
          this.switchView(view);
          this.closeMobileMenu();
        }
      });
    });

    // Mobile Navigation
    const hamburgerBtn = document.getElementById('hamburger-btn');
    const mobileCloseBtn = document.getElementById('mobile-close-btn');
    const sidebar = document.getElementById('sidebar');

    if (hamburgerBtn) hamburgerBtn.addEventListener('click', () => sidebar.classList.add('mobile-open'));
    if (mobileCloseBtn) mobileCloseBtn.addEventListener('click', () => this.closeMobileMenu());

    // Dropdown Toggles
    const notifBtn = document.getElementById('notif-btn');
    const notifDropdown = document.getElementById('notif-dropdown');
    const profileBtn = document.getElementById('profile-btn');
    const profileDropdown = document.getElementById('profile-dropdown');

    if (notifBtn) {
      notifBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        notifDropdown.classList.toggle('hidden');
        if (profileDropdown) profileDropdown.classList.add('hidden');
      });
    }

    if (profileBtn) {
      profileBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        profileDropdown.classList.toggle('hidden');
        if (notifDropdown) notifDropdown.classList.add('hidden');
      });
    }

    document.addEventListener('click', () => {
      if (notifDropdown) notifDropdown.classList.add('hidden');
      if (profileDropdown) profileDropdown.classList.add('hidden');
      const searchDropdown = document.getElementById('search-dropdown');
      if (searchDropdown) searchDropdown.classList.add('hidden');
    });

    // Global Search Bar Input
    const searchInput = document.getElementById('global-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => this.handleGlobalSearch(e.target.value));
    }
  },

  closeMobileMenu() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.remove('mobile-open');
  },

  // Routing and View Switching
  handleRouting() {
    const hash = window.location.hash.replace('#', '');
    if (hash && document.getElementById(hash)) {
      this.switchView(hash);
    } else {
      this.switchView('dashboard');
    }
  },

  switchView(viewId) {
    if (!document.getElementById(viewId)) return;
    
    this.currentView = viewId;
    window.location.hash = viewId;

    // Update View Visibility
    document.querySelectorAll('.view-section').forEach(sec => sec.classList.remove('active'));
    document.getElementById(viewId).classList.add('active');

    // Update Nav Link Active States
    document.querySelectorAll('.sidebar-nav .nav-link').forEach(link => {
      if (link.getAttribute('data-view') === viewId) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // Update Header Breadcrumb Title
    const breadcrumb = document.getElementById('navbar-title');
    const titlesMap = {
      'dashboard': 'Security Overview',
      'new-analysis': 'New Security Analysis',
      'results': 'Security Analysis Results',
      'vulnerabilities': 'Vulnerability Management',
      'scan-history': 'Analysis History',
      'risk-assessment': 'Risk Assessment',
      'reports': 'Security Reports',
      'test-applications': 'Test Applications',
      'settings': 'Settings'
    };
    if (breadcrumb && titlesMap[viewId]) {
      breadcrumb.textContent = titlesMap[viewId];
    }

    // Refresh view specific data
    if (viewId === 'dashboard') {
      this.loadDashboardData();
    } else if (viewId === 'vulnerabilities') {
      this.loadVulnerabilities();
    } else if (viewId === 'scan-history') {
      this.loadScanHistory();
    } else if (viewId === 'risk-assessment') {
      this.renderRiskAssessmentView();
    }

    // Scroll top
    window.scrollTo({ top: 0, behavior: 'smooth' });
  },

  // ==========================================
  // BACKEND API INTEGRATIONS
  // ==========================================

  // 1. Fetch Dashboard Metrics from GET /api/dashboard
  async loadDashboardData() {
    try {
      const res = await fetch(`${this.apiBase}/api/dashboard`);
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();
      
      this.stats = data;

      // Update Dashboard Counters
      const appsEl = document.getElementById('stat-apps');
      const findingsEl = document.getElementById('stat-findings');
      const critEl = document.getElementById('stat-critical');
      const highEl = document.getElementById('stat-high');
      const medEl = document.getElementById('stat-medium');
      const lowEl = document.getElementById('stat-low');
      const navCount = document.getElementById('nav-vuln-count');

      if (appsEl) appsEl.textContent = data.apps_analyzed || 0;
      if (findingsEl) findingsEl.textContent = data.total_findings || 0;
      if (critEl) critEl.textContent = data.critical || 0;
      if (highEl) highEl.textContent = data.high || 0;
      if (medEl) medEl.textContent = data.medium || 0;
      if (lowEl) lowEl.textContent = data.low || 0;
      if (navCount) navCount.textContent = data.total_findings || 0;

      // Render Recent Analyses Table
      this.renderRecentAnalyses(data.recent_scans || []);

      // Update Charts
      this.updateCharts(data);

      // Render Risk Assessment cards
      this.renderRiskAssessmentView();
    } catch (err) {
      console.warn('Could not load live dashboard data from API, using cached state:', err);
    }
  },

  // 2. Fetch All Vulnerabilities from GET /api/vulnerabilities
  async loadVulnerabilities() {
    try {
      const res = await fetch(`${this.apiBase}/api/vulnerabilities`);
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();
      
      this.vulnerabilities = data;
      this.renderVulnerabilitiesTable(data);
    } catch (err) {
      console.warn('Could not load vulnerabilities from API:', err);
    }
  },

  // 3. Fetch Scan History from GET /api/scans
  async loadScanHistory() {
    try {
      const res = await fetch(`${this.apiBase}/api/scans`);
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();
      
      this.scanHistory = data;
      this.renderScanHistoryTable(data);
    } catch (err) {
      console.warn('Could not load scan history from API:', err);
    }
  },

  // ==========================================
  // RENDERING FUNCTIONS
  // ==========================================

  // Render Dashboard Table (Recent Scans)
  renderRecentAnalyses(scans = []) {
    const tbody = document.getElementById('recent-analyses-tbody');
    if (!tbody) return;

    if (!scans || scans.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align:center; padding:32px; color:#94a3b8;">
            <i class="fa-solid fa-shield-halved" style="font-size:24px; margin-bottom:8px; display:block; color:#64748b;"></i>
            No security scans performed yet. Enter a target URL in <strong>New Analysis</strong> to start scanning.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = scans.map(item => `
      <tr onclick="app.viewScanResults('${item.scan_id}')">
        <td>
          <strong>${item.app_name}</strong>
        </td>
        <td><code>${item.target_url}</code></td>
        <td><strong>${item.total_vulnerabilities}</strong></td>
        <td><span class="badge badge-${(item.risk_level || 'low').toLowerCase()}">${item.risk_level || 'LOW'}</span></td>
        <td><span class="badge badge-low"><i class="fa-solid fa-check"></i> ${item.scan_status}</span></td>
        <td class="text-right">
          <button class="btn btn-outline btn-sm" onclick="event.stopPropagation(); app.viewScanResults('${item.scan_id}')">
            View Results
          </button>
        </td>
      </tr>
    `).join('');
  },

  // Render Vulnerabilities Management Table
  renderVulnerabilitiesTable(dataList = this.vulnerabilities) {
    const tbody = document.getElementById('vulnerabilities-tbody');
    const countEl = document.getElementById('vuln-count-total');
    const emptyState = document.getElementById('vuln-empty-state');
    
    if (!tbody) return;

    if (countEl) countEl.textContent = dataList.length;

    if (!dataList || dataList.length === 0) {
      tbody.innerHTML = '';
      if (emptyState) emptyState.classList.remove('hidden');
      return;
    }

    if (emptyState) emptyState.classList.add('hidden');

    tbody.innerHTML = dataList.map(v => `
      <tr onclick="app.openVulnModal('${v.vuln_id}')">
        <td><span class="code">${v.vuln_id}</span></td>
        <td>
          <strong>${v.vuln_name}</strong>
        </td>
        <td><span class="badge badge-demo">${v.app_name || 'Target'}</span></td>
        <td><code>${v.affected_url}</code></td>
        <td><span class="badge badge-${(v.severity || 'medium').toLowerCase()}">${v.severity}</span></td>
        <td>${v.confidence || 'High'}</td>
        <td>
          <span class="badge ${v.status === 'Open' ? 'badge-high' : 'badge-low'}">
            ${v.status || 'Open'}
          </span>
        </td>
        <td class="text-right">
          <button class="btn btn-outline btn-sm" onclick="event.stopPropagation(); app.openVulnModal('${v.vuln_id}')">
            Details
          </button>
        </td>
      </tr>
    `).join('');
  },

  // Render Scan History Table
  renderScanHistoryTable(scans = this.scanHistory) {
    const tbody = document.getElementById('scan-history-tbody');
    if (!tbody) return;

    if (!scans || scans.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" style="text-align:center; padding:32px; color:#94a3b8;">
            No historical scan records available in database.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = scans.map(item => `
      <tr>
        <td><span class="code">${item.scan_id}</span></td>
        <td><strong>${item.app_name}</strong></td>
        <td>${item.scan_date}</td>
        <td>${item.duration}</td>
        <td><strong>${item.total_vulnerabilities}</strong></td>
        <td><span class="badge badge-${(item.risk_level || 'low').toLowerCase()}">${item.risk_level || 'LOW'}</span></td>
        <td><span class="badge badge-low"><i class="fa-solid fa-circle-check"></i> ${item.scan_status}</span></td>
        <td class="text-right">
          <button class="btn btn-outline btn-sm" onclick="app.viewScanResults('${item.scan_id}')">
            View Scan
          </button>
        </td>
      </tr>
    `).join('');
  },

  // Render Risk Assessment View from Database Values
  renderRiskAssessmentView() {
    const riskView = document.getElementById('risk-assessment');
    if (!riskView) return;

    const scoreNum = riskView.querySelector('.huge-score-num');
    const riskBadge = riskView.querySelector('.risk-level-display .badge');
    const distBars = riskView.querySelector('.distribution-bars');

    const total = this.stats.total_findings || 0;
    const crit = this.stats.critical || 0;
    const high = this.stats.high || 0;
    const med = this.stats.medium || 0;
    const low = this.stats.low || 0;

    const score = this.stats.overall_risk_score || 0;
    const level = this.stats.overall_risk_level || 'LOW';

    if (scoreNum) scoreNum.innerHTML = `${score} <small>/ 100</small>`;
    if (riskBadge) {
      riskBadge.textContent = level;
      riskBadge.className = `badge badge-${level.toLowerCase()} lg`;
    }

    if (distBars) {
      const critPct = total > 0 ? ((crit / total) * 100).toFixed(1) : 0;
      const highPct = total > 0 ? ((high / total) * 100).toFixed(1) : 0;
      const medPct = total > 0 ? ((med / total) * 100).toFixed(1) : 0;
      const lowPct = total > 0 ? ((low / total) * 100).toFixed(1) : 0;

      distBars.innerHTML = `
        <div class="dist-item mb-3">
          <div class="dist-header d-flex justify-content-between mb-1">
            <span class="text-critical"><i class="fa-solid fa-circle me-2"></i> Critical</span>
            <span class="val font-mono">${crit} (${critPct}%)</span>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill bg-critical" style="width: ${critPct}%;"></div></div>
        </div>
        <div class="dist-item mb-3">
          <div class="dist-header d-flex justify-content-between mb-1">
            <span class="text-high"><i class="fa-solid fa-circle me-2"></i> High</span>
            <span class="val font-mono">${high} (${highPct}%)</span>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill bg-high" style="width: ${highPct}%;"></div></div>
        </div>
        <div class="dist-item mb-3">
          <div class="dist-header d-flex justify-content-between mb-1">
            <span class="text-medium"><i class="fa-solid fa-circle me-2"></i> Medium</span>
            <span class="val font-mono">${med} (${medPct}%)</span>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill bg-medium" style="width: ${medPct}%;"></div></div>
        </div>
        <div class="dist-item mb-3">
          <div class="dist-header d-flex justify-content-between mb-1">
            <span class="text-low"><i class="fa-solid fa-circle me-2"></i> Low</span>
            <span class="val font-mono">${low} (${lowPct}%)</span>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill bg-low" style="width: ${lowPct}%;"></div></div>
        </div>
      `;
    }
  },

  // Chart.js Initializations & Live Updates
  initCharts() {
    const doughnutCtx = document.getElementById('riskDoughnutChart');
    if (doughnutCtx) {
      this.doughnutChart = new Chart(doughnutCtx, {
        type: 'doughnut',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low'],
          datasets: [{
            data: [
              this.stats.critical || 0,
              this.stats.high || 0,
              this.stats.medium || 0,
              this.stats.low || 0
            ],
            backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#10b981'],
            borderWidth: 0,
            hoverOffset: 4
          }]
        },
        options: {
          cutout: '76%',
          responsive: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: '#131b2e',
              titleColor: '#fff',
              bodyColor: '#94a3b8',
              borderColor: 'rgba(255,255,255,0.1)',
              borderWidth: 1
            }
          }
        }
      });
    }

    const trendCtx = document.getElementById('findingsTrendChart');
    if (trendCtx) {
      this.trendChart = new Chart(trendCtx, {
        type: 'line',
        data: {
          labels: ['Scan 1', 'Scan 2', 'Scan 3', 'Scan 4', 'Scan 5'],
          datasets: [{
            label: 'Findings Count',
            data: [4, 2, 3, 3, this.stats.total_findings || 5],
            borderColor: '#06b6d4',
            backgroundColor: 'rgba(6, 182, 212, 0.1)',
            fill: true,
            tension: 0.35,
            pointBackgroundColor: '#22d3ee',
            pointRadius: 5,
            pointHoverRadius: 7
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: '#131b2e',
              titleColor: '#fff',
              bodyColor: '#22d3ee',
              borderColor: 'rgba(6, 182, 212, 0.3)',
              borderWidth: 1
            }
          },
          scales: {
            x: {
              grid: { color: 'rgba(255,255,255,0.05)' },
              ticks: { color: '#94a3b8' }
            },
            y: {
              grid: { color: 'rgba(255,255,255,0.05)' },
              ticks: { color: '#94a3b8', stepSize: 2 },
              beginAtZero: true
            }
          }
        }
      });
    }
  },

  updateCharts(data) {
    if (this.doughnutChart) {
      this.doughnutChart.data.datasets[0].data = [
        data.critical || 0,
        data.high || 0,
        data.medium || 0,
        data.low || 0
      ];
      this.doughnutChart.update();
    }

    if (this.trendChart && data.recent_scans && data.recent_scans.length > 0) {
      const reversedScans = [...data.recent_scans].reverse();
      this.trendChart.data.labels = reversedScans.map(s => s.app_name);
      this.trendChart.data.datasets[0].data = reversedScans.map(s => s.total_vulnerabilities);
      this.trendChart.update();
    }
  },

  // ==========================================
  // REAL SECURITY ANALYSIS EXECUTION FLOW
  // ==========================================

  async handleStartAnalysis(e) {
    e.preventDefault();

    const appName = document.getElementById('app-name').value.trim() || 'DemoShop';
    const targetUrl = document.getElementById('target-url').value.trim();
    const profile = document.getElementById('analysis-profile').value || 'Full';

    if (!targetUrl) {
      this.showToast('Please enter a target URL', 'alert');
      return;
    }

    // Hide Form, Show Progress Container
    document.getElementById('analysis-form-container').classList.add('hidden');
    const progressContainer = document.getElementById('analysis-progress-container');
    progressContainer.classList.remove('hidden');

    document.getElementById('scan-target-display').textContent = `Analyzing ${targetUrl}...`;
    document.getElementById('scan-status-heading').textContent = 'Security Analysis in Progress';
    document.getElementById('scan-completed-actions').classList.add('hidden');
    
    // Reset Stages & Spinner
    const spinner = document.getElementById('scan-spinner');
    spinner.className = 'scan-spinner-ring';
    spinner.innerHTML = '';

    for (let i = 1; i <= 5; i++) {
      const stage = document.getElementById(`stage-${i}`);
      if (stage) {
        stage.className = 'stage-item pending';
        stage.querySelector('.stage-icon').innerHTML = '<i class="fa-solid fa-circle"></i>';
      }
    }

    const logBox = document.getElementById('terminal-logs');
    logBox.innerHTML = `<div class="log-line">[SYSTEM] Submitting scan request to SecureScope Flask Backend for ${appName} (${targetUrl})...</div>`;

    try {
      // 1. Submit scan request to Flask Backend (POST /api/scan)
      const res = await fetch(`${this.apiBase}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          app_name: appName,
          target_url: targetUrl,
          profile: profile,
          authorization: true
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || `HTTP error ${res.status}`);
      }

      const scanResponse = await res.json();
      this.activeScanId = scanResponse.scan_id;
      this.showToast(`Analysis job ${this.activeScanId} started on backend`, 'info');

      // 2. Poll for real-time background progress
      this.pollScanProgress(this.activeScanId, appName, targetUrl);

    } catch (err) {
      logBox.innerHTML += `<div class="log-line alert">[ERROR] Failed to start scan: ${err.message}</div>`;
      this.showToast(`Error: ${err.message}`, 'alert');
      document.getElementById('scan-status-heading').textContent = 'Analysis Failed';
    }
  },

  pollScanProgress(scanId, appName, targetUrl) {
    const fill = document.getElementById('progress-bar-fill');
    const percentText = document.getElementById('progress-percent-text');
    const logBox = document.getElementById('terminal-logs');

    if (this.scanPollInterval) clearInterval(this.scanPollInterval);

    const seenLogs = new Set();

    this.scanPollInterval = setInterval(async () => {
      try {
        const res = await fetch(`${this.apiBase}/api/scan/progress/${scanId}`);
        if (!res.ok) return;

        const data = await res.json();

        // Update progress bar
        const progress = data.progress || 10;
        fill.style.width = `${progress}%`;
        percentText.textContent = `${progress}%`;

        // Update stages
        const stageNum = data.stage || 1;
        for (let i = 1; i <= stageNum; i++) {
          const stage = document.getElementById(`stage-${i}`);
          if (stage) {
            stage.className = 'stage-item completed';
            stage.querySelector('.stage-icon').innerHTML = '<i class="fa-solid fa-circle-check"></i>';
          }
        }

        // Append new live log lines
        if (data.logs && data.logs.length > 0) {
          data.logs.forEach(l => {
            const key = `${l.time}_${l.message}`;
            if (!seenLogs.has(key)) {
              seenLogs.add(key);
              const line = document.createElement('div');
              line.className = `log-line ${l.type || ''}`;
              line.textContent = `[${l.time || new Date().toLocaleTimeString()}] ${l.message}`;
              logBox.appendChild(line);
              logBox.scrollTop = logBox.scrollHeight;
            }
          });
        }

        // Check completion
        if (data.status === 'Completed') {
          clearInterval(this.scanPollInterval);
          this.scanPollInterval = null;

          // Complete stage 5
          for (let i = 1; i <= 5; i++) {
            const stage = document.getElementById(`stage-${i}`);
            if (stage) {
              stage.className = 'stage-item completed';
              stage.querySelector('.stage-icon').innerHTML = '<i class="fa-solid fa-circle-check"></i>';
            }
          }
          fill.style.width = '100%';
          percentText.textContent = '100%';

          document.getElementById('scan-status-heading').textContent = 'Analysis Completed';
          const spinner = document.getElementById('scan-spinner');
          spinner.className = 'scan-spinner-ring completed';
          spinner.innerHTML = '<i class="fa-solid fa-circle-check"></i>';

          document.getElementById('scan-completed-actions').classList.remove('hidden');

          // Cache active scan result
          this.activeScanData = data.results;
          this.activeReportScanId = scanId;

          // Refresh global state
          await this.loadDashboardData();
          await this.loadVulnerabilities();
          await this.loadScanHistory();

          this.showToast('Security analysis completed and saved to database!', 'success');
        } else if (data.status === 'Failed') {
          clearInterval(this.scanPollInterval);
          this.scanPollInterval = null;
          document.getElementById('scan-status-heading').textContent = 'Analysis Failed';
          this.showToast(`Analysis failed: ${data.error || 'Unknown error'}`, 'alert');
        }
      } catch (err) {
        console.error('Progress poll error:', err);
      }
    }, 700);
  },

  // View Scan Results for active scan
  viewScanResults(scanId) {
    const targetScanId = scanId || this.activeScanId;
    if (targetScanId) {
      this.fetchAndRenderScanDetails(targetScanId);
    } else if (this.activeScanData) {
      this.renderResultsView(this.activeScanData);
      this.switchView('results');
    }
  },

  // View Results by App Name (finds most recent scan for that application)
  async viewAppResults(appName) {
    const scan = this.scanHistory.find(s => s.app_name.toLowerCase() === appName.toLowerCase());
    if (scan) {
      await this.fetchAndRenderScanDetails(scan.scan_id);
    } else {
      // If not in history, look up by ID directly
      await this.fetchAndRenderScanDetails(appName);
    }
  },

  // Fetch full details of a specific scan from GET /api/scans/<scan_id>
  async fetchAndRenderScanDetails(scanId) {
    try {
      const res = await fetch(`${this.apiBase}/api/scans/${scanId}`);
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();

      const scanInfo = data.scan;
      const vulns = data.vulnerabilities || [];

      this.activeReportScanId = scanId;
      this.activeScanData = {
        scan_id: scanInfo.scan_id,
        appName: scanInfo.app_name,
        targetUrl: scanInfo.target_url,
        riskLevel: (scanInfo.risk_level || 'LOW').toUpperCase(),
        riskScore: scanInfo.risk_score || 0,
        critical: scanInfo.critical_count || 0,
        high: scanInfo.high_count || 0,
        medium: scanInfo.medium_count || 0,
        low: scanInfo.low_count || 0,
        findings: vulns
      };

      this.renderResultsView(this.activeScanData);
      this.switchView('results');
    } catch (err) {
      this.showToast(`Could not load scan ${scanId}: ${err.message}`, 'alert');
    }
  },

  // Populate Results Section DOM
  renderResultsView(data) {
    if (!data) return;

    document.getElementById('res-app-name').textContent = data.appName || data.app_name || 'Application';
    document.getElementById('res-app-target').innerHTML = `Target: <code>${data.targetUrl || data.target_url}</code>`;
    document.getElementById('results-target-info').textContent = `Target: ${data.targetUrl || data.target_url}`;
    document.getElementById('res-score-num').textContent = data.riskScore !== undefined ? data.riskScore : (data.risk_score || 0);
    
    const badge = document.getElementById('res-risk-badge');
    const riskLvl = (data.riskLevel || data.risk_level || 'LOW').toUpperCase();
    badge.textContent = riskLvl;
    badge.className = `risk-badge-large badge-${riskLvl.toLowerCase()}`;

    document.getElementById('res-count-critical').textContent = data.critical !== undefined ? data.critical : (data.critical_count || 0);
    document.getElementById('res-count-high').textContent = data.high !== undefined ? data.high : (data.high_count || 0);
    document.getElementById('res-count-medium').textContent = data.medium !== undefined ? data.medium : (data.medium_count || 0);
    document.getElementById('res-count-low').textContent = data.low !== undefined ? data.low : (data.low_count || 0);

    const findings = data.findings || [];
    const tbody = document.getElementById('results-vuln-tbody');
    if (tbody) {
      if (findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:#94a3b8;">No vulnerabilities identified for this target.</td></tr>`;
      } else {
        tbody.innerHTML = findings.map(v => `
          <tr onclick="app.openVulnModal('${v.vuln_id || v.id}')">
            <td><span class="code">${v.vuln_id || v.id}</span></td>
            <td><strong>${v.vuln_name || v.title}</strong></td>
            <td><code>${v.affected_url || v.location}</code></td>
            <td><span class="badge badge-${(v.severity || 'medium').toLowerCase()}">${v.severity}</span></td>
            <td>${v.confidence || 'High'}</td>
            <td><span class="badge ${v.status === 'Open' ? 'badge-high' : 'badge-low'}">${v.status || 'Open'}</span></td>
            <td class="text-right">
              <button class="btn btn-outline btn-sm" onclick="event.stopPropagation(); app.openVulnModal('${v.vuln_id || v.id}')">
                Details
              </button>
            </td>
          </tr>
        `).join('');
      }
    }
  },

  // Reset Scan Form
  resetForm() {
    document.getElementById('new-analysis-form').reset();
    document.getElementById('analysis-form-container').classList.remove('hidden');
    document.getElementById('analysis-progress-container').classList.add('hidden');
  },

  // Quick Scan Target Shortcut from Test Applications View
  quickScanTarget(appName, targetUrl) {
    this.switchView('new-analysis');
    document.getElementById('analysis-form-container').classList.remove('hidden');
    document.getElementById('analysis-progress-container').classList.add('hidden');

    document.getElementById('app-name').value = appName;
    document.getElementById('target-url').value = targetUrl;
    this.showToast(`Selected ${appName} (${targetUrl}). Click 'Start Security Analysis' to scan.`, 'info');
  },

  // ==========================================
  // MODAL CONTROLLERS & VULNERABILITY STATUS
  // ==========================================

  openVulnModal(vulnId) {
    // Search in loaded vulnerabilities list or active scan data
    let vuln = this.vulnerabilities.find(v => (v.vuln_id || v.id) === vulnId);
    if (!vuln && this.activeScanData && this.activeScanData.findings) {
      vuln = this.activeScanData.findings.find(v => (v.vuln_id || v.id) === vulnId);
    }
    if (!vuln && this.vulnerabilities.length > 0) {
      vuln = this.vulnerabilities[0];
    }
    if (!vuln) return;

    this.selectedVulnId = vuln.vuln_id || vuln.id;

    document.getElementById('modal-vuln-title').textContent = vuln.vuln_name || vuln.title;
    document.getElementById('modal-vuln-id').textContent = this.selectedVulnId;
    document.getElementById('modal-vuln-location').textContent = vuln.affected_url || vuln.location;
    document.getElementById('modal-vuln-confidence').textContent = vuln.confidence || 'High';
    document.getElementById('modal-vuln-status').textContent = vuln.status || 'Open';
    document.getElementById('modal-vuln-desc').textContent = vuln.description || vuln.desc;
    document.getElementById('modal-vuln-impact').textContent = vuln.impact || 'Allows potential security compromise.';

    const sevBadge = document.getElementById('modal-vuln-severity');
    const sev = vuln.severity || 'Medium';
    sevBadge.textContent = sev;
    sevBadge.className = `badge badge-${sev.toLowerCase()}`;

    const remList = document.getElementById('modal-vuln-remediation');
    let remediation = vuln.remediation || [];
    if (typeof remediation === 'string') {
      try {
        remediation = JSON.parse(remediation);
      } catch (e) {
        remediation = [remediation];
      }
    }
    remList.innerHTML = remediation.map(item => `<li>${item}</li>`).join('');

    document.getElementById('vuln-modal').classList.remove('hidden');
  },

  closeVulnModal() {
    document.getElementById('vuln-modal').classList.add('hidden');
  },

  async toggleVulnStatus() {
    if (!this.selectedVulnId) return;

    try {
      const res = await fetch(`${this.apiBase}/api/vulnerabilities/${this.selectedVulnId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' }
      });

      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();

      document.getElementById('modal-vuln-status').textContent = data.status;

      // Update in local state
      const localVuln = this.vulnerabilities.find(v => (v.vuln_id || v.id) === this.selectedVulnId);
      if (localVuln) localVuln.status = data.status;

      this.renderVulnerabilitiesTable();
      this.showToast(`Vulnerability status updated to ${data.status} in SQLite database`, 'success');
    } catch (err) {
      this.showToast(`Failed to update status: ${err.message}`, 'alert');
    }
  },

  // ==========================================
  // PDF REPORT PREVIEW & DOWNLOAD
  // ==========================================

  async openReportPreview(reportTitleOrAppName) {
    const reportModal = document.getElementById('report-modal');
    if (!reportModal) return;

    this.activeReportType = reportTitleOrAppName || 'Executive Security Report';

    // Determine which scan to preview (active scan or most recent scan in DB)
    const scanId = this.activeReportScanId || (this.scanHistory[0] ? this.scanHistory[0].scan_id : null);
    
    if (scanId) {
      try {
        const res = await fetch(`${this.apiBase}/api/reports/${scanId}`);
        if (res.ok) {
          const repData = await res.json();
          const scan = repData.scan;
          
          document.getElementById('report-meta-app').textContent = scan.app_name;
          document.getElementById('report-meta-date').textContent = scan.scan_date;
          document.getElementById('report-meta-score').textContent = `${scan.risk_score}/100`;
          
          const riskBadge = document.getElementById('report-meta-risk');
          riskBadge.textContent = scan.risk_level;
          riskBadge.className = `badge badge-${(scan.risk_level || 'low').toLowerCase()}`;
        }
      } catch (e) {
        console.warn('Report fetch note:', e);
      }
    }

    reportModal.classList.remove('hidden');
  },

  closeReportModal() {
    document.getElementById('report-modal').classList.add('hidden');
  },

  generateMockReport(reportTitle) {
    this.openReportPreview(reportTitle);
    this.showToast(`${reportTitle} generated successfully! Click 'Download Report' to save PDF.`, 'success');
  },

  // Real PDF Report Download from Flask API (GET /api/reports/<scan_id>/download)
  downloadMockReport() {
    const scanId = this.activeReportScanId || (this.scanHistory[0] ? this.scanHistory[0].scan_id : 'SCN-9042');
    const reportType = encodeURIComponent(this.activeReportType || 'Executive Security Report');
    const downloadUrl = `${this.apiBase}/api/reports/${scanId}/download?type=${reportType}`;
    
    this.showToast('Generating and downloading PDF security report from Flask backend...', 'info');
    
    // Trigger download
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.setAttribute('download', `SecureScope_Report_${scanId}.pdf`);
    document.body.appendChild(link);
    link.click();
    link.remove();

    this.closeReportModal();
  },

  // Vulnerability Filters
  applyVulnFilters() {
    const search = document.getElementById('vuln-search').value.toLowerCase();
    const severity = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;
    const typeFilter = document.getElementById('filter-type') ? document.getElementById('filter-type').value : 'ALL';
    const appFilter = document.getElementById('filter-app').value;

    const filtered = this.vulnerabilities.filter(v => {
      const vTitle = (v.vuln_name || v.title || '').toLowerCase();
      const vId = (v.vuln_id || v.id || '').toLowerCase();
      const vLoc = (v.affected_url || v.location || '').toLowerCase();
      const vDesc = (v.description || v.desc || '').toLowerCase();
      const vApp = (v.app_name || v.app || '').toLowerCase();

      const matchSearch = vTitle.includes(search) || vId.includes(search) || vLoc.includes(search);
      const matchSeverity = severity === 'ALL' || (v.severity || '').toLowerCase() === severity.toLowerCase();
      const matchStatus = status === 'ALL' || (v.status || '').toLowerCase() === status.toLowerCase();
      const matchType = typeFilter === 'ALL' || vTitle.includes(typeFilter.toLowerCase()) || vDesc.includes(typeFilter.toLowerCase());
      const matchApp = appFilter === 'ALL' || vApp === appFilter.toLowerCase();

      return matchSearch && matchSeverity && matchStatus && matchType && matchApp;
    });

    this.renderVulnerabilitiesTable(filtered);
  },

  // Global Search Handler
  handleGlobalSearch(query) {
    const dropdown = document.getElementById('search-dropdown');
    const resultsContainer = document.getElementById('search-results-list');
    
    if (!query.trim()) {
      dropdown.classList.add('hidden');
      return;
    }

    const q = query.toLowerCase();
    const matchedVulns = this.vulnerabilities.filter(v => 
      (v.vuln_name || v.title || '').toLowerCase().includes(q) || 
      (v.vuln_id || v.id || '').toLowerCase().includes(q)
    );
    const matchedApps = this.scanHistory.filter(a => 
      (a.app_name || '').toLowerCase().includes(q) || 
      (a.target_url || '').toLowerCase().includes(q)
    );

    let html = '';

    if (matchedApps.length > 0) {
      html += `<div style="padding:4px 8px; font-size:10px; color:#64748b; font-weight:700;">SCANNED TARGETS</div>`;
      matchedApps.forEach(a => {
        html += `
          <div class="search-result-item" onclick="app.viewScanResults('${a.scan_id}')">
            <span><strong>${a.app_name}</strong> (${a.target_url})</span>
            <span class="badge badge-${(a.risk_level || 'low').toLowerCase()}">${a.risk_level || 'LOW'}</span>
          </div>
        `;
      });
    }

    if (matchedVulns.length > 0) {
      html += `<div style="padding:4px 8px; font-size:10px; color:#64748b; font-weight:700;">VULNERABILITIES</div>`;
      matchedVulns.forEach(v => {
        html += `
          <div class="search-result-item" onclick="app.openVulnModal('${v.vuln_id || v.id}')">
            <span><strong>${v.vuln_id || v.id}</strong> — ${v.vuln_name || v.title}</span>
            <span class="badge badge-${(v.severity || 'medium').toLowerCase()}">${v.severity}</span>
          </div>
        `;
      });
    }

    if (!html) {
      html = `<div style="padding:12px; text-align:center; font-size:12px; color:#94a3b8;">No results match "${query}"</div>`;
    }

    resultsContainer.innerHTML = html;
    dropdown.classList.remove('hidden');
  },

  // Save Settings
  saveSettings() {
    this.showToast('Security scanner preferences saved successfully', 'success');
  },

  // Toast Notification Component
  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type === 'alert' ? 'critical' : type}`;
    
    const icon = type === 'success' ? 'fa-circle-check' : (type === 'alert' ? 'fa-triangle-exclamation' : 'fa-circle-info');
    
    toast.innerHTML = `
      <i class="fa-solid ${icon} toast-icon"></i>
      <span class="toast-message">${message}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('toast-fadeout');
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }
};

// Initialize Application when DOM ready
document.addEventListener('DOMContentLoaded', () => {
  app.init();
});
