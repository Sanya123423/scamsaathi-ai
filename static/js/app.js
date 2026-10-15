/**
 * ScamSaathi - Frontend Application Script
 * Connects UI to Flask Backend (/api/analyze & /api/scan)
 * Handles telemetry, safe URL forensics, explainable indicators, and scan history.
 */

document.addEventListener('DOMContentLoaded', () => {
  // --- DOM Elements ---
  const scanForm = document.getElementById('scan-form');
  const messageInput = document.getElementById('message-input');
  const urlInput = document.getElementById('url-input');
  const charCounter = document.getElementById('char-counter');
  const btnAnalyze = document.getElementById('btn-analyze');
  const btnCheckUrlOnly = document.getElementById('btn-check-url-only');
  const btnClearInputs = document.getElementById('btn-clear-inputs');
  const inputError = document.getElementById('input-error');
  const inputErrorText = document.getElementById('input-error-text');

  // Backend Status Banner & Pill
  const backendStatusBanner = document.getElementById('backend-status-banner');
  const btnRetryBackend = document.getElementById('btn-retry-backend');
  const statusDot = document.getElementById('status-dot');
  const statusLabel = document.getElementById('status-label');
  const btnRefreshStats = document.getElementById('btn-refresh-stats');

  // State Containers
  const stateIdle = document.getElementById('state-idle');
  const stateLoading = document.getElementById('state-loading');
  const stateError = document.getElementById('state-error');
  const stateSuccess = document.getElementById('state-success');
  const btnErrorRetry = document.getElementById('btn-error-retry');
  const resultIdleBadge = document.getElementById('result-idle-badge');
  const resultSeverityContainer = document.getElementById('result-severity-container');

  // Success State Elements
  const riskScoreValue = document.getElementById('risk-score-value');
  const gaugeProgressCircle = document.getElementById('gauge-progress-circle');
  const dynamicSeverityBadge = document.getElementById('dynamic-severity-badge');
  const primaryThreatType = document.getElementById('primary-threat-type');
  const threatSummaryDescription = document.getElementById('threat-summary-description');
  const threatCategoryTags = document.getElementById('threat-category-tags');
  const indicatorsContainer = document.getElementById('indicators-container');
  const indicatorCountBadge = document.getElementById('indicator-count-badge');
  const mlClassificationSection = document.getElementById('ml-classification-section');
  const mlCategoryBadge = document.getElementById('ml-category-badge');
  const mlConfidenceValue = document.getElementById('ml-confidence-value');
  const mlExplanationText = document.getElementById('ml-explanation-text');
  const mlDisclaimerText = document.getElementById('ml-disclaimer-text');
  const urlForensicsSection = document.getElementById('url-forensics-section');
  const forensicUrlText = document.getElementById('forensic-url-text');
  const forensicUrlSignals = document.getElementById('forensic-url-signals');
  const safetyRecommendationsList = document.getElementById('safety-recommendations-list');
  const privacyRedactedInfo = document.getElementById('privacy-redacted-info');

  // Metrics Stat Cards
  const metricTotalScans = document.getElementById('metric-total-scans');
  const metricHighThreats = document.getElementById('metric-high-threats');
  const metricSuspiciousUrls = document.getElementById('metric-suspicious-urls');
  const metricSafeScans = document.getElementById('metric-safe-scans');

  // Scan History
  const historyTableBody = document.getElementById('history-table-body');
  const emptyHistoryPlaceholder = document.getElementById('empty-history-placeholder');
  const btnClearHistory = document.getElementById('btn-clear-history');

  // Quick Demo Presets
  const presetButtons = document.querySelectorAll('.preset-btn');

  // Internal client state
  let localScanHistory = [];
  try {
    const saved = localStorage.getItem('scamsaathi_scan_history');
    if (saved) {
      localScanHistory = JSON.parse(saved);
    }
  } catch (e) {
    console.warn('Could not read scan history from localStorage:', e);
  }

  // --- Preset Scenarios for Hackathon Demonstrations ---
  const demoPresets = {
    electricity: {
      message: 'Urgent: Your electricity power will be disconnected at 9:30 PM tonight due to unpaid bill. Immediately update your KYC by calling electricity officer at 9876543210 or pay bill here: http://bijli-bill-pay.xyz/update',
      url: 'http://bijli-bill-pay.xyz/update'
    },
    telegram_job: {
      message: 'Congratulations! Selected for part-time work from home job. Earn ₹3000 to ₹8000 daily by simply subscribing YouTube channels and liking posts. No experience needed. Pay ₹500 registration deposit. Contact HR manager on Telegram https://t.me/hr_officer_jobs_daily',
      url: 'https://t.me/hr_officer_jobs_daily'
    },
    bank_phishing: {
      message: 'Dear Customer, your State Bank NetBanking account has been suspended due to pending PAN card verification. Submit your 6-digit OTP and login password immediately to avoid permanent deactivation: http://192.168.1.100/sbi-kyc-login.php',
      url: 'http://192.168.1.100/sbi-kyc-login.php'
    },
    clean_order: {
      message: 'Your order #402-8921 has been shipped via BlueDart with tracking ID A128938. Expected delivery by tomorrow 6:00 PM. Track shipment at official courier portal.',
      url: 'https://www.bluedart.com'
    }
  };

  // --- Character Counter ---
  messageInput.addEventListener('input', () => {
    const count = messageInput.value.length;
    charCounter.textContent = `${count} chars`;
    hideInputError();
  });

  urlInput.addEventListener('input', () => {
    hideInputError();
  });

  // --- Preset Buttons Click ---
  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const sampleKey = btn.dataset.sample;
      const sampleData = demoPresets[sampleKey];
      if (sampleData) {
        messageInput.value = sampleData.message;
        urlInput.value = sampleData.url || '';
        charCounter.textContent = `${sampleData.message.length} chars`;
        hideInputError();
        messageInput.focus();
      }
    });
  });

  // --- Clear Form Inputs ---
  btnClearInputs.addEventListener('click', () => {
    messageInput.value = '';
    urlInput.value = '';
    charCounter.textContent = '0 chars';
    hideInputError();
    showIdleState();
  });

  // --- Clear Scan History ---
  btnClearHistory.addEventListener('click', async () => {
    localScanHistory = [];
    localStorage.removeItem('scamsaathi_scan_history');
    renderHistoryTable();
    updateTelemetryMetrics();
    try {
      await fetch('/api/clear', { method: 'POST' });
    } catch (e) {
      // Backend may be offline; local clear already handled
    }
  });

  // --- Check Backend Connectivity & Load Initial Stats ---
  async function checkBackendHealth() {
    try {
      statusDot.className = 'status-dot status-checking';
      statusLabel.textContent = 'Checking Backend...';

      const res = await fetch('/api/stats', { method: 'GET', signal: AbortSignal.timeout(4000) });
      if (res.ok) {
        const stats = await res.json();
        statusDot.className = 'status-dot status-online';
        statusLabel.textContent = 'Backend Online';
        backendStatusBanner.classList.add('hidden');
        renderServerStats(stats);
      } else {
        markBackendOffline();
      }
    } catch (err) {
      markBackendOffline();
    }
  }

  function markBackendOffline() {
    statusDot.className = 'status-dot status-offline';
    statusLabel.textContent = 'Backend Offline';
    backendStatusBanner.classList.remove('hidden');
  }

  btnRetryBackend.addEventListener('click', checkBackendHealth);
  btnRefreshStats.addEventListener('click', checkBackendHealth);

  // --- Dedicated Check URL Button ---
  if (btnCheckUrlOnly) {
    btnCheckUrlOnly.addEventListener('click', async () => {
      hideInputError();
      const urlText = urlInput.value.trim();
      if (!urlText) {
        showInputError('Please enter a URL to inspect.');
        urlInput.focus();
        return;
      }
      await performUrlCheck(urlText);
    });
  }

  // --- Form Submit Handler ---
  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideInputError();

    const messageText = messageInput.value.trim();
    const urlText = urlInput.value.trim();

    if (!messageText && !urlText) {
      showInputError('Please enter a message or a URL to analyze.');
      return;
    }

    // If only a URL is provided, route directly to the dedicated URL inspector
    if (!messageText && urlText) {
      await performUrlCheck(urlText);
    } else {
      await performScan(messageText, urlText);
    }
  });

  if (btnErrorRetry) {
    btnErrorRetry.addEventListener('click', () => {
      const messageText = messageInput.value.trim();
      const urlText = urlInput.value.trim();
      if (!messageText && urlText) {
        performUrlCheck(urlText);
      } else if (messageText || urlText) {
        performScan(messageText, urlText);
      } else {
        showIdleState();
      }
    });
  }

  // --- Dedicated Safe Offline URL Analysis Function ---
  async function performUrlCheck(targetUrl) {
    showLoadingState();
    if (btnCheckUrlOnly) btnCheckUrlOnly.disabled = true;
    btnAnalyze.disabled = true;

    try {
      const response = await fetch('/api/check-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
        signal: AbortSignal.timeout(10000)
      });

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.error || `Server returned error ${response.status}`);
      }

      const report = await response.json();

      // Transform dedicated URL report into standard result presentation
      const transformedResult = {
        risk_score: report.risk_score,
        severity: report.severity,
        threat_type: `URL Forensics: ${report.severity} Threat Level`,
        explanation_summary: report.summary,
        threat_categories: [
          'URL Forensics',
          report.is_https ? 'HTTPS Encrypted' : 'Plaintext Insecure HTTP'
        ],
        detected_indicators: report.detected_indicators,
        recommended_actions: report.safe_next_steps,
        url_analysis: {
          url: report.normalized_url,
          hostname: report.hostname,
          is_suspicious: report.risk_score >= 25,
          signals: report.detected_indicators,
          summary: report.summary
        },
        redacted_message: `Inspected Target URL: ${report.normalized_url}`
      };

      statusDot.className = 'status-dot status-online';
      statusLabel.textContent = 'Backend Online';
      backendStatusBanner.classList.add('hidden');

      renderScanResult(transformedResult, '', report.normalized_url);
      saveToHistory(transformedResult, '', report.normalized_url);
      checkBackendHealth();

    } catch (err) {
      console.error('URL Check Error:', err);
      showErrorState(
        'URL Inspection Failed',
        `Could not inspect URL: ${err.message}. Please verify the backend is running at http://127.0.0.1:5000.`
      );
      markBackendOffline();
    } finally {
      if (btnCheckUrlOnly) btnCheckUrlOnly.disabled = false;
      btnAnalyze.disabled = false;
    }
  }

  // --- Core API Scan Function ---
  async function performScan(message, url) {
    showLoadingState();
    btnAnalyze.disabled = true;
    if (btnCheckUrlOnly) btnCheckUrlOnly.disabled = true;

    try {
      // ScamSaathi backend supports POST /api/analyze and POST /api/scan
      let response;
      try {
        response = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message, url }),
          signal: AbortSignal.timeout(12000)
        });
      } catch (firstErr) {
        // Fallback to /api/scan
        response = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message, url }),
          signal: AbortSignal.timeout(12000)
        });
      }

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.error || `Server responded with status ${response.status}`);
      }

      const result = await response.json();
      
      // Update system status
      statusDot.className = 'status-dot status-online';
      statusLabel.textContent = 'Backend Online';
      backendStatusBanner.classList.add('hidden');

      // Render actual backend result
      renderScanResult(result, message, url);

      // Record to history
      saveToHistory(result, message, url);

      // Refresh telemetry
      checkBackendHealth();

    } catch (err) {
      console.error('Threat scan error:', err);
      showErrorState(
        'Backend Service Unavailable',
        `Could not complete threat analysis: ${err.message}. Please ensure the Flask backend is running on http://127.0.0.1:5000.`
      );
      markBackendOffline();
    } finally {
      btnAnalyze.disabled = false;
      if (btnCheckUrlOnly) btnCheckUrlOnly.disabled = false;
    }
  }

  // --- Render Scan Result into UI ---
  function renderScanResult(data, originalMessage, originalUrl) {
    showSuccessState();

    const score = Number.isInteger(data.risk_score) ? data.risk_score : Math.round(data.risk_score || 0);
    const severity = (data.severity || 'Low').toUpperCase();

    // 1. Update Gauge & Score Counter
    animateScoreValue(score);
    updateGaugeProgress(score, severity);

    // 2. Severity Badge in Header & Summary
    const badgeClass = `badge-${severity.toLowerCase()}`;
    resultSeverityContainer.innerHTML = `<span class="badge ${badgeClass}" id="result-active-badge">${escapeHtml(data.severity || 'Low')} Threat</span>`;
    
    dynamicSeverityBadge.className = `severity-badge-dynamic badge-${severity.toLowerCase()}`;
    dynamicSeverityBadge.textContent = data.severity || 'Low';

    // 3. Primary Threat Label & Summary
    primaryThreatType.textContent = data.threat_type || (score > 55 ? 'High Risk Threat Identified' : (score > 25 ? 'Suspicious Indicators Found' : 'Clean / Benign Content'));
    threatSummaryDescription.textContent = data.explanation_summary || data.summary || (data.explanations && data.explanations[0]) || 'Analysis complete with explainable threat signals.';

    // 4. Threat Category Tags
    threatCategoryTags.innerHTML = '';
    const categories = data.threat_categories || data.categories || [];
    if (categories.length > 0) {
      categories.forEach(cat => {
        const tag = document.createElement('span');
        tag.className = 'threat-tag';
        tag.textContent = cat;
        threatCategoryTags.appendChild(tag);
      });
    } else {
      const tag = document.createElement('span');
      tag.className = 'threat-tag';
      tag.textContent = score > 25 ? 'Suspicious Pattern' : 'No Threat Category Triggered';
      threatCategoryTags.appendChild(tag);
    }

    // 5. Detected Warning Indicators
    indicatorsContainer.innerHTML = '';
    const indicators = data.detected_indicators || data.indicators || [];
    indicatorCountBadge.textContent = `${indicators.length} found`;

    if (indicators.length === 0) {
      indicatorsContainer.innerHTML = `
        <div class="indicator-card severity-low">
          <div class="indicator-headline">
            <span>No malicious urgency, credential harvesting, or spoofing patterns detected.</span>
          </div>
          <p class="indicator-detail">Message content aligns with standard legitimate communications.</p>
        </div>
      `;
    } else {
      indicators.forEach(ind => {
        const card = document.createElement('div');
        const indSeverity = (ind.severity || (score > 60 ? 'high' : (score > 30 ? 'medium' : 'low'))).toLowerCase();
        card.className = `indicator-card severity-${indSeverity}`;
        
        const title = typeof ind === 'string' ? ind : (ind.name || ind.title || ind.rule || 'Suspicious Pattern');
        const detail = typeof ind === 'object' && ind.explanation ? ind.explanation : (ind.detail || 'Pattern matched known cyber threat indicator.');
        const weight = typeof ind === 'object' && ind.weight ? ` (+${ind.weight} risk)` : '';

        card.innerHTML = `
          <div class="indicator-headline">
            <span>${escapeHtml(title)}</span>
            <span style="font-size:0.75rem; color:var(--text-dim); font-family:var(--font-mono);">${escapeHtml(weight)}</span>
          </div>
          <p class="indicator-detail">${escapeHtml(detail)}</p>
        `;
        indicatorsContainer.appendChild(card);
      });
    }

    // 5.5 Machine Learning Text Classifier (Kept Separate from Rules)
    const ml = data.ml_assessment;
    if (ml && ml.status === 'active' && mlClassificationSection) {
      mlClassificationSection.classList.remove('hidden');
      mlCategoryBadge.textContent = ml.predicted_category || 'Statistical Model';
      if (ml.predicted_category && ml.predicted_category.includes('Suspicious')) {
        mlCategoryBadge.className = 'ml-category-badge ml-badge-suspicious';
      } else {
        mlCategoryBadge.className = 'ml-category-badge ml-badge-legitimate';
      }
      const confPct = Math.round((ml.model_confidence || 0) * 100);
      mlConfidenceValue.textContent = `${confPct}%`;
      mlExplanationText.textContent = ml.explanation || 'Statistical feature similarity to training corpus distributions.';
      if (ml.disclaimer && mlDisclaimerText) {
        mlDisclaimerText.textContent = ml.disclaimer;
      }
    } else if (mlClassificationSection) {
      mlClassificationSection.classList.add('hidden');
    }

    // 6. Safe URL Forensic Inspection
    const urlForensics = data.url_analysis || data.url_forensics || null;
    const targetUrl = urlForensics?.url || originalUrl || extractFirstUrl(originalMessage);

    if (targetUrl) {
      urlForensicsSection.classList.remove('hidden');
      forensicUrlText.textContent = targetUrl;
      forensicUrlSignals.innerHTML = '';

      const signals = urlForensics?.signals || urlForensics?.indicators || [];
      if (signals.length > 0) {
        signals.forEach(sig => {
          const pill = document.createElement('div');
          pill.className = 'url-signal-pill';
          const text = typeof sig === 'string' ? sig : (sig.name || sig.desc || JSON.stringify(sig));
          pill.innerHTML = `<span class="chip-dot" style="background:var(--color-medium)"></span>${escapeHtml(text)}`;
          forensicUrlSignals.appendChild(pill);
        });
      } else {
        const pill = document.createElement('div');
        pill.className = 'url-signal-pill';
        pill.innerHTML = `<span class="chip-dot" style="background:var(--color-safe)"></span>Domain structure appears standard`;
        forensicUrlSignals.appendChild(pill);
      }
    } else {
      urlForensicsSection.classList.add('hidden');
    }

    // 7. Recommended Safety Actions
    safetyRecommendationsList.innerHTML = '';
    const actions = data.recommended_actions || data.recommendations || [
      'Do not share passwords, OTPs, or financial pins under any circumstances.',
      'Verify unexpected requests by contacting the institution via their official phone or portal.',
      'Report any suspicious or fraudulent communications to National Cyber Crime helpline 1930.'
    ];

    actions.forEach(act => {
      const li = document.createElement('li');
      li.className = 'safety-action-item';
      li.innerHTML = `
        <svg class="safety-check-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <polyline points="9 11 12 14 22 4"></polyline>
          <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
        </svg>
        <span>${escapeHtml(act)}</span>
      `;
      safetyRecommendationsList.appendChild(li);
    });

    // 8. Privacy redaction notice
    if (data.redacted_message && data.redacted_message !== originalMessage) {
      privacyRedactedInfo.textContent = 'Privacy Guard: Sensitive data (phone numbers, card digits, or OTPs) was masked before processing.';
    } else {
      privacyRedactedInfo.textContent = 'Privacy Guard: Processed locally without storing raw personal information.';
    }
  }

  // --- Gauge & Score Animations ---
  function animateScoreValue(targetScore) {
    let current = 0;
    const duration = 600;
    const stepTime = 15;
    const steps = duration / stepTime;
    const increment = targetScore / steps;

    const timer = setInterval(() => {
      current += increment;
      if (current >= targetScore) {
        current = targetScore;
        clearInterval(timer);
      }
      riskScoreValue.textContent = Math.round(current);
    }, stepTime);
  }

  function updateGaugeProgress(score, severity) {
    const circumference = 314.159; // 2 * PI * 50
    const offset = circumference - (score / 100) * circumference;
    gaugeProgressCircle.style.strokeDashoffset = offset;

    if (severity === 'CRITICAL') {
      gaugeProgressCircle.style.stroke = 'var(--color-critical)';
    } else if (severity === 'HIGH') {
      gaugeProgressCircle.style.stroke = 'var(--color-high)';
    } else if (severity === 'MEDIUM') {
      gaugeProgressCircle.style.stroke = 'var(--color-medium)';
    } else {
      gaugeProgressCircle.style.stroke = 'var(--color-safe)';
    }
  }

  // --- History Management ---
  function saveToHistory(result, message, url) {
    const entry = {
      id: Date.now(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      target: (message || url || 'Input').slice(0, 50),
      category: result.threat_type || (result.threat_categories && result.threat_categories[0]) || 'Analysis',
      score: result.risk_score || 0,
      severity: result.severity || 'Low'
    };

    localScanHistory.unshift(entry);
    if (localScanHistory.length > 20) {
      localScanHistory.pop();
    }

    try {
      localStorage.setItem('scamsaathi_scan_history', JSON.stringify(localScanHistory));
    } catch (e) {}

    renderHistoryTable();
    updateTelemetryMetrics();
  }

  function renderHistoryTable() {
    if (localScanHistory.length === 0) {
      historyTableBody.innerHTML = `
        <tr class="empty-history-row" id="empty-history-placeholder">
          <td colspan="6" class="empty-history-cell">
            <div class="empty-history-msg">
              <svg class="empty-history-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              <p>No scans recorded yet. Enter a message or URL above and click <strong>Analyze Cyber Threat</strong> to perform your first assessment.</p>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    historyTableBody.innerHTML = '';
    localScanHistory.forEach(item => {
      const tr = document.createElement('tr');
      const sevClass = `badge-${item.severity.toLowerCase()}`;
      tr.innerHTML = `
        <td class="history-time">${escapeHtml(item.timestamp)}</td>
        <td class="history-snippet" title="${escapeHtml(item.target)}">${escapeHtml(item.target)}</td>
        <td><span class="threat-tag">${escapeHtml(item.category)}</span></td>
        <td class="history-score-cell">${item.score}/100</td>
        <td><span class="badge ${sevClass}" style="font-size:0.74rem;">${escapeHtml(item.severity)}</span></td>
        <td><span style="font-size:0.75rem; color:var(--color-safe);">Scanned</span></td>
      `;
      historyTableBody.appendChild(tr);
    });
  }

  function updateTelemetryMetrics() {
    const total = localScanHistory.length;
    const highAndCritical = localScanHistory.filter(i => ['HIGH', 'CRITICAL'].includes(i.severity.toUpperCase())).length;
    const safe = localScanHistory.filter(i => i.severity.toUpperCase() === 'LOW').length;
    const urls = localScanHistory.filter(i => i.target.includes('http://') || i.target.includes('https://') || i.target.includes('.')).length;

    metricTotalScans.textContent = total;
    metricHighThreats.textContent = highAndCritical;
    metricSafeScans.textContent = safe;
    metricSuspiciousUrls.textContent = urls;
  }

  function renderServerStats(stats) {
    if (stats.total_scans !== undefined) {
      metricTotalScans.textContent = stats.total_scans;
    }
    if (stats.high_critical_count !== undefined) {
      metricHighThreats.textContent = stats.high_critical_count;
    }
    if (stats.suspicious_urls_count !== undefined) {
      metricSuspiciousUrls.textContent = stats.suspicious_urls_count;
    }
    if (stats.safe_scans_count !== undefined) {
      metricSafeScans.textContent = stats.safe_scans_count;
    }
  }

  // --- UI State Changers ---
  function showIdleState() {
    stateIdle.classList.remove('hidden');
    stateLoading.classList.add('hidden');
    stateError.classList.add('hidden');
    stateSuccess.classList.add('hidden');
    resultSeverityContainer.innerHTML = '<span class="badge badge-idle" id="result-idle-badge">Awaiting Input</span>';
  }

  function showLoadingState() {
    stateIdle.classList.add('hidden');
    stateLoading.classList.remove('hidden');
    stateError.classList.add('hidden');
    stateSuccess.classList.add('hidden');
    resultSeverityContainer.innerHTML = '<span class="badge badge-idle">Scanning...</span>';
  }

  function showErrorState(title, desc) {
    stateIdle.classList.add('hidden');
    stateLoading.classList.add('hidden');
    stateError.classList.remove('hidden');
    stateSuccess.classList.add('hidden');
    
    document.getElementById('error-title').textContent = title || 'Analysis Failed';
    document.getElementById('error-description').textContent = desc || 'An error occurred during threat inspection.';
    resultSeverityContainer.innerHTML = '<span class="badge badge-critical">Error</span>';
  }

  function showSuccessState() {
    stateIdle.classList.add('hidden');
    stateLoading.classList.add('hidden');
    stateError.classList.add('hidden');
    stateSuccess.classList.remove('hidden');
  }

  function showInputError(msg) {
    inputErrorText.textContent = msg;
    inputError.classList.remove('hidden');
  }

  function hideInputError() {
    inputError.classList.add('hidden');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function extractFirstUrl(text) {
    if (!text) return null;
    const match = text.match(/https?:\/\/[^\s]+/i);
    return match ? match[0] : null;
  }

  // Initial setup
  renderHistoryTable();
  updateTelemetryMetrics();
  checkBackendHealth();
});
