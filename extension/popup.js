/**
 * ScamSaathi - Chrome Extension Popup Logic
 * Interacts with ScamSaathi backend (http://127.0.0.1:5000)
 * Includes instant offline fallback heuristics if backend is unreachable.
 */

const API_BASE = "http://127.0.0.1:5000";

document.addEventListener("DOMContentLoaded", async () => {
  const currentUrlInput = document.getElementById("ext-current-url");
  const messageInput = document.getElementById("ext-message-input");
  const btnScanUrl = document.getElementById("btn-ext-scan-url");
  const btnScanMsg = document.getElementById("btn-ext-scan-msg");

  const resultsContainer = document.getElementById("ext-results-container");
  const scoreNum = document.getElementById("ext-score-num");
  const severityBadge = document.getElementById("ext-severity-badge");
  const threatSummary = document.getElementById("ext-threat-summary");
  const indicatorsBox = document.getElementById("ext-indicators-box");
  const indicatorsList = document.getElementById("ext-indicators-list");
  const safetyAdvice = document.getElementById("ext-safety-advice");

  const statusDot = document.getElementById("ext-status-dot");
  const statusText = document.getElementById("ext-status-text");

  // Tab switching
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      tabButtons.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPane = document.getElementById(btn.getAttribute("data-tab"));
      if (targetPane) targetPane.classList.add("active");
    });
  });

  // Query Current Active Chrome Tab
  if (chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        const url = tabs[0].url;
        // Don't auto-flag chrome:// internal urls
        if (!url.startsWith("chrome://") && !url.startsWith("edge://")) {
          currentUrlInput.value = url;
        } else {
          currentUrlInput.value = "";
          currentUrlInput.placeholder = "Enter URL (e.g. http://192.168.1.1/login)";
        }
      }
    });
  }

  // Check Backend Connection
  async function checkHealth() {
    try {
      const res = await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        statusDot.className = "status-dot";
        statusText.textContent = "Online";
        return true;
      }
    } catch (e) {
      statusDot.className = "status-dot offline";
      statusText.textContent = "Offline Mode";
      return false;
    }
    return false;
  }
  checkHealth();

  // Scan Current URL
  btnScanUrl.addEventListener("click", async () => {
    const url = currentUrlInput.value.trim();
    if (!url) {
      alert("Please provide a valid URL to analyze.");
      return;
    }

    btnScanUrl.disabled = true;
    btnScanUrl.textContent = "Inspecting...";

    try {
      let report;
      try {
        const res = await fetch(`${API_BASE}/api/check-url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
          signal: AbortSignal.timeout(4000)
        });
        if (res.ok) {
          report = await res.json();
        }
      } catch (e) {
        // Fallback local heuristic
        report = localUrlHeuristic(url);
      }

      if (!report) report = localUrlHeuristic(url);
      displayResult(report.risk_score, report.severity, report.summary, report.detected_indicators || report.signals, report.safe_next_steps || report.recommendations);
    } finally {
      btnScanUrl.disabled = false;
      btnScanUrl.innerHTML = `
        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <span>Inspect Page Link</span>
      `;
    }
  });

  // Scan Message Text
  btnScanMsg.addEventListener("click", async () => {
    const message = messageInput.value.trim();
    if (!message) {
      alert("Please enter text to analyze.");
      return;
    }

    btnScanMsg.disabled = true;
    btnScanMsg.textContent = "Analyzing...";

    try {
      let report;
      try {
        const res = await fetch(`${API_BASE}/api/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message }),
          signal: AbortSignal.timeout(4000)
        });
        if (res.ok) {
          report = await res.json();
        }
      } catch (e) {
        report = localTextHeuristic(message);
      }

      if (!report) report = localTextHeuristic(message);
      displayResult(report.risk_score, report.severity, report.explanation_summary || report.summary || "Completed text risk evaluation.", report.detected_indicators, report.recommended_actions);
    } finally {
      btnScanMsg.disabled = false;
      btnScanMsg.innerHTML = `
        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
        <span>Analyze Threat Signals</span>
      `;
    }
  });

  function displayResult(score, severity, summary, indicators, recommendations) {
    resultsContainer.classList.remove("hidden");
    scoreNum.textContent = score !== undefined ? score : 0;

    const sev = (severity || "LOW").toUpperCase();
    severityBadge.className = `badge badge-${sev.toLowerCase()}`;
    severityBadge.textContent = `${sev} RISK`;

    threatSummary.textContent = summary || "Threat inspection completed.";

    // Render indicators
    if (indicators && indicators.length > 0) {
      indicatorsBox.classList.remove("hidden");
      indicatorsList.innerHTML = indicators.map(ind => `
        <span class="indicator-chip">${escapeHtml(ind.name || ind.label || ind.rule || ind.category || "Suspicious Flag")}</span>
      `).join("");
    } else {
      indicatorsBox.classList.add("hidden");
    }

    // Render safety guidance
    if (recommendations && recommendations.length > 0) {
      safetyAdvice.textContent = recommendations[0];
    } else {
      safetyAdvice.textContent = "Always verify source independently before submitting passwords or money.";
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // Fallback client heuristics in case Python server is briefly stopped
  function localUrlHeuristic(url) {
    let score = 0;
    const indicators = [];
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      score += 50;
      indicators.push({ name: "Numerical IP Host Detected" });
    }
    if (url.startsWith("http://")) {
      score += 15;
      indicators.push({ name: "Unencrypted Plaintext HTTP" });
    }
    if (/\.(xyz|top|work|click|buzz|club|tk|ml)\b/i.test(url)) {
      score += 35;
      indicators.push({ name: "High-Abuse Disposable TLD" });
    }
    if (/(bit\.ly|tinyurl\.com|rb\.gy|is\.gd|t\.co)/i.test(url)) {
      score += 20;
      indicators.push({ name: "URL Shortening Service" });
    }
    score = Math.min(100, score);
    const severity = score >= 80 ? "CRITICAL" : (score >= 55 ? "HIGH" : (score >= 25 ? "MEDIUM" : "LOW"));
    return {
      risk_score: score,
      severity,
      summary: score > 0 ? "Flagged structural URL phishing indicators." : "Clean URL syntax (Zero network visits).",
      detected_indicators: indicators,
      safe_next_steps: ["Never input confidential bank credentials on unverified websites."]
    };
  }

  function localTextHeuristic(text) {
    let score = 0;
    const indicators = [];
    if (/\b(otp|pin|password|cvv|secret\s*code|ओटीपी|पिन)\b/i.test(text)) {
      score += 40;
      indicators.push({ name: "Confidential Credential Request" });
    }
    if (/\b(urgent|immediately|within\s*\d+\s*hours|power\s*cut|suspended|disconnected|तुरंत|बिजली\s*काट)\b/i.test(text)) {
      score += 30;
      indicators.push({ name: "Psychological Urgency / Threat" });
    }
    if (/\b(registration\s*fee|deposit|earn\s*rs|wfh|part\s*time\s*job)\b/i.test(text)) {
      score += 25;
      indicators.push({ name: "Advance Fee / Job Lure" });
    }
    score = Math.min(100, score);
    const severity = score >= 80 ? "CRITICAL" : (score >= 55 ? "HIGH" : (score >= 25 ? "MEDIUM" : "LOW"));
    return {
      risk_score: score,
      severity,
      summary: score > 0 ? "Detected suspicious coercion/credential triggers in message." : "No high-risk keywords detected.",
      detected_indicators: indicators,
      recommended_actions: ["Legitimate banks and agencies never demand OTPs or advance payments over SMS."]
    };
  }
});
