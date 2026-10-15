/**
 * ScamSaathi - Background Service Worker (Manifest V3)
 * Registers context menu to inspect highlighted text on any webpage.
 */

const API_BASE = "http://127.0.0.1:5000";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scamsaathi-scan-selection",
    title: "🛡️ Inspect with ScamSaathi",
    contexts: ["selection", "link"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "scamsaathi-scan-selection") {
    const textToScan = info.selectionText || info.linkUrl || "";
    if (!textToScan) return;

    try {
      const isUrl = textToScan.startsWith("http://") || textToScan.startsWith("https://") || textToScan.includes(".com") || textToScan.includes(".xyz");
      const endpoint = isUrl ? `${API_BASE}/api/check-url` : `${API_BASE}/api/analyze`;
      const body = isUrl ? { url: textToScan } : { message: textToScan };

      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      if (res.ok) {
        const data = await res.json();
        const score = data.risk_score || 0;
        const severity = data.severity || "LOW";
        
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon128.png",
          title: `ScamSaathi: ${severity.toUpperCase()} RISK (${score}/100)`,
          message: data.summary || data.explanation_summary || `Analyzed: ${textToScan.slice(0, 80)}`,
          priority: 2
        });
      }
    } catch (e) {
      // Fallback notification
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "ScamSaathi Alert",
        message: "Scanned text. Check ScamSaathi extension popup for details.",
        priority: 1
      });
    }
  }
});
