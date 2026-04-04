// Background Service Worker for Phishing URL Analyzer Extension

const API_URL = "http://127.0.0.1:8000/api/v1/scan";

// Listen for tab updates (when user navigates to a new page)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Ignore chrome://, file://, and extension pages
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('file://')) {
      return;
    }
    
    console.log(`[Background] Tab updated: ${tab.url}`);
    checkURL(tab.url, tabId);
  }
});

// Listen for tab activation (when user switches tabs)
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('chrome-extension://') && !tab.url.startsWith('file://')) {
      console.log(`[Background] Tab activated: ${tab.url}`);
      checkURL(tab.url, activeInfo.tabId);
    }
  });
});

async function checkURL(url, tabId) {
  try {
    console.log(`[Background] Checking URL: ${url}`);
    
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }

    const result = await response.json();
    console.log(`[Background] Result for ${url}:`, result);

    // Store the result for the popup to access
    chrome.storage.local.set({ 
      [tabId]: {
        url: result.url,
        status: result.status,
        risk_score: result.risk_score,
        verdict_source: result.verdict_source,
        recommendation: result.recommendation,
        reasons: result.reasons,
        tgis_score: result.tgis_score,
        tis_score: result.tis_score,
        scp_score: result.scp_score,
        domain_age_days: result.domain_age_days,
        scp_activated: result.scp_activated,
        siblings: result.siblings,
        timestamp: Date.now()
      }
    });

    // If the site is malicious or highly suspicious, send message to content script
    if (result.status === 'malicious' || result.risk_score >= 70) {
      chrome.tabs.sendMessage(tabId, {
        action: 'showWarning',
        result: result
      }).catch(err => {
        // Content script might not be ready yet, fallback to executeScript
        chrome.scripting.executeScript({
          target: { tabId: tabId },
          files: ['content.js']
        }).then(() => {
          chrome.tabs.sendMessage(tabId, {
            action: 'showWarning',
            result: result
          });
        }).catch(console.error);
      });
    }

  } catch (error) {
    console.error(`[Background] Error checking URL ${url}:`, error);
    // Store error state
    chrome.storage.local.set({ 
      [tabId]: {
        url: url,
        status: 'error',
        risk_score: 0,
        verdict_source: 'Error',
        recommendation: 'Unable to scan URL. Backend may be offline.',
        reasons: [error.message],
        timestamp: Date.now()
      }
    });
  }
}
