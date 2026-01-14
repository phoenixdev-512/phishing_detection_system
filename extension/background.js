// Background Service Worker for Phishing URL Analyzer Extension

const API_URL = "http://127.0.0.1:8000/api/v1/scan";

// Listen for tab updates (when user navigates to a new page)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Ignore chrome:// and extension pages
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      return;
    }
    
    console.log(`[Background] Tab updated: ${tab.url}`);
    checkURL(tab.url, tabId);
  }
});

// Listen for tab activation (when user switches tabs)
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('chrome-extension://')) {
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
        timestamp: Date.now()
      }
    });

    // If the site is malicious or highly suspicious, inject warning
    if (result.status === 'malicious' || result.risk_score >= 70) {
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: showWarningBanner,
        args: [result]
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

// Function that will be injected into the page
function showWarningBanner(result) {
  // Remove any existing warning
  const existingWarning = document.getElementById('phishing-analyzer-warning');
  if (existingWarning) {
    existingWarning.remove();
  }

  // Create warning banner
  const banner = document.createElement('div');
  banner.id = 'phishing-analyzer-warning';
  banner.className = 'phishing-warning-banner';
  
  const statusEmoji = result.status === 'malicious' ? '🔴' : '⚠️';
  const statusText = result.status === 'malicious' ? 'MALICIOUS' : 'SUSPICIOUS';
  
  banner.innerHTML = `
    <div class="phishing-warning-content">
      <div class="phishing-warning-header">
        <span class="phishing-warning-icon">${statusEmoji}</span>
        <span class="phishing-warning-title">
          ${statusText} WEBSITE DETECTED - Risk Score: ${result.risk_score}/100
        </span>
        <button class="phishing-warning-close" onclick="this.parentElement.parentElement.parentElement.remove()">✕</button>
      </div>
      <div class="phishing-warning-body">
        <p><strong>${result.recommendation}</strong></p>
        <p>Source: ${result.verdict_source}</p>
        <details>
          <summary>View Detection Details</summary>
          <ul>
            ${result.reasons.map(reason => `<li>${reason}</li>`).join('')}
          </ul>
        </details>
      </div>
    </div>
  `;

  document.body.insertBefore(banner, document.body.firstChild);
}
