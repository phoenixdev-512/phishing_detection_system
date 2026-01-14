// Content Script - Runs on every page
// This script is injected into web pages and can interact with the DOM

console.log('[Phishing Analyzer] Content script loaded');

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'showWarning') {
    showWarningBanner(message.result);
    sendResponse({ success: true });
  }
  return true;
});

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
