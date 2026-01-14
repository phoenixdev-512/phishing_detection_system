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
  
  // Create elements safely to prevent XSS
  const content = document.createElement('div');
  content.className = 'phishing-warning-content';
  
  const header = document.createElement('div');
  header.className = 'phishing-warning-header';
  
  const icon = document.createElement('span');
  icon.className = 'phishing-warning-icon';
  icon.textContent = statusEmoji;
  
  const title = document.createElement('span');
  title.className = 'phishing-warning-title';
  title.textContent = `${statusText} WEBSITE DETECTED - Risk Score: ${result.risk_score}/100`;
  
  const closeBtn = document.createElement('button');
  closeBtn.className = 'phishing-warning-close';
  closeBtn.textContent = '✕';
  closeBtn.addEventListener('click', () => {
    banner.remove();
  });
  
  header.appendChild(icon);
  header.appendChild(title);
  header.appendChild(closeBtn);
  
  const body = document.createElement('div');
  body.className = 'phishing-warning-body';
  
  const recommendationP = document.createElement('p');
  const recommendationStrong = document.createElement('strong');
  recommendationStrong.textContent = result.recommendation || 'No recommendation available';
  recommendationP.appendChild(recommendationStrong);
  
  const sourceP = document.createElement('p');
  sourceP.textContent = `Source: ${result.verdict_source || 'Unknown'}`;
  
  const details = document.createElement('details');
  const summary = document.createElement('summary');
  summary.textContent = 'View Detection Details';
  details.appendChild(summary);
  
  const reasonsList = document.createElement('ul');
  if (result.reasons && result.reasons.length > 0) {
    result.reasons.forEach(reason => {
      const li = document.createElement('li');
      li.textContent = reason;
      reasonsList.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.textContent = 'No specific reasons provided';
    reasonsList.appendChild(li);
  }
  details.appendChild(reasonsList);
  
  body.appendChild(recommendationP);
  body.appendChild(sourceP);
  body.appendChild(details);
  
  content.appendChild(header);
  content.appendChild(body);
  banner.appendChild(content);

  document.body.insertBefore(banner, document.body.firstChild);
}
