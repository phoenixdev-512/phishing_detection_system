// Popup script - Runs when user clicks the extension icon

document.addEventListener('DOMContentLoaded', async () => {
  try {
    // Get the current active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.id) {
      showError('Unable to get current tab information');
      return;
    }

    // Retrieve the stored scan result for this tab
    const result = await chrome.storage.local.get([tab.id.toString()]);
    const scanData = result[tab.id];

    if (scanData) {
      displayResults(scanData);
    } else {
      showError('No scan data available for this page. The page may still be loading.');
    }

    // Dashboard Button Handler
    document.getElementById('openDashboard').addEventListener('click', () => {
        chrome.tabs.create({ url: 'http://127.0.0.1:8000/' });
    });

  } catch (error) {
    console.error('Error loading popup:', error);
    showError('Error loading scan results: ' + error.message);
  }
});

function displayResults(data) {
  // Hide loading
  document.getElementById('loading').style.display = 'none';
  document.getElementById('results').style.display = 'block';

  // Display URL
  document.getElementById('url').textContent = data.url || 'Unknown URL';

  // Display status badge
  const statusElement = document.getElementById('status');
  const statusClass = data.status === 'error' ? 'status-error' :
                     data.status === 'malicious' ? 'status-malicious' :
                     data.status === 'suspicious' ? 'status-suspicious' : 'status-safe';
  statusElement.className = `status-badge ${statusClass}`;
  statusElement.textContent = data.status.toUpperCase();

  // Display risk score
  const riskScoreElement = document.getElementById('risk-score');
  riskScoreElement.textContent = data.risk_score || 0;
  
  // Color code the risk score
  if (data.risk_score >= 70) {
    riskScoreElement.style.color = '#ef4444';
  } else if (data.risk_score >= 40) {
    riskScoreElement.style.color = '#eab308';
  } else {
    riskScoreElement.style.color = '#22c55e';
  }

  // Display recommendation
  document.getElementById('recommendation').textContent = data.recommendation || 'No recommendation available';

  // Display verdict source
  document.getElementById('verdict-source').textContent = data.verdict_source || 'Unknown';

  // Display reasons
  const reasonsList = document.getElementById('reasons');
  reasonsList.innerHTML = '';
  if (data.reasons && data.reasons.length > 0) {
    data.reasons.forEach(reason => {
      const li = document.createElement('li');
      li.textContent = reason;
      reasonsList.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.textContent = 'No specific reasons provided';
    reasonsList.appendChild(li);
  }

  // Show timestamp if available
  if (data.timestamp) {
    const timeSince = Math.floor((Date.now() - data.timestamp) / 1000);
    const timeText = timeSince < 60 ? 'Just now' : 
                     timeSince < 3600 ? `${Math.floor(timeSince / 60)} minutes ago` :
                     `${Math.floor(timeSince / 3600)} hours ago`;
    
    const footer = document.querySelector('.footer');
    footer.innerHTML = `Last scanned: ${timeText}<br>` + footer.innerHTML;
  }
}

function showError(message) {
  document.getElementById('loading').innerHTML = `
    <div style="color: #ef4444; text-align: center;">
      <p style="font-size: 24px; margin-bottom: 12px;">⚠️</p>
      <p>${message}</p>
    </div>
  `;
}
