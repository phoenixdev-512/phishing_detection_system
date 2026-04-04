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

  // --- TGIS Additional Data ---
  if (data.tgis_score !== undefined && data.tgis_score !== null) {
    const tgisRow = document.createElement('div');
    tgisRow.style.marginTop = '12px';
    tgisRow.style.fontSize = '12px';
    tgisRow.style.padding = '8px';
    tgisRow.style.backgroundColor = '#f3f4f6';
    tgisRow.style.borderRadius = '4px';
    
    const scoresPara = document.createElement('p');
    scoresPara.style.marginBottom = '4px';
    scoresPara.textContent = `TGIS Score: ${data.tgis_score.toFixed(2)} | TIS: ${data.tis_score.toFixed(2)} | SCP: ${data.scp_score.toFixed(2)}`;
    tgisRow.appendChild(scoresPara);
    
    if (data.scp_activated) {
      const scpBadge = document.createElement('span');
      scpBadge.textContent = 'Sibling Analysis Active';
      scpBadge.style.backgroundColor = '#FF9800';
      scpBadge.style.color = '#fff';
      scpBadge.style.padding = '2px 6px';
      scpBadge.style.borderRadius = '12px';
      scpBadge.style.fontSize = '10px';
      scpBadge.style.marginRight = '8px';
      tgisRow.appendChild(scpBadge);
    }
    
    if (data.domain_age_days !== undefined && data.domain_age_days !== null && data.domain_age_days < 1.0) {
      const ageHours = Math.round(data.domain_age_days * 24);
      const ageLabel = document.createElement('span');
      ageLabel.textContent = `New domain: ${ageHours}h old`;
      ageLabel.style.color = '#ef4444';
      ageLabel.style.fontWeight = 'bold';
      ageLabel.style.fontSize = '10px';
      ageLabel.style.marginRight = '8px';
      tgisRow.appendChild(ageLabel);
    }
    
    if (data.siblings && data.siblings.length > 0) {
      const maliciousCount = data.siblings.filter(s => s.is_known_malicious).length;
      if (maliciousCount > 0) {
        const neighborLabel = document.createElement('span');
        neighborLabel.textContent = `Malicious neighbors: ${maliciousCount}`;
        neighborLabel.style.color = '#ef4444';
        neighborLabel.style.fontSize = '10px';
        tgisRow.appendChild(neighborLabel);
      }
    }
    
    document.getElementById('results').appendChild(tgisRow);
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
