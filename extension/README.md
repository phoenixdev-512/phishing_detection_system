# Phishing URL Analyzer - Browser Extension

## Overview

A Chrome extension that provides **real-time phishing detection** for every website you visit. It integrates with the Phishing URL Analyzer backend to provide proactive protection against malicious websites.

## Features

### Real-Time Scanning
- Automatically scans every website you visit
- Works silently in the background
- No manual input required

### Instant Warnings
- Displays prominent warning banners on malicious/suspicious sites
- Color-coded alerts (Red for malicious, Yellow for suspicious)
- Shows risk score (0-100) and detection reasons

### Detailed Analysis
- Click the extension icon to see full analysis
- View risk score, verdict source, and detection layers
- See all reasons for the security verdict

### Multi-Layer Detection
- Local database checks
- External API threat intelligence
- Heuristic analysis for zero-day threats
- Typosquatting and keyword detection

## Installation

### Prerequisites
1. Ensure the Phishing URL Analyzer backend is running:
   ```bash
   cd phishing-url-analyzer
   uvicorn app.main:app --reload
   ```

2. Verify the API is accessible at `http://127.0.0.1:8000`

### Load the Extension

1. Open Chrome and navigate to `chrome://extensions/`

2. Enable **Developer mode** (toggle in top-right corner)

3. Click **Load unpacked**

4. Navigate to and select the `extension` folder:
   ```
   phishing-url-analyzer/extension/
   ```

5. The extension icon should appear in your browser toolbar

## Usage

### Automatic Protection
- Simply browse the web normally
- The extension automatically scans each page you visit
- If a threat is detected, you'll see a warning banner at the top of the page

### Manual Check
1. Click the extension icon in your toolbar
2. View the security analysis for the current page
3. See risk score, detection reasons, and recommendations

### Warning Banner
- Appears automatically on malicious/suspicious sites
- Shows risk score and status
- Click the "✕" button to dismiss
- Expand "View Detection Details" for full analysis

## How It Works

### Background Process
1. Extension monitors tab changes and navigation
2. Sends each URL to the backend API for analysis
3. Stores results in local storage
4. Injects warning banner if threat detected

### Detection Pipeline
1. **Preprocessing**: URL normalization and feature extraction
2. **Database Check**: Instant lookup in local blacklist
3. **API Check**: Query external threat feeds (Google Safe Browsing, PhishTank)
4. **Heuristic Analysis**: Pattern-based zero-day detection
5. **Risk Aggregation**: Calculate final score and verdict

## Configuration

### Change API Endpoint
Edit `extension/background.js`:
```javascript
const API_URL = "http://your-server:8000/api/v1/scan";
```

### Adjust Warning Threshold
Edit `extension/background.js`:
```javascript
// Show warning if score >= 70 (currently)
if (result.status === 'malicious' || result.risk_score >= 70) {
  // Inject warning
}
```

## Privacy & Security

### Data Handling
- URLs are only sent to your local backend (127.0.0.1)
- No data is sent to third parties
- Results are stored locally in the browser

### Permissions Explained
- `activeTab`: Access current tab URL
- `scripting`: Inject warning banners
- `storage`: Store scan results
- `host_permissions`: Communication with your backend API

## Troubleshooting

### Extension Not Working
1. Check that backend is running: `http://127.0.0.1:8000/docs`
2. Open browser console (F12) and check for errors
3. Verify extension has required permissions
4. Try reloading the extension

### No Warning Appears
1. Check extension popup to see if site was scanned
2. Verify risk score meets warning threshold (>= 70)
3. Check browser console for content script errors

### "Backend may be offline" Error
1. Ensure FastAPI server is running
2. Check that API is accessible at `http://127.0.0.1:8000`
3. Verify no firewall blocking localhost connections

## Development

### File Structure
```
extension/
├── manifest.json       # Extension configuration
├── background.js       # Background service worker
├── content.js          # Content script (runs on pages)
├── content.css         # Warning banner styles
├── popup.html          # Extension popup UI
├── popup.js            # Popup logic
└── icons/              # Extension icons
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

### Debugging
- Background script: `chrome://extensions/` → Inspect service worker
- Content script: F12 on any web page
- Popup: Right-click extension icon → Inspect popup

### Testing
1. Visit a known safe site (e.g., google.com)
2. Add a test malicious URL to your database
3. Visit the test URL to verify warning appears
4. Click extension icon to verify popup displays results

## Manifest V3 Compliance
This extension uses Manifest V3, the latest Chrome extension platform:
- Service workers instead of background pages
- Enhanced security and privacy
- Better performance and resource management

## Known Limitations
- Only works with Chrome/Chromium browsers
- Requires local backend to be running
- HTTPS sites may require additional CORS configuration
- Some sites with strict CSP may block warning banner

## Future Enhancements
- [ ] Firefox support
- [ ] Configurable warning thresholds
- [ ] Whitelist management
- [ ] Historical scan reports
- [ ] Offline mode with cached results
- [ ] Custom icon based on risk level

## Support
For issues or questions:
1. Check backend API logs
2. Review browser console errors
3. Verify all prerequisites are met
4. Ensure extension has latest code

## License
Same as the main Phishing URL Analyzer project.
