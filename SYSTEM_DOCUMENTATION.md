# Phishing URL Analyzer - Complete System Documentation

## Project Overview

A comprehensive multi-layer phishing URL detection system with real-time protection capabilities. The system combines local database lookups, external threat intelligence APIs, heuristic analysis, and machine learning-ready architecture to provide instant, accurate phishing detection.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USER INTERFACES                           │
├──────────────────────┬──────────────────────────────────────┤
│   Web Dashboard      │     Browser Extension (Chrome)        │
│  (Dark Mode UI)      │    (Real-time Protection)            │
└──────────┬───────────┴───────────────┬──────────────────────┘
           │                           │
           └───────────┬───────────────┘
                       │
           ┌───────────▼────────────┐
           │   FastAPI Backend       │
           │   (Async Processing)    │
           └───────────┬────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
┌───────────┐  ┌──────────────┐  ┌──────────┐
│ Layer 1:  │  │  Layer 2:    │  │ Layer 3: │
│ Database  │──│  External    │──│ Heuristic│
│ (Bloom +  │  │  APIs        │  │ Analysis │
│  SQLite)  │  │ (Safe Browse)│  │ (ML-Ready)│
└───────────┘  └──────────────┘  └──────────┘
     │              │                  │
     └──────────────┼──────────────────┘
                    │
            ┌───────▼────────┐
            │ Risk Aggregator │
            │ (Weighted Score)│
            └────────────────┘
```

## Detection Layers

### Layer 0: Preprocessing
- **URL Sanitization**: Removes whitespace, control characters
- **Protocol Validation**: Auto-adds http:// if missing
- **IDN Conversion**: Converts Unicode to Punycode (homoglyph detection)
- **Feature Extraction**: Protocol, domain, TLD, path, query parameters
- **Performance**: < 1ms per URL

### Layer 1: Local Database (Speed Layer)
- **Bloom Filter**: Sub-microsecond lookups (0.69µs average)
  - 623,522 bits for 100k URLs
  - 5% false positive rate
  - Zero false negatives
- **SQLite Database**: Persistent malicious URL storage
  - Metadata tracking (source, risk_score, timestamp)
  - Duplicate prevention
  - Automatic Bloom Filter sync
- **Performance**: < 1ms total

### Layer 2: External APIs (Threat Intelligence)
- **Google Safe Browsing**: Malware and phishing database
- **PhishTank**: Community-driven phishing intelligence
- **Features**:
  - Parallel async execution
  - Thread-safe LRU cache (1000 entries, 5-minute TTL)
  - 5-second timeout per API
  - Graceful degradation
- **Performance**: ~1.6ms (cached), ~4ms (fresh)

### Layer 3: Heuristic Analysis (Zero-Day Detection)
- **Typosquatting Detection**: String similarity analysis
  - Monitors 9 major brands
  - 70-100% similarity threshold
  - 40 points risk penalty
- **Keyword Analysis**: Suspicious term detection
  - 9 monitored keywords (login, verify, secure, etc.)
  - 20 points risk penalty
- **Domain Age Analysis**: WHOIS-based age checking
  - < 30 days: 30 points
  - < 90 days: 15 points
- **Structural Analysis**:
  - IP addresses: 50 points
  - Long URLs (> 75 chars): 15 points
  - Excessive subdomains (3+): 20 points
- **Performance**: ~1-2ms

### Layer 4: Risk Aggregation
- **Weighted Scoring**: Combines all layer signals
- **Classification**:
  - 0-39: Safe
  - 40-69: Suspicious (medium risk)
  - 70-100: Malicious (high risk)
- **Transparency**: Detailed explanations for all verdicts
- **Recommendations**: Actionable guidance for users

## Web Dashboard

### Features
- **Dark Mode Interface**: Modern, professional design
- **Real-Time Scanning**: Instant URL analysis
- **Visual Risk Display**: Color-coded scores (0-100)
- **Status Badges**: Green (safe), Yellow (suspicious), Red (malicious)
- **Detection Breakdown**: Comprehensive reasons and layer details
- **URL Features**: Domain, protocol, length analysis
- **Accessibility**: Responsive, keyboard-navigable

### Technical Stack
- Pure HTML/CSS/JavaScript
- No external dependencies
- Gradient backgrounds (#1a1a2e to #16213e)
- Served via FastAPI static files

## Browser Extension

### Features
- **Real-Time Protection**: Automatic scanning on page navigation
- **Proactive Warnings**: Prominent banners on malicious sites
- **Detailed Popup**: Full analysis on icon click
- **Background Monitoring**: Silent tab tracking
- **Local Storage**: Scan result caching

### Technical Details
- **Manifest V3**: Modern Chrome extension platform
- **Service Worker**: Efficient background processing
- **Content Scripts**: DOM manipulation for warnings
- **Message Passing**: Secure background-content communication
- **Security**: XSS prevention, CSP compliance, no inline handlers

### Installation
1. Clone repository
2. Load `extension/` folder in Chrome
3. Enable in `chrome://extensions/`
4. Ensure backend running at localhost:8000

## Technology Stack

### Backend
- **FastAPI**: Modern async Python framework
- **Pydantic**: Type validation and settings management
- **aiohttp**: Async HTTP client
- **tldextract**: Domain parsing
- **python-whois**: Domain metadata
- **bitarray**: Bloom Filter implementation
- **mmh3**: Fast hashing (MurmurHash3)
- **SQLite**: Embedded database

### Frontend
- **HTML5/CSS3**: Modern web standards
- **JavaScript ES6+**: Native browser APIs
- **Chrome Extension API**: Manifest V3

### Security
- **CORS**: Configured for frontend integration
- **Input Validation**: Pydantic models
- **XSS Prevention**: Content escaping
- **CSP Compliance**: No inline handlers
- **HTTPS Support**: Ready for production

## Performance Metrics

| Layer | Operation | Performance |
|-------|-----------|-------------|
| Preprocessing | URL normalization | < 1ms |
| Bloom Filter | Membership check | 0.69µs |
| Database | Exact lookup | < 1ms |
| API (cached) | Threat intelligence | ~1.6ms |
| API (fresh) | Parallel queries | ~4ms |
| Heuristics | Full analysis | ~1-2ms |
| **Total (cached)** | **End-to-end** | **~4-5ms** |
| **Total (fresh)** | **End-to-end** | **~7-8ms** |

## Testing

### Test Coverage
- URL preprocessing (protocol, IDN, subdomain extraction)
- Bloom Filter performance (1000 lookups in 0.69ms)
- Database operations (add, check, duplicates)
- API integration (parallel execution, caching)
- Heuristic analysis (typosquatting, keywords, domain age)
- Risk aggregation (weighted scoring, classification)
- Web dashboard (UI functionality, real-time scanning)
- Browser extension (structure, integration, security)
- Security scanning (CodeQL: 0 vulnerabilities)

### Test URLs
```bash
# Safe URL
{"url": "https://google.com"}
# → Risk: 0, Status: safe

# Typosquatting
{"url": "http://paypa1.com/login"}
# → Risk: 60, Status: suspicious

# IP + Suspicious keyword
{"url": "http://192.168.1.1/secure"}
# → Risk: 70, Status: suspicious

# Database match
{"url": "http://bad.com"}
# → Risk: 100, Status: malicious
```

## Deployment

### Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run backend
uvicorn app.main:app --reload

# Access dashboard
http://127.0.0.1:8000/

# API documentation
http://127.0.0.1:8000/docs
```

### Production Considerations
- Use production ASGI server (Gunicorn + Uvicorn workers)
- Enable HTTPS with SSL certificates
- Configure CORS for specific origins
- Use Redis for distributed caching
- Set up monitoring and logging
- Deploy database to persistent storage
- Scale API workers for high traffic

## API Documentation

### POST /api/v1/scan

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com/",
  "status": "safe",
  "risk_score": 0,
  "verdict_source": "Complete Analysis",
  "recommendation": "SAFE - No immediate threats detected.",
  "reasons": [
    "No heuristic red flags detected."
  ],
  "details": {
    "db_checked": false,
    "api_checked": true,
    "heuristic_score": 0,
    "layers_triggered": ["heuristics", "database_clean", "api_clean"],
    "final_score": 0,
    "classification": "safe",
    "url_features": {
      "domain": "example.com",
      "is_ip": false,
      "url_length": 20,
      "has_subdomain": false
    }
  }
}
```

## Security Features

### Input Validation
- Pydantic HttpUrl validation
- Protocol normalization
- Control character removal
- IDN/Punycode conversion

### XSS Prevention
- Content escaping in web dashboard
- No innerHTML in extension
- CSP-compliant code
- Event listeners instead of inline handlers

### Data Protection
- Local-only database
- No data sent to third parties (except configured APIs)
- Secure API communication
- Local extension storage

## Project Structure

```
phishing-url-analyzer/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application
│   ├── core/
│   │   ├── __init__.py
│   │   └── config.py           # Settings management
│   ├── api/
│   │   ├── __init__.py
│   │   └── endpoints.py        # API routes
│   ├── schemas/
│   │   ├── __init__.py
│   │   └── url_schema.py       # Pydantic models
│   ├── services/
│   │   ├── __init__.py
│   │   ├── preprocessing.py    # URL normalization
│   │   ├── database.py         # Bloom Filter + SQLite
│   │   ├── api_integration.py  # External APIs
│   │   ├── heuristics.py       # Pattern analysis
│   │   └── scoring.py          # Risk aggregation
│   └── static/
│       └── index.html          # Web dashboard
├── extension/
│   ├── manifest.json           # Extension config
│   ├── background.js           # Service worker
│   ├── content.js              # Page script
│   ├── content.css             # Warning styles
│   ├── popup.html              # Extension UI
│   ├── popup.js                # Popup logic
│   └── icons/                  # Extension icons
├── .env                        # Environment variables
├── .env.example                # Template
├── .gitignore                  # Git exclusions
├── requirements.txt            # Python dependencies
├── seed_db.py                  # Database seeding
└── README.md                   # Documentation
```

## Educational Value

This project demonstrates:
- Modern async Python with FastAPI
- Probabilistic data structures (Bloom Filter)
- API integration patterns
- Heuristic analysis techniques
- Browser extension development
- Security best practices
- Clean architecture principles
- Real-time web applications

## Future Enhancements

### Phase 8: Machine Learning (Planned)
- Train ML model on URL features
- Real-time prediction integration
- Continuous learning from user feedback
- Feature importance analysis

### Additional Features
- [ ] Firefox extension support
- [ ] Whitelist management UI
- [ ] Historical scan reports
- [ ] Customizable warning thresholds
- [ ] Multi-language support
- [ ] Mobile app integration
- [ ] Enterprise deployment guide
- [ ] API rate limiting
- [ ] Advanced analytics dashboard

## License

Same as the main Phishing URL Analyzer project.

## Acknowledgments

Built following modern security practices and industry standards for phishing detection systems.
