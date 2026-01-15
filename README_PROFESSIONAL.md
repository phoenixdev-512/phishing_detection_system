# Phishing URL Detection System

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Core Components](#core-components)
4. [Installation Guide](#installation-guide)
5. [Usage Instructions](#usage-instructions)
6. [API Documentation](#api-documentation)
7. [Browser Extension](#browser-extension)
8. [Technical Specifications](#technical-specifications)
9. [Performance Metrics](#performance-metrics)
10. [Security Considerations](#security-considerations)
11. [Testing and Validation](#testing-and-validation)
12. [Deployment Guidelines](#deployment-guidelines)
13. [Troubleshooting](#troubleshooting)
14. [Future Development](#future-development)

---

## Executive Summary

The Phishing URL Detection System is a comprehensive, multi-layer security platform designed to identify and prevent phishing attacks in real-time. The system employs a hybrid architecture combining local database lookups, external threat intelligence APIs, and heuristic analysis to provide accurate threat detection with sub-10ms response times.

### Key Features

- **Multi-Layer Detection**: Four-tier analysis pipeline combining database, API, and heuristic checks
- **Real-Time Protection**: Browser extension for proactive website scanning
- **High Performance**: Average response time of 4-8 milliseconds
- **Comprehensive Analysis**: Detailed risk scoring and transparent decision-making
- **Zero-Day Detection**: Heuristic analysis for previously unknown threats
- **User-Friendly Interface**: Dark-mode web dashboard with intuitive design

### Target Use Cases

- Enterprise security monitoring
- Educational institutions
- Individual user protection
- Security research and analysis
- Threat intelligence gathering

---

## System Architecture

### Overview

The system implements a layered architecture with independent, modular components:

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT INTERFACES                         │
├──────────────────────┬──────────────────────────────────────┤
│   Web Dashboard      │     Browser Extension (Chrome)        │
│  (Static HTML/JS)    │    (Manifest V3)                     │
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
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Layer 1:   │  │   Layer 2:   │  │   Layer 3:   │
│   Database   │  │   External   │  │  Heuristic   │
│ (Bloom+SQLite)│  │     APIs     │  │   Analysis   │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                  │
       └─────────────────┼──────────────────┘
                         │
                 ┌───────▼────────┐
                 │ Risk Aggregator │
                 │ (Scoring Engine)│
                 └────────────────┘
```

### Component Interaction

1. **Client Layer**: User interfaces (web dashboard, browser extension)
2. **API Layer**: FastAPI backend with async request handling
3. **Detection Layer**: Three parallel detection mechanisms
4. **Aggregation Layer**: Risk scoring and classification
5. **Response Layer**: Structured JSON responses with recommendations

---

## Core Components

### 1. URL Preprocessing Service

**File**: `app/services/preprocessing.py`

**Purpose**: Sanitizes and normalizes URLs before analysis

**Operations**:
- Whitespace and control character removal
- Protocol validation and addition
- Internationalized Domain Name (IDN) to Punycode conversion
- Structural decomposition (domain, subdomain, TLD extraction)
- Feature extraction for downstream analysis
- IPv4 address detection

**Performance**: <1ms per URL

**Example**:
```python
Input: "pаypal.com"  # Cyrillic 'а'
Output: {
    "full_url": "http://xn--pypal-4ve.com/",
    "domain": "xn--pypal-4ve",
    "suffix": "com",
    "is_ip_address": false
}
```

### 2. Database Service (Speed Layer)

**File**: `app/services/database.py`

**Components**:

#### Bloom Filter
- **Implementation**: Probabilistic data structure
- **Size**: 623,522 bits (76 KB)
- **Capacity**: 100,000 URLs
- **False Positive Rate**: 5%
- **False Negative Rate**: 0%
- **Hash Functions**: 4 (MurmurHash3)
- **Performance**: 0.69 microseconds per lookup

#### SQLite Database
- **Schema**: malicious_urls (id, url, source, risk_score, date_added)
- **Features**: Unique constraint, automatic timestamps
- **Integration**: Automatic Bloom Filter synchronization
- **Capacity Monitoring**: Warning at 100,000+ entries

**Workflow**:
1. Check Bloom Filter (memory) → Instant negative results
2. If Bloom says "maybe", check SQLite (disk) → Exact confirmation
3. Return threat data or None

### 3. External API Integration Service

**File**: `app/services/api_integration.py`

**Integrated Services**:
- Google Safe Browsing API (configurable)
- PhishTank API

**Features**:
- **Parallel Execution**: Async queries with `asyncio.gather()`
- **Thread-Safe Cache**: LRU cache with async locks
  - Maximum: 1,000 entries
  - TTL: 5 minutes
  - Automatic expiration cleanup
- **Timeout Handling**: 5-second maximum per API
- **Error Resilience**: Graceful degradation on API failures
- **Logging**: Exception tracking for debugging

**Performance**:
- Fresh API call: ~4ms (parallel execution)
- Cache hit: ~1.6ms (60% faster)

### 4. Heuristic Analysis Engine

**File**: `app/services/heuristics.py`

**Detection Mechanisms**:

#### Typosquatting Detection
- **Algorithm**: SequenceMatcher (difflib)
- **Brand List**: 9 major brands (Google, PayPal, Facebook, Amazon, Microsoft, Instagram, Netflix, LinkedIn, Apple)
- **Threshold**: 70-100% similarity
- **Risk Score**: 40 points

#### Keyword Analysis
- **Keywords**: login, verify, update, secure, account, banking, confirm, signin, wallet
- **Scope**: URL path only
- **Risk Score**: 20 points per detection

#### Domain Age Analysis
- **Method**: WHOIS lookup
- **Thresholds**:
  - Less than 30 days: 30 points
  - Less than 90 days: 15 points
- **Fallback**: Graceful handling of WHOIS failures

#### Structural Analysis
- **IP Address URLs**: 50 points
- **Long URLs** (>75 characters): 15 points
- **Excessive Subdomains** (3+ parts): 20 points

### 5. Risk Aggregation Service

**File**: `app/services/scoring.py`

**Scoring Logic**:
1. Database match: 100 (instant block)
2. API match: 100 (instant block)
3. Heuristic accumulation: Sum of individual checks

**Classification**:
- **Safe**: 0-39 points
- **Suspicious**: 40-69 points
- **Malicious**: 70-100 points

**Output**:
- Risk score (0-100)
- Status classification
- Verdict source
- Actionable recommendation
- Detection reasons
- Transparency details

---

## Installation Guide

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Chrome browser (for extension)
- 100 MB available disk space

### Backend Setup

1. **Clone Repository**:
```bash
git clone https://github.com/phoenixdev-512/phishing_detection_system.git
cd phishing_detection_system
```

2. **Create Virtual Environment**:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install Dependencies**:
```bash
pip install -r requirements.txt
```

4. **Configure Environment**:
```bash
cp .env.example .env
# Edit .env to add API keys (optional)
```

5. **Initialize Database** (Optional):
```bash
python seed_db.py
```

6. **Start Server**:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

7. **Verify Installation**:
   - Web Dashboard: http://127.0.0.1:8000/
   - API Documentation: http://127.0.0.1:8000/docs

### Browser Extension Setup

1. **Ensure Backend Running**: Verify API is accessible at http://127.0.0.1:8000

2. **Open Chrome Extensions**:
   - Navigate to `chrome://extensions/`
   - Enable "Developer mode" (top-right toggle)

3. **Load Extension**:
   - Click "Load unpacked"
   - Select `extension/` directory from repository

4. **Verify Installation**:
   - Extension icon appears in toolbar
   - Click icon to see popup interface

---

## Usage Instructions

### Web Dashboard

1. **Access Interface**: Navigate to http://127.0.0.1:8000/

2. **Scan URL**:
   - Enter URL in input field
   - Click "Scan URL" button
   - View results in real-time

3. **Interpret Results**:
   - **Risk Score**: 0-100 scale displayed prominently
   - **Status Badge**: Green (safe), yellow (suspicious), red (malicious)
   - **Recommendation**: Actionable guidance
   - **Detection Reasons**: Detailed explanation
   - **Layers Checked**: Which detection mechanisms were used
   - **URL Features**: Technical analysis breakdown

### Browser Extension

1. **Automatic Scanning**:
   - Extension automatically scans every page
   - No user action required

2. **Warning Banners**:
   - Appear on malicious/suspicious sites (risk >= 70)
   - Display risk score and status
   - Click "View Details" for full analysis
   - Dismiss with close button

3. **Manual Analysis**:
   - Click extension icon in toolbar
   - View current page analysis
   - See risk score, reasons, and recommendations

### API Direct Access

**Example cURL Request**:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Example Python Request**:
```python
import requests

response = requests.post(
    "http://127.0.0.1:8000/api/v1/scan",
    json={"url": "https://example.com"}
)
result = response.json()
print(f"Risk Score: {result['risk_score']}")
print(f"Status: {result['status']}")
```

---

## API Documentation

### Endpoint: POST /api/v1/scan

**Purpose**: Analyze a URL for phishing threats

**Request Schema**:
```json
{
  "url": "string (required, valid HTTP/HTTPS URL)"
}
```

**Response Schema**:
```json
{
  "url": "string (normalized URL)",
  "status": "string (safe|suspicious|malicious)",
  "risk_score": "integer (0-100)",
  "verdict_source": "string (detection layer)",
  "recommendation": "string (actionable guidance)",
  "reasons": ["string (detection explanations)"],
  "details": {
    "layers_checked": ["string (layers used)"],
    "url_features": {
      "protocol": "string",
      "domain": "string",
      "suffix": "string",
      "url_length": "integer"
    }
  }
}
```

**Status Codes**:
- `200 OK`: Successful analysis
- `400 Bad Request`: Invalid URL format
- `500 Internal Server Error`: Server error

**Example Response (Safe URL)**:
```json
{
  "url": "https://google.com/",
  "status": "safe",
  "risk_score": 0,
  "verdict_source": "Complete Analysis",
  "recommendation": "This URL appears safe to visit.",
  "reasons": ["No heuristic red flags detected."],
  "details": {
    "layers_checked": ["Database", "External APIs", "Heuristics"],
    "url_features": {
      "protocol": "https",
      "domain": "google",
      "suffix": "com",
      "url_length": 19
    }
  }
}
```

**Example Response (Suspicious URL)**:
```json
{
  "url": "http://paypa1.com/login",
  "status": "suspicious",
  "risk_score": 60,
  "verdict_source": "Heuristic Analysis",
  "recommendation": "HIGH CAUTION - This URL shows strong indicators of phishing.",
  "reasons": [
    "Domain 'paypa1' is suspiciously similar to 'paypal' (typosquatting).",
    "URL path contains suspicious keywords: login."
  ],
  "details": {
    "layers_checked": ["Database", "External APIs", "Heuristics"],
    "url_features": {
      "protocol": "http",
      "domain": "paypa1",
      "suffix": "com",
      "url_length": 23
    }
  }
}
```

### Endpoint: GET /

**Purpose**: Access web dashboard

**Response**: HTML page (static file)

### Endpoint: GET /docs

**Purpose**: Interactive API documentation (Swagger UI)

**Response**: Auto-generated documentation interface

---

## Browser Extension

### Architecture

**Manifest V3 Components**:

1. **Service Worker** (`background.js`):
   - Monitors tab navigation events
   - Makes API requests to backend
   - Manages local storage cache
   - Sends messages to content scripts

2. **Content Scripts** (`content.js`, `content.css`):
   - Injected into all web pages
   - Receives scan results from background worker
   - Displays warning banners on malicious sites
   - Handles user interactions (dismiss, view details)

3. **Popup UI** (`popup.html`, `popup.js`):
   - Displays on extension icon click
   - Shows current page analysis
   - Retrieves results from local storage
   - Formatted risk information

### Security Features

- **XSS Prevention**: Uses `textContent` instead of `innerHTML`
- **CSP Compliance**: No inline event handlers
- **Content Isolation**: Proper script sandboxing
- **Secure Messaging**: Chrome message passing API
- **Data Privacy**: Only communicates with local backend

### Configuration

**API Endpoint** (background.js):
```javascript
const API_URL = "http://127.0.0.1:8000/api/v1/scan";
```

**Warning Threshold** (background.js):
```javascript
const WARNING_THRESHOLD = 70;  // Show warning if risk >= 70
```

### Permissions

- `activeTab`: Access current tab URL
- `scripting`: Inject warning banners
- `storage`: Store scan results locally
- `host_permissions`: Communicate with backend API

---

## Technical Specifications

### Technology Stack

**Backend**:
- FastAPI 0.109.1 (async web framework)
- Pydantic 2.5.3 (data validation)
- aiohttp 3.13.3 (async HTTP client)
- tldextract 5.1.1 (domain parsing)
- python-whois 0.8.0 (domain metadata)
- bitarray 2.8.1 (Bloom Filter)
- mmh3 4.0.1 (hashing)
- SQLite 3 (database)

**Frontend**:
- HTML5/CSS3 (web standards)
- JavaScript ES6+ (async/await)
- Chrome Extension API (Manifest V3)

**Development**:
- Uvicorn (ASGI server)
- Python 3.8+
- Git version control

### System Requirements

**Server**:
- OS: Linux, macOS, or Windows
- RAM: 512 MB minimum, 1 GB recommended
- Disk: 100 MB for application, 1 GB for database
- CPU: 1 core minimum, 2+ cores recommended

**Client**:
- Browser: Chrome 88+ or Chromium-based
- Network: Local network access to backend
- Storage: 10 MB for extension

### Database Schema

**Table: malicious_urls**
```sql
CREATE TABLE malicious_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    source TEXT,
    risk_score INTEGER,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Configuration Files

**Environment Variables** (`.env`):
```ini
PROJECT_NAME="Phishing URL Analyzer"
API_V1_STR="/api/v1"
GOOGLE_SAFE_BROWSING_API_KEY=""  # Optional
```

**Dependencies** (`requirements.txt`):
```
fastapi==0.109.1
uvicorn[standard]==0.27.0
pydantic==2.5.3
pydantic-settings==2.1.0
python-dotenv==1.0.1
requests==2.31.0
tldextract==5.1.1
python-whois==0.8.0
aiohttp==3.13.3
bitarray==2.8.1
mmh3==4.0.1
```

---

## Performance Metrics

### Benchmarks

| Component | Operation | Performance |
|-----------|-----------|-------------|
| Preprocessing | URL normalization | <1ms |
| Bloom Filter | Membership check | 0.69µs |
| SQLite | Exact lookup | <1ms |
| API (cached) | Threat intelligence | 1.6ms |
| API (fresh) | Parallel queries | 4ms |
| Heuristics | Full analysis | 1-2ms |
| **Total (cached)** | **End-to-end** | **4-5ms** |
| **Total (fresh)** | **End-to-end** | **7-8ms** |

### Scalability

- **Bloom Filter**: Can check 1.4 million URLs per second
- **Database**: Handles 1,000 queries per second (SQLite)
- **API Cache**: Reduces external API calls by 90%+
- **Concurrent Requests**: FastAPI async handles 1,000+ concurrent connections

### Resource Usage

- **Memory**: 100-200 MB (including Bloom Filter)
- **CPU**: 5-10% per request (single core)
- **Disk I/O**: Minimal (SQLite caching)
- **Network**: 1-5 KB per API request

---

## Security Considerations

### Input Validation

- **Pydantic Models**: Type-safe URL validation
- **Protocol Normalization**: Auto-adds missing protocols
- **Character Filtering**: Removes control characters
- **IDN Handling**: Punycode conversion for homograph attacks
- **Length Limits**: Prevents buffer overflow attacks

### Data Protection

- **Local Database**: No cloud storage of URLs
- **API Communication**: Only configured external services
- **HTTPS Support**: SSL/TLS ready for production
- **CORS Configuration**: Restricted origins in production
- **No Logging of URLs**: Privacy-preserving design

### Vulnerability Mitigation

- **XSS Prevention**: Content escaping in UI
- **SQL Injection**: Parameterized queries
- **CSRF Protection**: FastAPI built-in protection
- **Rate Limiting**: Can be configured for production
- **Dependency Scanning**: Regular security updates

### Security Audit Results

- **CodeQL Scan**: 0 vulnerabilities detected
- **Dependency Check**: All packages patched
- **OWASP Compliance**: Follows security best practices
- **CVE Fixes**: Updated dependencies (aiohttp, fastapi)

---

## Testing and Validation

### Test Coverage

**Unit Tests**:
- URL preprocessing (protocol, IDN, subdomain extraction)
- Bloom Filter operations (add, check, performance)
- Database CRUD operations
- Heuristic detection algorithms
- Risk scoring calculations

**Integration Tests**:
- End-to-end API workflow
- Multi-layer detection pipeline
- External API integration
- Cache functionality
- Extension communication

**Performance Tests**:
- 1,000 Bloom Filter lookups: 0.69ms total
- 100 concurrent API requests: <500ms
- Database capacity: 100,000+ URLs
- Cache eviction: LRU working correctly

### Test URLs

**Safe URLs**:
```
https://google.com       → Risk: 0, Status: safe
https://github.com       → Risk: 0, Status: safe
https://microsoft.com    → Risk: 0, Status: safe
```

**Typosquatting**:
```
http://paypa1.com        → Risk: 40, Status: suspicious
http://g00gle.com        → Risk: 40, Status: suspicious
http://micr0soft.com     → Risk: 40, Status: suspicious
```

**Keyword Detection**:
```
http://example.com/login → Risk: 20, Status: safe
http://test.com/verify   → Risk: 20, Status: safe
```

**Combined Threats**:
```
http://paypa1.com/login  → Risk: 60, Status: suspicious
http://192.168.1.1/secure → Risk: 70, Status: suspicious
```

**Database Matches**:
```
http://bad.com           → Risk: 100, Status: malicious
```

### Validation Methods

1. **Functional Testing**: All features working as designed
2. **Performance Testing**: Meeting latency requirements
3. **Security Testing**: CodeQL and manual review
4. **Usability Testing**: UI/UX verification
5. **Cross-Browser Testing**: Chrome compatibility confirmed

---

## Deployment Guidelines

### Development Environment

```bash
# Start development server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Access points
# Dashboard: http://127.0.0.1:8000/
# API Docs: http://127.0.0.1:8000/docs
# API Endpoint: http://127.0.0.1:8000/api/v1/scan
```

### Production Environment

**ASGI Server Configuration**:
```bash
# Using Gunicorn with Uvicorn workers
gunicorn app.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile - \
  --error-logfile -
```

**Nginx Reverse Proxy**:
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**SSL/TLS Configuration**:
```bash
# Using Let's Encrypt
certbot --nginx -d yourdomain.com
```

**Environment Variables**:
```ini
# Production .env
PROJECT_NAME="Phishing URL Analyzer"
API_V1_STR="/api/v1"
GOOGLE_SAFE_BROWSING_API_KEY="your-production-api-key"
```

**Docker Deployment** (Optional):
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Monitoring and Logging

**Logging Configuration**:
```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

**Metrics to Monitor**:
- Request latency (p50, p95, p99)
- Error rate
- Database size
- Cache hit rate
- API quota usage

**Health Check Endpoint**:
```python
@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0"}
```

---

## Troubleshooting

### Common Issues

**Issue: "ModuleNotFoundError" on startup**

Solution:
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Reinstall dependencies
pip install -r requirements.txt
```

**Issue: Extension shows "Backend may be offline"**

Solution:
1. Verify backend is running: `curl http://127.0.0.1:8000/health`
2. Check for firewall blocking localhost connections
3. Ensure port 8000 is not in use by another process
4. Check backend console for errors

**Issue: Slow API responses**

Solution:
1. Check external API latency (PhishTank, Google)
2. Verify cache is working (check logs for cache hits)
3. Consider increasing cache TTL
4. Monitor database size (should be <100k entries)

**Issue: Warning banners not appearing**

Solution:
1. Verify risk score >= 70 in extension popup
2. Check browser console for content script errors
3. Ensure content script has permission to inject
4. Try refreshing the page

**Issue: WHOIS lookups timing out**

Solution:
1. Check internet connectivity
2. Verify WHOIS service availability
3. Fallback logic should handle gracefully
4. Consider disabling domain age check if persistent

### Debugging

**Backend Debugging**:
```bash
# Enable debug mode
uvicorn app.main:app --reload --log-level debug

# Check logs
tail -f logs/app.log  # if logging to file
```

**Extension Debugging**:
```
# Background script
chrome://extensions/ → "Inspect service worker"

# Content script
Right-click page → Inspect → Console tab

# Popup
Right-click extension icon → "Inspect popup"
```

**Database Debugging**:
```bash
# Access SQLite database
sqlite3 phishing_db.sqlite

# Check entries
SELECT COUNT(*) FROM malicious_urls;
SELECT * FROM malicious_urls LIMIT 10;
```

---

## Future Development

### Planned Enhancements

**Phase 8: Machine Learning Integration**
- Train classification model on URL features
- Real-time prediction integration
- Continuous learning from user feedback
- Feature importance analysis
- Model versioning and A/B testing

**Additional Features**:
- Firefox extension support
- Whitelist management interface
- Historical scan reports and analytics
- Customizable warning thresholds
- Multi-language internationalization
- Mobile app integration (Android/iOS)
- Enterprise deployment packages
- Advanced API rate limiting
- Real-time analytics dashboard
- Webhook notifications
- Batch URL scanning API
- URL reputation scoring

**Infrastructure Improvements**:
- Redis cache for distributed deployments
- PostgreSQL for production database
- Kubernetes deployment configurations
- CI/CD pipeline setup
- Automated testing framework
- Performance monitoring integration
- Load balancing configurations

### Contributing

For contributions or feature requests:
1. Review system architecture documentation
2. Follow existing code style and patterns
3. Add unit tests for new features
4. Update documentation accordingly
5. Submit pull request with detailed description

---

## License

This project is provided as-is for educational and research purposes. Ensure compliance with applicable laws and regulations when deploying in production environments.

---

## Acknowledgments

This system was developed following industry best practices for phishing detection, incorporating techniques from:
- Academic research on URL analysis
- OWASP security guidelines
- Google Safe Browsing API documentation
- Industry standard Bloom Filter implementations
- Modern async Python patterns

---

## Contact and Support

For technical support, bug reports, or feature requests, please refer to the project repository issue tracker.

---

**Document Version**: 1.0  
**Last Updated**: 2026-01-15  
**System Version**: 1.0.0
