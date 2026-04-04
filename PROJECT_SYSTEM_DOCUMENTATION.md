# Phishing Detection System

## 1. Executive Summary

The Phishing Detection System is a hybrid URL threat analysis platform that combines:
- A FastAPI backend API for real-time URL scanning
- A web dashboard for manual analysis and operational visibility
- A Chrome extension (Manifest V3) for passive, in-browser protection
- A multi-layer risk pipeline (preprocessing, local intelligence, external APIs, heuristics, aggregation)

The system is designed with modular services and an explainable response model, returning not only a verdict (`safe`, `suspicious`, `malicious`) but also risk scores, reasons, and recommendation text.

At present, the project is in a functional prototype / early production-candidate stage:
- Core scanning flow is implemented end-to-end
- Dashboard and extension are integrated
- Logging/history/stats are persisted to SQLite
- Significant hardening, testing, and productionization work remains

## 2. Project Goals

### 2.1 Primary Goal
Provide fast and explainable phishing URL detection with practical user interfaces.

### 2.2 Secondary Goals
- Layered defense: avoid single-point failure in detection logic
- Human-readable rationale for trust decisions
- Extensibility toward advanced threat intelligence and ML models
- Low operational complexity in local development

## 3. System Context

### 3.1 Actors
- End User (manual scanner via dashboard)
- Browser User (passive protection via extension)
- System Operator / Developer (maintains threat feeds, APIs, infra)

### 3.2 Trust Boundaries
- Client-side extension and dashboard are untrusted input surfaces
- Backend sanitizes and validates URL payloads
- External APIs are partially trusted and treated as best-effort signal providers
- Local SQLite storage is trusted system state (subject to deployment hardening)

## 4. Architecture Overview

```text
+-------------------------------------------------------------+
|                      Client Surfaces                        |
|-------------------------------------------------------------|
|  Web Dashboard (static HTML/JS)  |  Chrome Extension (MV3) |
+----------------------+----------------------+---------------+
                       |                      |
                       +----------HTTP--------+
                                  |
                         FastAPI API Layer
                        (/api/v1/scan, etc.)
                                  |
                 +----------------+----------------+
                 |                |                |
           Preprocessing     Local DB Layer   External API Layer
          (normalize URL)   (RAM cache +      (PhishTank + optional
                             SQLite lookup)    Google Safe Browsing)
                 |                |                |
                 +----------------+----------------+
                                  |
                          Heuristic Engine
                                  |
                           Risk Aggregator
                                  |
                          AnalysisResult JSON
                                  |
                 +----------------+----------------+
                 |                                 |
         Web dashboard render             Extension warning/popup
```

## 5. Detailed System Design

### 5.1 Backend Framework and Routing
- **Framework**: FastAPI
- **Entry point**: `app/main.py`
- **API version prefix**: configurable (`/api/v1` default)
- **Exposed endpoints**:
  - `POST /api/v1/scan`
  - `GET /api/v1/history`
  - `GET /api/v1/stats`
  - `GET /` serves dashboard (`app/static/index.html`)

#### Design Rationale
- FastAPI provides strict request validation with Pydantic, automatic OpenAPI docs, and async-native route handling.
- Versioned API prefix supports future backward-compatible expansion.
- Static dashboard serving from the same backend simplifies local deployment and onboarding.

### 5.2 Request/Response Contract
- **Request schema** (`URLRequest`):
  - `url: HttpUrl` (Pydantic-level URL validation)
- **Response schema** (`AnalysisResult`):
  - `url: str`
  - `status: str`
  - `risk_score: int` (0-100)
  - `verdict_source: str`
  - `reasons: list[str]`
  - `recommendation: str | None`
  - `details: dict | None`

#### Design Rationale
- Strong typing prevents malformed payload propagation.
- Explainability fields are first-class, improving user trust and analyst utility.

### 5.3 Detection Pipeline
The `POST /scan` route executes these stages:

1. **Preprocessing** (`preprocessor.normalize`)
2. **Local DB check** (`db_service.check_url`)
3. **External API check** (`api_manager.check_url`, async)
4. **Heuristic analysis** (`heuristic_engine.analyze`)
5. **Risk aggregation** (`risk_aggregator.calculate_risk`)
6. **Recommendation generation** (`risk_aggregator.get_recommendation`)
7. **History logging** (`db_service.log_scan`)

#### Design Characteristics
- Logical layering improves maintainability and extension.
- The pipeline currently runs all layers (API + heuristics) even if DB matched; this favors richer observability over minimum latency.
- Aggregation uses deterministic thresholds for predictable behavior.

## 6. Core Service Internals

### 6.1 URL Preprocessing Service
Implemented in `app/services/preprocessing.py`.

#### Responsibilities
- Trim and sanitize URL input
- Add scheme if absent (`http://` fallback)
- IDN conversion to ASCII/Punycode
- Parse domain components with `tldextract`
- Compute structural features:
  - protocol
  - subdomain/domain/suffix
  - registered domain
  - path/query
  - URL length
  - IP-address usage

#### Why This Matters
- Canonicalization minimizes false negatives caused by obfuscation.
- Feature extraction centralizes shared logic for downstream heuristics.

### 6.2 Local Database Service
Implemented in `app/services/database.py`.

#### Current Implementation
- SQLite database file (`phishing_db.sqlite` by default)
- In-memory Python `set` cache of known malicious URLs
- Tables:
  - `malicious_urls` (blacklist)
  - `scan_history` (operational log)

#### Notable Behavior
- Cache is loaded from SQLite at startup
- Lookup path:
  - RAM set negative -> immediate clean
  - RAM set positive -> SQLite confirm
- Provides stats and recent history retrieval for dashboard

#### Design Tradeoff
- A `set` is simpler than Bloom filters and has no false positives, but memory footprint grows linearly with blacklist size.

### 6.3 External API Integration Service
Implemented in `app/services/api_integration.py`.

#### Current Providers
- PhishTank (active)
- Google Safe Browsing (key-aware path is currently mock/placeholder branch)

#### Architecture
- Async `aiohttp` session
- Parallel provider calls via `asyncio.gather`
- In-memory LRU cache with TTL:
  - max entries: 1000
  - TTL: 300 seconds
- Fail-open style for provider errors/timeouts (returns safe unless malicious evidence is found)

#### Why This Design
- API parallelism limits total network latency.
- Caching reduces cost and improves UX on repeated URLs.
- Graceful degradation preserves system availability.

### 6.4 Heuristic Engine
Implemented in `app/services/heuristics.py`.

#### Checks
- Typosquatting similarity against high-value brand list
- Suspicious URL path keywords
- Domain age via WHOIS (best effort)
- Structural risks:
  - IP-based URL
  - long URL length
  - excessive subdomains

#### Scoring Model
Heuristic checks add weighted penalties and cap at 100.

#### Why This Design
- Captures zero-day and non-listed phishing patterns.
- Transparent, deterministic logic enables explainability.

### 6.5 Risk Aggregator
Implemented in `app/services/scoring.py`.

#### Decision Logic
- If local DB says malicious -> score 100
- Else if external API says malicious -> score 100
- Else use heuristic score

#### Classification
- `0-39`: safe
- `40-69`: suspicious
- `70-100`: malicious

#### Output Enrichment
- Source attribution (`verdict_source`)
- Explanation list (`reasons`)
- `details` object with layer traces and URL features
- Text recommendations tuned by severity

## 7. Web Dashboard Design

### 7.1 Interface
- Single-page static dashboard served by FastAPI
- URL scan form with asynchronous API call
- Result card with score, reasons, source, layer badges, URL features
- Live operational panels:
  - aggregate stats
  - recent scan history table

### 7.2 UX Characteristics
- Dark-theme glassmorphism style
- Auto-refresh of stats/history every 10s
- Keyboard support for Enter-to-scan
- Clear visual severity mapping

### 7.3 Security Considerations in UI
- Uses textContent/DOM APIs in key places for safer rendering
- However, history table uses template-string `innerHTML` for URL row rendering, which should be hardened to remove XSS risk if stored data is tainted

## 8. Browser Extension Design

### 8.1 Platform
- Chrome Extension Manifest V3
- Components:
  - `background.js` service worker
  - `content.js` for warning overlays
  - `popup.html` + `popup.js` for tab-specific status

### 8.2 Flow
1. On tab update/activation, background script scans current URL via backend API
2. Result stored in `chrome.storage.local` keyed by tab id
3. If high risk, warning message sent to content script
4. Popup reads stored result and renders details

### 8.3 Security Posture
- Content script builds warning DOM with safe node creation (avoids untrusted HTML insertion)
- Host permissions include `<all_urls>` (broad capability by design, should be reviewed before release)

## 9. Data Model and Persistence

### 9.1 `malicious_urls`
- `id` (PK)
- `url` (UNIQUE)
- `source`
- `risk_score`
- `date_added`

### 9.2 `scan_history`
- `id` (PK)
- `url`
- `status`
- `risk_score`
- `verdict_source`
- `timestamp`

### 9.3 Seed Data
`seed_db.py` inserts `http://bad.com/` for validation/testing.

## 10. Technology Stack and Rationale

### 10.1 Backend
- **Python**: rapid development, rich security ecosystem
- **FastAPI**: async performance + strict contracts + OpenAPI
- **Pydantic**: robust validation and typed schemas
- **aiohttp**: non-blocking external API integration
- **SQLite**: zero-admin local persistence for prototype/edge deployments

### 10.2 Detection/Analysis Libraries
- **tldextract**: reliable domain segmentation
- **python-whois**: domain age heuristics
- **requests**: utility HTTP library (currently limited backend use)
- **mmh3**, **bitarray**: installed but not actively used in current DB implementation

### 10.3 Frontend and Extension
- **Vanilla HTML/CSS/JS**: low complexity, no build pipeline
- **Chrome Extension APIs (MV3)**: modern browser security model and background worker lifecycle

### 10.4 Why This Stack Fits
- Minimal operational burden for development
- High iteration speed for security heuristics
- Good path to later production hardening (cache externalization, database migration, containerization)

## 11. API Specification

### 11.1 POST `/api/v1/scan`
Request:
```json
{
  "url": "https://example.com"
}
```

Response (example):
```json
{
  "url": "https://example.com/",
  "status": "safe",
  "risk_score": 0,
  "verdict_source": "Heuristic Analysis",
  "reasons": ["No heuristic red flags detected."],
  "recommendation": "SAFE - No immediate threats detected. However, always verify the URL matches your intended destination.",
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

### 11.2 GET `/api/v1/history`
- Query parameter: `limit` (default 20)
- Returns list of recent scan records

### 11.3 GET `/api/v1/stats`
Returns counters:
- total scans
- malicious detects
- suspicious detects
- safe detects

## 12. Runtime and Operational Considerations

### 12.1 Configuration
Environment-driven settings in `app/core/config.py`:
- `PROJECT_NAME`
- `API_V1_STR`
- `GOOGLE_SAFE_BROWSING_API_KEY`

### 12.2 Logging
- Root logging configured in `app/main.py`
- Service-level warnings/errors for API failures and cache initialization issues

### 12.3 Performance Characteristics (Expected)
- Local cache blacklist checks: near-constant-time
- External API checks: dominant latency contributor (network dependent)
- Caching strategy mitigates repeated URL lookup overhead

## 13. Security Assessment Summary

### Strengths
- Typed input validation for scan endpoint
- URL normalization and control-character sanitization
- Explainable scoring with layer traceability
- Extension content warning built with safe DOM creation

### Current Risks / Gaps
- CORS allows all origins (`*`) in backend
- Dashboard history rendering contains string-inserted HTML (XSS hardening needed)
- Extension host permissions are very broad (`<all_urls>`)
- External threat feeds are not fully authenticated/production configured by default
- No auth/rate limiting on scan endpoint

## 14. Deployment and Environments

### 14.1 Current State
- Local development deployment via Uvicorn
- Monolithic process with local SQLite persistence

### 14.2 Production Target Pattern (Recommended)
- Reverse proxy + HTTPS termination
- Gunicorn/Uvicorn workers
- Managed DB (PostgreSQL or hardened SQLite-on-persistent-volume)
- Redis for distributed cache
- Secret manager for API keys
- Structured logs + monitoring + alerting

## 15. Quality and Testing Posture

### 15.1 Observed Current State
- Functional manual testing pathways are present
- No formal automated test suite found in repository structure
- No CI pipeline definitions observed in workspace files

### 15.2 Consequence
- Regression risk remains high as detection logic evolves
- Security-sensitive changes are harder to validate systematically

## 16. Remaining Work (Prioritized Backlog)

## P0 - Security and Reliability (Must Do Before Public Release)
1. Implement strict CORS origin allowlist and environment-specific CORS profiles.
2. Add authentication and rate limiting for backend endpoints.
3. Harden dashboard rendering by replacing templated `innerHTML` row insertion with safe DOM node creation.
4. Add robust input/output audit logging and sensitive-data redaction strategy.
5. Add failure budgets and fallback controls for external API outages.

## P1 - Detection Fidelity and Signal Quality
1. Complete real Google Safe Browsing integration path (currently placeholder branch when API key is present).
2. Expand and maintain brand/keyword threat corpus with update policy.
3. Introduce confidence scoring and calibration metrics (precision/recall tracking dataset).
4. Add URL canonicalization edge-case coverage (ports, punycode corner cases, mixed encodings).
5. Add feed ingestion jobs for trusted threat intel providers.

## P1 - Engineering Quality
1. Add full automated test suite:
   - Unit tests for preprocessing, heuristics, scoring
   - Integration tests for endpoints and DB behavior
   - Extension smoke tests for messaging and warning banner flow
2. Add linting/formatting/type-check gates (e.g., Ruff/Black/MyPy).
3. Add CI pipeline with test, lint, and security checks.
4. Refactor duplicated class definition in database service to single clean implementation.

## P2 - Scalability and Operations
1. Move cache from in-process memory to Redis for horizontal scaling.
2. Introduce asynchronous job queue for heavy/slow enrichments (WHOIS/API retries).
3. Migrate scan history analytics to dedicated store/index for high-volume reporting.
4. Add configurable circuit breakers and retries for external providers.
5. Containerize app and publish repeatable deployment manifests.

## P2 - Product and UX Enhancements
1. Add user-configurable sensitivity profile (strict/balanced/lenient).
2. Add downloadable scan reports and case notes for SOC workflows.
3. Improve extension UX for unavailable backend (offline mode with clearer remediation).
4. Add role-based admin view for threat feed management.

## P3 - Advanced Capabilities
1. Add ML-assisted model as optional fourth signal channel.
2. Build feedback loop from user-corrected verdicts for model/heuristic tuning.
3. Add multi-browser support (Firefox/Edge extension packaging).
4. Add internationalization for dashboard and extension UI.

## 17. Suggested Delivery Plan

### Phase A (1-2 weeks)
- Security hardening (CORS, auth, rate limiting, XSS-safe rendering)
- CI + baseline unit tests

### Phase B (2-4 weeks)
- Complete external API integrations and calibration suite
- Observability and reliability controls

### Phase C (4-8 weeks)
- Scale architecture improvements (Redis, queue, containerized deploy)
- Product-level enhancements and policy tooling

## 18. Conclusion

The project already demonstrates a strong foundation: modular architecture, explainable pipeline logic, and dual user interfaces (dashboard + browser extension). The most important next step is moving from functional prototype to production-grade security service by hardening trust boundaries, formalizing tests, and tightening operational controls.

With prioritized execution of the P0 and P1 backlog, this system can transition from a capable demo platform into a robust real-world phishing protection solution.
