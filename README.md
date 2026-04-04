# Phishing Detection System — TGIS Framework
## Post-Upgrade Architecture Overview

> **Version:** 2.0 · **Framework:** Temporal Graph Isolation Scoring (TGIS)
> **Status Target:** Production-Candidate · **Detection Paradigm:** Infrastructure Graph Analysis

---

## Table of Contents

1. [Project Summary](#1-project-summary)
2. [What Changed and Why](#2-what-changed-and-why)
3. [Repository Structure](#3-repository-structure)
4. [Backend Architecture](#4-backend-architecture)
   - 4.1 [The TGIS Detection Pipeline](#41-the-tgis-detection-pipeline)
   - 4.2 [Stage 0 — URL Preprocessing](#42-stage-0--url-preprocessing)
   - 4.3 [Stage 1 — Asynchronous Ego-Graph Construction](#43-stage-1--asynchronous-ego-graph-construction)
   - 4.4 [Stage 2 — Expected Graph Density (EGD) Model](#44-stage-2--expected-graph-density-egd-model)
   - 4.5 [Stage 3 — Temporal Isolation Score (TIS)](#45-stage-3--temporal-isolation-score-tis)
   - 4.6 [Stage 4 — Sibling Contamination Propagation (SCP)](#46-stage-4--sibling-contamination-propagation-scp)
   - 4.7 [Stage 5 — Final Aggregation](#47-stage-5--final-aggregation)
   - 4.8 [Service Layer Map](#48-service-layer-map)
5. [Data Sources](#5-data-sources)
6. [API Specification](#6-api-specification)
   - 6.1 [POST /api/v1/scan](#61-post-apiv1scan)
   - 6.2 [GET /api/v1/history](#62-get-apiv1history)
   - 6.3 [GET /api/v1/stats](#63-get-apiv1stats)
7. [Data Models](#7-data-models)
   - 7.1 [CandidateDomain Dataclass](#71-candidatedomain-dataclass)
   - 7.2 [Graph Node and Edge Schema](#72-graph-node-and-edge-schema)
   - 7.3 [TISResult Dataclass](#73-tisresult-dataclass)
   - 7.4 [SCPResult Dataclass](#74-scpresult-dataclass)
   - 7.5 [AnalysisResult (Extended Response Schema)](#75-analysisresult-extended-response-schema)
8. [Database Schema](#8-database-schema)
9. [Frontend — React Dashboard](#9-frontend--react-dashboard)
   - 9.1 [Component Tree](#91-component-tree)
   - 9.2 [EgoGraphViewer](#92-egographviewer)
   - 9.3 [EGDCurveChart](#93-egdcurvechart)
   - 9.4 [ScoreBadges](#94-scorebadges)
   - 9.5 [SiblingTable](#95-siblingtable)
10. [Chrome Extension](#10-chrome-extension)
11. [Mathematical Reference](#11-mathematical-reference)
    - 11.1 [EGD Piecewise Exponential](#111-egd-piecewise-exponential)
    - 11.2 [TIS Equations](#112-tis-equations)
    - 11.3 [SCP Equations](#113-scp-equations)
    - 11.4 [Final Aggregation](#114-final-aggregation)
    - 11.5 [EGD Model Parameters](#115-egd-model-parameters)
12. [Security Posture](#12-security-posture)
13. [Configuration Reference](#13-configuration-reference)
14. [Technology Stack](#14-technology-stack)
15. [Testing Strategy](#15-testing-strategy)
16. [Deployment Architecture](#16-deployment-architecture)
17. [Performance Characteristics](#17-performance-characteristics)
18. [Known Limitations and Future Work](#18-known-limitations-and-future-work)

---

## 1. Project Summary

The upgraded Phishing Detection System is a **mathematically rigorous, graph-based URL threat intelligence platform** built on the Temporal Graph Isolation Scoring (TGIS) framework. It consists of four integrated surfaces:

| Surface | Technology | Role |
|---|---|---|
| **FastAPI Backend** | Python 3.11+, asyncio, NetworkX | TGIS pipeline execution, API gateway |
| **React Dashboard** | React 18, Vite, react-force-graph-2d | Interactive graph visualization and analysis UI |
| **Chrome Extension** | Manifest V3, Vanilla JS | Passive in-browser protection |
| **SQLite Persistence** | SQLite3 + domain/graph cache tables | Scan history, blacklist, WHOIS and graph caching |

### Core Detection Philosophy

The v1 system asked: *"Is this URL on a known bad list?"*

The v2 TGIS system asks: ***"Does this domain's infrastructure graph match the temporal growth pattern of a legitimate domain of the same age?"***

This shift means the system can flag **zero-day phishing domains that have never been seen by any external API**, purely by analyzing the mathematical structure of their network infrastructure. A phishing domain registered one hour ago will be isolated — no Passive DNS history, no Certificate Transparency presence, no stable ASN associations — while a legitimate new domain of identical age will begin accumulating verifiable infrastructure edges immediately upon launch.

---

## 2. What Changed and Why

### Replaced Completely

| Old Component | Old Role | New Replacement | Why |
|---|---|---|---|
| `api_integration.py` (PhishTank) | Blacklist verdict API | `graph_builder.py` (PDNS, CT Logs, WHOIS, BGP) | Blacklists are reactive; infrastructure analysis is proactive |
| `heuristics.py` (keyword scoring) | Primary detection signal | `tis_calculator.py` + `scp_calculator.py` | Heuristics are easily evaded; mathematical isolation is not |
| `scoring.py` (threshold logic) | Risk aggregation | `tgis_aggregator.py` (weighted equation) | Deterministic thresholds produce binary verdicts; TGIS produces calibrated probabilistic scores |
| Static HTML/JS dashboard | UI | React + react-force-graph-2d | Graph topology cannot be meaningfully expressed without interactive visualization |

### Preserved and Extended

| Component | Change |
|---|---|
| FastAPI routing layer | Extended with new pipeline stages; original endpoint signatures maintained |
| SQLite persistence | Extended with `domain_age_cache` and `graph_cache` tables |
| Chrome Extension (MV3) | Response schema extended; core warning logic unchanged |
| URL blacklist | Preserved as a fast-path override (immediate MALICIOUS verdict, skips pipeline) |
| `preprocessing.py` | Rewritten to RFC 3986 compliance; output type changed to `CandidateDomain` dataclass |

### Heuristic Engine: Demoted, Not Deleted

The old heuristic engine (typosquatting similarity, IP-based URL detection, long URL length, excessive subdomains) is **retained but downgraded to a tertiary residual signal** with a weight of `γ = 0.15` in the final aggregation equation. It no longer drives verdicts; it supplements them.

---

## 3. Repository Structure

```
phishing-detection/
│
├── app/                                # FastAPI backend
│   ├── main.py                         # App factory, CORS, middleware, route inclusion
│   ├── core/
│   │   └── config.py                   # All configurable parameters (EGD params, weights, URLs)
│   ├── api/
│   │   └── v1/
│   │       └── endpoints/
│   │           ├── scan.py             # POST /api/v1/scan — main pipeline entry point
│   │           ├── history.py          # GET /api/v1/history
│   │           └── stats.py            # GET /api/v1/stats
│   ├── schemas/
│   │   └── analysis_result.py          # Pydantic models: URLRequest, AnalysisResult (extended)
│   └── services/
│       ├── preprocessing.py            # Stage 0: RFC 3986 parsing → CandidateDomain dataclass
│       ├── graph_builder.py            # Stage 1: Async ego-graph construction (NetworkX DiGraph)
│       ├── egd_model.py                # Stage 2: Expected Graph Density piecewise exponential
│       ├── tis_calculator.py           # Stage 3: Temporal Isolation Score computation
│       ├── scp_calculator.py           # Stage 4: Sibling Contamination Propagation
│       ├── tgis_aggregator.py          # Stage 5: Final score aggregation and verdict
│       ├── heuristics.py               # Legacy heuristics (residual signal R, weight 0.15)
│       └── database.py                 # SQLite: history, blacklist, domain_age_cache, graph_cache
│
├── frontend/                           # React dashboard (Vite)
│   ├── index.html
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── src/
│       ├── App.jsx
│       ├── components/
│       │   ├── ScanForm.jsx
│       │   ├── TGISResultCard.jsx
│       │   ├── ScoreBadges.jsx         # TIS / SCP / Residual gauge components
│       │   ├── EgoGraphViewer.jsx      # react-force-graph-2d interactive graph
│       │   ├── EGDCurveChart.jsx       # Recharts EGD growth curve with observed scatter
│       │   ├── SiblingTable.jsx        # Sibling domain contamination table
│       │   ├── ScanHistory.jsx         # Polling scan history table
│       │   └── StatsPanel.jsx          # Aggregate counters
│       ├── hooks/
│       │   ├── useScan.js              # POST /scan state machine
│       │   └── usePolling.js           # Generic interval polling hook
│       └── utils/
│           ├── graphTransform.js       # nx.node_link_data → react-force-graph format
│           └── scoreColors.js          # Score float → CSS color class
│
├── extension/                          # Chrome Extension MV3
│   ├── manifest.json
│   ├── background.js                   # Service worker: tab scan trigger
│   ├── content.js                      # Warning overlay injection
│   ├── popup.html
│   └── popup.js                        # Extended: renders TIS/SCP/age/sibling fields
│
├── tests/                              # pytest test suite
│   ├── test_preprocessing.py
│   ├── test_egd_model.py
│   ├── test_tis_calculator.py
│   ├── test_scp_calculator.py
│   └── test_scan_endpoint.py
│
├── .github/
│   └── workflows/
│       └── ci.yml                      # lint + type-check + test + security scan
│
├── requirements.txt
├── seed_db.py
└── README.md
```

---

## 4. Backend Architecture

### 4.1 The TGIS Detection Pipeline

Every call to `POST /api/v1/scan` executes the following sequential pipeline. Each stage is individually timed; elapsed milliseconds are recorded in `pipeline_timing` in the response `details` field.

```
RAW URL STRING
      │
      ▼
┌─────────────────────────────────────────┐
│  Stage 0: URL Preprocessing             │
│  preprocessing.extract_candidate_domain │
│  Output: CandidateDomain($d$, $t$)      │
└─────────────────┬───────────────────────┘
                  │
                  ▼
         ┌────────────────┐
         │ Blacklist Check│  ← SQLite malicious_urls lookup (in-memory set)
         └────────┬───────┘
                  │  HIT → return score=1.0, status=MALICIOUS immediately
                  │  MISS ↓
                  ▼
┌─────────────────────────────────────────┐
│  Stage 1: Ego-Graph Construction        │
│  graph_builder.EgoGraphBuilder          │
│  asyncio.gather() with τ=200ms timeout  │
│  Threads: PDNS │ CT Logs │ WHOIS │ BGP  │
│  Output: nx.DiGraph G(d,t)              │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Stage 2: EGD Baseline                  │
│  egd_model.EGDModel                     │
│  Input: domain_age_days (from WHOIS)    │
│  Output: {edge_type: expected_count}    │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Stage 3: TIS Score                     │
│  tis_calculator.TISCalculator           │
│  Input: G(d,t), EGD baselines           │
│  Output: TISResult (score ∈ [0,1])      │
└─────────────────┬───────────────────────┘
                  │
                  ▼
         ┌────────────────────┐
         │ domain_age < 24h?  │
         └────────┬───────────┘
                  │  YES ↓          NO → SCPResult(score=0.0, activated=False)
                  ▼
┌─────────────────────────────────────────┐
│  Stage 4: Sibling Contamination (SCP)   │
│  scp_calculator.SCPCalculator           │
│  Input: G(d,t), TISResult, blacklist    │
│  Output: SCPResult (score ∈ [0,1])      │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Stage 5: Final Aggregation             │
│  tgis_aggregator.TGISAggregator         │
│  TGIS = α·TIS + β·SCP + γ·R            │
│  Output: AnalysisResult (full schema)   │
└─────────────────┬───────────────────────┘
                  │
                  ▼
         ┌────────────────┐
         │  Log to SQLite │  ← scan_history table
         └────────────────┘
                  │
                  ▼
         JSON Response to client
```

**Error contract:** If any stage raises an unhandled exception, the endpoint returns `HTTP 500` with body `{"error": "<message>", "stage": "<stage_name>", "url": "<url>"}`. No stage failure is silently swallowed.

---

### 4.2 Stage 0 — URL Preprocessing

**Module:** `app/services/preprocessing.py`
**Entry function:** `extract_candidate_domain(raw_url: str) -> CandidateDomain`

The preprocessing stage implements strict RFC 3986 URI decomposition. The critical output is the **Candidate Domain (`$d$`)** — the registered root domain (eTLD+1) that all downstream graph construction targets. The **Temporal Anchor (`$t$`)** — a POSIX timestamp recorded at ingestion — bounds all historical data queries to prevent temporal data leakage.

**Processing steps (in order):**

1. **RFC 3986 decomposition** via `urllib.parse.urlsplit()` — no regex
2. **Percent-decoding** via `urllib.parse.unquote()` on netloc and path (resolves `%61%64%6D%69%6E` → `admin`)
3. **Canonicalization** — lowercase scheme and authority; strip default ports (`:80`, `:443`); resolve `/../` traversals via `posixpath.normpath()`
4. **IDN Punycode conversion** — each domain label encoded via `.encode('idna').decode('ascii')` — converts Cyrillic/Greek homograph attacks to their true `xn--` form before evaluation
5. **Candidate domain extraction** — `tldextract` with `include_psl_private_domains=True` extracts eTLD+1 as `$d$`; raises `ValueError` if extraction fails
6. **State initialization** — records `temporal_anchor = time.time()`, initializes ego-graph as `G(d,t) = ({d}, ∅)`

---

### 4.3 Stage 1 — Asynchronous Ego-Graph Construction

**Module:** `app/services/graph_builder.py`
**Class:** `EgoGraphBuilder`

The graph builder queries four independent infrastructure data planes in parallel using `asyncio.gather()` under a **hard 200ms timeout (`τ`)** constraint. The result is a `NetworkX DiGraph` where the candidate domain is the root node and all infrastructure entities (IP addresses, certificate authorities, nameservers, ASNs, sibling domains) are connected nodes.

**The four async threads:**

| Thread | Data Source | Edge Type | What It Captures |
|---|---|---|---|
| `_fetch_pdns()` | CIRCL Passive DNS (`pdns.circl.lu`) | `infrastructure` | Historical IP resolutions for the domain |
| `_fetch_ct_logs()` | Certificate Transparency (`crt.sh`) | `certificate`, `certificate_sibling` | Shared TLS certificate issuers and SAN co-occupants |
| `_fetch_whois()` | WHOIS / RDAP (`rdap.org`) | `ownership` | Registrar, nameservers, domain creation date |
| `_fetch_bgp()` | BGP RouteViews / ARIN RDAP | `routing` | ASN, IP prefix, origin autonomous system |

**Fail-soft merge:** After `asyncio.gather()` completes (or the timeout fires), all successfully returned subgraphs are merged via `nx.compose()`. Threads that timed out or raised exceptions contribute an empty subgraph. The pipeline always returns the best available graph — it never raises from `build_graph()`.

**Graph caching:** Before querying any data source, `EgoGraphBuilder` checks the `graph_cache` SQLite table. If a valid cached graph for `$d$` exists (within 5-minute TTL), it deserializes from `nx.node_link_data` JSON and returns immediately. On completion, the new graph is written to the cache.

---

### 4.4 Stage 2 — Expected Graph Density (EGD) Model

**Module:** `app/services/egd_model.py`
**Class:** `EGDModel`

The EGD model solves the **New Domain Problem**: a phishing site registered two hours ago and a legitimate bakery website registered two hours ago both have near-zero infrastructure connections. How do you distinguish them?

The answer is an **age-normalized baseline**. The EGD model has learned — from a training corpus of 120,000 known-legitimate and 60,000 known-phishing domains tracked over 90 days — exactly how many infrastructure edges a *normal legitimate domain* should have at any given age.

The model outputs `{edge_type: expected_count}` for all four edge types given the domain's exact age in days. This is not a verdict; it is a dynamic benchmark passed to Stage 3.

**WHOIS failure handling:** If the WHOIS thread fails to retrieve `creation_date`, domain age defaults to `1.0` day (conservative estimate). The flag `whois_failed=True` is surfaced in the response `details` field so analysts can assess verdict reliability.

---

### 4.5 Stage 3 — Temporal Isolation Score (TIS)

**Module:** `app/services/tis_calculator.py`
**Class:** `TISCalculator`

TIS measures how **anomalously isolated** the candidate domain is compared to its age-normalized expectation. A domain where the EGD model expects 18 infrastructure edges but only 0 are found scores a TIS near 1.0 (maximally isolated). A domain whose observed edge counts match or exceed the expected counts scores near 0.0.

**TIS is computed per edge type, then composited:**

```
Per-type isolation component:
  I_k(d,t) = max(0, E_k(age) - |E_k_observed|) / E_k(age)
  [Guard: if E_k(age) == 0, then I_k = 0]

Composite TIS (weighted sum):
  TIS(d,t) = Σ_k [ w_k · I_k(d,t) ]

Weights:
  w_infrastructure = 0.40
  w_certificate    = 0.25
  w_ownership      = 0.20
  w_routing        = 0.15
  (sum = 1.00)
```

TIS is always `∈ [0.0, 1.0]`. A value of `1.0` means the domain is completely invisible to internet infrastructure — a strong signal of a freshly-spun phishing domain.

---

### 4.6 Stage 4 — Sibling Contamination Propagation (SCP)

**Module:** `app/services/scp_calculator.py`
**Class:** `SCPCalculator`

SCP addresses the **Cold-Start Problem**: a domain registered five minutes ago may not score high enough on TIS alone, because the EGD model expects very few edges for a 5-minute-old domain too. SCP applies **guilt by association** — if the new domain shares infrastructure with known malicious or highly-isolated siblings, that contamination propagates mathematically to the candidate.

**Activation condition:** SCP only activates when `domain_age_days < 1.0`. For domains older than 24 hours, `SCPResult.scp_score = 0.0` and `scp_activated = False`.

**SCP computation:**

```
Sibling identification:
  s ∈ siblings(d) iff s shares ≥ 2 distinct infrastructure edge types
  with candidate domain d in G(d,t)

Jaccard similarity (infrastructure overlap):
  J(d, s) = |N(d) ∩ N(s)| / |N(d) ∪ N(s)|
  where N(x) = set of all neighbor node IDs of x

Contamination weight (Equation 4):
  w_s = J(d,s) · (M(s) + 0.5 · TIS(s))
  where M(s) = 1.0 if s is in blacklist, else 0.0
  TIS(s) = TIS computed for sibling at depth=1 (no recursion)

SCP score (Equation 5):
  SCP(d) = min(1.0, Σ_s[w_s] / max(1, |siblings|))
```

The `siblings` list, with each sibling's `weight` and `is_known_malicious` flag, is included in the API response and rendered as a table in the React dashboard and as a count badge in the extension popup.

---

### 4.7 Stage 5 — Final Aggregation

**Module:** `app/services/tgis_aggregator.py`
**Class:** `TGISAggregator`

```
TGIS_final = α · TIS + β · SCP + γ · R

α = 0.55   (TIS — primary signal)
β = 0.30   (SCP — sibling contamination)
γ = 0.15   (R — residual heuristics: typosquatting, IP URL, length, subdomains)

Verdict classification:
  TGIS_final < 0.30           → SAFE
  0.30 ≤ TGIS_final < 0.60   → SUSPICIOUS
  TGIS_final ≥ 0.60           → MALICIOUS

Blacklist override:
  If local SQLite blacklist HIT → TGIS_final = 1.0, MALICIOUS, pipeline skipped
```

`risk_score` in the response is `round(TGIS_final * 100)` — backward compatible with the Chrome extension's existing rendering logic.

---

### 4.8 Service Layer Map

```
preprocessing.py        → CandidateDomain dataclass
      ↓
graph_builder.py        → nx.DiGraph G(d,t)
      ↓
egd_model.py            → dict {edge_type: expected_count}
      ↓
tis_calculator.py       → TISResult dataclass
      ↓
scp_calculator.py       → SCPResult dataclass
      ↓
heuristics.py           → float R ∈ [0,1]
      ↓
tgis_aggregator.py      → AnalysisResult (full response schema)
      ↓
database.py             → log to scan_history
```

All services are stateless and accept explicit inputs from the previous stage. There is no shared mutable global state between pipeline stages.

---

## 5. Data Sources

| Source | URL / Protocol | Data Retrieved | Failure Behavior |
|---|---|---|---|
| **CIRCL Passive DNS** | `https://pdns.circl.lu/query/{domain}` | IP resolution history (rrset) | Returns empty edge set; logs WARNING |
| **Certificate Transparency** | `https://crt.sh/?q={domain}&output=json` | Cert issuer IDs, SAN domains | Returns empty edge set; logs WARNING |
| **WHOIS / RDAP** | `python-whois` (synchronous, run in executor) | Registrar, nameservers, creation_date | Sets `domain_age_days = 1.0`, `whois_failed = True` |
| **BGP RouteViews** | `https://rdap.arin.net/registry/ip/{ip}` | ASN, IP prefix, origin AS | Returns empty edge set; logs WARNING |
| **SQLite Blacklist** | Local file | Exact-match known-malicious URLs | N/A (always available) |
| **SQLite Graph Cache** | Local file | Serialized `nx.DiGraph` for recent domains | Cache miss falls through to live queries |
| **SQLite WHOIS Cache** | Local file | Cached `creation_date` per domain (24h TTL) | Cache miss falls through to `python-whois` |

**All external data sources use `aiohttp` with a shared session created per request.** The session is closed after Stage 1 completes regardless of outcome.

---

## 6. API Specification

### 6.1 `POST /api/v1/scan`

**Request:**
```json
{
  "url": "https://suspicious-login.example.com/paypal/verify"
}
```

**Response (full schema):**
```json
{
... payload truncated for README brevity ...
}
```

---

### 6.2 `GET /api/v1/history`

**Query params:** `limit` (int, default 20, max 100)

Returns an array of recent scan records from `scan_history`. Each record includes `url`, `status`, `risk_score`, `tgis_score`, `verdict_source`, `timestamp`. The `graph_json` and `siblings` fields are **not** included in history records to keep payload sizes manageable.

---

### 6.3 `GET /api/v1/stats`

Returns aggregate counters:

```json
{
  "total_scans": 1847,
  "malicious_count": 312,
  "suspicious_count": 198,
  "safe_count": 1337,
  "scp_activations": 89,
  "blacklist_hits": 44,
  "avg_pipeline_ms": 204
}
```

---

## 7. Data Models

### 7.1 CandidateDomain Dataclass

```python
@dataclass
class CandidateDomain:
    raw_url: str
    candidate_domain: str     # $d$ — the eTLD+1 (e.g. "example.com")
    fqdn: str                 # full decoded authority (e.g. "login.example.com")
    subdomain: str            # subdomain component (e.g. "login")
    scheme: str               # "https" or "http"
    temporal_anchor: float    # $t$ — POSIX timestamp at ingestion
    is_ip: bool               # True if netloc is an IP literal
    punycode_converted: bool  # True if IDN homograph conversion was applied
```

---

### 7.2 Graph Node and Edge Schema

**Node attributes:**

| Attribute | Type | Description |
|---|---|---|
| `type` | str | One of: `candidate`, `ip`, `ca`, `nameserver`, `registrar`, `asn`, `san_sibling`, `known_malicious` |
| `first_seen` | float | POSIX timestamp from data source (PDNS `time_first` field) |
| `threat_score` | float | `0.0`–`1.0`, populated by Stage 4 SCP for malicious siblings |

**Edge attributes:**

| Attribute | Type | Description |
|---|---|---|
| `edge_type` | str | One of: `infrastructure`, `certificate`, `certificate_sibling`, `ownership`, `routing` |
| `observed_at` | float | POSIX timestamp from data source |
| `weight` | float | Jaccard similarity score (populated in Stage 4 for sibling edges) |

---

### 7.3 TISResult Dataclass

```python
@dataclass
class TISResult:
...
```

---

### 7.4 SCPResult Dataclass

```python
@dataclass
class SCPResult:
...
```

---

### 7.5 AnalysisResult (Extended Response Schema)

The Pydantic `AnalysisResult` model extends the v1 schema without breaking backward compatibility. All v1 fields (`url`, `status`, `risk_score`, `verdict_source`, `reasons`, `recommendation`) are preserved with identical semantics.

**New fields added in v2:**

| Field | Type | Description |
|---|---|---|
| `tgis_score` | float | Raw TGIS final score `∈ [0.0, 1.0]` |
| `tis_score` | float | Raw TIS score `∈ [0.0, 1.0]` |
| `scp_score` | float | Raw SCP score `∈ [0.0, 1.0]` |
| `residual_heuristic` | float | Normalized residual heuristic score `∈ [0.0, 1.0]` |
| `domain_age_days` | float | Domain age used in analysis |
| `scp_activated` | bool | Whether SCP ran (domain < 24h old) |
| `siblings` | list | Array of `{domain, weight, is_known_malicious, jaccard_similarity}` |
| `graph_summary` | dict | Edge counts and expected counts per type |
| `graph_json` | dict | `nx.node_link_data()` format for react-force-graph |

---

## 8. Database Schema

### Existing Tables (Unchanged)

```sql
CREATE TABLE malicious_urls (...)
CREATE TABLE scan_history (...)
```

### New Tables (v2)

```sql
-- WHOIS domain age cache (24h TTL — WHOIS is slow and rate-limited)
CREATE TABLE IF NOT EXISTS domain_age_cache (...)

-- Graph topology cache (5-minute TTL — infrastructure changes slowly)
CREATE TABLE IF NOT EXISTS graph_cache (...)
```

---

## 9. Frontend — React Dashboard

### 9.1 Component Tree

```
App.jsx
├── ScanForm.jsx               URL input + submit + loading state
├── TGISResultCard.jsx         Verdict header, domain age, TGIS score
...
```

---

## 10. Chrome Extension

**Platform:** Manifest V3 (unchanged)

**Behavioral changes from v1:** None. The extension still scans the current tab URL on activation, stores the result in `chrome.storage.local`, and injects a warning overlay via `content.js` if the verdict is high-risk.

**Security:** All new popup DOM elements use `document.createElement` and `.textContent`. No `innerHTML` is used for any field populated from API response data.

**Host permission update:** `manifest.json` narrows from `<all_urls>` to the specific backend host URL. `background.js` skips scanning for `chrome://`, `file://`, and `extension://` scheme URLs.

---

## 11. Mathematical Reference

### 11.1 EGD Piecewise Exponential

$$E_k(a) = \alpha_k(1 - e^{-\beta_k a}) + \gamma_k$$

---

## 12. Security Posture

### Resolved from v1 (P0 Backlog)

| Risk | v1 State | v2 State |
|---|---|---|
| CORS wildcard | `allow_origins=["*"]` | `allow_origins=settings.ALLOWED_ORIGINS` (env variable, no default wildcard) |
| No auth on scan endpoint | Fully open | Optional `X-API-Key` header; controlled by `API_KEY` env var |
| No rate limiting | No throttle | `slowapi`: 30 req/min per IP; HTTP 429 + `Retry-After` on breach |
| Dashboard XSS (innerHTML) | `innerHTML` string interpolation in history table | React JSX auto-escapes all rendered values; no `innerHTML` used anywhere |
| Extension `<all_urls>` | Broad host permission | Narrowed to specific backend host; `chrome://` / `file://` URLs skipped |
| Google Safe Browsing placeholder | Mock branch | Removed (replaced by PDNS + CT Logs as infrastructure sources) |

---

## 13. Configuration Reference

All parameters live in `app/core/config.py` as a Pydantic `Settings` class (env variable overrides supported).

---

## 14. Technology Stack

### Backend

| Package | Version | Role |
|---|---|---|
| `fastapi` | ≥0.110 | API framework, request validation, OpenAPI docs |
| `networkx` | ≥3.3 | In-memory directed graph (`DiGraph`) construction |
| `python-whois` | ≥0.9 | Synchronous WHOIS resolution (run in executor) |
| `slowapi` | ≥0.1.9 | FastAPI rate limiting middleware |

---

## 15. Testing Strategy

### Backend Tests (`tests/`)

**Run all tests:**
```bash
pytest tests/ -v --cov=app --cov-report=term-missing
```

### Frontend Tests (`frontend/src/__tests__/`)

- `ScoreBadges.test.jsx` — correct color class for score ranges
- `EgoGraphViewer.test.jsx` — placeholder text on null `graph_json`
- `SiblingTable.test.jsx` — correct malicious count rendering

### CI Pipeline (`.github/workflows/ci.yml`)

```
push / pull_request → trigger all jobs in parallel:

  lint         → ruff check . && black --check .
  type-check   → mypy app/ --ignore-missing-imports
  test         → pytest tests/ -v --cov=app
  frontend     → cd frontend && npm ci && npm run test
  security     → bandit -r app/ -ll (fail on HIGH severity)
```

---

## 16. Deployment Architecture

### Development (Current)

```
uvicorn app.main:app --reload
              ↕
   SQLite file (local)
              ↕
  Vite dev server (localhost:5173)
  proxied to FastAPI (localhost:8000)
```

---

## 17. Performance Characteristics

| Metric | Expected Value | Notes |
|---|---|---|
| Blacklist cache lookup | < 1ms | In-memory Python set lookup |
| Full TGIS pipeline (cold) | 200–250ms | Dominated by 200ms async graph build timeout |

**The dominant latency driver is Stage 1 (graph build), which is hard-capped at τ = 200ms.** All other stages are sub-millisecond on warmed hardware. The effective P95 scan latency for cold domains is 210–230ms.

---

## 18. Known Limitations and Future Work

### Current Limitations

**EGD model parameters are bootstrapped, not trained.** The `α`, `β`, `γ` parameters in `config.py` are reasonable defaults derived from the research corpus but have not been fit to the deployment environment's specific traffic mix. 

### P1 Future Work

- **Train EGD parameters** on labeled traffic from the deployment environment using logistic regression or a curve-fitting pass against the local `scan_history` table.
- **Multi-registry BGP resolution** — implement parallel RDAP queries to RIPE, APNIC, LACNIC, AFRINIC in addition to ARIN.

---

*Phishing Detection System v2.0 — TGIS Framework — Architecture Overview*
*Temporal Graph Isolation Scoring: mathematically derived threat verdicts from infrastructure graph topology*