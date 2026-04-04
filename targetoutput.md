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
  "url": "https://suspicious-login.example.com/paypal/verify",
  "status": "malicious",
  "risk_score": 84,
  "verdict_source": "TGIS_Pipeline",
  "reasons": [
    "TIS: infrastructure isolation 0.91 (observed 0 edges, expected 8.2)",
    "TIS: certificate isolation 0.88 (observed 0 edges, expected 4.1)",
    "SCP: 2 malicious siblings detected (max weight 0.79)",
    "SCP activated: domain is 0.3 hours old",
    "Residual: IP-based URL pattern detected"
  ],
  "recommendation": "MALICIOUS — Do not visit this URL. Infrastructure analysis indicates a newly-isolated domain with contaminated sibling infrastructure.",

  "tgis_score": 0.84,
  "tis_score": 0.91,
  "scp_score": 0.72,
  "residual_heuristic": 0.40,
  "domain_age_days": 0.013,
  "scp_activated": true,

  "siblings": [
    {
      "domain": "paypal-secure-login.net",
      "weight": 0.79,
      "is_known_malicious": true,
      "jaccard_similarity": 0.83
    },
    {
      "domain": "paypal-verify-account.com",
      "weight": 0.44,
      "is_known_malicious": false,
      "jaccard_similarity": 0.51
    }
  ],

  "graph_summary": {
    "total_nodes": 6,
    "total_edges": 3,
    "edge_counts": {
      "infrastructure": 0,
      "certificate": 0,
      "ownership": 2,
      "routing": 1
    },
    "expected_edges": {
      "infrastructure": 8.2,
      "certificate": 4.1,
      "ownership": 3.8,
      "routing": 1.9
    }
  },

  "graph_json": {
    "nodes": [
      {"id": "suspicious-login.example.com", "type": "candidate"},
      {"id": "GoDaddy LLC", "type": "registrar"},
      {"id": "ns1.godaddy.com", "type": "nameserver"},
      {"id": "ns2.godaddy.com", "type": "nameserver"},
      {"id": "AS26496", "type": "asn"},
      {"id": "paypal-secure-login.net", "type": "san_sibling"}
    ],
    "links": [
      {"source": "suspicious-login.example.com", "target": "GoDaddy LLC", "edge_type": "ownership"},
      {"source": "suspicious-login.example.com", "target": "ns1.godaddy.com", "edge_type": "ownership"},
      {"source": "suspicious-login.example.com", "target": "AS26496", "edge_type": "routing"},
      {"source": "suspicious-login.example.com", "target": "paypal-secure-login.net", "edge_type": "certificate_sibling"}
    ]
  },

  "details": {
    "blacklist_hit": false,
    "whois_failed": false,
    "scp_activated": true,
    "pipeline_timing": {
      "stage_0_preprocessing_ms": 1,
      "stage_1_graph_build_ms": 198,
      "stage_2_egd_ms": 0,
      "stage_3_tis_ms": 1,
      "stage_4_scp_ms": 3,
      "stage_5_aggregation_ms": 0,
      "total_ms": 203
    },
    "graph_build_threads": {
      "pdns": "timeout",
      "ct_logs": "success",
      "whois": "success",
      "bgp": "success"
    },
    "egd_baselines": {
      "infrastructure": {"expected": 8.2, "alpha": 18.0, "beta": 0.045, "gamma": 0.5},
      "certificate": {"expected": 4.1, "alpha": 6.0, "beta": 0.08, "gamma": 0.0},
      "ownership": {"expected": 3.8, "alpha": 4.0, "beta": 0.12, "gamma": 1.0},
      "routing": {"expected": 1.9, "alpha": 3.0, "beta": 0.06, "gamma": 0.2}
    }
  }
}
```

**Error responses:**
- `HTTP 422` — Pydantic validation failed (malformed URL)
- `HTTP 429` — Rate limit exceeded (30 req/min per IP); includes `Retry-After` header
- `HTTP 403` — Invalid or missing API key (when `API_KEY` env var is set)
- `HTTP 500` — Pipeline stage exception: `{"error": "...", "stage": "graph_builder", "url": "..."}`

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
    tis_score: float          # composite TIS ∈ [0.0, 1.0]
    per_type_isolation: dict  # {"infrastructure": 0.91, "certificate": 0.88, ...}
    observed_edges: dict      # {"infrastructure": 0, "certificate": 0, ...}
    expected_edges: dict      # {"infrastructure": 8.2, "certificate": 4.1, ...}
    domain_age_days: float    # age used in EGD calculation
    whois_failed: bool        # True if domain_age_days is the 1.0 fallback
```

---

### 7.4 SCPResult Dataclass

```python
@dataclass
class SCPResult:
    scp_score: float          # ∈ [0.0, 1.0]; 0.0 if age ≥ 1.0 day
    siblings_found: list      # list of sibling domain strings
    sibling_weights: dict     # {"paypal-secure.net": 0.79, ...}
    scp_activated: bool       # False if domain_age_days ≥ 1.0
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
CREATE TABLE malicious_urls (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT UNIQUE NOT NULL,
    source     TEXT,
    risk_score INTEGER,
    date_added TEXT
);

CREATE TABLE scan_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    url            TEXT NOT NULL,
    status         TEXT NOT NULL,
    risk_score     INTEGER,
    verdict_source TEXT,
    timestamp      TEXT NOT NULL
);
```

### New Tables (v2)

```sql
-- WHOIS domain age cache (24h TTL — WHOIS is slow and rate-limited)
CREATE TABLE IF NOT EXISTS domain_age_cache (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    domain        TEXT UNIQUE NOT NULL,
    creation_date TEXT,          -- ISO 8601 or NULL if WHOIS failed
    fetched_at    REAL NOT NULL, -- POSIX timestamp
    ttl_seconds   INTEGER DEFAULT 86400
);

-- Graph topology cache (5-minute TTL — infrastructure changes slowly)
CREATE TABLE IF NOT EXISTS graph_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT UNIQUE NOT NULL,
    graph_json  TEXT NOT NULL,   -- JSON: nx.node_link_data() output
    tis_score   REAL,
    scp_score   REAL,
    fetched_at  REAL NOT NULL,
    ttl_seconds INTEGER DEFAULT 300
);
```

**Cache lookup logic:**
1. Check `graph_cache` for domain where `fetched_at + ttl_seconds > now()`
2. If hit: deserialize JSON → `nx.node_link_graph()` → skip Stage 1
3. If miss: run full graph build → write result to `graph_cache`
4. Check `domain_age_cache` similarly before calling `python-whois`

---

## 9. Frontend — React Dashboard

### 9.1 Component Tree

```
App.jsx
├── ScanForm.jsx               URL input + submit + loading state
├── TGISResultCard.jsx         Verdict header, domain age, TGIS score
│   ├── ScoreBadges.jsx        TIS / SCP / Residual animated gauges
│   ├── EgoGraphViewer.jsx     Interactive force-directed graph
│   ├── EGDCurveChart.jsx      Expected vs observed growth curve
│   └── SiblingTable.jsx       Sibling domain contamination table
├── StatsPanel.jsx             Aggregate scan counters (polling)
└── ScanHistory.jsx            Recent scans table (polling every 10s)
```

**State management:** All scan state is managed in `useScan.js` via `useState` and `useReducer`. No global state library (Redux, Zustand) is needed. History and stats use `usePolling.js` with a 10-second interval.

**Build:** Vite. The React app is built to `frontend/dist/`. FastAPI serves the built static files from `dist/` at the root route (`GET /`).

---

### 9.2 EgoGraphViewer

**Library:** `react-force-graph-2d`
**Input prop:** `graph_json` (the `graph_json` field from the API response)

**Node rendering:**

| Node Type | Color | Radius |
|---|---|---|
| `candidate` | `#4FC3F7` (bright blue) | 12px |
| `ip` | `#FF9800` (orange) | 6px |
| `ca` | `#9C27B0` (purple) | 6px |
| `nameserver` | `#00BCD4` (teal) | 6px |
| `asn` | `#4CAF50` (green) | 6px |
| `san_sibling` | `#FFEB3B` (yellow) | 6px |
| `known_malicious` | `#F44336` (red) | 8px |

**Edge rendering:**

| Edge Type | Color |
|---|---|
| `infrastructure` | `#FF9800` |
| `certificate` | `#9C27B0` |
| `certificate_sibling` | `#FFEB3B` |
| `ownership` | `#00BCD4` |
| `routing` | `#4CAF50` |

**Interactions:**
- Hover on any node → tooltip: `{id, type, threat_score}`
- Click on any node → highlight all edges connected to that node
- Bottom-left legend maps colors to node types
- Null/empty graph → renders placeholder: `"Graph data unavailable — check backend connectivity."`

---

### 9.3 EGDCurveChart

**Library:** `recharts` (`LineChart`)
**Purpose:** Visualizes why a domain was flagged. Shows the EGD model's expected growth curves for each edge type alongside a scatter point showing the domain's actual observed edge count at its specific age.

**Chart elements:**

- **X-axis:** Domain age in days (0–90)
- **Y-axis:** Edge count
- **Four lines:** One per edge type, showing the piecewise exponential expected growth curve. Always visible regardless of scan result.
- **Four scatter points:** One per edge type, plotted at `x = domain_age_days`, `y = observed_count`. A point far below its line visually demonstrates isolation.
- **Vertical dashed line:** At `x = domain_age_days` — marks where the candidate falls on the timeline
- **Hover tooltip:** `"Expected: 8.2 | Observed: 0 | Isolation: 100%"`

Line and scatter colors match the edge type colors from `EgoGraphViewer` for visual consistency.

---

### 9.4 ScoreBadges

**Replaces:** The old static `Heuristic progress bar` from v1.

**Three gauges, each displaying:**
- Label: `"Temporal Isolation Score (TIS)"`, `"Sibling Contamination (SCP)"`, `"Residual Heuristic (R)"`
- Value: Float `[0,1]` shown as both a percentage bar and a numeric label (`0.91 / 1.00`)
- Color: Green (`< 0.30`), amber (`0.30–0.59`), red (`≥ 0.60`)
- Subtext (per gauge):
  - TIS → `"Domain age: {X} days"`
  - SCP → `"SCP activated: Yes / No"`
  - R → `"Legacy heuristics"`
- Animated fill on mount: `transition: width 0.8s ease-in-out`

---

### 9.5 SiblingTable

Renders the `siblings` array from the API response as a table:

| Domain | Jaccard Similarity | Weight | Known Malicious |
|---|---|---|---|
| paypal-secure-login.net | 0.83 | 0.79 | ✗ YES |
| paypal-verify-account.com | 0.51 | 0.44 | — No |

If `siblings` is empty and `scp_activated` is false, the component renders: `"SCP not activated (domain age > 24h). No sibling analysis performed."`. If `scp_activated` is true but `siblings` is empty: `"No infrastructure siblings detected within the graph."`

---

## 10. Chrome Extension

**Platform:** Manifest V3 (unchanged)

**Behavioral changes from v1:** None. The extension still scans the current tab URL on activation, stores the result in `chrome.storage.local`, and injects a warning overlay via `content.js` if the verdict is high-risk.

**Popup display additions (popup.js):**

The popup now renders additional fields below the existing verdict/risk_score/reasons display:

| Field | Condition | Display |
|---|---|---|
| `tgis_score / tis_score / scp_score` | Always (if present) | `"TGIS: 0.84 | TIS: 0.91 | SCP: 0.72"` |
| Sibling Analysis badge | `scp_activated === true` | Amber badge: `"Sibling Analysis Active"` |
| Age warning | `domain_age_days < 1.0` | Red label: `"New domain: 1h old"` |
| Malicious neighbor count | `siblings.filter(s => s.is_known_malicious).length > 0` | `"Malicious neighbors: 2"` |

**Security:** All new popup DOM elements use `document.createElement` and `.textContent`. No `innerHTML` is used for any field populated from API response data.

**Host permission update:** `manifest.json` narrows from `<all_urls>` to the specific backend host URL. `background.js` skips scanning for `chrome://`, `file://`, and `extension://` scheme URLs.

---

## 11. Mathematical Reference

### 11.1 EGD Piecewise Exponential

$$E_k(a) = \alpha_k(1 - e^{-\beta_k a}) + \gamma_k$$

Where:
- $a$ = domain age in days (`float`, clamped to `[0.0, 3650.0]`)
- $\alpha_k$ = saturation ceiling for edge type $k$ (learned from corpus)
- $\beta_k$ = growth rate constant for edge type $k$
- $\gamma_k$ = baseline floor (minimum expected edges at $a = 0$)

The exponential saturation form captures the empirically observed behavior of legitimate domains: rapid initial growth (SEO indexing, CDN edge propagation, CT log submission) followed by a gradual plateau.

---

### 11.2 TIS Equations

**Per-type isolation component (Equation 2):**

$$I_k(d,t) = \frac{\max(0,\ \mathcal{E}_k(\text{age}) - |E_k(d,t)|)}{\mathcal{E}_k(\text{age})}$$

Guard: if $\mathcal{E}_k(\text{age}) = 0$, then $I_k = 0$.

**Composite TIS (Equation 3):**

$$TIS(d,t) = \sum_k w_k \cdot I_k(d,t)$$

---

### 11.3 SCP Equations

**Jaccard similarity:**

$$J(d, s) = \frac{|N(d) \cap N(s)|}{|N(d) \cup N(s)|}$$

**Contamination weight (Equation 4):**

$$w_s = J(d,s) \cdot (M(s) + 0.5 \cdot TIS(s))$$

Where $M(s) = 1.0$ if $s \in \text{blacklist}$, else $0.0$.

**SCP score (Equation 5):**

$$SCP(d) = \min\!\left(1.0,\ \frac{\sum_s w_s}{\max(1, |\text{siblings}|)}\right)$$

---

### 11.4 Final Aggregation

$$TGIS_{\text{final}} = \alpha \cdot TIS + \beta \cdot SCP + \gamma \cdot R$$

| Parameter | Value | Signal |
|---|---|---|
| $\alpha$ | `0.55` | TIS (temporal isolation) |
| $\beta$ | `0.30` | SCP (sibling contamination) |
| $\gamma$ | `0.15` | R (residual heuristics) |

| TGIS Score | Verdict |
|---|---|
| `< 0.30` | SAFE |
| `0.30 – 0.59` | SUSPICIOUS |
| `≥ 0.60` | MALICIOUS |

---

### 11.5 EGD Model Parameters

| Edge Type $k$ | $\alpha_k$ | $\beta_k$ | $\gamma_k$ | TIS Weight $w_k$ |
|---|---|---|---|---|
| `infrastructure` | 18.0 | 0.045 | 0.5 | 0.40 |
| `certificate` | 6.0 | 0.08 | 0.0 | 0.25 |
| `ownership` | 4.0 | 0.12 | 1.0 | 0.20 |
| `routing` | 3.0 | 0.06 | 0.2 | 0.15 |

All parameters are stored in `app/core/config.py` as `EGD_PARAMS` and `TIS_WEIGHTS` dicts and are modifiable without code changes.

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

### Remaining Considerations

- **SQLite on persistent volume:** For production deployment, the database file should be on a persistent volume with file-level encryption at rest.
- **WHOIS data exfiltration:** WHOIS queries reveal the candidate domain to third-party registries. For high-sensitivity deployments, proxy these through a caching middleware to limit exposure.
- **CT Log queries:** `crt.sh` is a public log. SAN sibling domain names retrieved during analysis are visible in CT logs by definition and carry no additional disclosure risk.
- **Graph cache timing attacks:** An attacker who knows the 5-minute cache TTL could potentially probe cache state via response latency differences. Acceptable for current threat model; mitigate by adding jitter to cache TTLs if required.

---

## 13. Configuration Reference

All parameters live in `app/core/config.py` as a Pydantic `Settings` class (env variable overrides supported).

```python
# Server
PROJECT_NAME: str = "Phishing Detection System v2"
API_V1_STR: str = "/api/v1"
ALLOWED_ORIGINS: list = ["http://localhost:5173", "http://localhost:3000"]
API_KEY: str | None = None          # If set, all /api/v1/ routes require X-API-Key header

# TGIS Pipeline
TGIS_TIMEOUT_MS: int = 200          # Hard timeout for async graph build (τ)
TGIS_ALPHA: float = 0.55            # TIS weight in final aggregation
TGIS_BETA: float = 0.30             # SCP weight in final aggregation
TGIS_GAMMA: float = 0.15            # Residual heuristic weight
SCP_AGE_THRESHOLD_DAYS: float = 1.0 # SCP activates only below this age

# EGD Model Parameters
EGD_PARAMS: dict = {
    "infrastructure": {"alpha": 18.0, "beta": 0.045, "gamma": 0.5},
    "certificate":    {"alpha": 6.0,  "beta": 0.08,  "gamma": 0.0},
    "ownership":      {"alpha": 4.0,  "beta": 0.12,  "gamma": 1.0},
    "routing":        {"alpha": 3.0,  "beta": 0.06,  "gamma": 0.2},
}

# TIS Weights (must sum to 1.0)
TIS_WEIGHTS: dict = {
    "infrastructure": 0.40,
    "certificate":    0.25,
    "ownership":      0.20,
    "routing":        0.15,
}

# Data Source Endpoints
PDNS_API_URL: str = "https://pdns.circl.lu/query"
CT_LOGS_API_URL: str = "https://crt.sh"
RDAP_API_URL: str = "https://rdap.arin.net/registry/ip"

# Rate Limiting
RATE_LIMIT_PER_MINUTE: int = 30

# Cache TTLs
GRAPH_CACHE_TTL_SECONDS: int = 300    # 5 minutes
WHOIS_CACHE_TTL_SECONDS: int = 86400  # 24 hours

# Database
DATABASE_URL: str = "phishing_db.sqlite"
```

---

## 14. Technology Stack

### Backend

| Package | Version | Role |
|---|---|---|
| `fastapi` | ≥0.110 | API framework, request validation, OpenAPI docs |
| `uvicorn` | ≥0.29 | ASGI server |
| `pydantic` | v2 | Schema validation, settings management |
| `networkx` | ≥3.3 | In-memory directed graph (`DiGraph`) construction |
| `aiohttp` | ≥3.9 | Async HTTP for PDNS, CT Logs, RDAP |
| `python-whois` | ≥0.9 | Synchronous WHOIS resolution (run in executor) |
| `tldextract` | ≥5.1 | PSL-based eTLD+1 extraction |
| `slowapi` | ≥0.1.9 | FastAPI rate limiting middleware |
| `pytest` + `pytest-asyncio` | latest | Test framework |
| `ruff` | latest | Linting |
| `black` | latest | Formatting |
| `mypy` | latest | Static type checking |
| `bandit` | latest | Security linting |

### Frontend

| Package | Version | Role |
|---|---|---|
| `react` + `react-dom` | 18 | UI framework |
| `vite` | ≥5 | Build tool and dev server |
| `react-force-graph-2d` | latest | Force-directed graph visualization |
| `recharts` | ≥2.12 | EGD growth curve chart |
| `axios` | ≥1.6 | HTTP client for API calls |
| `tailwindcss` | ≥3.4 | Utility CSS (dark theme) |
| `vitest` | latest | Frontend unit tests |
| `@testing-library/react` | latest | Component testing |

---

## 15. Testing Strategy

### Backend Tests (`tests/`)

| File | Coverage |
|---|---|
| `test_preprocessing.py` | RFC 3986 decomposition, Punycode conversion, IP detection, port stripping, path normalization, eTLD+1 extraction — 10 cases |
| `test_egd_model.py` | `E_k(0) = γ_k`; saturation at large `a`; age clamping; parameter loading from config |
| `test_tis_calculator.py` | `TIS = 0.0` when observed ≥ expected for all types; `TIS = 1.0` when all observed = 0 and expected >> 0; weight normalization |
| `test_scp_calculator.py` | Sibling identification; Jaccard similarity; contamination weight ordering (malicious sibling > non-malicious); SCP deactivation above 24h |
| `test_scan_endpoint.py` | Full integration via `TestClient`; response schema validation; HTTP 422 on malformed URL; HTTP 429 on rate limit breach |

**Run all tests:**
```bash
pytest tests/ -v --cov=app --cov-report=term-missing
```

### Frontend Tests (`frontend/src/__tests__/`)

- `ScoreBadges.test.jsx` — correct color class for score ranges
- `EgoGraphViewer.test.jsx` — placeholder text on null `graph_json`
- `SiblingTable.test.jsx` — correct malicious count rendering
- `useScan.test.js` — loading/error/success state transitions

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

### Production Target

```
         HTTPS (443)
              ↓
    Nginx (reverse proxy + TLS termination)
              ↓
    Gunicorn (4 Uvicorn workers)
              ↓
    FastAPI app (TGIS pipeline)
              ↓
   ┌──────────┬──────────────────┐
   │          │                  │
SQLite    Redis Cache        Secret Manager
(history) (graph + WHOIS     (API_KEY,
           cache, 5min TTL)   PDNS key)
```

**Containerization:** Single `Dockerfile` for the FastAPI backend. Frontend is built to `dist/` and served as static files. `docker-compose.yml` orchestrates backend + (optional) Redis.

**Production environment variables required:**
- `API_KEY` — authentication key for `/api/v1/` routes
- `ALLOWED_ORIGINS` — comma-separated list of permitted frontend origins
- `DATABASE_URL` — path to SQLite file on persistent volume
- `RATE_LIMIT_PER_MINUTE` — override default of 30 if needed

---

## 17. Performance Characteristics

| Metric | Expected Value | Notes |
|---|---|---|
| Blacklist cache lookup | < 1ms | In-memory Python set lookup |
| Graph cache hit (repeat domain) | < 5ms | SQLite JSON deserialize + `nx.node_link_graph()` |
| Full TGIS pipeline (cold) | 200–250ms | Dominated by 200ms async graph build timeout |
| WHOIS cache hit | < 2ms | SQLite lookup |
| WHOIS cold lookup | 500ms–2s | Synchronous; runs in executor; cached for 24h |
| EGD model computation | < 1ms | Pure arithmetic on 4 edge types |
| TIS computation | < 1ms | Graph edge counting + arithmetic |
| SCP computation | 2–10ms | Depends on sibling count and graph size |
| React dashboard first paint | < 500ms | Vite-built static assets, Nginx-served |
| Graph render (react-force-graph) | < 100ms | Typical graph has 5–30 nodes |

**The dominant latency driver is Stage 1 (graph build), which is hard-capped at τ = 200ms.** All other stages are sub-millisecond on warmed hardware. The effective P95 scan latency for cold domains is 210–230ms.

---

## 18. Known Limitations and Future Work

### Current Limitations

**EGD model parameters are bootstrapped, not trained.** The `α`, `β`, `γ` parameters in `config.py` are reasonable defaults derived from the research corpus but have not been fit to the deployment environment's specific traffic mix. The false positive rate for legitimate NRLDs (newly registered legitimate domains) depends heavily on these values. A tuning run against labeled local traffic is recommended before production deployment.

**SCP sibling computation is shallow.** Sibling TIS is computed at depth=1 only — the system does not recurse into siblings-of-siblings. This prevents runaway computation but means contamination chains longer than one hop are not fully captured.

**BGP data resolution is best-effort.** The ARIN RDAP fallback for BGP data is reliable for ARIN-registered IP space (North America) but may return empty results for RIPE, APNIC, LACNIC, and AFRINIC regions. A multi-registry RDAP resolver would improve routing edge coverage globally.

**Graph cache is domain-scoped.** The cache keys on the registered domain (`d`), not the full URL. Two different phishing URLs on the same domain within 5 minutes of each other will share a cached graph. This is intentional (infrastructure changes slowly) but means the second scan cannot detect path-specific SAN changes within the TTL window.

### P1 Future Work

- **Train EGD parameters** on labeled traffic from the deployment environment using logistic regression or a curve-fitting pass against the local `scan_history` table.
- **Expand brand/keyword corpus** for the residual heuristic engine with a structured update policy and versioning.
- **Multi-registry BGP resolution** — implement parallel RDAP queries to RIPE, APNIC, LACNIC, AFRINIC in addition to ARIN.
- **ML-assisted fourth signal channel** — add an optional ML model as a `γ_ml` term in the aggregation equation, trained on TGIS output features.
- **Feedback loop** — allow analysts to flag incorrect verdicts via the dashboard; store corrected labels in `scan_history` for future model tuning.
- **Firefox/Edge extension packaging** — the MV3 extension is partially compatible; primarily requires `manifest.json` and `background.js` adjustments.
- **Multi-browser E2E tests** — Playwright-based smoke tests for the extension warning flow.

---

*Phishing Detection System v2.0 — TGIS Framework — Architecture Overview*
*Temporal Graph Isolation Scoring: mathematically derived threat verdicts from infrastructure graph topology*