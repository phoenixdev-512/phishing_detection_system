# Phishing Detection System - Architecture & Flow Diagrams
## Technical Overview with Clear Explanations

This document provides a comprehensive view of the system architecture, data flow, and workflows with technical accuracy while maintaining clarity.

---

## 1. High-Level System Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        WEB[Web Dashboard<br/>React/HTML5<br/>Port: 8000/]
        EXT[Chrome Extension<br/>Manifest V3<br/>Real-time Monitoring]
    end
    
    subgraph "API Layer - FastAPI"
        ROUTER[API Router<br/>/api/v1/scan]
        ENDPOINTS[Endpoint Handlers<br/>Request Validation]
        SCHEMAS[Pydantic Schemas<br/>URLRequest/AnalysisResult]
    end
    
    subgraph "Service Layer"
        PREPROC[URL Preprocessor<br/>- Sanitization<br/>- IDN Conversion<br/>- Feature Extraction]
        
        DB_SVC[Database Service<br/>- Bloom Filter<br/>- SQLite Queries<br/>- Scan Logging]
        
        API_SVC[API Integration<br/>- Google Safe Browsing<br/>- PhishTank<br/>- LRU Cache (5min TTL)]
        
        HEUR_SVC[Heuristic Engine<br/>- Typosquatting<br/>- Keyword Detection<br/>- Domain Age (WHOIS)<br/>- Structural Analysis]
        
        AGG_SVC[Risk Aggregator<br/>- Weighted Scoring<br/>- Classification Logic<br/>- Recommendation Engine]
    end
    
    subgraph "Data Layer"
        SQLITE[(SQLite Database<br/>malicious_urls<br/>scan_history)]
        BLOOM[Bloom Filter<br/>In-Memory<br/>Fast Lookup]
        CACHE[LRU Cache<br/>1000 entries<br/>Thread-safe]
    end
    
    subgraph "External APIs"
        GSB[Google Safe Browsing]
        PT[PhishTank]
    end
    
    WEB -->|HTTP POST| ROUTER
    EXT -->|HTTP POST| ROUTER
    ROUTER --> ENDPOINTS
    ENDPOINTS --> SCHEMAS
    ENDPOINTS --> PREPROC
    
    PREPROC --> DB_SVC
    PREPROC --> API_SVC
    PREPROC --> HEUR_SVC
    
    DB_SVC <--> SQLITE
    DB_SVC <--> BLOOM
    
    API_SVC -.->|Async| GSB
    API_SVC -.->|Async| PT
    API_SVC <--> CACHE
    
    DB_SVC --> AGG_SVC
    API_SVC --> AGG_SVC
    HEUR_SVC --> AGG_SVC
    
    AGG_SVC --> SCHEMAS
    SCHEMAS --> ENDPOINTS
    ENDPOINTS -->|JSON Response| WEB
    ENDPOINTS -->|JSON Response| EXT
    
    style WEB fill:#4299e1,stroke:#2c5282,color:#fff
    style EXT fill:#4299e1,stroke:#2c5282,color:#fff
    style ROUTER fill:#48bb78,stroke:#2f855a,color:#fff
    style AGG_SVC fill:#ed8936,stroke:#c05621,color:#fff
    style DB_SVC fill:#9f7aea,stroke:#6b46c1,color:#fff
    style API_SVC fill:#f6ad55,stroke:#dd6b20,color:#000
    style HEUR_SVC fill:#fc8181,stroke:#c53030,color:#fff
```

**Architecture Highlights:**
- **Client Layer**: Web dashboard + Chrome extension for user interaction
- **API Layer**: FastAPI with async support, Pydantic validation
- **Service Layer**: 5 core services handling different detection aspects
- **Data Layer**: SQLite for persistence, Bloom filter for speed, LRU cache for APIs
- **External Layer**: Integration with Google Safe Browsing and PhishTank

---

## 2. Request Processing Flow

```mermaid
flowchart TD
    START[User Submits URL] --> VALIDATE
    
    subgraph "Input Processing"
        VALIDATE[Pydantic Schema Validation<br/>URLRequest model]
        SANITIZE[Sanitization<br/>Remove whitespace & control chars]
        IDN[IDN Conversion<br/>Unicode → Punycode]
        EXTRACT[Feature Extraction<br/>protocol, domain, TLD, path, params]
    end
    
    subgraph "Layer 1: Database Lookup"
        BF_CHECK{Bloom Filter<br/>Probabilistic Check}
        SQL_QUERY[SQLite Query<br/>Get full metadata]
        DB_RESULT[Database Result<br/>status, source, risk_score]
    end
    
    subgraph "Layer 2: External API Check"
        CACHE_CHECK{LRU Cache<br/>5-minute TTL}
        PARALLEL[Parallel Async Calls]
        GSB_API[Google Safe Browsing API<br/>Timeout: 5s]
        PT_API[PhishTank API<br/>Timeout: 5s]
        API_RESULT[Combined API Result<br/>threat_type, confidence]
    end
    
    subgraph "Layer 3: Heuristic Analysis"
        TYPO[Typosquatting Check<br/>String similarity vs 9 brands]
        KEYWORD[Keyword Analysis<br/>9 suspicious terms]
        AGE[Domain Age Check<br/>WHOIS query]
        STRUCT[Structural Analysis<br/>IP, URL length, subdomains]
        HEUR_RESULT[Heuristic Score<br/>Accumulated points]
    end
    
    subgraph "Final Stage: Aggregation"
        WEIGHT[Apply Weights<br/>DB: 100, API: 100, etc.]
        SUM[Sum Risk Points<br/>Max capped at 100]
        CLASSIFY{Classification}
        SAFE[Safe: 0-39<br/>Low risk]
        SUSP[Suspicious: 40-69<br/>Medium risk]
        MALICIOUS[Malicious: 70-100<br/>High risk]
    end
    
    subgraph "Output & Logging"
        LOG[Log to scan_history table]
        RESPONSE[JSON Response<br/>AnalysisResult schema]
    end
    
    START --> VALIDATE
    VALIDATE --> SANITIZE
    SANITIZE --> IDN
    IDN --> EXTRACT
    
    EXTRACT --> BF_CHECK
    BF_CHECK -->|Positive| SQL_QUERY
    BF_CHECK -->|Negative| CACHE_CHECK
    SQL_QUERY --> DB_RESULT
    
    EXTRACT --> CACHE_CHECK
    CACHE_CHECK -->|Hit| API_RESULT
    CACHE_CHECK -->|Miss| PARALLEL
    PARALLEL --> GSB_API
    PARALLEL --> PT_API
    GSB_API --> API_RESULT
    PT_API --> API_RESULT
    
    EXTRACT --> TYPO
    TYPO --> KEYWORD
    KEYWORD --> AGE
    AGE --> STRUCT
    STRUCT --> HEUR_RESULT
    
    DB_RESULT --> WEIGHT
    API_RESULT --> WEIGHT
    HEUR_RESULT --> WEIGHT
    
    WEIGHT --> SUM
    SUM --> CLASSIFY
    CLASSIFY -->|0-39| SAFE
    CLASSIFY -->|40-69| SUSP
    CLASSIFY -->|70-100| MALICIOUS
    
    SAFE --> LOG
    SUSP --> LOG
    MALICIOUS --> LOG
    LOG --> RESPONSE
    
    style EXTRACT fill:#4299e1,color:#fff
    style DB_RESULT fill:#9f7aea,color:#fff
    style API_RESULT fill:#f6ad55,color:#000
    style HEUR_RESULT fill:#fc8181,color:#fff
    style SUM fill:#48bb78,color:#fff
    style MALICIOUS fill:#e53e3e,color:#fff
    style SUSP fill:#dd6b20,color:#fff
    style SAFE fill:#38a169,color:#fff
```

---

## 3. Detailed Sequence Diagram

```mermaid
sequenceDiagram
    actor User
    participant Client as Web/Extension
    participant API as FastAPI Endpoint
    participant PreProc as Preprocessor
    participant DB as Database Service
    participant SQLite as SQLite DB
    participant ExtAPI as API Manager
    participant Cache as LRU Cache
    participant Heur as Heuristic Engine
    participant Agg as Risk Aggregator
    
    User->>Client: Submit URL
    Client->>API: POST /api/v1/scan {url}
    activate API
    
    API->>PreProc: normalize(raw_url)
    activate PreProc
    PreProc->>PreProc: Sanitize input
    PreProc->>PreProc: Add protocol if missing
    PreProc->>PreProc: Convert IDN to Punycode
    PreProc->>PreProc: Extract components
    PreProc-->>API: url_components dict
    deactivate PreProc
    
    par Database Check
        API->>DB: check_url(clean_url)
        activate DB
        DB->>DB: Bloom filter lookup
        alt Found in Bloom
            DB->>SQLite: SELECT * WHERE url = ?
            SQLite-->>DB: Row data
            DB-->>API: {status: "malicious", ...}
        else Not in Bloom
            DB-->>API: {status: "unknown"}
        end
        deactivate DB
    and API Check (Parallel)
        API->>ExtAPI: check_url(clean_url)
        activate ExtAPI
        ExtAPI->>Cache: Check cache
        alt Cache Hit
            Cache-->>ExtAPI: Cached result
        else Cache Miss
            par Parallel API Calls
                ExtAPI->>ExtAPI: Google Safe Browsing
            and
                ExtAPI->>ExtAPI: PhishTank
            end
            ExtAPI->>Cache: Store result (5min TTL)
        end
        ExtAPI-->>API: API results
        deactivate ExtAPI
    and Heuristic Analysis
        API->>Heur: analyze(url_components)
        activate Heur
        Heur->>Heur: Check typosquatting
        Heur->>Heur: Scan for keywords
        Heur->>Heur: Verify domain age
        Heur->>Heur: Analyze structure
        Heur-->>API: {risk_score, reasons[]}
        deactivate Heur
    end
    
    API->>Agg: calculate_risk(db, api, heuristic)
    activate Agg
    Agg->>Agg: Apply weighted scoring
    Agg->>Agg: Sum all signals
    Agg->>Agg: Classify risk (0-39/40-69/70-100)
    Agg->>Agg: Generate recommendation
    Agg-->>API: Aggregated result
    deactivate Agg
    
    API->>DB: log_scan(url, result)
    DB->>SQLite: INSERT INTO scan_history
    SQLite-->>DB: Success
    
    API-->>Client: AnalysisResult JSON
    deactivate API
    Client-->>User: Display verdict + details
```

---

## 4. Detection Layers Detail

```mermaid
graph LR
    subgraph "Detection Pipeline"
        INPUT[Normalized URL] --> L1
        
        subgraph "Layer 1: Database"
            L1[Bloom Filter Check<br/>⚡ 0.69µs average]
            L1 --> L1A{Match?}
            L1A -->|Yes| L1B[SQLite Lookup<br/>Get metadata]
            L1A -->|No| L2
            L1B --> BLOCK1[⛔ BLOCK<br/>Score: 100]
        end
        
        subgraph "Layer 2: External APIs"
            L2[Cache Check<br/>1000 entries, 5min]
            L2 --> L2A{Cached?}
            L2A -->|No| L2B[Parallel Async<br/>GSB + PhishTank]
            L2A -->|Yes| L2C[Use cached result]
            L2B --> L2D{Threat found?}
            L2C --> L2D
            L2D -->|Yes| BLOCK2[⛔ BLOCK<br/>Score: 100]
            L2D -->|No| L3
        end
        
        subgraph "Layer 3: Heuristics"
            L3[Pattern Analysis]
            L3 --> L3A[Typosquatting: +80pts]
            L3 --> L3B[Keywords: +20pts each]
            L3 --> L3C[New domain: +30-40pts]
            L3 --> L3D[IP address: +60pts]
            L3 --> L3E[Long URL: +15pts]
            L3 --> L3F[Many subdomains: +20pts]
            L3A --> SCORE
            L3B --> SCORE
            L3C --> SCORE
            L3D --> SCORE
            L3E --> SCORE
            L3F --> SCORE
        end
        
        subgraph "Aggregation"
            SCORE[Sum Points<br/>Cap at 100]
            BLOCK1 --> FINAL
            BLOCK2 --> FINAL
            SCORE --> FINAL[Final Verdict]
        end
    end
    
    style L1 fill:#9f7aea,color:#fff
    style L2 fill:#4299e1,color:#fff
    style L3 fill:#f6ad55,color:#000
    style BLOCK1 fill:#e53e3e,color:#fff
    style BLOCK2 fill:#e53e3e,color:#fff
    style FINAL fill:#48bb78,color:#fff
```

---

## 5. Risk Scoring Matrix

```mermaid
graph TB
    subgraph "Detection Sources & Weights"
        S1[Database Match<br/>Weight: 100<br/>Instant Block]
        S2[API Match<br/>Weight: 100<br/>Instant Block]
        S3[Typosquatting<br/>Weight: 80<br/>High Risk]
        S4[IP Address URL<br/>Weight: 60<br/>Medium-High]
        S5[New Domain <30d<br/>Weight: 40<br/>Medium]
        S6[Excessive Subdomains<br/>Weight: 20<br/>Low-Medium]
        S7[Suspicious Keywords<br/>Weight: 20<br/>Low-Medium]
        S8[Long URL >75 chars<br/>Weight: 15<br/>Low]
    end
    
    S1 --> AGG[Risk Aggregator]
    S2 --> AGG
    S3 --> AGG
    S4 --> AGG
    S5 --> AGG
    S6 --> AGG
    S7 --> AGG
    S8 --> AGG
    
    AGG --> CALC[Calculate Total<br/>Max: 100]
    
    CALC --> C1{Score?}
    C1 -->|0-39| R1[✅ SAFE<br/>Proceed]
    C1 -->|40-69| R2[⚠️ SUSPICIOUS<br/>Caution advised]
    C1 -->|70-100| R3[🚫 MALICIOUS<br/>Block access]
    
    style S1 fill:#e53e3e,color:#fff
    style S2 fill:#e53e3e,color:#fff
    style S3 fill:#fc8181,color:#fff
    style AGG fill:#ed8936,color:#fff
    style R1 fill:#48bb78,color:#fff
    style R2 fill:#f6ad55,color:#000
    style R3 fill:#e53e3e,color:#fff
```

---

## 6. Performance Breakdown

```mermaid
gantt
    title Processing Time per Layer (milliseconds)
    dateFormat X
    axisFormat %L ms
    
    section Preprocessing
    Sanitization          :0, 1
    IDN Conversion        :1, 1
    Feature Extraction    :1, 1
    
    section Detection Layers
    Bloom Filter Check    :2, 1
    SQLite Query          :2, 1
    API Cache Check       :3, 1
    External API Calls    :3, 4
    Heuristic Analysis    :3, 2
    
    section Aggregation
    Weight Calculation    :7, 1
    Classification        :7, 1
    
    section Output
    Database Logging      :8, 1
    Response Generation   :8, 1
```

**Performance Metrics:**
- **Preprocessing**: ~1ms (sanitization, IDN, extraction)
- **Database Layer**: <1ms (Bloom + SQLite)
- **API Layer**: ~1.6ms (cached) / ~4ms (fresh)
- **Heuristic Layer**: ~1-2ms
- **Total**: ~6-8ms (fresh) / ~3-5ms (cached)

---

## 7. Data Schema Overview

```mermaid
erDiagram
    MALICIOUS_URLS ||--o{ SCAN_HISTORY : referenced_by
    
    MALICIOUS_URLS {
        int id PK
        string url UK
        string source
        int risk_score
        datetime added_at
    }
    
    SCAN_HISTORY {
        int id PK
        string url
        string status
        int risk_score
        string verdict_source
        json details
        datetime scanned_at
    }
    
    BLOOM_FILTER {
        string in_memory
        int size_bits
        int hash_functions
        float false_positive_rate
    }
    
    LRU_CACHE {
        string key
        json value
        datetime expiry
        int max_size
    }
```

**Database Details:**
- **malicious_urls**: Known phishing/malicious sites
- **scan_history**: Audit log of all scans performed
- **Bloom Filter**: In-memory probabilistic data structure
- **LRU Cache**: Time-limited cache for API responses

---

## 8. Real-World Processing Example

```mermaid
flowchart TB
    START["Input URL:<br/>http://paypa1-verify.com/login"] --> PREP
    
    PREP[Preprocessing<br/>✓ Clean URL<br/>✓ Extract domain: paypa1-verify.com<br/>✓ TLD: .com<br/>✓ Path: /login] --> CHECK
    
    CHECK[Run All Checks]
    
    CHECK --> DB[Database Check<br/>❌ Not in Bloom filter<br/>❌ Not in SQLite<br/>Points: 0]
    
    CHECK --> API[API Check<br/>❌ Google: No threat<br/>❌ PhishTank: Unknown<br/>Points: 0]
    
    CHECK --> HEUR[Heuristic Check<br/>✓ Typo: paypa1 vs paypal (83% similar)<br/>✓ Keyword: 'verify' detected<br/>✓ Domain age: 12 days old<br/>✓ Structure: Normal]
    
    DB --> AGG
    API --> AGG
    HEUR --> AGG
    
    AGG[Risk Aggregation<br/>━━━━━━━━━━━━━━━<br/>Typosquatting: +80<br/>Keyword 'verify': +20<br/>New domain <30d: +40<br/>━━━━━━━━━━━━━━━<br/>Total: 140 → Capped at 100]
    
    AGG --> RESULT[Final Verdict<br/>━━━━━━━━━━━━━<br/>Status: MALICIOUS<br/>Score: 100/100<br/>Source: Heuristic Analysis<br/>━━━━━━━━━━━━━<br/>Reasons:<br/>• Domain mimics PayPal<br/>• Contains verification keyword<br/>• Domain created recently]
    
    RESULT --> OUTPUT[Response to User<br/>🔴 DANGEROUS - DO NOT VISIT<br/>This appears to be a phishing attempt]
    
    style PREP fill:#4299e1,color:#fff
    style HEUR fill:#fc8181,color:#fff
    style AGG fill:#ed8936,color:#fff
    style RESULT fill:#e53e3e,color:#fff
    style OUTPUT fill:#c53030,color:#fff
```

---

## Component Responsibilities

| Component | Responsibility | Performance |
|-----------|---------------|-------------|
| **Preprocessor** | URL sanitization, IDN conversion, feature extraction | <1ms |
| **Database Service** | Bloom filter + SQLite lookups, scan logging | <1ms |
| **API Manager** | Parallel async calls to GSB/PhishTank, caching | 1.6-4ms |
| **Heuristic Engine** | Pattern matching, domain analysis, structural checks | 1-2ms |
| **Risk Aggregator** | Weighted scoring, classification, recommendations | <1ms |

---

## Technology Stack

```mermaid
graph TB
    subgraph "Backend"
        FASTAPI[FastAPI<br/>Async Python Framework]
        PYDANTIC[Pydantic<br/>Data Validation]
        UVICORN[Uvicorn<br/>ASGI Server]
    end
    
    subgraph "Data Storage"
        SQLITE[SQLite<br/>Lightweight SQL DB]
        BLOOM[Bloom Filter<br/>bitarray library]
        CACHE[LRU Cache<br/>functools.lru_cache]
    end
    
    subgraph "External Integration"
        GSB[Google Safe Browsing API]
        PT[PhishTank API]
        WHOIS[WHOIS<br/>Domain Age Lookup]
    end
    
    subgraph "Frontend"
        HTML[HTML5/CSS3<br/>Dark Mode UI]
        EXT[Chrome Extension<br/>Manifest V3]
    end
    
    style FASTAPI fill:#009688,color:#fff
    style SQLITE fill:#003B57,color:#fff
    style HTML fill:#E44D26,color:#fff
    style EXT fill:#4285F4,color:#fff
```

---

## Key Takeaways

- **Multi-Layer Defense**: 3 independent detection layers ensure comprehensive coverage
- **Fast Performance**: Sub-second response time with intelligent caching
- **Weighted Scoring**: Transparent risk calculation based on multiple signals
- **Async Processing**: Parallel API calls maximize throughput
- **Bloom Filter**: Probabilistic data structure enables microsecond lookups
- **Graceful Degradation**: System functions even if external APIs are unavailable

---

*This balanced documentation provides technical accuracy while maintaining readability for developers, security analysts, and technical stakeholders.*
