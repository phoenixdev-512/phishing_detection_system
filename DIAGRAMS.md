# Phishing Detection System - Diagrams

This document contains Mermaid diagrams illustrating the system's architecture, data flow, and workflow.

---

## 1. System Architecture Diagram

```mermaid
graph TB
    subgraph "User Interfaces"
        WD[Web Dashboard<br/>Dark Mode UI]
        BE[Browser Extension<br/>Chrome]
    end
    
    subgraph "FastAPI Backend"
        API[API Router<br/>/api/v1/scan]
        EP[Endpoints<br/>endpoints.py]
        STATIC[Static Files<br/>index.html]
    end
    
    subgraph "Core Services"
        PREP[Preprocessing Service<br/>URL Sanitization & IDN]
        DB[Database Service<br/>SQLite + Bloom Filter]
        APIINT[API Integration<br/>Safe Browsing + PhishTank]
        HEUR[Heuristic Engine<br/>Pattern Analysis]
        SCORE[Risk Aggregator<br/>Weighted Scoring]
    end
    
    subgraph "Data Layer"
        SQLITE[(SQLite DB<br/>Malicious URLs)]
        BLOOM[Bloom Filter<br/>Fast Lookup]
        CACHE[LRU Cache<br/>API Results]
    end
    
    subgraph "External Services"
        GSB[Google Safe Browsing API]
        PT[PhishTank API]
    end
    
    subgraph "Schemas"
        REQ[URLRequest Schema]
        RES[AnalysisResult Schema]
    end
    
    WD -->|HTTP POST| API
    BE -->|HTTP POST| API
    API --> EP
    EP --> REQ
    EP --> PREP
    PREP -->|URL Components| DB
    DB -->|Check Result| SCORE
    PREP -->|Clean URL| APIINT
    APIINT -.->|Async Parallel| GSB
    APIINT -.->|Async Parallel| PT
    APIINT -->|Cache Check| CACHE
    APIINT -->|API Result| SCORE
    PREP -->|URL Components| HEUR
    HEUR -->|Heuristic Score| SCORE
    SCORE -->|Aggregated Result| RES
    RES -->|JSON Response| EP
    EP -->|Response| WD
    EP -->|Response| BE
    DB <-->|Read/Write| SQLITE
    DB <-->|Fast Check| BLOOM
    SQLITE -.->|Log Scans| DB
    
    style WD fill:#2d3748,stroke:#4a5568,color:#fff
    style BE fill:#2d3748,stroke:#4a5568,color:#fff
    style API fill:#3182ce,stroke:#2c5282,color:#fff
    style SCORE fill:#48bb78,stroke:#2f855a,color:#fff
    style DB fill:#ed8936,stroke:#c05621,color:#fff
    style APIINT fill:#9f7aea,stroke:#6b46c1,color:#fff
    style HEUR fill:#f56565,stroke:#c53030,color:#fff
```

---

## 2. Data Flow Diagram

```mermaid
flowchart LR
    subgraph "Input"
        U1[User enters URL<br/>via Web Dashboard]
        U2[Browser Extension<br/>detects navigation]
    end
    
    subgraph "Phase 0: Preprocessing"
        P1[Sanitize URL<br/>Remove whitespace]
        P2[Validate Protocol<br/>Add http:// if missing]
        P3[IDN Conversion<br/>Unicode → Punycode]
        P4[Feature Extraction<br/>domain, TLD, path, query]
    end
    
    subgraph "Phase 1: Database Layer"
        D1{Bloom Filter<br/>Check}
        D2[SQLite Lookup<br/>Get metadata]
        D3[Return DB Result<br/>risk_score, source]
    end
    
    subgraph "Phase 2: API Layer"
        A1[Check Cache<br/>LRU 5min TTL]
        A2[Parallel API Calls]
        A3[Google Safe Browsing]
        A4[PhishTank]
        A5[Combine Results]
    end
    
    subgraph "Phase 3: Heuristic Layer"
        H1[Typosquatting Check<br/>9 brands, 70% similarity]
        H2[Keyword Analysis<br/>9 suspicious terms]
        H3[Domain Age Check<br/>WHOIS lookup]
        H4[Structural Analysis<br/>IP, length, subdomains]
        H5[Calculate Heuristic Score]
    end
    
    subgraph "Phase 4: Aggregation"
        S1[Weight All Signals<br/>DB: 100, API: 100, Heuristics: varied]
        S2[Calculate Final Score<br/>0-100 scale]
        S3{Risk Classification}
        S4[Safe<br/>0-39]
        S5[Suspicious<br/>40-69]
        S6[Malicious<br/>70-100]
    end
    
    subgraph "Output"
        O1[JSON Response<br/>status, risk_score, reasons]
        O2[Log to Database<br/>Scan history]
        O3[Update Dashboard<br/>Display result]
        O4[Extension Alert<br/>Visual warning]
    end
    
    U1 --> P1
    U2 --> P1
    P1 --> P2 --> P3 --> P4
    P4 --> D1
    D1 -->|Match| D2 --> D3
    D1 -->|No Match| A1
    P4 --> A1
    A1 -->|Cache Miss| A2
    A2 --> A3
    A2 --> A4
    A3 --> A5
    A4 --> A5
    P4 --> H1
    H1 --> H2 --> H3 --> H4 --> H5
    D3 --> S1
    A5 --> S1
    H5 --> S1
    S1 --> S2 --> S3
    S3 -->|0-39| S4
    S3 -->|40-69| S5
    S3 -->|70-100| S6
    S4 --> O1
    S5 --> O1
    S6 --> O1
    O1 --> O2
    O1 --> O3
    O1 --> O4
    
    style P4 fill:#4299e1,color:#fff
    style D3 fill:#ed8936,color:#fff
    style A5 fill:#9f7aea,color:#fff
    style H5 fill:#f56565,color:#fff
    style S2 fill:#48bb78,color:#fff
    style S6 fill:#fc8181,color:#000
    style S5 fill:#f6ad55,color:#000
    style S4 fill:#68d391,color:#000
```

---

## 3. Workflow Diagram (Sequential Process)

```mermaid
sequenceDiagram
    participant User
    participant UI as Web/Extension
    participant API as FastAPI Backend
    participant Prep as Preprocessing
    participant DB as Database Layer
    participant ExtAPI as External APIs
    participant Heur as Heuristic Engine
    participant Agg as Risk Aggregator
    participant Storage as SQLite DB
    
    User->>UI: Enter URL or Navigate
    UI->>API: POST /api/v1/scan
    activate API
    
    API->>Prep: normalize(raw_url)
    activate Prep
    Prep->>Prep: Sanitize & validate
    Prep->>Prep: Convert IDN to Punycode
    Prep->>Prep: Extract features
    Prep-->>API: url_components
    deactivate Prep
    
    API->>DB: check_url(clean_url)
    activate DB
    DB->>DB: Bloom filter lookup (0.69µs)
    alt URL in Bloom Filter
        DB->>DB: SQLite query for details
        DB-->>API: {status: "malicious", source: "database"}
    else Not in Bloom Filter
        DB-->>API: {status: "unknown"}
    end
    deactivate DB
    
    par Parallel External API Calls
        API->>ExtAPI: check_url(clean_url)
        activate ExtAPI
        ExtAPI->>ExtAPI: Check LRU cache
        alt Cache Hit
            ExtAPI-->>API: Cached result
        else Cache Miss
            ExtAPI->>ExtAPI: Google Safe Browsing
            ExtAPI->>ExtAPI: PhishTank
            ExtAPI-->>API: Combined API result
        end
        deactivate ExtAPI
    end
    
    API->>Heur: analyze(url_components)
    activate Heur
    Heur->>Heur: Typosquatting detection
    Heur->>Heur: Keyword analysis
    Heur->>Heur: Domain age check
    Heur->>Heur: Structural analysis
    Heur-->>API: {risk_score, reasons}
    deactivate Heur
    
    API->>Agg: calculate_risk(db, api, heuristic)
    activate Agg
    Agg->>Agg: Apply weighted scoring
    Agg->>Agg: Sum all signals
    Agg->>Agg: Classify risk level
    Agg->>Agg: Generate reasons & recommendation
    Agg-->>API: {status, risk_score, reasons, details}
    deactivate Agg
    
    API->>Storage: log_scan(url, result)
    activate Storage
    Storage->>Storage: INSERT INTO scans
    Storage-->>API: Success
    deactivate Storage
    
    API-->>UI: AnalysisResult JSON
    deactivate API
    UI-->>User: Display result with recommendation
    
    alt Malicious URL (70-100)
        UI->>User: 🔴 RED Alert
    else Suspicious URL (40-69)
        UI->>User: 🟡 YELLOW Warning
    else Safe URL (0-39)
        UI->>User: 🟢 GREEN Safe
    end
```

---

## Performance Metrics

| Layer | Average Latency | Cache Hit Latency |
|-------|----------------|-------------------|
| Preprocessing | < 1ms | N/A |
| Database (Bloom + SQLite) | < 1ms | N/A |
| External APIs | ~4ms | ~1.6ms |
| Heuristics | ~1-2ms | N/A |
| **Total Pipeline** | **~6-8ms** | **~3-5ms (cached)** |

---

## Risk Score Classification

```mermaid
graph LR
    A[Risk Score: 0-100] --> B{Classification}
    B -->|0-39| C[✅ SAFE<br/>Proceed with confidence]
    B -->|40-69| D[⚠️ SUSPICIOUS<br/>Exercise caution]
    B -->|70-100| E[🚫 MALICIOUS<br/>Block immediately]
    
    style C fill:#48bb78,color:#fff
    style D fill:#ed8936,color:#fff
    style E fill:#f56565,color:#fff
```

---

## Detection Layer Weights

```mermaid
pie title Risk Score Contribution by Source
    "Database Match" : 100
    "API Match (Safe Browsing/PhishTank)" : 100
    "Typosquatting" : 80
    "IP Address in URL" : 60
    "New Domain (<30 days)" : 40
    "Excessive Subdomains" : 20
    "Suspicious Keywords" : 20
    "Long URL" : 15
```
