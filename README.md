# Phishing Detection System

A Hybrid Multi-Layer Phishing URL Detection System built with FastAPI, implementing advanced URL analysis and threat detection capabilities.

## Project Overview

This system provides a comprehensive phishing detection solution with:
- **Asynchronous request handling** using FastAPI
- **Multi-layer detection** approach (Database, API, Heuristics)
- **Real-time URL scanning** via REST API
- **Extensible architecture** for future ML integration

## Current Status: Phase 1 Complete ✅

Phase 1 implements the foundational environment setup and core skeleton:
- ✅ Full project structure with modular design
- ✅ FastAPI application with CORS support
- ✅ URL validation using Pydantic models
- ✅ RESTful `/scan` endpoint for URL analysis
- ✅ OpenAPI documentation (Swagger UI)
- ✅ Placeholder services for future phases

## Project Structure

```
phishing_detection_system/
│
├── app/
│   ├── __init__.py
│   ├── main.py              # Application entry point
│   ├── core/                # Core configurations
│   │   ├── __init__.py
│   │   └── config.py        # Environment variables settings
│   ├── api/                 # API Routes
│   │   ├── __init__.py
│   │   └── endpoints.py     # The /scan endpoint
│   ├── schemas/             # Pydantic models (Data validation)
│   │   ├── __init__.py
│   │   └── url_schema.py    # Request/Response structures
│   └── services/            # Business logic layers
│       ├── __init__.py
│       ├── preprocessing.py # [Phase 2] URL preprocessing
│       └── database.py      # [Phase 3] Database integration
│
├── .env                     # Environment variables
├── .gitignore
├── requirements.txt         # Project dependencies
└── README.md

```

## Installation

### Prerequisites
- Python 3.12+ (or Python 3.8+)
- pip package manager

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/phoenixdev-512/phishing_detection_system.git
   cd phishing_detection_system
   ```

2. **Create and activate virtual environment (recommended)**
   ```bash
   python -m venv venv
   
   # On Mac/Linux:
   source venv/bin/activate
   
   # On Windows:
   venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

### Start the Server

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The server will start at: `http://127.0.0.1:8000`

### Interactive API Documentation

FastAPI automatically generates interactive API documentation:

- **Swagger UI**: http://127.0.0.1:8000/docs
- **ReDoc**: http://127.0.0.1:8000/redoc
- **OpenAPI Schema**: http://127.0.0.1:8000/openapi.json

## API Endpoints

### Root Endpoint
```bash
GET /
```
Returns a simple health check message.

**Example:**
```bash
curl http://127.0.0.1:8000/
```

**Response:**
```json
{
  "message": "Phishing URL Analyzer Backend is Running"
}
```

### URL Scan Endpoint
```bash
POST /api/v1/scan
```
Analyzes a URL for phishing threats.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Example:**
```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response:**
```json
{
  "url": "https://example.com/",
  "status": "unknown",
  "risk_score": 0,
  "verdict_source": "System Initialization",
  "reasons": [
    "Phase 1 Skeleton: System is operational but analysis layers are empty."
  ]
}
```

### Response Fields

- `url` (string): The analyzed URL
- `status` (string): Risk status - "safe", "suspicious", "malicious", or "unknown"
- `risk_score` (integer): Numerical risk score from 0-100
- `verdict_source` (string): Which layer detected the threat (DB, API, Heuristic)
- `reasons` (array): Detailed explanation of the verdict

## Dependencies

The project uses the following core libraries:

- **FastAPI (0.109.1)**: Modern web framework with automatic API documentation
- **Uvicorn (0.27.0)**: ASGI server for running the application
- **Pydantic (2.5.3)**: Data validation using Python type hints
- **pydantic-settings (2.1.0)**: Settings management from environment variables
- **python-dotenv (1.0.1)**: Load environment variables from .env file
- **requests (2.31.0)**: HTTP library for external API calls
- **tldextract (5.1.1)**: Domain parsing and extraction
- **python-whois (0.8.0)**: WHOIS lookups for domain metadata
- **aiohttp (3.13.3)**: Async HTTP client for concurrent API calls

All dependencies have been verified for security vulnerabilities and updated to safe versions.

## Configuration

Configuration is managed through the `.env` file in the root directory:

```env
PROJECT_NAME="Phishing URL Analyzer"
API_V1_STR="/api/v1"
```

Additional configuration options will be added in future phases (database URLs, API keys, etc.).

## Development Roadmap

### ✅ Phase 1: Environment Setup & Core Skeleton (Complete)
- Project structure and dependencies
- FastAPI application setup
- Basic URL scanning endpoint
- Input validation and API documentation

### 🔄 Phase 2: URL Preprocessing (Upcoming)
- Protocol validation
- Structural decomposition
- IDN conversion
- URL normalization

### 📋 Phase 3: Database Integration (Planned)
- Local blacklist/whitelist database
- SQLite setup and management
- Caching mechanisms

### 📋 Phase 4: External API Integration (Planned)
- Google Safe Browsing API
- VirusTotal API integration
- Rate limiting and error handling

### 📋 Phase 5: Heuristic Analysis (Planned)
- URL pattern analysis
- Domain age and SSL checks
- Statistical analysis

### 📋 Phase 6: Machine Learning Layer (Planned)
- Feature extraction
- ML model integration
- Ensemble predictions

## Testing

To verify the Phase 1 implementation:

1. **Start the server**
2. **Test the root endpoint:**
   ```bash
   curl http://127.0.0.1:8000/
   ```

3. **Test URL scanning:**
   ```bash
   curl -X POST http://127.0.0.1:8000/api/v1/scan \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
   ```

4. **Test URL validation (should fail):**
   ```bash
   curl -X POST http://127.0.0.1:8000/api/v1/scan \
     -H "Content-Type: application/json" \
     -d '{"url": "not-a-valid-url"}'
   ```

5. **Visit the interactive docs:**
   - Open http://127.0.0.1:8000/docs in your browser
   - Try out the endpoints using the Swagger UI

## Contributing

This is a development project implementing a multi-layer phishing detection system. Contributions are welcome for future phases.

## License

[Add appropriate license]

## Contact

For questions or feedback about this project, please open an issue in the repository.