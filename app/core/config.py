"""
Configuration settings for the Phishing Detection System.

Groups:
- Core: Basic project info.
- Security: CORS allowed origins, optional API key, and rate limiting rules.
- TGIS Pipeline: Scoring weights and temporal thresholds for TGIS logic.
- EGD Model: Baseline parameters (alpha, beta, gamma) for age-normalized graphs.
- TIS Weights: Component weights controlling isolation scoring distribution.
- Data Source Endpoints: Target URLs for external infrastructure APIs.
- Cache TTLs: Expiration limits for graph building and WHOIS fast-path caching.
"""

from typing import Dict, List, Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Core
    PROJECT_NAME: str = "Phishing Detection System"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str = "phishing_db.sqlite"

    # Security
    ALLOWED_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    API_KEY: str | None = None
    RATE_LIMIT_PER_MINUTE: int = 30

    # TGIS Pipeline
    TGIS_TIMEOUT_MS: int = 200
    TGIS_ALPHA: float = 0.55
    TGIS_BETA: float = 0.30
    TGIS_GAMMA: float = 0.15
    SCP_AGE_THRESHOLD_DAYS: float = 1.0

    # EGD Model
    EGD_PARAMS: dict = {
        "infrastructure": {"alpha": 18.0, "beta": 0.045, "gamma": 0.5},
        "certificate":    {"alpha": 6.0,  "beta": 0.08,  "gamma": 0.0},
        "ownership":      {"alpha": 4.0,  "beta": 0.12,  "gamma": 1.0},
        "routing":        {"alpha": 3.0,  "beta": 0.06,  "gamma": 0.2},
    }

    # TIS Weights
    TIS_WEIGHTS: dict = {
        "infrastructure": 0.40,
        "certificate":    0.25,
        "ownership":      0.20,
        "routing":        0.15,
    }

    @field_validator("TIS_WEIGHTS")
    @classmethod
    def validate_weights(cls, v: dict) -> dict:
        total = sum(v.values())
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"TIS_WEIGHTS must sum to 1.0, got {total}")
        return v

    # Data Source Endpoints
    PDNS_API_URL: str = "https://pdns.circl.lu/query"
    CT_LOGS_API_URL: str = "https://crt.sh"
    RDAP_API_URL: str = "https://rdap.arin.net/registry/ip"

    # Cache TTLs
    GRAPH_CACHE_TTL_SECONDS: int = 300
    WHOIS_CACHE_TTL_SECONDS: int = 86400

    class Config:
        env_file = ".env"

settings = Settings()
