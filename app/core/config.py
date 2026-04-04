import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "Phishing URL Analyzer")
    API_V1_STR: str = os.getenv("API_V1_STR", "/api/v1")
    
    # External API Keys (optional - system works without them)
    GOOGLE_SAFE_BROWSING_API_KEY: str | None = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    # TGIS Pipeline Configuration
    TGIS_TIMEOUT_MS: int = 200
    TGIS_ALPHA: float = 0.55       # TIS weight in final aggregation
    TGIS_BETA: float = 0.30        # SCP weight in final aggregation
    TGIS_GAMMA: float = 0.15       # Residual heuristic weight
    SCP_AGE_THRESHOLD_DAYS: float = 1.0  # SCP only activates below this

    # EGD Model Parameters (per edge type)
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

    # Data Source API Endpoints
    PDNS_API_URL: str = "https://pdns.circl.lu/query"
    CT_LOGS_API_URL: str = "https://crt.sh"
    RDAP_API_URL: str = "https://rdap.arin.net/registry/ip"
    
    ALLOWED_ORIGINS: list = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000,*").split(",")]

settings = Settings()
