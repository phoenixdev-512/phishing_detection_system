import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "Phishing URL Analyzer")
    API_V1_STR: str = os.getenv("API_V1_STR", "/api/v1")
    
    # External API Keys (optional - system works without them)
    GOOGLE_SAFE_BROWSING_API_KEY: str | None = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

settings = Settings()
