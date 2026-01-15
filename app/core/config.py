from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "Phishing URL Analyzer"
    API_V1_STR: str = "/api/v1"
    
    # External API Keys (optional - system works without them)
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    
    class Config:
        env_file = ".env"

settings = Settings()
