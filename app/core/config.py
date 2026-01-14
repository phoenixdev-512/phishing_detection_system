import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Phishing URL Analyzer"
    API_V1_STR: str = "/api/v1"
    
    # We will add Database URL and API Keys (Google Safe Browsing) here in later phases
    class Config:
        env_file = ".env"

settings = Settings()
