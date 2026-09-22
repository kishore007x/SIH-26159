from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
import os


class Settings(BaseSettings):
    app_name: str = "SecureMailScope"
    app_version: str = "1.0.0"
    debug: bool = True
    secret_key: str = Field(default="dev-secret-change-in-production")
    
    host: str = "0.0.0.0"
    port: int = 8000
    frontend_url: str = "http://localhost:5173"
    
    database_url: str = "sqlite+aiosqlite:///./securemailscope.db"
    
    max_upload_size: int = 104857600
    upload_dir: str = "./uploads"
    
    tshark_path: str = "tshark"
    
    model_dir: str = "./models"
    anomaly_contamination: float = 0.1
    
    reports_dir: str = "./reports"
    templates_dir: str = "./backend/app/reports/templates"
    
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    enable_ollama: bool = False
    
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()

os.makedirs(settings.upload_dir, exist_ok=True)
os.makedirs(settings.reports_dir, exist_ok=True)
os.makedirs(settings.model_dir, exist_ok=True)
os.makedirs(settings.templates_dir, exist_ok=True)