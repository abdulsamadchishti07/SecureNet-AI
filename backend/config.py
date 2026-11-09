"""Backend configuration and environment loader."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Search for backend/.env first, then root .env
_BACKEND_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _BACKEND_DIR.parent

if (_BACKEND_DIR / ".env").is_file():
    load_dotenv(_BACKEND_DIR / ".env")
elif (_PROJECT_DIR / ".env").is_file():
    load_dotenv(_PROJECT_DIR / ".env")


class Settings:
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./securenet.db")

    # JWT Authentication
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY", "securenet-default-insecure-secret-key-change-in-production"
    )
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

    # Redis Event Broker
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Email SMTP Alerts
    EMAIL_HOST_USER: str = os.getenv("EMAIL_HOST_USER", "")
    EMAIL_HOST_PASSWORD: str = os.getenv("EMAIL_HOST_PASSWORD", "")
    DEFAULT_FROM_EMAIL: str = os.getenv("DEFAULT_FROM_EMAIL", "")
    EMAIL_SMTP_SERVER: str = os.getenv("EMAIL_SMTP_SERVER", "smtp.gmail.com")
    EMAIL_SMTP_PORT: int = int(os.getenv("EMAIL_SMTP_PORT", "587"))


settings = Settings()
