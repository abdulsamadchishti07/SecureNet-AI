"""Backend configuration and environment loader."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

# Search for backend/.env first, then root .env
_BACKEND_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _BACKEND_DIR.parent

if (_BACKEND_DIR / ".env").is_file():
    load_dotenv(_BACKEND_DIR / ".env")
elif (_PROJECT_DIR / ".env").is_file():
    load_dotenv(_PROJECT_DIR / ".env")


@dataclass
class Settings:
    DATABASE_URL: str = field(default_factory=lambda: os.getenv("DATABASE_URL", ""), repr=False)
    SECRET_KEY: str = field(default_factory=lambda: os.getenv("SECRET_KEY", ""), repr=False)
    SENSOR_API_TOKEN: str = field(default_factory=lambda: os.getenv("SENSOR_API_TOKEN", ""), repr=False)
    SENSOR_ID: str = field(default_factory=lambda: os.getenv("SENSOR_ID", "sensor-local"))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = field(default_factory=lambda: int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")))
    CORS_ORIGINS: tuple = field(default_factory=lambda: tuple(
        origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()))

    def validate(self):
        if (not self.DATABASE_URL.startswith(("sqlite:", "sqlite+", "postgresql:", "postgresql+"))
                or "\n" in self.DATABASE_URL or "\r" in self.DATABASE_URL):
            raise ValueError("Configure an explicit SQLite or PostgreSQL DATABASE_URL")
        for name in ("SECRET_KEY", "SENSOR_API_TOKEN"):
            value = getattr(self, name)
            if (len(value.encode("utf-8")) < 32 or value != value.strip()
                    or "default" in value.lower() or "change-in-production" in value.lower()):
                raise ValueError(f"{name} must be an independently generated secret of at least 32 bytes")
        if self.SECRET_KEY == self.SENSOR_API_TOKEN:
            raise ValueError("User JWT and sensor credentials must differ")
        if self.ALGORITHM != "HS256" or not 1 <= self.ACCESS_TOKEN_EXPIRE_MINUTES <= 1440:
            raise ValueError("Invalid JWT algorithm or token lifetime")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.SENSOR_ID):
            raise ValueError("SENSOR_ID must contain 1 to 64 letters, digits, dots, dashes or underscores")
        if "*" in self.CORS_ORIGINS:
            raise ValueError("Configure explicit CORS origins")
        return self


settings = Settings()
