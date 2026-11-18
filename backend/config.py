"""Backend configuration and environment loader."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
from dotenv import load_dotenv

# Search for backend/.env first, then root .env
_BACKEND_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _BACKEND_DIR.parent

if (_BACKEND_DIR / ".env").is_file():
    load_dotenv(_BACKEND_DIR / ".env")
elif (_PROJECT_DIR / ".env").is_file():
    load_dotenv(_PROJECT_DIR / ".env")


DISABLED_NOTIFICATION_ENV = {
    "ALERT_NOTIFICATIONS_ENABLED": "false",
    "ALERT_INCLUDE_DRY_RUN": "false",
    "SMTP_HOST": "",
    "SMTP_PORT": "587",
    "SMTP_SECURITY": "starttls",
    "SMTP_USER": "",
    "SMTP_PASSWORD": "",
    "SMTP_SENDER": "",
    "ALERT_EMAIL_RECIPIENT": "",
    "ALERT_WEBHOOK_URL": "",
    "ALERT_WEBHOOK_FORMAT": "generic",
    "ALERT_COOLDOWN_SECONDS": "600",
    "ALERT_MAX_PER_HOUR": "30",
    "ALERT_QUEUE_SIZE": "64",
}


@dataclass
class NotificationSettings:
    ALERT_NOTIFICATIONS_ENABLED: bool = field(default_factory=lambda: os.getenv("ALERT_NOTIFICATIONS_ENABLED", "false").lower() == "true")
    SMTP_HOST: str = field(default_factory=lambda: os.getenv("SMTP_HOST", ""))
    SMTP_PORT: int = field(default_factory=lambda: int(os.getenv("SMTP_PORT", "587")))
    SMTP_SECURITY: str = field(default_factory=lambda: os.getenv("SMTP_SECURITY", "starttls"))
    SMTP_USER: str = field(default_factory=lambda: os.getenv("SMTP_USER", ""), repr=False)
    SMTP_PASSWORD: str = field(default_factory=lambda: os.getenv("SMTP_PASSWORD", ""), repr=False)
    SMTP_SENDER: str = field(default_factory=lambda: os.getenv("SMTP_SENDER", ""))
    ALERT_EMAIL_RECIPIENT: str = field(default_factory=lambda: os.getenv("ALERT_EMAIL_RECIPIENT", ""))
    ALERT_WEBHOOK_URL: str = field(default_factory=lambda: os.getenv("ALERT_WEBHOOK_URL", ""), repr=False)
    ALERT_WEBHOOK_FORMAT: str = field(default_factory=lambda: os.getenv("ALERT_WEBHOOK_FORMAT", "generic"))
    ALERT_COOLDOWN_SECONDS: int = field(default_factory=lambda: int(os.getenv("ALERT_COOLDOWN_SECONDS", "600")))
    ALERT_MAX_PER_HOUR: int = field(default_factory=lambda: int(os.getenv("ALERT_MAX_PER_HOUR", "30")))
    ALERT_QUEUE_SIZE: int = field(default_factory=lambda: int(os.getenv("ALERT_QUEUE_SIZE", "64")))
    ALERT_INCLUDE_DRY_RUN: bool = field(default_factory=lambda: os.getenv("ALERT_INCLUDE_DRY_RUN", "false").lower() == "true")

    def validate_notifications(self):
        for name in ("ALERT_NOTIFICATIONS_ENABLED", "ALERT_INCLUDE_DRY_RUN"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a boolean")
        for name, low, high in (("SMTP_PORT", 1, 65535), ("ALERT_COOLDOWN_SECONDS", 600, 86400),
                                ("ALERT_MAX_PER_HOUR", 1, 30), ("ALERT_QUEUE_SIZE", 1, 1024)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f"{name} must be an integer from {low} to {high}")
        if self.SMTP_SECURITY not in ("starttls", "ssl", "plain"):
            raise ValueError("SMTP_SECURITY must be starttls, ssl or plain")
        if self.ALERT_WEBHOOK_FORMAT not in ("generic", "slack", "discord"):
            raise ValueError("ALERT_WEBHOOK_FORMAT must be generic, slack or discord")
        if self.ALERT_WEBHOOK_URL:
            url = urlsplit(self.ALERT_WEBHOOK_URL)
            if (not url.hostname or url.username or url.password or url.fragment
                    or any(c.isspace() for c in self.ALERT_WEBHOOK_URL)
                    or (url.scheme != "https" and not (
                        url.scheme == "http" and url.hostname in ("localhost", "127.0.0.1", "::1")))):
                raise ValueError("ALERT_WEBHOOK_URL requires HTTPS (HTTP only on loopback), no userinfo or fragment")
            try:
                url.port
            except ValueError:
                raise ValueError("Invalid ALERT_WEBHOOK_URL port") from None
        if self.ALERT_NOTIFICATIONS_ENABLED and self.SMTP_HOST:
            if (any(c.isspace() for c in self.SMTP_HOST)
                    or self.SMTP_SECURITY == "plain" and self.SMTP_HOST not in ("localhost", "127.0.0.1", "::1")):
                raise ValueError("SMTP requires TLS except for a loopback development server")
            from email_validator import validate_email, EmailNotValidError
            for name in ("SMTP_SENDER", "ALERT_EMAIL_RECIPIENT"):
                try:
                    validate_email(getattr(self, name), check_deliverability=False)
                except EmailNotValidError:
                    raise ValueError(f"Configure a valid {name}") from None
            if bool(self.SMTP_USER) != bool(self.SMTP_PASSWORD):
                raise ValueError("Configure both SMTP_USER and SMTP_PASSWORD or neither")
        return self


@dataclass
class Settings(NotificationSettings):
    DATABASE_URL: str = field(default_factory=lambda: os.getenv("DATABASE_URL", ""), repr=False)
    SECRET_KEY: str = field(default_factory=lambda: os.getenv("SECRET_KEY", ""), repr=False)
    SENSOR_API_TOKEN: str = field(default_factory=lambda: os.getenv("SENSOR_API_TOKEN", ""), repr=False)
    SENSOR_ID: str = field(default_factory=lambda: os.getenv("SENSOR_ID", "sensor-local"))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = field(default_factory=lambda: int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "5")))
    REFRESH_TOKEN_EXPIRE_DAYS: int = field(default_factory=lambda: int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "15")))
    CORS_ORIGINS: tuple = field(default_factory=lambda: tuple(
        origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()))

    def validate(self):
        self.validate_notifications()
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
        if (self.ALGORITHM != "HS256" or not 1 <= self.ACCESS_TOKEN_EXPIRE_MINUTES <= 1440
                or not 1 <= self.REFRESH_TOKEN_EXPIRE_DAYS <= 365):
            raise ValueError("Invalid JWT algorithm or token lifetime")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.SENSOR_ID):
            raise ValueError("SENSOR_ID must contain 1 to 64 letters, digits, dots, dashes or underscores")
        if "*" in self.CORS_ORIGINS:
            raise ValueError("Configure explicit CORS origins")
        return self


settings = Settings()
