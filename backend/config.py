"""
PhishGuard configuration.

All tunables are read from environment variables (optionally loaded from a
`.env` file in the project root). Every value has a safe local-development
default so the application runs with zero configuration.

Import the singleton:   from backend.config import settings
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
BASE_DIR = Path(__file__).resolve().parent.parent          # .../phishguard
BACKEND_DIR = BASE_DIR / "backend"
FRONTEND_DIR = BASE_DIR / "frontend"
ML_DIR = BASE_DIR / "ml"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BACKEND_DIR / "data"

load_dotenv(BASE_DIR / ".env", override=False)


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value not in (None, "") else default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if not value:
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _env_int_list(name: str, default: list[int]) -> list[int]:
    result: list[int] = []
    for item in _env_list(name, [str(d) for d in default]):
        try:
            result.append(int(item))
        except ValueError:
            continue
    return result


@dataclass(frozen=True)
class Settings:
    # ---- Application ----------------------------------------------------- #
    APP_NAME: str = "PhishGuard"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = field(default_factory=lambda: _env_str("PHISHGUARD_ENV", "development"))
    DEBUG: bool = field(default_factory=lambda: _env_bool("PHISHGUARD_DEBUG", False))
    # Set by the test-suite; relaxes nothing security-related, only disables
    # background/network conveniences (e.g. automatic admin bootstrap).
    TESTING: bool = field(default_factory=lambda: _env_bool("PHISHGUARD_TESTING", False))

    # ---- Database -------------------------------------------------------- #
    DATABASE_URL: str = field(
        default_factory=lambda: _env_str("DATABASE_URL", f"sqlite:///{(BASE_DIR / 'phishguard.db').as_posix()}")
    )

    # ---- Authentication -------------------------------------------------- #
    # If JWT_SECRET is not provided a random one is generated per process
    # (sessions are then invalidated on restart - acceptable for development).
    JWT_SECRET: str = field(default_factory=lambda: _env_str("JWT_SECRET", secrets.token_urlsafe(48)))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_MINUTES: int = field(default_factory=lambda: _env_int("ACCESS_TOKEN_MINUTES", 120))
    AUTH_COOKIE_NAME: str = "pg_session"
    ANON_COOKIE_NAME: str = "pg_anon"
    # Secure cookies require HTTPS; default False for http://localhost dev.
    COOKIE_SECURE: bool = field(default_factory=lambda: _env_bool("COOKIE_SECURE", False))
    PASSWORD_MIN_LENGTH: int = 8
    RESET_TOKEN_MINUTES: int = field(default_factory=lambda: _env_int("RESET_TOKEN_MINUTES", 30))
    # Optional bootstrap admin (created at startup if both are set).
    ADMIN_EMAIL: str = field(default_factory=lambda: _env_str("ADMIN_EMAIL", ""))
    ADMIN_PASSWORD: str = field(default_factory=lambda: _env_str("ADMIN_PASSWORD", ""))
    # Optional SMTP for password-reset e-mails. If SMTP_HOST is empty the reset
    # link is written to the server log (development mode) and never returned
    # in an API response.
    SMTP_HOST: str = field(default_factory=lambda: _env_str("SMTP_HOST", ""))
    SMTP_PORT: int = field(default_factory=lambda: _env_int("SMTP_PORT", 587))
    SMTP_USER: str = field(default_factory=lambda: _env_str("SMTP_USER", ""))
    SMTP_PASSWORD: str = field(default_factory=lambda: _env_str("SMTP_PASSWORD", ""))
    SMTP_FROM: str = field(default_factory=lambda: _env_str("SMTP_FROM", "phishguard@localhost"))
    PUBLIC_BASE_URL: str = field(default_factory=lambda: _env_str("PUBLIC_BASE_URL", "http://127.0.0.1:8000"))

    # ---- Safe fetching / SSRF ------------------------------------------- #
    FETCH_CONNECT_TIMEOUT: float = field(default_factory=lambda: _env_float("FETCH_CONNECT_TIMEOUT", 5.0))
    FETCH_READ_TIMEOUT: float = field(default_factory=lambda: _env_float("FETCH_READ_TIMEOUT", 8.0))
    # Hard wall-clock budget for one complete page fetch incl. redirects.
    FETCH_TOTAL_TIMEOUT: float = field(default_factory=lambda: _env_float("FETCH_TOTAL_TIMEOUT", 10.0))
    FETCH_MAX_BYTES: int = field(default_factory=lambda: _env_int("FETCH_MAX_BYTES", 2 * 1024 * 1024))
    FETCH_MAX_REDIRECTS: int = field(default_factory=lambda: _env_int("FETCH_MAX_REDIRECTS", 8))
    FETCH_USER_AGENT: str = field(
        default_factory=lambda: _env_str(
            "FETCH_USER_AGENT",
            "Mozilla/5.0 (compatible; PhishGuard/1.0; +defensive-phishing-research)",
        )
    )
    # Destination ports the scanner may connect to.
    ALLOWED_PORTS: list[int] = field(
        default_factory=lambda: _env_int_list("ALLOWED_PORTS", [80, 443, 8080, 8443, 8000, 8888])
    )
    # Extra hostnames that are always refused (comma separated).
    BLOCKED_HOSTNAMES: list[str] = field(default_factory=lambda: _env_list("BLOCKED_HOSTNAMES", []))
    RESPECT_ROBOTS_TXT: bool = field(default_factory=lambda: _env_bool("RESPECT_ROBOTS_TXT", False))
    MAX_URL_LENGTH: int = 2048

    # ---- Rate limiting ---------------------------------------------------- #
    RATE_LIMIT_SCANS_PER_MINUTE_IP: int = field(default_factory=lambda: _env_int("RATE_LIMIT_SCANS_PER_MINUTE_IP", 10))
    RATE_LIMIT_SCANS_PER_MINUTE_SESSION: int = field(
        default_factory=lambda: _env_int("RATE_LIMIT_SCANS_PER_MINUTE_SESSION", 10)
    )
    RATE_LIMIT_AUTH_PER_MINUTE_IP: int = field(default_factory=lambda: _env_int("RATE_LIMIT_AUTH_PER_MINUTE_IP", 10))
    MAX_CONCURRENT_SCANS: int = field(default_factory=lambda: _env_int("MAX_CONCURRENT_SCANS", 4))
    # Wall-clock budget for the whole analysis pipeline (all analyzers).
    SCAN_TOTAL_TIMEOUT: float = field(default_factory=lambda: _env_float("SCAN_TOTAL_TIMEOUT", 30.0))
    # Only honour X-Forwarded-For when running behind a trusted reverse proxy.
    TRUST_PROXY_HEADERS: bool = field(default_factory=lambda: _env_bool("TRUST_PROXY_HEADERS", False))

    # ---- Domain intelligence --------------------------------------------- #
    DNS_TIMEOUT: float = field(default_factory=lambda: _env_float("DNS_TIMEOUT", 4.0))
    RDAP_TIMEOUT: float = field(default_factory=lambda: _env_float("RDAP_TIMEOUT", 6.0))
    RDAP_BOOTSTRAP_URL: str = field(default_factory=lambda: _env_str("RDAP_BOOTSTRAP_URL", "https://rdap.org/domain/"))
    ENABLE_WHOIS_FALLBACK: bool = field(default_factory=lambda: _env_bool("ENABLE_WHOIS_FALLBACK", True))
    ENABLE_ASN_LOOKUP: bool = field(default_factory=lambda: _env_bool("ENABLE_ASN_LOOKUP", True))
    # Optional Google Safe Browsing v4 key. Empty => reputation "not configured".
    GOOGLE_SAFE_BROWSING_API_KEY: str = field(default_factory=lambda: _env_str("GOOGLE_SAFE_BROWSING_API_KEY", ""))
    # Optional Tranco popularity list (CSV "rank,domain"), see scripts/download_tranco.py
    TRANCO_LIST_PATH: str = field(
        default_factory=lambda: _env_str("TRANCO_LIST_PATH", str(DATA_DIR / "tranco_top.csv"))
    )
    TRANCO_TOP_N: int = field(default_factory=lambda: _env_int("TRANCO_TOP_N", 100000))

    # ---- Machine learning ------------------------------------------------- #
    ML_MODEL_PATH: str = field(default_factory=lambda: _env_str("ML_MODEL_PATH", str(ML_DIR / "model.pkl")))
    ML_METRICS_PATH: str = field(default_factory=lambda: _env_str("ML_METRICS_PATH", str(ML_DIR / "metrics.json")))

    # ---- Risk engine ------------------------------------------------------ #
    # Component weights for the final score (renormalised when a component
    # is unavailable). See docs/METHODOLOGY.md.
    WEIGHT_ML: float = field(default_factory=lambda: _env_float("WEIGHT_ML", 0.30))
    WEIGHT_RULES: float = field(default_factory=lambda: _env_float("WEIGHT_RULES", 0.35))
    WEIGHT_WEBPAGE: float = field(default_factory=lambda: _env_float("WEIGHT_WEBPAGE", 0.20))
    WEIGHT_DOMAIN: float = field(default_factory=lambda: _env_float("WEIGHT_DOMAIN", 0.15))
    # "Application Risk Classification" bands (NOT an industry standard).
    RISK_BAND_MODERATE: int = field(default_factory=lambda: _env_int("RISK_BAND_MODERATE", 30))
    RISK_BAND_HIGH: int = field(default_factory=lambda: _env_int("RISK_BAND_HIGH", 60))
    RISK_BAND_CRITICAL: int = field(default_factory=lambda: _env_int("RISK_BAND_CRITICAL", 80))
    # ML probability thresholds used to describe the ML verdict on its own.
    ML_SUSPICIOUS_THRESHOLD: float = field(default_factory=lambda: _env_float("ML_SUSPICIOUS_THRESHOLD", 0.40))
    ML_PHISHING_THRESHOLD: float = field(default_factory=lambda: _env_float("ML_PHISHING_THRESHOLD", 0.70))

    # ---- HTTP server ------------------------------------------------------ #
    CORS_ORIGINS: list[str] = field(default_factory=lambda: _env_list("CORS_ORIGINS", []))
    HISTORY_PAGE_SIZE: int = 20


settings = Settings()

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
