from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PRODUCTION_DATABASE_PATH = (BASE_DIR / "pqbank.db").resolve()
TEST_DATABASE_PATH = (BASE_DIR / "test_pqbank.db").resolve()


def _normalize_sqlite_path(value: str | None, default_path: Path) -> str:
    if value is None or not value.strip():
        return f"sqlite:///{default_path}"

    candidate = value.strip()
    if candidate.startswith("sqlite:///:memory:"):
        return candidate
    if candidate.startswith("sqlite:///./"):
        relative_path = candidate.replace("sqlite:///./", "", 1)
        return f"sqlite:///{(BASE_DIR / relative_path).resolve()}"
    if candidate.startswith("sqlite:///"):
        if candidate.startswith("sqlite:///C:") or candidate.startswith("sqlite:///c:"):
            return candidate
        remainder = candidate.replace("sqlite:///", "", 1)
        if remainder.startswith("/"):
            return candidate
        return f"sqlite:///{(BASE_DIR / remainder).resolve()}"
    if candidate.startswith("sqlite://"):
        return candidate
    if os.path.isabs(candidate):
        return f"sqlite:///{Path(candidate).resolve()}"
    return f"sqlite:///{(BASE_DIR / candidate).resolve()}"


def normalize_app_environment(value: str | None) -> str:
    if value is None:
        return "development"
    cleaned = value.strip().lower()
    if not cleaned:
        return "development"
    if cleaned in {"dev", "development"}:
        return "development"
    if cleaned in {"test", "testing"}:
        return "testing"
    if cleaned in {"demo", "staging"}:
        return "demo"
    if cleaned in {"prod", "production", "live"}:
        return "production"
    return cleaned


def _coerce_bool(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _sqlite_path_for_url(url: str | None) -> Path | None:
    if not url or not url.startswith("sqlite") or "memory" in url:
        return None
    if url.startswith("sqlite:///"):
        candidate = url.replace("sqlite:///", "", 1)
        if candidate.startswith("/"):
            return Path(candidate)
        return (BASE_DIR / candidate).resolve()
    return None


def is_production_database(url: str | None) -> bool:
    if not url:
        return False
    if url.startswith("sqlite:///:memory:"):
        return False
    candidate = _sqlite_path_for_url(url)
    return candidate is not None and candidate.resolve() == PRODUCTION_DATABASE_PATH


def resolve_database_url(raw_url: str | None, *, default_path: Path | None = None) -> str:
    return _normalize_sqlite_path(raw_url, default_path or PRODUCTION_DATABASE_PATH)


def resolve_app_config() -> dict[str, object]:
    app_env = normalize_app_environment(os.getenv("APP_ENV") or os.getenv("FLASK_ENV"))
    debug = _coerce_bool(os.getenv("FLASK_DEBUG") or os.getenv("APP_DEBUG"), default=False)
    host = os.getenv("APP_HOST") or os.getenv("HOST") or "127.0.0.1"
    port = int(os.getenv("APP_PORT") or os.getenv("PORT") or "5000")
    secure_cookies = _coerce_bool(os.getenv("SESSION_COOKIE_SECURE"), default=(app_env == "production"))
    session_lifetime_seconds = int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "1800"))
    absolute_lifetime_seconds = int(os.getenv("SESSION_ABSOLUTE_TIMEOUT_SECONDS", "43200"))
    config = {
        "APP_ENV": app_env,
        "DEBUG": debug,
        "HOST": host,
        "PORT": port,
        "SECRET_KEY": os.getenv("SECRET_KEY"),
        "DATABASE_URL": resolve_database_url(os.getenv("DATABASE_URL"), default_path=PRODUCTION_DATABASE_PATH),
        "TEST_DATABASE_URL": resolve_database_url(os.getenv("TEST_DATABASE_URL"), default_path=TEST_DATABASE_PATH),
        "DATABASE_ECHO": _coerce_bool(os.getenv("DATABASE_ECHO"), default=False),
        "SESSION_COOKIE_SECURE": secure_cookies,
        "SESSION_IDLE_TIMEOUT_SECONDS": session_lifetime_seconds,
        "SESSION_ABSOLUTE_TIMEOUT_SECONDS": absolute_lifetime_seconds,
    }
    if app_env == "production" and not config["SECRET_KEY"]:
        raise RuntimeError("Production configuration requires SECRET_KEY to be set before starting the application.")
    if app_env == "production" and config["DEBUG"]:
        raise RuntimeError("Debug mode must remain disabled in production.")
    return config


DATABASE_URL = resolve_database_url(os.getenv("DATABASE_URL"), default_path=PRODUCTION_DATABASE_PATH)
TEST_DATABASE_URL = resolve_database_url(os.getenv("TEST_DATABASE_URL"), default_path=TEST_DATABASE_PATH)
DATABASE_ECHO = _coerce_bool(os.getenv("DATABASE_ECHO"), default=False)

__all__ = [
    "BASE_DIR",
    "PRODUCTION_DATABASE_PATH",
    "TEST_DATABASE_PATH",
    "DATABASE_URL",
    "TEST_DATABASE_URL",
    "DATABASE_ECHO",
    "_normalize_sqlite_path",
    "normalize_app_environment",
    "is_production_database",
    "resolve_app_config",
    "resolve_database_url",
    "_coerce_bool",
]
