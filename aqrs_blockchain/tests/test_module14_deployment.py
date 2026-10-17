from __future__ import annotations

import pytest

from app import app, create_app
from backend.database.seed import seed_database


def test_health_endpoint_returns_status_without_secrets():
    client = app.test_client()
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert "SECRET_KEY" not in response.get_data(as_text=True)
    assert payload["environment"] in {"development", "testing", "demo", "production"}


def test_create_app_rejects_missing_production_secret(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./pqbank.db")
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app()


def test_seed_database_refuses_production_target(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./pqbank.db")
    with pytest.raises(RuntimeError, match="Refusing to seed demo data"):
        seed_database(admin_password="StrongPass123", customer_password="StrongPass123")


def test_create_app_supports_testing_defaults(monkeypatch):
    monkeypatch.setenv("APP_ENV", "testing")
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    app_instance = create_app(test_config={"TESTING": True})
    assert app_instance.config["APP_ENV"] == "testing"
    assert app_instance.config["SECRET_KEY"] == "test-secret"
    assert app_instance.config["SESSION_COOKIE_SECURE"] is False
