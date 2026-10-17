from __future__ import annotations

import os

import pytest
from sqlalchemy import inspect, text
from werkzeug.security import check_password_hash, generate_password_hash

os.environ.setdefault("DATABASE_URL", os.environ.get("TEST_DATABASE_URL", "sqlite:///./test_module11_pqbank.db"))

import app as app_module
import backend.database.database as database_module
from app import app
from backend.database.database import Base, DatabaseManager, SessionLocal, engine
from backend.models.audit_log import AuditLog
from backend.models.user import User, UserRole


def reset_database() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def make_client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "module11-test-secret"
    app.config["SESSION_COOKIE_SECURE"] = False
    return app.test_client()


def create_user(role: UserRole = UserRole.CUSTOMER) -> User:
    with SessionLocal() as db:
        user = User(
            name="Module Eleven User",
            username=f"module11-{role.value.lower()}",
            email=f"module11-{role.value.lower()}@example.com",
            password_hash=generate_password_hash("CurrentPass123!"),
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def login(client, user: User, password: str = "CurrentPass123!"):
    return client.post("/api/auth/login", json={"email": user.email, "password": password})


def test_password_security_page_and_api_require_authentication():
    reset_database()
    client = make_client()

    assert client.get("/account/security").status_code == 302
    assert client.post("/api/auth/password", json={}).status_code == 401


@pytest.mark.parametrize("role", list(UserRole))
def test_password_change_revokes_sessions_and_persists_for_every_role(role):
    reset_database()
    user = create_user(role)
    client = make_client()
    other_session = make_client()
    assert login(client, user).status_code == 200
    assert login(other_session, user).status_code == 200
    assert client.get("/account/security").status_code == 200

    response = client.post(
        "/api/auth/password",
        json={
            "current_password": "CurrentPass123!",
            "new_password": "UpdatedPass456!",
            "confirm_password": "UpdatedPass456!",
        },
    )

    assert response.status_code == 200
    assert client.get("/api/auth/me").status_code == 401
    assert other_session.get("/api/auth/me").status_code == 401
    assert login(client, user).status_code == 401
    new_login = login(client, user, "UpdatedPass456!")
    assert new_login.status_code == 200
    assert new_login.get_json()["user"]["role"] == role.value

    with SessionLocal() as db:
        stored_user = db.get(User, user.id)
        assert check_password_hash(stored_user.password_hash, "UpdatedPass456!")
        assert stored_user.password_hash != "UpdatedPass456!"
        assert stored_user.auth_version == 1
        event = db.query(AuditLog).filter_by(event_type="password_changed", user_id=user.id).one()
        assert "UpdatedPass456!" not in str(event.metadata_)


def test_password_change_rejects_invalid_inputs_and_audits_failures():
    reset_database()
    user = create_user()
    client = make_client()
    assert login(client, user).status_code == 200

    wrong_current = client.post("/api/auth/password", json={
        "current_password": "WrongPass123!", "new_password": "UpdatedPass456!", "confirm_password": "UpdatedPass456!",
    })
    weak_password = client.post("/api/auth/password", json={
        "current_password": "CurrentPass123!", "new_password": "weak", "confirm_password": "weak",
    })
    mismatched = client.post("/api/auth/password", json={
        "current_password": "CurrentPass123!", "new_password": "UpdatedPass456!", "confirm_password": "DifferentPass456!",
    })
    unchanged = client.post("/api/auth/password", json={
        "current_password": "CurrentPass123!", "new_password": "CurrentPass123!", "confirm_password": "CurrentPass123!",
    })
    missing_fields = client.post("/api/auth/password", json={"current_password": "CurrentPass123!"})

    assert wrong_current.status_code == 401
    assert wrong_current.get_json()["error"] == "Current password is incorrect."
    assert weak_password.status_code == 400
    assert mismatched.status_code == 400
    assert unchanged.status_code == 400
    assert missing_fields.status_code == 400
    assert client.get("/api/auth/me").status_code == 200

    with SessionLocal() as db:
        stored_user = db.get(User, user.id)
        assert check_password_hash(stored_user.password_hash, "CurrentPass123!")
        events = db.query(AuditLog).filter_by(event_type="password_change_failed", user_id=user.id).all()
        assert len(events) == 5
        assert "CurrentPass123!" not in str([event.metadata_ for event in events])


def test_password_change_rolls_back_on_unexpected_service_failure(monkeypatch):
    reset_database()
    user = create_user()
    client = make_client()
    assert login(client, user).status_code == 200

    def fail_after_mutation(db, stored_user, current_password, new_password):
        stored_user.password_hash = generate_password_hash("UncommittedPass789!")
        raise RuntimeError("simulated persistence failure")

    monkeypatch.setattr(app_module, "change_password", fail_after_mutation)
    response = client.post("/api/auth/password", json={
        "current_password": "CurrentPass123!", "new_password": "UpdatedPass456!", "confirm_password": "UpdatedPass456!",
    })

    assert response.status_code == 500
    assert response.get_json() == {"error": "Password change could not be completed."}
    assert client.get("/api/auth/me").status_code == 200
    with SessionLocal() as db:
        stored_user = db.get(User, user.id)
        assert check_password_hash(stored_user.password_hash, "CurrentPass123!")
        assert db.query(AuditLog).filter_by(event_type="password_change_failed", user_id=user.id).count() == 1


def test_existing_user_schema_gets_auth_version_without_losing_rows(monkeypatch):
    manager = DatabaseManager("sqlite:///:memory:")
    with manager.engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, username VARCHAR(80) NOT NULL, "
            "email VARCHAR(120) NOT NULL, password_hash VARCHAR(255) NOT NULL, role VARCHAR(30) NOT NULL, "
            "is_active BOOLEAN NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)"
        ))
        connection.execute(text(
            "INSERT INTO users (id, username, email, password_hash, role, is_active, created_at, updated_at) "
            "VALUES ('legacy-id', 'legacy-user', 'legacy@example.com', 'hash', 'CUSTOMER', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        ))

    monkeypatch.setattr(database_module, "engine", manager.engine)
    database_module._migrate_existing_sqlite_schema()

    columns = {column["name"] for column in inspect(manager.engine).get_columns("users")}
    with manager.engine.connect() as connection:
        version = connection.execute(text("SELECT auth_version FROM users WHERE id = 'legacy-id'")).scalar_one()
    assert "auth_version" in columns
    assert version == 0
    manager.engine.dispose()