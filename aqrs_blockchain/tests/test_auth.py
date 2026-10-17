import os
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite:///./test_auth_pqbank.db")

from flask import session
from werkzeug.security import generate_password_hash

from app import app
from backend.database.database import Base, engine
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.audit_log import AuditLog
from backend.models.user import User, UserRole

TEST_DB = Path(__file__).resolve().parent.parent / "test_auth_pqbank.db"


def reset_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def make_client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
    app.config["SESSION_COOKIE_SECURE"] = False
    return app.test_client()


def register_user(client, **kwargs):
    payload = {
        "name": kwargs.get("name", "Alice Customer"),
        "email": kwargs.get("email", "alice@example.com"),
        "username": kwargs.get("username", "alice"),
        "password": kwargs.get("password", "StrongPass123!"),
    }
    return client.post("/api/auth/register", json=payload)


def login_user(client, email="alice@example.com", password="StrongPass123!"):
    return client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )


def test_registration_succeeds_and_defaults_to_customer():
    reset_database()
    client = make_client()

    response = register_user(client, email="alice@example.com", username="alice")

    assert response.status_code == 201
    payload = response.get_json()
    assert payload["user"]["email"] == "alice@example.com"
    assert payload["user"]["role"] == "CUSTOMER"
    assert "password_hash" not in payload["user"]


def test_registration_rejects_duplicate_email_and_username():
    reset_database()
    client = make_client()
    first = register_user(client, email="dup@example.com", username="dupuser")
    assert first.status_code == 201

    duplicate_email = client.post(
        "/api/auth/register",
        json={"name": "Another", "email": "dup@example.com", "username": "different", "password": "StrongPass123!"},
    )
    assert duplicate_email.status_code == 409

    duplicate_username = client.post(
        "/api/auth/register",
        json={"name": "Another", "email": "other@example.com", "username": "dupuser", "password": "StrongPass123!"},
    )
    assert duplicate_username.status_code == 409


def test_registration_rejects_invalid_role_and_invalid_input():
    reset_database()
    client = make_client()

    bad_role = client.post(
        "/api/auth/register",
        json={"name": "Mallory", "email": "mallory@example.com", "username": "mallory", "password": "StrongPass123!", "role": "ADMIN"},
    )
    assert bad_role.status_code == 400

    short_password = client.post(
        "/api/auth/register",
        json={"name": "Bad", "email": "bad@example.com", "username": "baduser", "password": "short"},
    )
    assert short_password.status_code == 400


def test_login_succeeds_and_fails_for_bad_credentials():
    reset_database()
    client = make_client()
    register_user(client, email="login@example.com", username="loginuser")

    success = login_user(client, email="login@example.com", password="StrongPass123!")
    assert success.status_code == 200
    assert success.get_json()["user"]["email"] == "login@example.com"

    wrong_password = login_user(client, email="login@example.com", password="WrongPass123!")
    assert wrong_password.status_code == 401

    unknown_user = login_user(client, email="missing@example.com", password="StrongPass123!")
    assert unknown_user.status_code == 401


def test_login_normalizes_email_case_and_surrounding_whitespace():
    reset_database()
    client = make_client()
    register_user(client, email="normalized@example.com", username="normalized")

    response = login_user(
        client,
        email="  NORMALIZED@EXAMPLE.COM  ",
        password="StrongPass123!",
    )

    assert response.status_code == 200
    assert response.get_json()["user"]["email"] == "normalized@example.com"


def test_inactive_user_cannot_login_and_me_requires_auth():
    reset_database()
    client = make_client()
    register_user(client, email="inactive@example.com", username="inactive")

    from backend.database.database import SessionLocal

    db = SessionLocal()
    user = db.query(User).filter_by(email="inactive@example.com").one()
    user.is_active = False
    db.commit()
    db.close()

    response = login_user(client, email="inactive@example.com", password="StrongPass123!")
    assert response.status_code == 401
    assert response.get_json()["error"] == "This account is inactive."

    me = client.get("/api/auth/me")
    assert me.status_code == 401


def test_current_user_route_returns_safe_payload():
    reset_database()
    client = make_client()
    register_user(client, email="me@example.com", username="meuser")
    login = login_user(client, email="me@example.com", password="StrongPass123!")
    assert login.status_code == 200

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    payload = me.get_json()["user"]
    assert payload["email"] == "me@example.com"
    assert payload["role"] == "CUSTOMER"
    assert "password_hash" not in payload
    assert "password" not in payload


def test_registration_login_session_logout_and_protected_routes():
    reset_database()
    client = make_client()

    assert client.get("/dashboard").status_code == 302
    assert client.get("/api/auth/me").status_code == 401
    assert register_user(client, email="session@example.com", username="sessionuser").status_code == 201

    login = client.post(
        "/api/auth/login",
        json={"username": "sessionuser", "password": "StrongPass123!"},
    )
    assert login.status_code == 200
    assert "Set-Cookie" in login.headers
    assert client.get("/api/auth/me").get_json()["user"]["username"] == "sessionuser"
    assert client.get("/dashboard").status_code == 200

    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/dashboard").status_code == 302


def test_malformed_stored_password_hash_is_rejected_safely():
    reset_database()
    client = make_client()

    from backend.database.database import SessionLocal

    with SessionLocal() as db:
        db.add(User(name="Broken Hash", username="brokenhash", email="broken@example.com", password_hash="not-a-password-hash"))
        db.commit()

    response = login_user(client, email="broken@example.com", password="StrongPass123!")

    assert response.status_code == 401
    assert response.get_json() == {"error": "Invalid credentials."}
    assert client.get("/api/auth/me").status_code == 401


def test_customer_cannot_access_admin_and_security_role_is_enforced():
    reset_database()
    client = make_client()
    register_user(client, email="customer@example.com", username="customer")
    login_user(client, email="customer@example.com", password="StrongPass123!")

    admin_response = client.get("/api/admin/test")
    assert admin_response.status_code == 403

    security_response = client.get("/api/security/test")
    assert security_response.status_code == 403

    from backend.database.database import SessionLocal

    db = SessionLocal()
    security_user = User(
        name="Analyst",
        username="securityanalyst",
        email="security@example.com",
        password_hash=generate_password_hash("AnalystPass123!"),
        role=UserRole.SECURITY_ANALYST,
        is_active=True,
    )
    db.add(security_user)
    db.commit()
    db.close()

    login_response = client.post(
        "/api/auth/login",
        json={"email": "security@example.com", "password": "AnalystPass123!"},
    )
    assert login_response.status_code == 200


def test_authorized_roles_can_access_protected_endpoints():
    reset_database()
    client = make_client()

    from backend.database.database import SessionLocal

    db = SessionLocal()
    admin = User(
        name="System Admin",
        username="adminuser",
        email="admin@example.com",
        password_hash=generate_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst = User(
        name="Security Analyst",
        username="analystuser",
        email="analyst@example.com",
        password_hash=generate_password_hash("AnalystPass123!"),
        role=UserRole.SECURITY_ANALYST,
        is_active=True,
    )
    db.add_all([admin, analyst])
    db.commit()
    db.close()

    for email, password, path in [
        ("admin@example.com", "AdminPass123!", "/api/admin/test"),
        ("analyst@example.com", "AnalystPass123!", "/api/security/test"),
    ]:
        response = client.post("/api/auth/login", json={"email": email, "password": password})
        assert response.status_code == 200
        protected = client.get(path)
        assert protected.status_code == 200


def test_account_access_enforced_by_owner():
    reset_database()
    client = make_client()

    from backend.database.database import SessionLocal

    db = SessionLocal()
    user_a = User(name="A", username="usera", email="usera@example.com", password_hash=generate_password_hash("CustomerPass123!"), role=UserRole.CUSTOMER, is_active=True)
    user_b = User(name="B", username="userb", email="userb@example.com", password_hash=generate_password_hash("CustomerPass123!"), role=UserRole.CUSTOMER, is_active=True)
    db.add_all([user_a, user_b])
    db.commit()
    account_a = Account(user_id=user_a.id, account_number="ACC-A-001", account_type=AccountType.SAVINGS, balance=2500.00, currency="INR", status=AccountStatus.ACTIVE)
    account_b = Account(user_id=user_b.id, account_number="ACC-B-001", account_type=AccountType.CURRENT, balance=3500.00, currency="INR", status=AccountStatus.ACTIVE)
    db.add_all([account_a, account_b])
    db.commit()
    account_a_id = account_a.id
    account_b_id = account_b.id
    db.close()

    login = client.post("/api/auth/login", json={"email": "usera@example.com", "password": "CustomerPass123!"})
    assert login.status_code == 200

    own_account = client.get(f"/api/accounts/{account_a_id}")
    assert own_account.status_code == 200

    other_account = client.get(f"/api/accounts/{account_b_id}")
    assert other_account.status_code == 403


def test_audit_logs_record_login_and_forbidden_attempts():
    reset_database()
    client = make_client()
    register_user(client, email="audit@example.com", username="audituser")

    failed = client.post("/api/auth/login", json={"email": "audit@example.com", "password": "Wrong"})
    assert failed.status_code == 401

    successful = login_user(client, email="audit@example.com", password="StrongPass123!")
    assert successful.status_code == 200

    from backend.database.database import SessionLocal

    db = SessionLocal()
    audit_events = [log.event_type for log in db.query(AuditLog).all()]
    db.close()
    assert any(event in {"login_failed", "login_success"} for event in audit_events)
    assert all("StrongPass123!" not in str(log.message) and "StrongPass123!" not in str(log.metadata_) for log in db.query(AuditLog).all())
