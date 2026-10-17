from __future__ import annotations

import uuid
import csv
import io
from decimal import Decimal

import pytest
from werkzeug.security import generate_password_hash

from app import app
from backend.config import DATABASE_URL
from backend.database.database import Base, SessionLocal, engine, is_production_database
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.aqrs_decision import AQRSDecision
from backend.models.transaction import RiskLevel, Transaction, TransactionStatus
from backend.models.user import User, UserRole
from backend.services.crypto_service import CryptoSignatureService


@pytest.fixture(autouse=True)
def reset_isolated_database():
    assert not is_production_database(DATABASE_URL), "Tests must never use pqbank.db."
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    app.config.update(TESTING=True, SECRET_KEY="module11-system-test-secret", SESSION_COOKIE_SECURE=False)


def create_user(role: UserRole = UserRole.CUSTOMER) -> tuple[str, str]:
    suffix = uuid.uuid4().hex[:12]
    email = f"module11-{suffix}@example.test"
    with SessionLocal() as db:
        user = User(
            name="Module Eleven Test User",
            username=f"module11-{suffix}",
            email=email,
            password_hash=generate_password_hash("StrongTestPass123!"),
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        return user.id, email


def login(client, email: str):
    return client.post(
        "/api/auth/login",
        json={"email": email, "password": "StrongTestPass123!"},
    )


def test_security_headers_are_set_on_success_and_error_responses():
    client = app.test_client()

    for response in (client.get("/"), client.get("/missing-module11-route")):
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert "Strict-Transport-Security" not in response.headers


def test_secure_transport_enables_secure_cookie_and_hsts():
    app.config["SESSION_COOKIE_SECURE"] = True
    _, email = create_user()
    client = app.test_client()

    response = login(client, email)
    assert response.status_code == 200
    assert "Secure" in response.headers["Set-Cookie"]

    secure_response = client.get("/", base_url="https://localhost")
    assert secure_response.headers["Strict-Transport-Security"].startswith("max-age=")


def test_authentication_cookie_is_http_only_same_site_and_logout_revokes_session():
    _, email = create_user()
    client = app.test_client()

    response = login(client, email)
    assert response.status_code == 200
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert "Secure" not in cookie
    assert client.get("/api/auth/me").status_code == 200

    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_forged_session_cookie_does_not_authenticate():
    client = app.test_client()
    client.set_cookie("session", "forged-session-value")
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert "forged-session-value" not in response.get_data(as_text=True)


def test_failed_login_throttle_counts_each_failure_once_and_ignores_forwarded_ip():
    client = app.test_client()
    identity = f"throttle-{uuid.uuid4().hex[:12]}@example.test"

    for _ in range(5):
        response = client.post(
            "/api/auth/login",
            json={"email": identity, "password": "WrongPass123!"},
            headers={"X-Forwarded-For": uuid.uuid4().hex},
        )
        assert response.status_code == 401
        assert response.get_json() == {"error": "Invalid credentials."}

    limited = client.post(
        "/api/auth/login",
        json={"email": identity, "password": "WrongPass123!"},
        headers={"X-Forwarded-For": uuid.uuid4().hex},
    )
    assert limited.status_code == 429
    assert "Too many failed login attempts" in limited.get_json()["error"]


@pytest.mark.parametrize(
    ("endpoint", "allowed_roles"),
    [
        ("/api/admin/test", {UserRole.ADMIN}),
        ("/api/admin/overview", {UserRole.ADMIN}),
        ("/api/admin/users", {UserRole.ADMIN}),
        ("/api/admin/transactions", {UserRole.ADMIN}),
        ("/api/admin/audit", {UserRole.ADMIN}),
        ("/api/security/test", {UserRole.SECURITY_ANALYST}),
        ("/api/security/overview", {UserRole.ADMIN, UserRole.SECURITY_ANALYST}),
        ("/api/security/aqrs", {UserRole.ADMIN, UserRole.SECURITY_ANALYST}),
        ("/api/security/crypto", {UserRole.ADMIN, UserRole.SECURITY_ANALYST}),
        ("/api/security/blockchain", {UserRole.ADMIN, UserRole.SECURITY_ANALYST}),
        ("/api/security/audit", {UserRole.ADMIN, UserRole.SECURITY_ANALYST}),
        ("/api/security/aqrs/decisions", {UserRole.ADMIN, UserRole.SECURITY_ANALYST}),
        ("/api/blockchain", {UserRole.ADMIN, UserRole.SECURITY_ANALYST}),
        ("/api/blockchain/validate", {UserRole.ADMIN, UserRole.SECURITY_ANALYST}),
        ("/api/research/experiments", {UserRole.ADMIN, UserRole.SECURITY_ANALYST}),
    ],
)
def test_protected_api_role_matrix(endpoint, allowed_roles):
    anonymous = app.test_client()
    assert anonymous.get(endpoint).status_code == 401

    for role in UserRole:
        _, email = create_user(role)
        client = app.test_client()
        assert login(client, email).status_code == 200
        response = client.get(endpoint)
        assert response.status_code == (200 if role in allowed_roles else 403), (endpoint, role.value)


def test_registration_research_and_password_endpoints_reject_non_object_json():
    anonymous = app.test_client()
    bad_registration = anonymous.post("/api/auth/register", json=["unexpected", "array"])
    bad_login = anonymous.post("/api/auth/login", json=["unexpected", "array"])
    assert bad_registration.status_code == 400
    assert bad_login.status_code == 400

    _, email = create_user()
    customer = app.test_client()
    assert login(customer, email).status_code == 200
    bad_password_request = customer.post("/api/auth/password", json=["unexpected"])
    assert bad_password_request.status_code == 400

    _, analyst_email = create_user(UserRole.SECURITY_ANALYST)
    analyst = app.test_client()
    assert login(analyst, analyst_email).status_code == 200
    bad_research_request = analyst.post("/api/research/experiments", json=["unexpected"])
    assert bad_research_request.status_code == 400


def test_research_endpoint_rejects_invalid_types_empty_modes_and_unknown_modes():
    _, analyst_email = create_user(UserRole.SECURITY_ANALYST)
    analyst = app.test_client()
    assert login(analyst, analyst_email).status_code == 200

    invalid_payloads = [
        {"transaction_count": 1.5},
        {"transaction_count": True},
        {"seed": True},
        {"modes": []},
        {"modes": ["UNSUPPORTED"]},
        {"modes": [None]},
    ]
    for payload in invalid_payloads:
        response = analyst.post("/api/research/experiments", json=payload)
        assert response.status_code == 400, payload


def test_research_api_persists_results_and_exports_documented_csv_columns():
    _, analyst_email = create_user(UserRole.SECURITY_ANALYST)
    analyst = app.test_client()
    assert login(analyst, analyst_email).status_code == 200

    created = analyst.post(
        "/api/research/experiments",
        json={"transaction_count": 1, "seed": 42, "modes": ["ECDSA"]},
    )
    assert created.status_code == 201
    experiment = created.get_json()["experiment"]
    assert experiment["status"] == "COMPLETED"
    assert experiment["configuration"]["seed"] == 42
    assert len(experiment["results"]) == 1
    metrics = experiment["results"][0]
    assert metrics["mode"] == "ECDSA"
    assert metrics["average_signing_time_ms"] >= 0
    assert metrics["average_verification_time_ms"] >= 0
    assert metrics["average_signature_size_bytes"] > 0
    assert metrics["throughput_tps"] > 0

    loaded = analyst.get(f"/api/research/experiments/{experiment['id']}")
    assert loaded.status_code == 200
    assert loaded.get_json()["experiment"]["id"] == experiment["id"]
    exported = analyst.get(f"/api/research/experiments/{experiment['id']}/export.csv")
    assert exported.status_code == 200
    rows = list(csv.DictReader(io.StringIO(exported.get_data(as_text=True))))
    assert list(rows[0]) == [
        "mode",
        "average_signing_time_ms",
        "average_verification_time_ms",
        "average_signature_size_bytes",
        "throughput_tps",
        "blockchain_size_bytes",
        "aqrs_score",
    ]
    assert rows[0]["mode"] == "ECDSA"
    assert "private_key" not in exported.get_data(as_text=True).lower()


def test_malformed_signature_is_reported_safely_by_verify_api():
    user_id, email = create_user()
    with SessionLocal() as db:
        sender = Account(
            user_id=user_id,
            account_number=f"VERIFY-S-{uuid.uuid4().hex[:8]}",
            account_type=AccountType.SAVINGS,
            balance=Decimal("100.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        receiver = Account(
            user_id=user_id,
            account_number=f"VERIFY-R-{uuid.uuid4().hex[:8]}",
            account_type=AccountType.CURRENT,
            balance=Decimal("0.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add_all([sender, receiver])
        db.flush()
        transaction = Transaction(
            transaction_id=f"TX-VERIFY-{uuid.uuid4().hex[:10]}",
            sender_account_id=sender.id,
            receiver_account_id=receiver.id,
            amount=Decimal("10.00"),
            currency="INR",
            status=TransactionStatus.COMPLETED,
            risk_level=RiskLevel.LOW,
            aqrs_level=2,
            cryptographic_mode="ML-DSA-44",
        )
        db.add(transaction)
        db.flush()
        db.add(AQRSDecision(
            transaction_id=transaction.id,
            risk_score=Decimal("0.00"),
            risk_level=RiskLevel.LOW,
            selected_security_level=2,
            algorithm="ML-DSA-44",
            security_level="ML-DSA-44",
            decision_reason="LOW-risk verification regression.",
            aqrs_score=Decimal("0.0146"),
        ))
        db.flush()
        CryptoSignatureService.sign_transaction(db, transaction.id)
        signature = transaction.signature
        signature.signature_hex = "not-valid-hex-contains-private-detail"
        db.commit()
        transaction_id = transaction.transaction_id

    client = app.test_client()
    assert login(client, email).status_code == 200
    response = client.get(f"/api/transactions/{transaction_id}/verify")
    assert response.status_code == 409
    assert response.get_json() == {
        "error": "Transaction signature verification could not be completed."
    }
    assert "not-valid-hex" not in response.get_data(as_text=True)


def test_transfer_service_rejects_subcent_amount_without_rounding():
    from backend.services.transaction_service import TransactionService, ValidationError

    with pytest.raises(ValidationError, match="at most two decimal places"):
        TransactionService.parse_amount("0.001")
    with pytest.raises(ValidationError, match="at most two decimal places"):
        TransactionService.parse_amount("25.239")
    assert TransactionService.parse_amount("25.23") == Decimal("25.23")


@pytest.mark.parametrize("amount", ["0", "-0.01", "hello", "NaN", "Infinity", "1000000000001", None])
def test_transfer_service_rejects_invalid_amounts(amount):
    from backend.services.transaction_service import TransactionService, ValidationError

    with pytest.raises(ValidationError):
        TransactionService.parse_amount(amount)


def test_transfer_service_rejects_cross_currency_accounts():
    from backend.services.transaction_service import TransactionService, ValidationError

    _, user_id = create_user()
    with SessionLocal() as db:
        sender = Account(
            user_id=user_id,
            account_number=f"CUR-S-{uuid.uuid4().hex[:8]}",
            account_type=AccountType.SAVINGS,
            balance=Decimal("100.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        receiver = Account(
            user_id=user_id,
            account_number=f"CUR-R-{uuid.uuid4().hex[:8]}",
            account_type=AccountType.CURRENT,
            balance=Decimal("100.00"),
            currency="USD",
            status=AccountStatus.ACTIVE,
        )
        db.add_all([sender, receiver])
        db.commit()
        with pytest.raises(ValidationError, match="same currency"):
            TransactionService.apply_transfer_balances(
                db,
                sender=sender,
                receiver=receiver,
                amount=Decimal("10.00"),
            )
        db.rollback()
        db.refresh(sender)
        db.refresh(receiver)
        assert sender.balance == Decimal("100.00")
        assert receiver.balance == Decimal("100.00")


def test_conditional_debit_prevents_two_stale_sessions_spending_the_same_funds():
    from backend.services.transaction_service import InsufficientBalanceError, TransactionService

    _, user_id = create_user()
    with SessionLocal() as db:
        sender = Account(
            user_id=user_id,
            account_number=f"RACE-S-{uuid.uuid4().hex[:8]}",
            account_type=AccountType.SAVINGS,
            balance=Decimal("100.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        receiver = Account(
            user_id=user_id,
            account_number=f"RACE-R-{uuid.uuid4().hex[:8]}",
            account_type=AccountType.CURRENT,
            balance=Decimal("0.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add_all([sender, receiver])
        db.commit()
        sender_id, receiver_id = sender.id, receiver.id

    with SessionLocal() as first, SessionLocal() as second:
        sender_one, receiver_one = first.get(Account, sender_id), first.get(Account, receiver_id)
        sender_two, receiver_two = second.get(Account, sender_id), second.get(Account, receiver_id)
        TransactionService.apply_transfer_balances(
            first, sender=sender_one, receiver=receiver_one, amount=Decimal("80.00")
        )
        first.commit()

        with pytest.raises(InsufficientBalanceError, match="Insufficient balance"):
            TransactionService.apply_transfer_balances(
                second, sender=sender_two, receiver=receiver_two, amount=Decimal("80.00")
            )
        second.rollback()

    with SessionLocal() as db:
        assert db.get(Account, sender_id).balance == Decimal("20.00")
        assert db.get(Account, receiver_id).balance == Decimal("80.00")


def test_transfer_internal_failure_is_safe_and_rolls_back_everything(monkeypatch):
    from app import AQRSDecisionService

    _, email = create_user()
    with SessionLocal() as db:
        user = db.query(User).filter_by(email=email).one()
        sender = Account(
            user_id=user.id,
            account_number=f"FAIL-S-{uuid.uuid4().hex[:8]}",
            account_type=AccountType.SAVINGS,
            balance=Decimal("100.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        receiver = Account(
            user_id=user.id,
            account_number=f"FAIL-R-{uuid.uuid4().hex[:8]}",
            account_type=AccountType.CURRENT,
            balance=Decimal("20.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add_all([sender, receiver])
        db.commit()
        sender_id, receiver_number = sender.id, receiver.account_number

    def fail_decision(_transaction):
        raise RuntimeError("synthetic internal detail that must not reach the client")

    monkeypatch.setattr(AQRSDecisionService, "evaluate_transaction", staticmethod(fail_decision))
    client = app.test_client()
    assert login(client, email).status_code == 200
    response = client.post(
        "/api/transactions",
        json={
            "sender_account_id": sender_id,
            "receiver_account_number": receiver_number,
            "amount": "25.00",
        },
    )

    assert response.status_code == 500
    assert response.get_json() == {"error": "Transfer could not be completed."}
    assert "synthetic internal detail" not in response.get_data(as_text=True)
    with SessionLocal() as db:
        assert db.get(Account, sender_id).balance == Decimal("100.00")
        recipient = db.query(Account).filter_by(account_number=receiver_number).one()
        assert recipient.balance == Decimal("20.00")
        assert db.query(Transaction).count() == 0


def test_transfer_rejects_malformed_json_and_invalid_descriptions():
    user_id, email = create_user()
    with SessionLocal() as db:
        sender = Account(
            user_id=user_id,
            account_number=f"BODY-S-{uuid.uuid4().hex[:8]}",
            account_type=AccountType.SAVINGS,
            balance=Decimal("100.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        recipient = Account(
            user_id=user_id,
            account_number=f"BODY-R-{uuid.uuid4().hex[:8]}",
            account_type=AccountType.CURRENT,
            balance=Decimal("10.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add_all([sender, recipient])
        db.commit()
        sender_id, recipient_number = sender.id, recipient.account_number

    client = app.test_client()
    assert login(client, email).status_code == 200

    malformed = client.post("/api/transactions", data="{", content_type="application/json")
    invalid_type = client.post(
        "/api/transactions",
        json={
            "sender_account_id": sender_id,
            "receiver_account_number": recipient_number,
            "amount": "10.00",
            "description": ["not", "text"],
        },
    )
    oversized = client.post(
        "/api/transactions",
        json={
            "sender_account_id": sender_id,
            "receiver_account_number": recipient_number,
            "amount": "10.00",
            "description": "x" * 256,
        },
    )

    assert malformed.status_code == 400
    assert invalid_type.status_code == 400
    assert oversized.status_code == 400
    with SessionLocal() as db:
        assert db.get(Account, sender_id).balance == Decimal("100.00")
        assert db.query(Transaction).count() == 0
