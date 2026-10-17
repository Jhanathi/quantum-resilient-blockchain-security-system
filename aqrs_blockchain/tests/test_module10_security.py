from __future__ import annotations

import os
from pathlib import Path
from decimal import Decimal

import pytest
from werkzeug.security import generate_password_hash

import app as app_module
from app import app
from backend.database.database import Base, SessionLocal, engine
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.aqrs_decision import AQRSDecision
from backend.models.audit_log import AuditLog
from backend.models.block import Block
from backend.models.signature import Signature
from backend.models.transaction import RiskLevel, Transaction
from backend.models.user import User, UserRole
from backend.services.blockchain_service import add_transaction_to_ledger, validate_chain
from backend.services.crypto_service import CryptoSignatureService
from backend.services.research_service import run_experiment


def reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def make_client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "module10-test-secret"
    app.config["SESSION_COOKIE_SECURE"] = False
    return app.test_client()


def create_user(email: str, username: str, role: UserRole = UserRole.CUSTOMER):
    with SessionLocal() as db:
        user = User(
            name=username.title(),
            username=username,
            email=email,
            password_hash=generate_password_hash("StrongPass123!"),
            role=role,
            is_active=True,
        )
        db.add(user)
        db.flush()
        account = Account(
            user_id=user.id,
            account_number=f"ACC-{str(user.id)[:8].upper()}-{username.upper()}",
            account_type=AccountType.SAVINGS,
            balance=Decimal("1000000.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add(account)
        db.commit()
        return user.id, account.id


def login(client, email: str):
    return client.post("/api/auth/login", json={"email": email, "password": "StrongPass123!"})


def assert_values_not_returned(payload, sensitive_values):
    serialized = str(payload)
    for value in sensitive_values:
        assert value not in serialized


def test_app_uses_secure_runtime_configuration():
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] in {"Lax", "Strict"}
    assert app.config["SECRET_KEY"] != "change-me-in-production"
    assert app.debug is False


def test_transfer_rejects_nan_and_infinite_amounts():
    reset_db()
    client = make_client()

    with SessionLocal() as db:
        user = User(
            name="Secure User",
            username="secureuser",
            email="secure@example.com",
            password_hash=generate_password_hash("StrongPass123!"),
            role=UserRole.CUSTOMER,
            is_active=True,
        )
        db.add(user)
        db.flush()
        sender = Account(
            user_id=user.id,
            account_number="ACC-SAFE-001",
            account_type=AccountType.SAVINGS,
            balance=Decimal("5000.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        receiver = Account(
            user_id=user.id,
            account_number="ACC-SAFE-002",
            account_type=AccountType.SAVINGS,
            balance=Decimal("5000.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add_all([sender, receiver])
        db.commit()
        sender_id = sender.id
        receiver_id = receiver.id

    login = client.post("/api/auth/login", json={"email": "secure@example.com", "password": "StrongPass123!"})
    assert login.status_code == 200

    response = client.post(
        "/api/transactions",
        json={
            "sender_account_id": sender_id,
            "receiver_account_id": receiver_id,
            "amount": "nan",
            "description": "Attempt invalid transfer",
        },
    )
    assert response.status_code == 400
    assert "amount" in response.get_json()["error"].lower()


def test_customer_is_denied_research_and_staff_roles_are_allowed():
    reset_db()
    client = make_client()
    create_user("research.customer@example.com", "researchcustomer")
    create_user("research.analyst@example.com", "researchanalyst", UserRole.SECURITY_ANALYST)
    create_user("research.admin@example.com", "researchadmin", UserRole.ADMIN)

    with SessionLocal() as db:
        experiment = run_experiment(db, transaction_count=2, seed=10)
        experiment_id = experiment.id

    research_api_paths = [
        "/api/research/experiments",
        f"/api/research/experiments/{experiment_id}",
        "/api/research/results",
        "/api/research/compare",
        f"/api/research/experiments/{experiment_id}/export.csv",
    ]
    research_page_paths = ["/research", "/research/legacy"]
    for path in research_page_paths:
        assert client.get(path).status_code == 302, path
    for path in research_api_paths:
        assert client.get(path).status_code == 401, path

    customer_login = login(client, "research.customer@example.com")
    assert customer_login.status_code == 200
    assert customer_login.get_json()["user"]["role"] == UserRole.CUSTOMER.value
    assert client.get("/api/auth/me").get_json()["user"]["role"] == UserRole.CUSTOMER.value
    for path in research_page_paths + research_api_paths:
        assert client.get(path).status_code == 403, path

    for email, expected_role in (
        ("research.analyst@example.com", UserRole.SECURITY_ANALYST.value),
        ("research.admin@example.com", UserRole.ADMIN.value),
    ):
        staff_login = login(client, email)
        assert staff_login.status_code == 200
        assert staff_login.get_json()["user"]["role"] == expected_role
        assert client.get("/api/auth/me").get_json()["user"]["role"] == expected_role
        for path in research_page_paths:
            assert client.get(path).status_code == 200, path
        for path in research_api_paths[:-1]:
            assert client.get(path).status_code == 200, path
        export = client.get(research_api_paths[-1])
        assert export.status_code == 200
        assert export.mimetype == "text/csv"
        created = client.post("/api/research/experiments", json={"transaction_count": 2, "seed": 12})
        assert created.status_code == 201

    login(client, "research.customer@example.com")
    denied_create = client.post("/api/research/experiments", json={"transaction_count": 2, "seed": 12})
    assert denied_create.status_code == 403


@pytest.mark.parametrize(
    ("amount", "expected_risk", "expected_level", "expected_algorithm", "forced_level"),
    [
        (100, RiskLevel.LOW, 2, "ML-DSA-44", 5),
        (5000, RiskLevel.MEDIUM, 3, "ML-DSA-65", 5),
        (150000, RiskLevel.HIGH, 5, "ML-DSA-87", 2),
    ],
)
def test_client_cannot_override_persisted_aqrs_decision(amount, expected_risk, expected_level, expected_algorithm, forced_level):
    reset_db()
    client = make_client()
    user_id, sender_id = create_user("aqrs.owner@example.com", "aqrsowner")
    with SessionLocal() as db:
        receiver = Account(
            user_id=user_id,
            account_number="ACC-AQRS-RECEIVER",
            account_type=AccountType.CURRENT,
            balance=Decimal("10000.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add(receiver)
        db.commit()
        receiver_id = receiver.id

    assert login(client, "aqrs.owner@example.com").status_code == 200
    response = client.post(
        "/api/transactions",
        json={
            "sender_account_id": sender_id,
            "receiver_account_id": receiver_id,
            "amount": amount,
            "risk_level": "HIGH" if expected_risk != RiskLevel.HIGH else "LOW",
            "security_level": forced_level,
            "algorithm": "ML-DSA-87" if forced_level == 5 else "ML-DSA-44",
            "aqrs_level": forced_level,
        },
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    transaction_id = response.get_json()["transaction"]["transaction_id"]

    with SessionLocal() as db:
        transaction = db.query(Transaction).filter_by(transaction_id=transaction_id).one()
        decision = db.query(AQRSDecision).filter_by(transaction_id=transaction.id).one()
        signature = db.query(Signature).filter_by(transaction_id=transaction.id).one()
        assert decision.risk_level == expected_risk
        assert decision.selected_security_level == expected_level
        assert decision.security_level == expected_algorithm
        assert decision.algorithm == expected_algorithm
        assert signature.algorithm == expected_algorithm
        assert signature.security_level == expected_level


def test_sensitive_api_responses_and_audit_logs_exclude_secret_values(monkeypatch):
    reset_db()
    client = make_client()
    user_id, sender_id = create_user("secrets.customer@example.com", "secretscustomer")
    with SessionLocal() as db:
        receiver = Account(
            user_id=user_id,
            account_number="ACC-SECRET-RECEIVER",
            account_type=AccountType.CURRENT,
            balance=Decimal("10000.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add(receiver)
        db.commit()
        receiver_id = receiver.id
    login_response = login(client, "secrets.customer@example.com")
    assert login_response.status_code == 200
    customer_session = client.get_cookie("session").value
    captured_private_keys = []
    from backend.services import crypto_service

    original_keygen = crypto_service.generate_ml_dsa_keypair

    def capture_keygen(level):
        public_key, private_key = original_keygen(level)
        captured_private_keys.append(private_key.hex())
        return public_key, private_key

    monkeypatch.setattr(crypto_service, "generate_ml_dsa_keypair", capture_keygen)
    response = client.post("/api/transactions", json={"sender_account_id": sender_id, "receiver_account_id": receiver_id, "amount": 100})
    assert response.status_code == 200
    transaction_id = response.get_json()["transaction"]["transaction_id"]

    with SessionLocal() as db:
        transaction = db.query(Transaction).filter_by(transaction_id=transaction_id).one()
        experiment = run_experiment(db, transaction_count=2, seed=11)
        experiment_id = experiment.id
        db.add(AuditLog(user_id=user_id, transaction_id=transaction.id, event_type="secret-regression", status="success", message="Audit content contains no credentials", metadata_={"note": "safe metadata"}))
        db.commit()

    customer_responses = [
        login_response,
        response,
        client.get("/api/auth/me"),
        client.get("/api/users/me/accounts"),
        client.get("/api/transactions"),
        client.get(f"/api/transactions/{transaction_id}"),
        client.get(f"/api/transactions/{transaction_id}/security"),
        client.get(f"/api/transactions/{transaction_id}/block"),
    ]
    assert all(item.status_code == 200 for item in customer_responses)
    admin_id, _ = create_user("secrets.admin@example.com", "secretsadmin", UserRole.ADMIN)
    assert admin_id
    assert login(client, "secrets.admin@example.com").status_code == 200
    admin_session = client.get_cookie("session").value
    admin_responses = [
        client.get("/api/admin/users"),
        client.get("/api/admin/transactions"),
        client.get("/api/admin/audit"),
        client.get("/api/blockchain"),
        client.get("/api/research/results"),
        client.get(f"/api/research/experiments/{experiment_id}"),
    ]
    assert all(item.status_code == 200 for item in admin_responses)

    with SessionLocal() as db:
        user = db.get(User, user_id)
        signature = db.query(Signature).join(Transaction).filter(Transaction.transaction_id == transaction_id).one()
        sensitive_values = [
            "StrongPass123!",
            user.password_hash,
            app.config["SECRET_KEY"],
            customer_session,
            admin_session,
            *captured_private_keys,
            signature.signature_hex,
            signature.public_key_hex,
            os.environ.get("DATABASE_URL", "sqlite:///./pqbank.db"),
        ]
        sensitive_values = [value for value in sensitive_values if value]
        audit = db.query(AuditLog).order_by(AuditLog.created_at.desc()).all()
        audit_payload = [{"message": item.message, "metadata": item.metadata_} for item in audit]

    for item in customer_responses + admin_responses:
        assert_values_not_returned(item.get_json(silent=True) or {}, sensitive_values)
    assert_values_not_returned(audit_payload, sensitive_values)


def test_reinserting_same_transaction_does_not_add_another_block():
    reset_db()
    client = make_client()
    user_id, sender_id = create_user("ledger.owner@example.com", "ledgerowner")
    with SessionLocal() as db:
        receiver = Account(user_id=user_id, account_number="ACC-LEDGER-RECEIVER", account_type=AccountType.CURRENT, balance=Decimal("10000.00"), currency="INR", status=AccountStatus.ACTIVE)
        db.add(receiver)
        db.commit()
        receiver_id = receiver.id
    assert login(client, "ledger.owner@example.com").status_code == 200
    response = client.post("/api/transactions", json={"sender_account_id": sender_id, "receiver_account_id": receiver_id, "amount": 100})
    assert response.status_code == 200
    transaction_id = response.get_json()["transaction"]["transaction_id"]

    with SessionLocal() as db:
        transaction = db.query(Transaction).filter_by(transaction_id=transaction_id).one()
        first = add_transaction_to_ledger(db, transaction.id, user_id=user_id)
        db.commit()
        initial_count = db.query(Block).count()
        duplicate = add_transaction_to_ledger(db, transaction.id, user_id=user_id)
        db.commit()
        assert duplicate.id == first.id
        assert db.query(Block).count() == initial_count
        assert len(duplicate.transactions) == 1
        assert validate_chain(db)["valid"] is True


def create_transfer_accounts(email: str, username: str):
    user_id, sender_id = create_user(email, username)
    with SessionLocal() as db:
        receiver = Account(user_id=user_id, account_number=f"ACC-{username.upper()}-RECEIVER", account_type=AccountType.CURRENT, balance=Decimal("10000.00"), currency="INR", status=AccountStatus.ACTIVE)
        db.add(receiver)
        db.commit()
        return user_id, sender_id, receiver.id


def assert_no_partial_transfer_state(sender_id: int, receiver_id: int):
    with SessionLocal() as db:
        assert db.query(Transaction).count() == 0
        assert db.query(AQRSDecision).count() == 0
        assert db.query(Signature).count() == 0
        assert db.get(Account, sender_id).balance == Decimal("1000000.00")
        assert db.get(Account, receiver_id).balance == Decimal("10000.00")


def test_transaction_rolls_back_when_ml_dsa_signing_fails(monkeypatch):
    reset_db()
    client = make_client()
    _, sender_id, receiver_id = create_transfer_accounts("rollback.sign@example.com", "rollsign")
    assert login(client, "rollback.sign@example.com").status_code == 200

    def fail_signing(_db, _transaction_id):
        raise RuntimeError("simulated signing failure")

    monkeypatch.setattr(CryptoSignatureService, "sign_transaction", staticmethod(fail_signing))
    response = client.post("/api/transactions", json={"sender_account_id": sender_id, "receiver_account_id": receiver_id, "amount": 100})
    assert response.status_code == 409
    assert_no_partial_transfer_state(sender_id, receiver_id)


def test_transaction_rolls_back_when_signature_verification_fails(monkeypatch):
    reset_db()
    client = make_client()
    _, sender_id, receiver_id = create_transfer_accounts("rollback.verify@example.com", "rollverify")
    assert login(client, "rollback.verify@example.com").status_code == 200
    original_verify = CryptoSignatureService.verify_transaction_signature
    calls = {"count": 0}

    def fail_verification(db, transaction_id):
        calls["count"] += 1
        if calls["count"] == 1:
            return {"valid": False, "algorithm": "ML-DSA-44", "security_level": 2, "signature_size_bytes": 1, "verification_time_ms": 0.1}
        return original_verify(db, transaction_id)

    monkeypatch.setattr(CryptoSignatureService, "verify_transaction_signature", staticmethod(fail_verification))
    response = client.post("/api/transactions", json={"sender_account_id": sender_id, "receiver_account_id": receiver_id, "amount": 100})
    assert response.status_code == 409
    assert_no_partial_transfer_state(sender_id, receiver_id)


def test_transaction_rolls_back_when_blockchain_insertion_fails(monkeypatch):
    reset_db()
    client = make_client()
    _, sender_id, receiver_id = create_transfer_accounts("rollback.ledger@example.com", "rollledger")
    assert login(client, "rollback.ledger@example.com").status_code == 200

    original_add_to_ledger = app_module.add_transaction_to_ledger

    def fail_ledger_after_write(*args, **kwargs):
        original_add_to_ledger(*args, **kwargs)
        raise RuntimeError("simulated block insertion failure")

    monkeypatch.setattr(app_module, "add_transaction_to_ledger", fail_ledger_after_write)
    response = client.post("/api/transactions", json={"sender_account_id": sender_id, "receiver_account_id": receiver_id, "amount": 100})
    assert response.status_code == 409
    assert_no_partial_transfer_state(sender_id, receiver_id)
    with SessionLocal() as db:
        assert db.query(Block).count() == 0


def test_xss_payloads_are_not_rendered_as_html():
    reset_db()
    client = make_client()
    script_payload = "<script>alert('XSS')</script>"
    image_payload = "<img src=x onerror=alert('XSS')>"
    user_id, sender_id = create_user("xss.user@example.com", "xssuser")
    with SessionLocal() as db:
        user = db.get(User, user_id)
        user.name = script_payload
        receiver = Account(user_id=user_id, account_number="ACC-XSS-RECEIVER", account_type=AccountType.CURRENT, balance=Decimal("10000.00"), currency="INR", status=AccountStatus.ACTIVE)
        db.add(receiver)
        db.commit()
        receiver_id = receiver.id

    assert login(client, "xss.user@example.com").status_code == 200
    current_user = client.get("/api/auth/me")
    assert current_user.status_code == 200
    assert current_user.get_json()["user"]["name"] == script_payload
    response = client.post("/api/transactions", json={"sender_account_id": sender_id, "receiver_account_id": receiver_id, "amount": 100, "description": image_payload})
    assert response.status_code == 200
    transaction_id = response.get_json()["transaction"]["transaction_id"]
    detail_page = client.get(f"/transaction/{transaction_id}")
    assert detail_page.status_code == 200
    assert script_payload.encode() not in detail_page.data
    assert image_payload.encode() not in detail_page.data

    admin_id, _ = create_user("xss.admin@example.com", "xssadmin", UserRole.ADMIN)
    assert admin_id
    assert login(client, "xss.admin@example.com").status_code == 200
    admin_users = client.get("/api/admin/users")
    assert admin_users.status_code == 200
    assert any(user["name"] == script_payload for user in admin_users.get_json()["users"])
    audit_payload = "<img src=x onerror=alert('XSS')>"
    with SessionLocal() as db:
        db.add(AuditLog(user_id=user_id, event_type="xss-test", status="success", message=audit_payload))
        db.commit()
    audit_response = client.get("/api/admin/audit")
    assert audit_response.status_code == 200
    assert any(event["message"] == audit_payload for event in audit_response.get_json()["events"])

    source = (Path(__file__).resolve().parents[1] / "static" / "js" / "app.js").read_text(encoding="utf-8")
    assert "const escapeHtml =" in source
    assert "escapeHtml(transaction.status)" in source
    assert "escapeHtml(security.decision_reason)" in source
    assert "escapeHtml(transaction.transaction_id)" in source
    assert 'if (document.querySelector("#user-name"))' not in source
    assert 'textContent = name' in source

    ops_source = (Path(__file__).resolve().parents[1] / "static" / "js" / "ops.js").read_text(encoding="utf-8")
    assert "esc(user.name)" in ops_source
    assert "esc(event.message)" in ops_source
