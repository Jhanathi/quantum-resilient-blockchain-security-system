from __future__ import annotations

from decimal import Decimal

import pytest
from werkzeug.security import generate_password_hash

from app import app
from backend.database.database import Base, SessionLocal, engine
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.aqrs_decision import AQRSDecision
from backend.models.transaction import RiskLevel, Transaction, TransactionStatus
from backend.models.user import User, UserRole


def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def make_client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SECRET_KEY"] = "test-secret-module4"
    return app.test_client()


def create_customer(email, username, password="StrongPass123!"):
    user = User(
        name=username.title(),
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        role=UserRole.CUSTOMER,
        is_active=True,
    )
    with SessionLocal() as db:
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def create_security_analyst(email="security@example.com", username="securityanalyst", password="AnalystPass123!"):
    user = User(
        name="Security Analyst",
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        role=UserRole.SECURITY_ANALYST,
        is_active=True,
    )
    with SessionLocal() as db:
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def create_account(user_id, number, balance="5000.00"):
    with SessionLocal() as db:
        account = Account(
            user_id=user_id,
            account_number=number,
            account_type=AccountType.SAVINGS,
            balance=Decimal(balance),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add(account)
        db.commit()
        db.refresh(account)
        return account


def login(client, email, password):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def test_risk_classification_thresholds():
    from backend.services.risk_service import classify_transaction_risk

    assert classify_transaction_risk(Decimal("999.00")) == RiskLevel.LOW
    assert classify_transaction_risk(Decimal("1000.00")) == RiskLevel.MEDIUM
    assert classify_transaction_risk(Decimal("99999.99")) == RiskLevel.MEDIUM
    assert classify_transaction_risk(Decimal("100000.00")) == RiskLevel.HIGH


@pytest.mark.parametrize(
    ("amount", "risk_level", "security_level"),
    [
        ("0.01", RiskLevel.LOW, 2),
        ("999.99", RiskLevel.LOW, 2),
        ("1000.00", RiskLevel.MEDIUM, 3),
        ("1000.01", RiskLevel.MEDIUM, 3),
        ("99999.99", RiskLevel.MEDIUM, 3),
        ("100000.00", RiskLevel.HIGH, 5),
        ("100000.01", RiskLevel.HIGH, 5),
    ],
)
def test_aqrs_exact_threshold_boundaries(amount, risk_level, security_level):
    from backend.services.risk_service import build_decision_for_amount

    decision = build_decision_for_amount(Decimal(amount))
    assert decision["risk_level"] == risk_level.value
    assert decision["selected_security_level"] == security_level


def test_aqrs_mapping_and_decision_values():
    from backend.services.risk_service import build_decision_for_amount, select_security_level

    low = build_decision_for_amount(Decimal("500.00"))
    medium = build_decision_for_amount(Decimal("50000.00"))
    high = build_decision_for_amount(Decimal("500000.00"))

    assert low["risk_level"] == RiskLevel.LOW.value
    assert low["security_level"] == "ML-DSA-44"
    assert low["algorithm"] == "ML-DSA-44"
    assert low["compatibility_name"] == "DIL2"

    assert medium["risk_level"] == RiskLevel.MEDIUM.value
    assert medium["security_level"] == "ML-DSA-65"
    assert medium["algorithm"] == "ML-DSA-65"
    assert medium["compatibility_name"] == "DIL3"

    assert high["risk_level"] == RiskLevel.HIGH.value
    assert high["security_level"] == "ML-DSA-87"
    assert high["algorithm"] == "ML-DSA-87"
    assert high["compatibility_name"] == "DIL5"

    assert select_security_level(RiskLevel.LOW)["selected_security_level"] == 2
    assert select_security_level(RiskLevel.MEDIUM)["selected_security_level"] == 3
    assert select_security_level(RiskLevel.HIGH)["selected_security_level"] == 5


def test_successful_low_risk_transaction_creates_aqrs_decision():
    reset_db()
    client = make_client()
    user_a = create_customer("lowrisk_a@example.com", "lowrisa")
    user_b = create_customer("lowrisk_b@example.com", "lowrisb")
    acc_a = create_account(user_a.id, "ACC-LR-A", "6000.00")
    acc_b = create_account(user_b.id, "ACC-LR-B", "2000.00")

    login(client, "lowrisk_a@example.com", "StrongPass123!")
    resp = client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "500.00"})
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["transaction"]["risk_level"] == "LOW"
    assert payload["transaction"]["security_level"] == "ML-DSA-44"

    with SessionLocal() as db:
        txn = db.query(Transaction).filter_by(transaction_id=payload["transaction"]["transaction_id"]).one()
        decision = db.query(AQRSDecision).filter_by(transaction_id=txn.id).one()
        assert decision.risk_level.value == "LOW"
        assert decision.selected_security_level == 2
        assert decision.algorithm == "ML-DSA-44"


def test_medium_and_high_risk_transactions_persist_decisions():
    reset_db()
    client = make_client()
    user_a = create_customer("riskmid_a@example.com", "riskmida")
    user_b = create_customer("riskmid_b@example.com", "riskmidb")
    acc_a = create_account(user_a.id, "ACC-MID-A", "150000.00")
    acc_b = create_account(user_b.id, "ACC-MID-B", "50000.00")

    login(client, "riskmid_a@example.com", "StrongPass123!")
    medium = client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "50000.00"})
    assert medium.status_code == 200
    medium_payload = medium.get_json()
    assert medium_payload["transaction"]["risk_level"] == "MEDIUM"
    assert medium_payload["transaction"]["security_level"] == "ML-DSA-65"

    high_user_a = create_customer("riskhigh_a@example.com", "riskhigha")
    high_user_b = create_customer("riskhigh_b@example.com", "riskhighb")
    high_acc_a = create_account(high_user_a.id, "ACC-HIGH-A", "1000000.00")
    high_acc_b = create_account(high_user_b.id, "ACC-HIGH-B", "500000.00")

    login(client, "riskhigh_a@example.com", "StrongPass123!")
    high = client.post("/api/transactions", json={"sender_account_id": high_acc_a.id, "receiver_account_id": high_acc_b.id, "amount": "500000.00"})
    assert high.status_code == 200
    high_payload = high.get_json()
    assert high_payload["transaction"]["risk_level"] == "HIGH"
    assert high_payload["transaction"]["security_level"] == "ML-DSA-87"

    with SessionLocal() as db:
        decisions = db.query(AQRSDecision).all()
        assert len(decisions) >= 2
        assert {d.risk_level.value for d in decisions} >= {"MEDIUM", "HIGH"}


def test_customer_can_view_own_transaction_security_and_cannot_view_others():
    reset_db()
    client = make_client()
    user_a = create_customer("sec_a@example.com", "seca")
    user_b = create_customer("sec_b@example.com", "secb")
    user_c = create_customer("sec_c@example.com", "secc")
    acc_a = create_account(user_a.id, "ACC-SEC-A", "8000.00")
    acc_b = create_account(user_b.id, "ACC-SEC-B", "6000.00")
    acc_c = create_account(user_c.id, "ACC-SEC-C", "9000.00")

    login(client, "sec_a@example.com", "StrongPass123!")
    tx = client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "1500.00"})
    tx_id = tx.get_json()["transaction"]["transaction_id"]
    own = client.get(f"/api/transactions/{tx_id}/security")
    assert own.status_code == 200
    payload = own.get_json()
    assert payload["risk_level"] == "MEDIUM"
    assert payload["security_level"] == "ML-DSA-65"

    login(client, "sec_c@example.com", "StrongPass123!")
    forbidden = client.get(f"/api/transactions/{tx_id}/security")
    assert forbidden.status_code in {403, 404}


def test_security_analyst_can_access_systemwide_aqrs_decisions():
    reset_db()
    client = make_client()
    cust_a = create_customer("analyst_a@example.com", "analysta")
    cust_b = create_customer("analyst_b@example.com", "analystb")
    acc_a = create_account(cust_a.id, "ACC-SA-A", "15000.00")
    acc_b = create_account(cust_b.id, "ACC-SA-B", "5000.00")

    login(client, "analyst_a@example.com", "StrongPass123!")
    tx = client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "2000.00"})
    assert tx.status_code == 200

    security_user = create_security_analyst()
    login(client, "security@example.com", "AnalystPass123!")
    resp = client.get("/api/security/aqrs/decisions")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["decisions"]


def test_customer_cannot_access_systemwide_aqrs_decisions():
    reset_db()
    client = make_client()
    cust_a = create_customer("customer_x@example.com", "customerx")
    cust_b = create_customer("customer_y@example.com", "customery")
    acc_a = create_account(cust_a.id, "ACC-CX-A", "15000.00")
    acc_b = create_account(cust_b.id, "ACC-CX-B", "5000.00")

    login(client, "customer_x@example.com", "StrongPass123!")
    tx = client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "1500.00"})
    assert tx.status_code == 200

    resp = client.get("/api/security/aqrs/decisions")
    assert resp.status_code in {403, 401}


def test_transaction_history_includes_risk_and_security_decision():
    reset_db()
    client = make_client()
    user_a = create_customer("hist_aqrs@example.com", "histaqrs")
    user_b = create_customer("hist_aqrs_b@example.com", "histaqrsb")
    acc_a = create_account(user_a.id, "ACC-HT-A", "10000.00")
    acc_b = create_account(user_b.id, "ACC-HT-B", "5000.00")

    login(client, "hist_aqrs@example.com", "StrongPass123!")
    resp = client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "1500.00"})
    tx_id = resp.get_json()["transaction"]["transaction_id"]

    history = client.get("/api/transactions")
    payload = history.get_json()
    tx = next(item for item in payload["transactions"] if item["transaction_id"] == tx_id)
    assert tx["risk_level"] == "MEDIUM"
    assert tx["security_level"] == "ML-DSA-65"


def test_aqrs_decision_is_not_orphaned_when_transaction_creation_fails():
    reset_db()
    client = make_client()
    user_a = create_customer("atomic_a@example.com", "atomica")
    user_b = create_customer("atomic_b@example.com", "atomicb")
    acc_a = create_account(user_a.id, "ACC-AT-A", "1000.00")
    acc_b = create_account(user_b.id, "ACC-AT-B", "2500.00")

    login(client, "atomic_a@example.com", "StrongPass123!")
    resp = client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "5000.00"})
    assert resp.status_code in {400, 409}

    with SessionLocal() as db:
        assert db.query(Transaction).count() == 0
        assert db.query(AQRSDecision).count() == 0
