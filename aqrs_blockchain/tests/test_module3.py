from __future__ import annotations

from decimal import Decimal

from werkzeug.security import generate_password_hash

from app import app
from backend.database.database import Base, SessionLocal, engine
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.audit_log import AuditLog
from backend.models.transaction import Transaction, TransactionStatus
from backend.models.user import User, UserRole


def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def make_client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SECRET_KEY"] = "test-secret-module3"
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


def test_customer_can_fetch_own_accounts():
    reset_db()
    client = make_client()
    user = create_customer("customerA@example.com", "customera")
    account = create_account(user.id, "ACC-A-001", "5000.00")

    login_response = login(client, "customerA@example.com", "StrongPass123!")
    assert login_response.status_code == 200

    resp = client.get("/api/users/me/accounts")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert len(payload["accounts"]) >= 1
    assert any(item["id"] == account.id for item in payload["accounts"])


def test_customer_cannot_fetch_another_customers_account():
    reset_db()
    client = make_client()
    user_a = create_customer("cust_a@example.com", "custa")
    user_b = create_customer("cust_b@example.com", "custb")
    acc_b = create_account(user_b.id, "ACC-B-001", "2000.00")

    login(client, "cust_a@example.com", "StrongPass123!")
    resp = client.get(f"/api/accounts/{acc_b.id}")
    assert resp.status_code == 403


def test_valid_transfer_succeeds_and_updates_balances():
    reset_db()
    client = make_client()
    user_a = create_customer("transfer_a@example.com", "transfera")
    user_b = create_customer("transfer_b@example.com", "transferb")
    acc_a = create_account(user_a.id, "ACC-T-A", "5000.00")
    acc_b = create_account(user_b.id, "ACC-T-B", "2000.00")

    login(client, "transfer_a@example.com", "StrongPass123!")
    response = client.post(
        "/api/transactions",
        json={"sender_account_id": acc_a.id, "receiver_account_number": acc_b.account_number, "amount": "1000.00"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["transaction"]["status"] == "COMPLETED"
    assert payload["transaction"]["amount"] == "1000.00"

    with SessionLocal() as db:
        updated_a = db.get(Account, acc_a.id)
        updated_b = db.get(Account, acc_b.id)
        txn = db.query(Transaction).filter_by(transaction_id=payload["transaction"]["transaction_id"]).one()
        assert str(updated_a.balance) == "4000.00"
        assert str(updated_b.balance) == "3000.00"
        assert txn.status == TransactionStatus.COMPLETED

    login(client, "transfer_b@example.com", "StrongPass123!")
    recipient_history = client.get("/api/transactions")
    assert recipient_history.status_code == 200
    assert any(item["transaction_id"] == payload["transaction"]["transaction_id"] for item in recipient_history.get_json()["transactions"])


def test_transaction_validation_rejects_invalid_amounts():
    reset_db()
    client = make_client()
    user_a = create_customer("val_a@example.com", "vala")
    user_b = create_customer("val_b@example.com", "valb")
    acc_a = create_account(user_a.id, "ACC-V-A", "5000.00")
    acc_b = create_account(user_b.id, "ACC-V-B", "2000.00")

    login(client, "val_a@example.com", "StrongPass123!")

    for payload in [
        {"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "0.00"},
        {"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "-10.00"},
        {"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "abc"},
        {"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id},
        {"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": ""},
    ]:
        resp = client.post("/api/transactions", json=payload)
        assert resp.status_code in {400, 409}


def test_sender_and_receiver_cannot_be_same_and_missing_accounts_rejected():
    reset_db()
    client = make_client()
    user = create_customer("sameuser@example.com", "sameuser")
    acc = create_account(user.id, "ACC-SAME", "5000.00")

    login(client, "sameuser@example.com", "StrongPass123!")

    same_resp = client.post("/api/transactions", json={"sender_account_id": acc.id, "receiver_account_number": acc.account_number, "amount": "50.00"})
    assert same_resp.status_code in {400, 409}

    missing_sender = client.post("/api/transactions", json={"sender_account_id": "missing", "receiver_account_id": acc.id, "amount": "50.00"})
    assert missing_sender.status_code == 404

    missing_receiver = client.post("/api/transactions", json={"sender_account_id": acc.id, "receiver_account_id": "missing", "amount": "50.00"})
    assert missing_receiver.status_code == 404


def test_transfer_rejects_malformed_or_nonexistent_recipient_account_number():
    reset_db()
    client = make_client()
    user_a = create_customer("recipient-validation@example.com", "recipientvalidation")
    sender = create_account(user_a.id, "ACC-VALID-SENDER", "5000.00")
    login(client, "recipient-validation@example.com", "StrongPass123!")

    malformed = client.post(
        "/api/transactions",
        json={"sender_account_id": sender.id, "receiver_account_number": "not an account", "amount": "50.00"},
    )
    nonexistent = client.post(
        "/api/transactions",
        json={"sender_account_id": sender.id, "receiver_account_number": "INR-99999", "amount": "50.00"},
    )

    assert malformed.status_code == 400
    assert malformed.get_json()["error"] == "Recipient account number is invalid."
    assert nonexistent.status_code == 404
    assert nonexistent.get_json()["error"] == "Account not found."
    with SessionLocal() as db:
        assert db.get(Account, sender.id).balance == Decimal("5000.00")
        assert db.query(Transaction).count() == 0


def test_inactive_accounts_and_insufficient_balance_are_rejected():
    reset_db()
    client = make_client()
    user_a = create_customer("inactive_a@example.com", "inactivea")
    user_b = create_customer("inactive_b@example.com", "inactiveb")
    acc_a = create_account(user_a.id, "ACC-IA", "2000.00")
    acc_b = create_account(user_b.id, "ACC-IB", "1000.00")

    with SessionLocal() as db:
        sender = db.get(Account, acc_a.id)
        receiver = db.get(Account, acc_b.id)
        sender.status = AccountStatus.BLOCKED
        receiver.status = AccountStatus.CLOSED
        db.commit()

    login(client, "inactive_a@example.com", "StrongPass123!")

    inactive_sender = client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "100.00"})
    assert inactive_sender.status_code in {400, 409, 403}

    with SessionLocal() as db:
        sender = db.get(Account, acc_a.id)
        sender.status = AccountStatus.ACTIVE
        db.commit()

    overdrawn = client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "5000.00"})
    assert overdrawn.status_code in {400, 409}


def test_customer_cannot_send_from_another_users_account_and_can_send_from_own():
    reset_db()
    client = make_client()
    user_a = create_customer("money_a@example.com", "moneya")
    user_b = create_customer("money_b@example.com", "moneyb")
    acc_a = create_account(user_a.id, "ACC-M-A", "5000.00")
    acc_b = create_account(user_b.id, "ACC-M-B", "2000.00")

    login(client, "money_a@example.com", "StrongPass123!")
    attack = client.post("/api/transactions", json={"sender_account_id": acc_b.id, "receiver_account_id": acc_a.id, "amount": "100.00"})
    assert attack.status_code == 403

    good = client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "100.00"})
    assert good.status_code == 200


def test_transaction_history_only_returns_own_transactions():
    reset_db()
    client = make_client()
    user_a = create_customer("hist_a@example.com", "hista")
    user_b = create_customer("hist_b@example.com", "histb")
    acc_a = create_account(user_a.id, "ACC-H-A", "5000.00")
    acc_b = create_account(user_b.id, "ACC-H-B", "2000.00")

    login(client, "hist_a@example.com", "StrongPass123!")
    client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "100.00"})
    resp = client.get("/api/transactions")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["transactions"]
    assert all(tx["sender_account_id"] == acc_a.id or tx["receiver_account_id"] == acc_a.id for tx in payload["transactions"])


def test_customer_cannot_view_another_customers_transaction():
    reset_db()
    client = make_client()
    user_a = create_customer("txview_a@example.com", "txviewa")
    user_b = create_customer("txview_b@example.com", "txviewb")
    acc_a = create_account(user_a.id, "ACC-TV-A", "5000.00")
    acc_b = create_account(user_b.id, "ACC-TV-B", "2000.00")

    with SessionLocal() as db:
        tx = Transaction(
            transaction_id="TX-OTHER-001",
            sender_account_id=acc_a.id,
            receiver_account_id=acc_b.id,
            amount=Decimal("250.00"),
            currency="INR",
            description="Other user tx",
            status=TransactionStatus.COMPLETED,
        )
        db.add(tx)
        db.commit()
        db.refresh(tx)
        tx_id = tx.id

    login(client, "txview_a@example.com", "StrongPass123!")
    resp = client.get(f"/api/transactions/{tx_id}")
    assert resp.status_code == 200

    another_user = create_customer("otherperson@example.com", "otherperson")
    with SessionLocal() as db:
        tx2 = Transaction(
            transaction_id="TX-OTHER-002",
            sender_account_id=acc_b.id,
            receiver_account_id=acc_a.id,
            amount=Decimal("400.00"),
            currency="INR",
            description="Other user tx 2",
            status=TransactionStatus.COMPLETED,
        )
        db.add(tx2)
        db.commit()
        db.refresh(tx2)
        second_id = tx2.id

    login_response = login(client, "otherperson@example.com", "StrongPass123!")
    assert login_response.status_code == 200
    unauthorized = client.get(f"/api/transactions/{tx_id}")
    assert unauthorized.status_code in {403, 404}

    other_forbidden = client.get(f"/api/transactions/{second_id}")
    assert other_forbidden.status_code in {403, 404}


def test_unauthenticated_transaction_requests_are_rejected():
    reset_db()
    client = make_client()
    response = client.post("/api/transactions", json={"sender_account_id": "x", "receiver_account_id": "y", "amount": "10.00"})
    assert response.status_code == 401

    history = client.get("/api/transactions")
    assert history.status_code == 401


def test_audit_log_records_transfer_success_and_failures():
    reset_db()
    client = make_client()
    user_a = create_customer("audit_a@example.com", "audita")
    user_b = create_customer("audit_b@example.com", "auditb")
    acc_a = create_account(user_a.id, "ACC-AL-A", "6000.00")
    acc_b = create_account(user_b.id, "ACC-AL-B", "2000.00")

    login(client, "audit_a@example.com", "StrongPass123!")
    transfer = client.post("/api/transactions", json={"sender_account_id": acc_a.id, "receiver_account_id": acc_b.id, "amount": "100.00"})
    assert transfer.status_code == 200

    with SessionLocal() as db:
        logs = db.query(AuditLog).filter(AuditLog.event_type.in_(["TRANSACTION_CREATED", "TRANSACTION_REJECTED", "INSUFFICIENT_BALANCE"])).all()
        assert logs
