from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Barrier

import pytest
from werkzeug.security import generate_password_hash

import app as app_module
from app import app
from backend.database.database import Base, SessionLocal, engine
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.audit_log import AuditLog
from backend.models.deposit import Deposit
from backend.models.idempotency_record import IdempotencyRecord
from backend.models.transaction import Transaction
from backend.models.user import User, UserRole
from backend.services.blockchain_service import validate_chain


@pytest.fixture(autouse=True)
def reset_account_money_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    app.config.update(TESTING=True, SECRET_KEY="account-money-test-secret", SESSION_COOKIE_SECURE=False)


def create_customer(label: str, balance: Decimal = Decimal("100.00")) -> tuple[str, str, str]:
    suffix = uuid.uuid4().hex[:12]
    with SessionLocal() as db:
        user = User(
            name=label,
            username=f"{label}-{suffix}",
            email=f"{label}-{suffix}@example.test",
            password_hash=generate_password_hash("StrongTestPass123!"),
            role=UserRole.CUSTOMER,
            is_active=True,
        )
        db.add(user)
        db.flush()
        account = Account(
            user_id=user.id,
            account_number=f"INR-{suffix.upper()}",
            account_type=AccountType.SAVINGS,
            balance=balance,
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add(account)
        db.commit()
        return user.id, account.id, account.account_number


def login(client, user_id: str) -> None:
    with SessionLocal() as db:
        email = db.get(User, user_id).email
    assert client.post(
        "/api/auth/login",
        json={"email": email, "password": "StrongTestPass123!"},
    ).status_code == 200


def add_owned_account(user_id: str, suffix: str, balance: Decimal = Decimal("0.00")) -> str:
    with SessionLocal() as db:
        account = Account(
            user_id=user_id,
            account_number=f"INR-{suffix.upper()}",
            account_type=AccountType.CURRENT,
            balance=balance,
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add(account)
        db.commit()
        return account.id


def test_transfer_uses_source_database_id_and_recipient_account_number_with_multiple_accounts():
    owner_id, original_account_id, _ = create_customer("multi-source")
    recipient_owner_id, recipient_account_id, recipient_number = create_customer("transfer-recipient")
    source_id = add_owned_account(owner_id, uuid.uuid4().hex[:12], Decimal("80.00"))
    client = app.test_client()
    login(client, owner_id)

    response = client.post(
        "/api/transactions",
        json={
            "sender_account_id": source_id,
            "receiver_account_number": recipient_number,
            "amount": "25.00",
        },
    )

    assert response.status_code == 200
    assert response.get_json()["transaction"]["transaction_type"] == "TRANSFER"
    visible_accounts = client.get("/api/users/me/accounts").get_json()["accounts"]
    assert {item["id"] for item in visible_accounts} == {original_account_id, source_id}
    assert recipient_owner_id != owner_id
    assert recipient_account_id not in {item["id"] for item in visible_accounts}
    with SessionLocal() as db:
        assert db.get(Account, source_id).balance == Decimal("55.00")
        assert db.query(Transaction).count() == 1
        assert db.query(Account).filter_by(user_id=owner_id).count() == 2


def test_transfer_rejects_foreign_source_and_unknown_recipient():
    owner_id, _, _ = create_customer("source-owner")
    foreign_id, foreign_account_id, _ = create_customer("source-foreign")
    client = app.test_client()
    login(client, owner_id)

    forbidden = client.post(
        "/api/transactions",
        json={
            "sender_account_id": foreign_account_id,
            "receiver_account_number": "INR-NOT-FOUND",
            "amount": "1.00",
        },
    )
    unknown = client.post(
        "/api/transactions",
        json={
            "sender_account_id": _account_id_for(owner_id),
            "receiver_account_number": "INR-NOT-FOUND",
            "amount": "1.00",
        },
    )

    assert forbidden.status_code == 403
    assert unknown.status_code == 404
    with SessionLocal() as db:
        assert db.get(Account, foreign_account_id).balance == Decimal("100.00")
        assert db.query(Transaction).count() == 0


def _account_id_for(user_id: str) -> str:
    with SessionLocal() as db:
        return db.query(Account.id).filter_by(user_id=user_id).one()[0]


def test_deposit_credits_only_owned_account_and_idempotency_prevents_double_credit():
    owner_id, account_id, account_number = create_customer("deposit-owner")
    client = app.test_client()
    login(client, owner_id)
    payload = {"account_id": account_id, "amount": "12.34"}
    headers = {"Idempotency-Key": f"deposit-{uuid.uuid4().hex}"}

    first = client.post("/api/deposits", json=payload, headers=headers)
    replay = client.post("/api/deposits", json=payload, headers=headers)

    assert first.status_code == 200
    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.get_json() == first.get_json()
    changed = client.post(
        "/api/deposits",
        json={"account_id": account_id, "amount": "12.35"},
        headers=headers,
    )
    assert changed.status_code == 409
    transaction = first.get_json()["transaction"]
    assert transaction["transaction_type"] == "DEPOSIT"
    assert transaction["account_number"] == account_number
    assert transaction["simulated"] is True
    assert transaction["block_number"] > 0
    assert len(transaction["block_hash"]) == 64
    with SessionLocal() as db:
        assert db.get(Account, account_id).balance == Decimal("112.34")
        assert db.query(Deposit).count() == 1
        assert db.query(IdempotencyRecord).filter_by(operation="deposit:create").count() == 1
        assert db.query(AuditLog).filter_by(event_type="DEPOSIT_COMPLETED").count() == 1
        assert validate_chain(db)["valid"] is True


@pytest.mark.parametrize("amount", ["0", "-1.00", "not-money", "1.001"])
def test_deposit_rejects_invalid_amount_without_changing_balance(amount):
    owner_id, account_id, _ = create_customer("invalid-deposit")
    client = app.test_client()
    login(client, owner_id)
    response = client.post(
        "/api/deposits",
        json={"account_id": account_id, "amount": amount},
        headers={"Idempotency-Key": f"invalid-{uuid.uuid4().hex}"},
    )
    assert response.status_code == 400
    with SessionLocal() as db:
        assert db.get(Account, account_id).balance == Decimal("100.00")
        assert db.query(Deposit).count() == 0


def test_deposit_rejects_foreign_account_and_requires_authentication():
    owner_id, _, _ = create_customer("deposit-owner-a")
    _, foreign_account_id, _ = create_customer("deposit-owner-b")
    client = app.test_client()
    login(client, owner_id)
    response = client.post(
        "/api/deposits",
        json={"account_id": foreign_account_id, "amount": "10.00"},
        headers={"Idempotency-Key": f"foreign-{uuid.uuid4().hex}"},
    )
    assert response.status_code == 403

    anonymous = app.test_client().post(
        "/api/deposits",
        json={"account_id": foreign_account_id, "amount": "10.00"},
        headers={"Idempotency-Key": f"anon-{uuid.uuid4().hex}"},
    )
    assert anonymous.status_code == 401
    with SessionLocal() as db:
        assert db.get(Account, foreign_account_id).balance == Decimal("100.00")


def test_deposit_requires_csrf_token():
    owner_id, account_id, _ = create_customer("deposit-csrf")
    client = app.test_client()
    login(client, owner_id)
    response = client.post(
        "/api/deposits",
        json={"account_id": account_id, "amount": "1.00"},
        headers={"Idempotency-Key": f"csrf-{uuid.uuid4().hex}"},
        csrf=False,
    )
    assert response.status_code == 400
    with SessionLocal() as db:
        assert db.get(Account, account_id).balance == Decimal("100.00")


def test_failed_deposit_rolls_back_credit_and_record(monkeypatch):
    owner_id, account_id, _ = create_customer("deposit-rollback")
    client = app.test_client()
    login(client, owner_id)

    def fail_deposit(*_args, **_kwargs):
        raise RuntimeError("injected record failure")

    monkeypatch.setattr(app_module, "Deposit", fail_deposit)
    response = client.post(
        "/api/deposits",
        json={"account_id": account_id, "amount": "10.00"},
        headers={"Idempotency-Key": f"rollback-{uuid.uuid4().hex}"},
    )

    assert response.status_code == 500
    with SessionLocal() as db:
        assert db.get(Account, account_id).balance == Decimal("100.00")
        assert db.query(Deposit).count() == 0
        assert db.query(IdempotencyRecord).filter_by(operation="deposit:create").count() == 0


def test_create_account_is_authenticated_owned_unique_and_unfunded():
    owner_id, _, _ = create_customer("account-create")
    client = app.test_client()
    login(client, owner_id)

    response = client.post("/api/users/me/accounts", json={"account_type": "CURRENT"})

    assert response.status_code == 201
    created = response.get_json()["account"]
    assert created["account_type"] == "CURRENT"
    assert created["balance"] == "0.00"
    with SessionLocal() as db:
        account = db.get(Account, created["id"])
        assert account.user_id == owner_id
        assert db.query(Account.account_number).filter_by(account_number=created["account_number"]).count() == 1
        assert db.query(AuditLog).filter_by(event_type="ACCOUNT_CREATED").count() == 1

    anonymous = app.test_client().post("/api/users/me/accounts", json={})
    assert anonymous.status_code == 401


def test_deposits_are_returned_as_deposits_in_history_not_transfers():
    owner_id, account_id, _ = create_customer("deposit-history")
    client = app.test_client()
    login(client, owner_id)
    created = client.post(
        "/api/deposits",
        json={"account_id": account_id, "amount": "5.00"},
        headers={"Idempotency-Key": f"history-{uuid.uuid4().hex}"},
    )
    transaction_id = created.get_json()["transaction"]["transaction_id"]

    history = client.get("/api/transactions")
    details = client.get(f"/api/transactions/{transaction_id}")

    assert history.status_code == details.status_code == 200
    item = history.get_json()["transactions"][0]
    assert item["transaction_type"] == "DEPOSIT"
    assert item["sender_account_id"] is None
    assert item["receiver_account_id"] == account_id
    assert details.get_json()["transaction"]["transaction_type"] == "DEPOSIT"
    assert client.get(f"/transaction/{transaction_id}").status_code == 200


def test_concurrent_transfers_cannot_overspend_account():
    owner_id, sender_id, _ = create_customer("concurrent-transfer", Decimal("50.00"))
    _, _, recipient_a = create_customer("concurrent-recipient-a")
    _, _, recipient_b = create_customer("concurrent-recipient-b")
    clients = [app.test_client(), app.test_client()]
    for client in clients:
        login(client, owner_id)
    barrier = Barrier(2)

    def send(client, recipient):
        barrier.wait(timeout=10)
        return client.post(
            "/api/transactions",
            json={
                "sender_account_id": sender_id,
                "receiver_account_number": recipient,
                "amount": "40.00",
            },
            headers={"Idempotency-Key": f"concurrent-{uuid.uuid4().hex}"},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda pair: send(*pair), zip(clients, [recipient_a, recipient_b])))

    assert sum(response.status_code == 200 for response in responses) == 1
    with SessionLocal() as db:
        assert db.get(Account, sender_id).balance == Decimal("10.00")
        assert db.query(Transaction).count() == 1
