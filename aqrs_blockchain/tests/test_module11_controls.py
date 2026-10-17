from __future__ import annotations

import ipaddress
import re
from threading import Barrier
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import pytest
from werkzeug.security import generate_password_hash

import app as app_module
from app import app
from backend.database.database import Base, SessionLocal, engine
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.idempotency_record import IdempotencyRecord
from backend.models.transaction import Transaction
from backend.models.user import User, UserRole
from backend.services.rate_limit_service import DatabaseRateLimitStore


@pytest.fixture(autouse=True)
def reset_controls_database(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    app.config.update(
        TESTING=True,
        SECRET_KEY="module11-controls-test-secret",
        SESSION_COOKIE_SECURE=False,
        SESSION_IDLE_TIMEOUT_SECONDS=1800,
        SESSION_ABSOLUTE_TIMEOUT_SECONDS=43200,
        SESSION_CLOCK=app_module.time.time,
        RATE_LIMIT_CLOCK=app_module.time.time,
        RATE_LIMIT_STORE=app.extensions["rate_limit_store"],
        AUTH_RATE_LIMIT=5,
        AUTH_RATE_WINDOW_SECONDS=300,
        REGISTRATION_RATE_LIMIT=10,
        REGISTRATION_RATE_WINDOW_SECONDS=3600,
        TRANSFER_RATE_LIMIT=30,
        TRANSFER_RATE_WINDOW_SECONDS=60,
        SENSITIVE_WRITE_RATE_LIMIT=30,
        SENSITIVE_WRITE_RATE_WINDOW_SECONDS=60,
        TRUSTED_PROXY_NETWORKS=(),
    )


def create_customer(
    label: str,
    balance: Decimal = Decimal("1000.00"),
    role: UserRole = UserRole.CUSTOMER,
) -> tuple[str, str, str]:
    suffix = uuid.uuid4().hex[:12]
    with SessionLocal() as db:
        user = User(
            name=f"Controls {label}",
            username=f"controls-{label}-{suffix}",
            email=f"controls-{label}-{suffix}@example.test",
            password_hash=generate_password_hash("StrongTestPass123!"),
            role=role,
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


def login(client, email: str):
    return client.post("/api/auth/login", json={"email": email, "password": "StrongTestPass123!"})


def transfer_payload(sender_id: str, receiver_number: str, amount: str = "25.00") -> dict[str, str]:
    return {
        "sender_account_id": sender_id,
        "receiver_account_number": receiver_number,
        "amount": amount,
    }


def test_csrf_token_is_rendered_rotated_on_login_and_read_only_get_is_allowed():
    user_id, _, _ = create_customer("csrf")
    with SessionLocal() as db:
        email = db.get(User, user_id).email

    client = app.test_client()
    login_page = client.get("/login")
    token = re.search(r'<meta name="csrf-token" content="([^"]+)"', login_page.get_data(as_text=True))
    assert token is not None
    old_token = token.group(1)
    assert len(old_token) >= 40

    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": "StrongTestPass123!"},
        headers={"X-CSRF-Token": old_token},
    )
    assert response.status_code == 200
    with client.session_transaction() as current_session:
        assert current_session["csrf_token"] != old_token
        assert current_session.permanent is True

    assert client.get("/api/auth/me").status_code == 200
    assert client.get("/static/js/app.js").status_code == 200


def test_legacy_research_page_renders_csrf_token_and_uses_it_for_mutations():
    user_id, _, _ = create_customer("legacy-csrf", role=UserRole.SECURITY_ANALYST)
    with SessionLocal() as db:
        email = db.get(User, user_id).email

    client = app.test_client()
    assert login(client, email).status_code == 200
    page = client.get("/research/legacy")
    assert page.status_code == 200
    token_match = re.search(
        r'<meta name="csrf-token" content="([^"]+)"',
        page.get_data(as_text=True),
    )
    assert token_match is not None
    assert "{{ csrf_token }}" not in page.get_data(as_text=True)

    signed = client.post("/api/sign-message", json={"message": "test", "mode": "ecdsa"})
    assert signed.status_code == 200


def test_csrf_rejects_missing_invalid_and_another_sessions_token():
    anonymous = app.test_client()
    first_page = anonymous.get("/register")
    first_token = re.search(
        r'<meta name="csrf-token" content="([^"]+)"',
        first_page.get_data(as_text=True),
    ).group(1)

    missing = anonymous.post(
        "/api/auth/register",
        json={},
        csrf=False,
    )
    invalid = anonymous.post(
        "/api/auth/register",
        json={},
        headers={"X-CSRF-Token": "not-the-session-token"},
    )
    assert missing.status_code == invalid.status_code == 400

    other_session = app.test_client()
    other_session.get("/register")
    mismatched = other_session.post(
        "/api/auth/register",
        json={},
        headers={"X-CSRF-Token": first_token},
    )
    assert mismatched.status_code == 400


def test_transfer_requires_csrf_and_an_idempotency_key():
    user_id, sender_id, _ = create_customer("transfer-csrf")
    _, _, recipient_number = create_customer("transfer-csrf-recipient")
    with SessionLocal() as db:
        email = db.get(User, user_id).email
    client = app.test_client()
    assert login(client, email).status_code == 200
    body = transfer_payload(sender_id, recipient_number)

    missing_csrf = client.post(
        "/api/transactions",
        json=body,
        csrf=False,
    )
    assert missing_csrf.status_code == 400

    with client.session_transaction() as current_session:
        csrf_token = current_session["csrf_token"]
    missing_idempotency = client.post(
        "/api/transactions",
        json=body,
        headers={"X-CSRF-Token": csrf_token},
        idempotency=False,
    )
    assert missing_idempotency.status_code == 400
    assert "Idempotency-Key" in missing_idempotency.get_json()["error"]


def test_valid_csrf_token_does_not_bypass_authentication_and_logout_invalidates_session():
    user_id, _, _ = create_customer("logout")
    with SessionLocal() as db:
        email = db.get(User, user_id).email

    client = app.test_client()
    assert client.get("/api/auth/me").status_code == 401
    assert login(client, email).status_code == 200
    assert client.get("/api/auth/me").status_code == 200
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_transfer_idempotency_replays_response_rejects_payload_change_and_scopes_by_user():
    user_a, account_a, number_a = create_customer("sender-a")
    user_b, account_b, number_b = create_customer("sender-b")
    with SessionLocal() as db:
        email_a = db.get(User, user_a).email
        email_b = db.get(User, user_b).email

    client_a = app.test_client()
    client_b = app.test_client()
    assert login(client_a, email_a).status_code == 200
    assert login(client_b, email_b).status_code == 200

    key = "transfer-key-" + uuid.uuid4().hex
    headers = {"Idempotency-Key": key}
    first = client_a.post(
        "/api/transactions",
        json=transfer_payload(account_a, number_b),
        headers=headers,
    )
    replay = client_a.post(
        "/api/transactions",
        json=transfer_payload(account_a, number_b),
        headers=headers,
    )
    assert first.status_code == replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.get_json() == first.get_json()

    changed = client_a.post(
        "/api/transactions",
        json=transfer_payload(account_a, number_b, "26.00"),
        headers=headers,
    )
    assert changed.status_code == 409

    same_key_other_user = client_b.post(
        "/api/transactions",
        json=transfer_payload(account_b, number_a),
        headers=headers,
    )
    assert same_key_other_user.status_code == 200

    with SessionLocal() as db:
        assert db.query(Transaction).count() == 2
        assert db.query(IdempotencyRecord).count() == 2
        assert db.get(Account, account_a).balance == Decimal("1000.00")
        assert db.get(Account, account_b).balance == Decimal("1000.00")


def test_failed_transfer_does_not_consume_idempotency_key():
    user_id, sender_id, _ = create_customer("retry", Decimal("10.00"))
    _, receiver_id, receiver_number = create_customer("retry-recipient")
    with SessionLocal() as db:
        email = db.get(User, user_id).email

    client = app.test_client()
    assert login(client, email).status_code == 200
    key = "retry-key-" + uuid.uuid4().hex
    headers = {"Idempotency-Key": key}
    body = transfer_payload(sender_id, receiver_number, "20.00")
    failed = client.post("/api/transactions", json=body, headers=headers)
    assert failed.status_code == 409

    with SessionLocal() as db:
        db.get(Account, sender_id).balance = Decimal("100.00")
        db.commit()

    body["amount"] = "20.00"
    retried = client.post("/api/transactions", json=body, headers=headers)
    assert retried.status_code == 200
    with SessionLocal() as db:
        assert db.query(Transaction).count() == 1
        assert db.query(IdempotencyRecord).count() == 1
        assert db.get(Account, sender_id).balance == Decimal("80.00")
        assert db.get(Account, receiver_id).balance == Decimal("1020.00")


def test_transfer_signature_failure_rolls_back_balances_transaction_and_key(monkeypatch):
    user_id, sender_id, _ = create_customer("rollback", Decimal("100.00"))
    _, receiver_id, receiver_number = create_customer("rollback-recipient")
    with SessionLocal() as db:
        email = db.get(User, user_id).email

    def fail_signing(_db, _transaction_id):
        raise RuntimeError("simulated signing failure")

    monkeypatch.setattr(
        app_module.CryptoSignatureService,
        "sign_transaction",
        staticmethod(fail_signing),
    )
    client = app.test_client()
    assert login(client, email).status_code == 200
    response = client.post(
        "/api/transactions",
        json=transfer_payload(sender_id, receiver_number),
        headers={"Idempotency-Key": "rollback-key-" + uuid.uuid4().hex},
    )

    assert response.status_code == 409
    with SessionLocal() as db:
        assert db.get(Account, sender_id).balance == Decimal("100.00")
        assert db.get(Account, receiver_id).balance == Decimal("1000.00")
        assert db.query(Transaction).count() == 0
        assert db.query(IdempotencyRecord).count() == 0


def test_concurrent_duplicate_transfer_key_creates_one_transaction():
    user_id, sender_id, _ = create_customer("concurrent", Decimal("100.00"))
    _, _, receiver_number = create_customer("concurrent-recipient")
    with SessionLocal() as db:
        email = db.get(User, user_id).email

    clients = [app.test_client(), app.test_client()]
    assert all(login(client, email).status_code == 200 for client in clients)
    key = "concurrent-key-" + uuid.uuid4().hex
    body = transfer_payload(sender_id, receiver_number, "40.00")
    barrier = Barrier(2)

    def send(client):
        barrier.wait(timeout=10)
        return client.post(
            "/api/transactions",
            json=body,
            headers={"Idempotency-Key": key},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(send, clients))

    assert all(response.status_code in {200, 409} for response in responses)
    assert any(response.status_code == 200 for response in responses)
    if all(response.status_code == 200 for response in responses):
        assert sum(response.headers.get("Idempotency-Replayed") == "true" for response in responses) == 1
    with SessionLocal() as db:
        assert db.query(Transaction).count() == 1
        assert db.get(Account, sender_id).balance == Decimal("60.00")

    replay = clients[0].post(
        "/api/transactions",
        json=body,
        headers={"Idempotency-Key": key},
    )
    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"


@pytest.mark.parametrize(
    ("amount", "expected_successes", "expected_sender_balance", "expected_transactions"),
    [
        ("30.00", 2, Decimal("40.00"), 2),
        ("70.00", 1, Decimal("30.00"), 1),
    ],
)
def test_concurrent_transfers_from_one_account_preserve_balance_and_ledger(
    amount,
    expected_successes,
    expected_sender_balance,
    expected_transactions,
):
    user_id, sender_id, _ = create_customer("parallel-sender", Decimal("100.00"))
    _, recipient_a_id, recipient_a_number = create_customer("parallel-recipient-a")
    _, recipient_b_id, recipient_b_number = create_customer("parallel-recipient-b")
    with SessionLocal() as db:
        email = db.get(User, user_id).email

    clients = [app.test_client(), app.test_client()]
    assert all(login(client, email).status_code == 200 for client in clients)
    requests = [
        (recipient_a_number, "parallel-key-" + uuid.uuid4().hex),
        (recipient_b_number, "parallel-key-" + uuid.uuid4().hex),
    ]
    barrier = Barrier(2)

    def send(indexed_item):
        client_index, item = indexed_item
        recipient_number, key = item
        barrier.wait(timeout=10)
        for attempt in range(3):
            response = clients[client_index].post(
                "/api/transactions",
                json=transfer_payload(sender_id, recipient_number, amount),
                headers={"Idempotency-Key": key},
            )
            if response.status_code != 409 or "Retry-After" not in response.headers or attempt == 2:
                return response
            time.sleep(min(int(response.headers["Retry-After"]), 1))
        raise AssertionError("Transfer retry loop ended without a response.")

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(send, enumerate(requests)))

    assert sum(response.status_code == 200 for response in responses) == expected_successes, [
        (response.status_code, response.get_json()) for response in responses
    ]
    assert all(response.status_code in {200, 409} for response in responses)
    with SessionLocal() as db:
        assert db.get(Account, sender_id).balance == expected_sender_balance
        recipient_total = db.get(Account, recipient_a_id).balance + db.get(Account, recipient_b_id).balance
        assert recipient_total == Decimal("2000.00") + Decimal(amount) * expected_successes
        assert db.query(Transaction).count() == expected_transactions


def test_database_rate_limit_store_is_shared_resettable_and_uses_controlled_time():
    first_store = DatabaseRateLimitStore()
    second_store = DatabaseRateLimitStore()

    assert first_store.consume("shared-test", limit=1, window_seconds=20, now=100.0) == (True, 20)
    allowed, retry_after = second_store.consume(
        "shared-test",
        limit=1,
        window_seconds=20,
        now=105.0,
    )
    assert allowed is False
    assert retry_after == 15
    first_store.clear("shared-test")
    assert second_store.consume("shared-test", limit=1, window_seconds=20, now=105.0)[0] is True
    assert first_store.consume("window-test", limit=1, window_seconds=20, now=100.0)[0] is True
    assert second_store.consume("window-test", limit=1, window_seconds=20, now=120.0)[0] is True


def test_login_rate_limit_boundaries_reset_and_retry_after(monkeypatch):
    clock = [1000.0]
    monkeypatch.setitem(app.config, "RATE_LIMIT_CLOCK", lambda: clock[0])
    monkeypatch.setitem(app.config, "AUTH_RATE_LIMIT", 2)
    monkeypatch.setitem(app.config, "AUTH_RATE_WINDOW_SECONDS", 30)
    client = app.test_client()
    identity = f"rate-{uuid.uuid4().hex}@example.test"
    body = {"email": identity, "password": "WrongPass123!"}

    assert client.post("/api/auth/login", json=body).status_code == 401
    assert client.post("/api/auth/login", json=body).status_code == 401
    limited = client.post("/api/auth/login", json=body)
    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "30"

    clock[0] += 30
    assert client.post("/api/auth/login", json=body).status_code == 401


def test_forwarded_ip_is_ignored_unless_remote_proxy_is_trusted(monkeypatch):
    class RecordingStore:
        def __init__(self):
            self.keys = []

        def consume(self, key, **_kwargs):
            self.keys.append(key)
            return True, 60

        def clear(self, _key):
            return None

    store = RecordingStore()
    monkeypatch.setitem(app.config, "RATE_LIMIT_STORE", store)
    client = app.test_client()
    client.post(
        "/api/auth/login",
        json={"email": "spoof@example.test", "password": "bad"},
        headers={"X-Forwarded-For": "203.0.113.88"},
        environ_overrides={"REMOTE_ADDR": "198.51.100.4"},
    )
    assert "198.51.100.4" in store.keys[-1]
    assert "203.0.113.88" not in store.keys[-1]

    monkeypatch.setitem(
        app.config,
        "TRUSTED_PROXY_NETWORKS",
        (ipaddress.ip_network("127.0.0.1/32"),),
    )
    client.post(
        "/api/auth/login",
        json={"email": "proxy@example.test", "password": "bad"},
        headers={"X-Forwarded-For": "203.0.113.89"},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert "203.0.113.89" in store.keys[-1]


def test_idle_and_absolute_session_expiration_are_enforced_without_sleep(monkeypatch):
    clock = [10_000.0]
    monkeypatch.setitem(app.config, "SESSION_CLOCK", lambda: clock[0])
    monkeypatch.setitem(app.config, "SESSION_IDLE_TIMEOUT_SECONDS", 60)
    monkeypatch.setitem(app.config, "SESSION_ABSOLUTE_TIMEOUT_SECONDS", 120)
    monkeypatch.setitem(app.config, "PERMANENT_SESSION_LIFETIME", 60)
    user_id, _, _ = create_customer("expiry")
    with SessionLocal() as db:
        email = db.get(User, user_id).email

    client = app.test_client()
    assert login(client, email).status_code == 200
    with client.session_transaction() as current_session:
        assert current_session.permanent is True
        assert current_session["auth_issued_at"] == 10_000.0

    clock[0] += 50
    assert client.get("/api/auth/me").status_code == 200
    with client.session_transaction() as current_session:
        assert current_session["auth_last_seen_at"] == 10_050.0
    clock[0] += 59
    assert client.get("/api/auth/me").status_code == 200
    clock[0] += 60
    expired_idle = client.get("/api/auth/me")
    assert expired_idle.status_code == 401
    assert expired_idle.get_json()["error"].startswith("Session expired")

    second = app.test_client()
    clock[0] = 20_000.0
    assert login(second, email).status_code == 200
    clock[0] += 40
    assert second.get("/api/auth/me").status_code == 200
    clock[0] += 40
    assert second.get("/api/auth/me").status_code == 200
    clock[0] += 41
    assert second.get("/api/auth/me").status_code == 401
