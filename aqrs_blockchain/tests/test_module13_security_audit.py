from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace

import pytest
from sqlalchemy import inspect
from werkzeug.security import generate_password_hash

import app as app_module
from app import app
from backend.services.security_demo_service import reset_demo_history
from backend.database.database import Base, SessionLocal, engine
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.security_audit_event import SecurityAuditEvent
from backend.models.user import User, UserRole
from backend.database.create_admin import create_admin_account
from backend.services.security_audit_service import (
    AuditFilterError,
    audit_dashboard_stats,
    list_audit_events,
    parse_audit_filters,
    record_security_event,
    sanitize_metadata,
    serialize_event,
)


@pytest.fixture(autouse=True)
def isolated_audit_database(monkeypatch):
    reset_demo_history()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setitem(app.config, "TESTING", True)
    monkeypatch.setitem(app.config, "SECRET_KEY", "module13-test-secret")
    monkeypatch.setitem(app.config, "SESSION_COOKIE_SECURE", False)
    monkeypatch.setitem(app.config, "SENSITIVE_WRITE_RATE_LIMIT", 1000)
    yield
    reset_demo_history()


def make_user(role: UserRole) -> User:
    suffix = uuid.uuid4().hex
    with SessionLocal() as db:
        user = User(
            name="Module Thirteen User",
            username=f"module13-{suffix}",
            email=f"module13-{suffix}@example.test",
            password_hash=generate_password_hash("AuditTestPass123!"),
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def login(client, user: User):
    return client.post(
        "/api/auth/login",
        json={"email": user.email, "password": "AuditTestPass123!"},
    )


def add_event(
    *,
    event_type: str = "TEST_EVENT",
    category: str = "TEST",
    severity: str = "INFO",
    outcome: str = "SUCCESS",
    title: str = "Test event",
    description: str = "A test audit event.",
    is_demo: bool = False,
    actor_id: str | None = None,
    metadata: dict | None = None,
    created_at: datetime | None = None,
) -> str:
    with SessionLocal() as db:
        event = record_security_event(
            db,
            event_type=event_type,
            category=category,
            severity=severity,
            title=title,
            description=description,
            outcome=outcome,
            source="test",
            actor_id=actor_id,
            is_demo=is_demo,
            metadata=metadata,
            created_at=created_at,
        )
        db.commit()
        return event.id


def test_security_audit_table_is_created_without_changing_existing_tables():
    tables = set(inspect(engine).get_table_names())
    assert "security_audit_events" in tables
    assert "users" in tables
    assert "transactions" in tables


def test_service_creates_persistent_event_and_allows_missing_actor():
    event_id = add_event(metadata={"block_number": 3})
    with SessionLocal() as db:
        event = db.get(SecurityAuditEvent, event_id)
        assert event is not None
        assert event.actor_id is None
        assert event.metadata_ == {"block_number": 3}
        assert event.created_at is not None
    with SessionLocal() as db:
        assert db.get(SecurityAuditEvent, event_id) is not None


@pytest.mark.parametrize(
    "field,value",
    [
        ("event_type", "bad event type"),
        ("severity", "SEVERE"),
        ("outcome", "MAYBE"),
        ("title", ""),
        ("metadata", ["not", "an", "object"]),
    ],
)
def test_service_rejects_invalid_required_fields_and_enums(field, value):
    fields = {
        "event_type": "TEST_EVENT",
        "severity": "INFO",
        "title": "Test",
        "description": "Description",
        "outcome": "SUCCESS",
        "source": "test",
        "metadata": {},
    }
    fields[field] = value
    with SessionLocal() as db:
        with pytest.raises(ValueError):
            record_security_event(db, **fields)
        db.rollback()


def test_metadata_sanitization_removes_sensitive_keys_and_rejects_oversize_values():
    safe = sanitize_metadata({
        "operation": "test",
        "password": "never persist",
        "nested": {"access_token": "never persist", "count": 2},
        "note": "password=should-not-persist",
        "signing_key": "never persist",
    })
    assert safe == {
        "operation": "test",
        "nested": {"count": 2},
        "note": "password=[redacted]",
    }
    bounded = sanitize_metadata({"payload": "x" * 9000})
    assert len(bounded["payload"]) <= 1000
    with pytest.raises(ValueError):
        sanitize_metadata({"payloads": ["x" * 1000 for _ in range(20)]})


def test_service_respects_caller_transaction_boundary():
    with SessionLocal() as db:
        record_security_event(
            db,
            event_type="ROLLBACK_TEST",
            severity="INFO",
            title="Rolled back",
            description="This record should not persist.",
            outcome="SUCCESS",
            source="test",
        )
        db.rollback()
    with SessionLocal() as db:
        assert db.query(SecurityAuditEvent).filter_by(event_type="ROLLBACK_TEST").count() == 0


def test_login_failure_success_and_logout_are_recorded_once_per_action():
    user = make_user(UserRole.CUSTOMER)
    client = app.test_client()
    wrong = client.post("/api/auth/login", json={"email": user.email, "password": "WrongPass123!"})
    assert wrong.status_code == 401
    assert login(client, user).status_code == 200
    assert client.post("/api/auth/logout").status_code == 200

    with SessionLocal() as db:
        assert db.query(SecurityAuditEvent).filter_by(event_type="LOGIN_FAILED").count() == 1
        assert db.query(SecurityAuditEvent).filter_by(event_type="LOGIN_SUCCEEDED").count() == 1
        assert db.query(SecurityAuditEvent).filter_by(event_type="LOGOUT_SUCCEEDED").count() == 1
        assert db.query(SecurityAuditEvent).filter_by(event_type="LOGIN_FAILED").one().metadata_ == {}


def test_registration_records_account_creation_without_sensitive_values():
    client = app.test_client()
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Audit Registration",
            "email": "audit-registration@example.test",
            "username": "audit-registration",
            "password": "AuditTestPass123!",
        },
    )
    assert response.status_code == 201
    with SessionLocal() as db:
        event = db.query(SecurityAuditEvent).filter_by(event_type="ACCOUNT_CREATED").one()
        assert event.actor_id == response.get_json()["user"]["id"]
        assert event.metadata_ == {}
        assert event.actor_email == "audit-registration@example.test"


def test_admin_provisioning_records_privileged_change_without_credentials():
    create_admin_account(
        name="Provisioned Administrator",
        email="provisioned-admin@example.test",
        username="provisioned-admin",
        password="AdminAuditPass123!",
    )
    with SessionLocal() as db:
        admin = db.query(User).filter_by(email="provisioned-admin@example.test").one()
        event = db.query(SecurityAuditEvent).filter_by(event_type="ADMIN_ACCOUNT_CREATED").one()
        assert admin.role == UserRole.ADMIN
        assert event.target_id == admin.id
        assert event.metadata_ == {"role": "ADMIN"}
        assert "AdminAuditPass123!" not in str(event.metadata_)


def test_role_denial_is_audited_and_customer_cannot_access_audit_data():
    customer = make_user(UserRole.CUSTOMER)
    client = app.test_client()
    assert client.get("/api/security/audit/dashboard").status_code == 401
    assert login(client, customer).status_code == 200
    assert client.get("/security/audit").status_code == 403
    assert client.get("/api/security/audit/events").status_code == 403
    assert client.get("/api/security/audit/export.csv").status_code == 403

    with SessionLocal() as db:
        denial = (
            db.query(SecurityAuditEvent)
            .filter_by(event_type="ROLE_ACCESS_DENIED", actor_id=customer.id)
            .first()
        )
        assert denial is not None
        assert denial.actor_id == customer.id
        assert denial.outcome == "BLOCKED"


def test_security_analyst_can_view_dashboard_filters_details_and_exports():
    analyst = make_user(UserRole.SECURITY_ANALYST)
    first_id = add_event(
        event_type="TRANSFER_REJECTED",
        category="TRANSACTION",
        severity="HIGH",
        outcome="FAILURE",
        title="Transfer declined",
        description="Insufficient balance in demo test.",
        actor_id=analyst.id,
        metadata={"reason": "balance"},
        created_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    add_event(
        event_type="SECURITY_LAB_SCENARIO_RUN",
        category="DEMO",
        severity="INFO",
        outcome="SUCCESS",
        title="=unsafe formula",
        description="Synthetic tampering simulation.",
        is_demo=True,
        actor_id=analyst.id,
        metadata={"scenario_id": "block-data", "password": "omit-me"},
    )

    client = app.test_client()
    assert login(client, analyst).status_code == 200
    assert client.get("/security/audit").status_code == 200
    dashboard = client.get("/api/security/audit/dashboard").get_json()["stats"]
    assert dashboard["total_events"] == 3  # Includes this analyst's successful login.
    assert dashboard["high_critical"] == 1
    assert dashboard["demo_events"] == 1
    assert dashboard["failed_or_blocked"] == 1

    filtered = client.get(
        "/api/security/audit/events?severity=HIGH&category=TRANSACTION&outcome=FAILURE"
    ).get_json()
    assert filtered["pagination"]["total"] == 1
    assert filtered["events"][0]["id"] == first_id

    by_actor = client.get(f"/api/security/audit/events?actor={analyst.id}").get_json()
    assert by_actor["pagination"]["total"] == 3
    demo = client.get("/api/security/audit/events?mode=demo&search=synthetic").get_json()
    assert demo["pagination"]["total"] == 1
    detail = client.get(f"/api/security/audit/events/{first_id}").get_json()["event"]
    assert detail["metadata"] == {"reason": "balance"}

    csv_response = client.get("/api/security/audit/export.csv?mode=demo")
    assert csv_response.status_code == 200
    assert csv_response.mimetype == "text/csv"
    csv_text = csv_response.get_data(as_text=True)
    assert "'=unsafe formula" in csv_text
    assert "omit-me" not in csv_text

    json_response = client.get("/api/security/audit/export.json?mode=demo")
    report = json.loads(json_response.get_data(as_text=True))
    assert json_response.mimetype == "application/json"
    assert report["matching_event_count"] == 1
    assert report["events"][0]["is_demo"] is True
    assert "password" not in json_response.get_data(as_text=True)
    with SessionLocal() as db:
        assert db.query(SecurityAuditEvent).filter_by(event_type="AUDIT_REPORT_EXPORTED").count() == 2


def test_audit_read_rate_limit_is_applied_and_the_block_is_recorded(monkeypatch):
    analyst = make_user(UserRole.SECURITY_ANALYST)
    client = app.test_client()
    assert login(client, analyst).status_code == 200
    monkeypatch.setitem(app.config, "SENSITIVE_WRITE_RATE_LIMIT", 1)
    first = client.get("/api/security/audit/dashboard")
    second = client.get("/api/security/audit/dashboard")
    assert first.status_code == 200
    assert second.status_code == 429
    with SessionLocal() as db:
        event = db.query(SecurityAuditEvent).filter_by(event_type="RATE_LIMIT_EXCEEDED").one()
        assert event.outcome == "BLOCKED"


def test_csrf_rejection_is_recorded_without_performing_demo_reset():
    analyst = make_user(UserRole.SECURITY_ANALYST)
    client = app.test_client()
    assert login(client, analyst).status_code == 200
    response = client.post("/api/security/lab/reset", csrf=False)
    assert response.status_code == 400
    with SessionLocal() as db:
        event = db.query(SecurityAuditEvent).filter_by(event_type="CSRF_VALIDATION_FAILED").one()
        assert event.outcome == "BLOCKED"
        assert event.actor_id == analyst.id


@pytest.mark.parametrize(
    "query",
    [
        "severity=SEVERE",
        "outcome=IGNORED",
        "start_date=2026-02-01&end_date=2026-01-01",
        "start_date=not-a-date",
        "page=0",
        "page_size=101",
        "sort=event_type",
        "mode=production",
        "category=bad%20category",
    ],
)
def test_invalid_audit_filters_return_bad_request(query):
    analyst = make_user(UserRole.SECURITY_ANALYST)
    client = app.test_client()
    assert login(client, analyst).status_code == 200
    response = client.get(f"/api/security/audit/events?{query}")
    assert response.status_code == 400


def test_filter_parser_accepts_date_range_and_sort_allowlist():
    filters = parse_audit_filters({
        "start_date": "2026-01-01",
        "end_date": "2026-01-31",
        "sort": "asc",
        "page": "2",
        "page_size": "50",
    })
    assert filters["sort"] == "asc"
    assert filters["page"] == 2
    assert filters["page_size"] == 50
    with pytest.raises(AuditFilterError):
        parse_audit_filters({"end_date": "9999-12-31"})


def test_dashboard_statistics_search_sort_and_pagination_use_database_rows():
    for index in range(3):
        add_event(
            event_type=f"QUERY_EVENT_{index}",
            category="QUERY",
            severity="MEDIUM" if index else "CRITICAL",
            outcome="BLOCKED" if index else "SUCCESS",
            title=f"Searchable result {index}",
            description="Paginated search",
            created_at=datetime(2024, 1, 1 + index, tzinfo=timezone.utc),
        )
    with SessionLocal() as db:
        stats = audit_dashboard_stats(db)
        assert stats["total_events"] == 3
        assert stats["high_critical"] == 1
        result = list_audit_events(
            db,
            parse_audit_filters({"search": "Searchable", "page_size": "2", "sort": "asc"}),
        )
        assert result["pagination"] == {"page": 1, "page_size": 2, "total": 3, "pages": 2}
        assert [row["title"] for row in result["events"]] == [
            "Searchable result 0",
            "Searchable result 1",
        ]
        date_filtered = list_audit_events(
            db,
            parse_audit_filters({"start_date": "2024-01-02", "end_date": "2024-01-02"}),
        )
        assert date_filtered["pagination"]["total"] == 1


def test_transfer_success_and_failure_are_recorded_without_duplicate_security_events(monkeypatch):
    user = make_user(UserRole.CUSTOMER)
    with SessionLocal() as db:
        sender = Account(
            user_id=user.id,
            account_number=f"SRC-{uuid.uuid4().hex[:10]}",
            account_type=AccountType.SAVINGS,
            balance=Decimal("1000.00"),
            status=AccountStatus.ACTIVE,
        )
        receiver_owner = User(
            name="Recipient",
            username=f"recipient-{uuid.uuid4().hex[:10]}",
            email=f"recipient-{uuid.uuid4().hex}@example.test",
            password_hash=generate_password_hash("RecipientPass123!"),
            role=UserRole.CUSTOMER,
            is_active=True,
        )
        db.add(receiver_owner)
        db.flush()
        receiver = Account(
            user_id=receiver_owner.id,
            account_number=f"DST-{uuid.uuid4().hex[:10]}",
            account_type=AccountType.SAVINGS,
            balance=Decimal("500.00"),
            status=AccountStatus.ACTIVE,
        )
        db.add_all([sender, receiver])
        db.commit()
        sender_id, receiver_number = sender.id, receiver.account_number

    def signed(*_args, **_kwargs):
        return {"signature_size_bytes": 1, "algorithm": "ML-DSA-44"}

    def verified(*_args, **_kwargs):
        return {"valid": True}

    def fake_ledger(*_args, **_kwargs):
        return SimpleNamespace(block_number=1, block_hash="demo")

    monkeypatch.setattr(app_module.CryptoSignatureService, "sign_transaction", signed)
    monkeypatch.setattr(app_module.CryptoSignatureService, "verify_transaction_signature", verified)
    monkeypatch.setattr(app_module, "add_transaction_to_ledger", fake_ledger)

    client = app.test_client()
    assert login(client, user).status_code == 200
    success = client.post(
        "/api/transactions",
        json={"sender_account_id": sender_id, "receiver_account_number": receiver_number, "amount": "25.00"},
        headers={"Idempotency-Key": "module13-idempotency-key-001"},
    )
    conflict = client.post(
        "/api/transactions",
        json={"sender_account_id": sender_id, "receiver_account_number": receiver_number, "amount": "26.00"},
        headers={"Idempotency-Key": "module13-idempotency-key-001"},
    )
    assert success.status_code == 200
    assert conflict.status_code == 409
    failure = client.post(
        "/api/transactions",
        json={"sender_account_id": sender_id, "receiver_account_number": receiver_number, "amount": "-4"},
    )
    assert failure.status_code == 400
    with SessionLocal() as db:
        assert db.query(SecurityAuditEvent).filter_by(event_type="TRANSFER_COMPLETED").count() == 1
        assert db.query(SecurityAuditEvent).filter_by(event_type="TRANSFER_REJECTED").count() == 1
        assert db.query(SecurityAuditEvent).filter_by(event_type="IDEMPOTENCY_CONFLICT").count() == 1


def test_module12_runs_are_marked_as_demo_simulations(monkeypatch):
    analyst = make_user(UserRole.SECURITY_ANALYST)
    monkeypatch.setattr(
        app_module,
        "run_security_demo",
        lambda scenario: {
            "scenario_id": scenario,
            "name": "Transaction amount tampering",
            "status": "INVALID",
            "baseline_status": "VALID",
            "detected": True,
            "operation_completed": True,
        },
    )
    client = app.test_client()
    assert login(client, analyst).status_code == 200
    response = client.post("/api/security/lab/run/transaction-amount")
    assert response.status_code == 200
    with SessionLocal() as db:
        event = db.query(SecurityAuditEvent).filter_by(event_type="SECURITY_LAB_SCENARIO_RUN").one()
        assert event.is_demo is True
        assert event.category == "DEMO"
        assert event.metadata_["tampering_detected"] is True
        assert "not a production incident" in event.description


def test_safe_serialization_omits_malformed_persisted_metadata():
    event_id = add_event()
    with SessionLocal() as db:
        event = db.get(SecurityAuditEvent, event_id)
        event.metadata_ = {"payload": "x" * 9000}
        db.commit()
    with SessionLocal() as db:
        event = db.get(SecurityAuditEvent, event_id)
        safe = serialize_event(event)
        assert len(safe["metadata"]["payload"]) <= 1000


def test_no_mutation_routes_are_registered_for_audit_events():
    methods = {
        (rule.rule, method)
        for rule in app.url_map.iter_rules()
        for method in rule.methods or ()
    }
    assert ("/api/security/audit/events/<event_id>", "DELETE") not in methods
    assert ("/api/security/audit/events/<event_id>", "PUT") not in methods
