from __future__ import annotations

from decimal import Decimal
import uuid

import pytest
from werkzeug.security import generate_password_hash

import backend.services.security_demo_service as demo_service
from app import app
from backend.database.database import Base, SessionLocal, engine
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.user import User, UserRole


def _reset_database() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _create_user(role: UserRole) -> User:
    suffix = uuid.uuid4().hex
    with SessionLocal() as db:
        user = User(
            name="Module Twelve Test User",
            username=f"module12-{suffix}",
            email=f"module12-{suffix}@example.test",
            password_hash=generate_password_hash("Module12Pass123!"),
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def _login(client, user: User) -> None:
    response = client.post(
        "/api/auth/login",
        json={"email": user.email, "password": "Module12Pass123!"},
    )
    assert response.status_code == 200


def test_fresh_demo_chain_is_valid_before_each_scenario():
    for scenario_id in demo_service.SCENARIOS:
        result = demo_service.run_demo(scenario_id)
        assert result["baseline_status"] == "VALID"


@pytest.mark.parametrize(
    "scenario_id",
    [
        "transaction-amount",
        "block-data",
        "previous-hash",
        "digital-signature",
        "recomputed-hash",
    ],
)
def test_supported_tampering_scenarios_are_detected(scenario_id: str):
    result = demo_service.run_demo(scenario_id)

    assert result["baseline_status"] == "VALID"
    assert result["operation_completed"] is True
    assert result["status"] == "INVALID"
    assert result["post_tampering_status"] == "INVALID"
    assert result["detected"] is True
    assert result["explanation"]


def test_amount_and_signature_checks_bind_the_changed_amount():
    amount_result = demo_service.run_demo("transaction-amount")
    signature_result = demo_service.run_demo("digital-signature")

    assert amount_result["details"]["original_amount"] == "125.50"
    assert amount_result["details"]["modified_amount"] == "126.50"
    assert amount_result["details"]["calculated_hash_matches"] is False
    assert amount_result["details"]["independent_transaction_hash"] is False
    assert signature_result["details"]["original_signature_valid"] is True
    assert signature_result["details"]["modified_payload_signature_valid"] is False


def test_recomputed_block_hash_does_not_restore_the_next_link():
    result = demo_service.run_demo("recomputed-hash")

    assert result["details"]["recomputed_block_valid"] is True
    assert result["details"]["next_previous_hash_valid"] is False
    assert result["details"]["next_block_valid"] is False
    assert result["detected"] is True


def test_repeat_and_reset_always_use_a_fresh_valid_baseline():
    first = demo_service.run_demo("block-data")
    demo_service.record_demo_result(first, "authorized-demo-user")
    assert demo_service.history_snapshot()["summary"]["detected"] == 1

    cleared = demo_service.reset_demo_history()
    second = demo_service.run_demo("block-data")

    assert cleared["results"] == []
    assert cleared["history"] == []
    assert second["baseline_status"] == "VALID"
    assert second["detected"] is True


def test_demonstrations_do_not_change_application_accounts_or_ledger():
    _reset_database()
    user = _create_user(UserRole.CUSTOMER)
    with SessionLocal() as db:
        db.add(
            Account(
                user_id=user.id,
                account_number=f"REALISH-{uuid.uuid4().hex[:12]}",
                account_type=AccountType.SAVINGS,
                balance=Decimal("4321.00"),
                status=AccountStatus.ACTIVE,
            )
        )
        db.commit()
        before = (
            db.query(User).count(),
            db.query(Account).count(),
            db.query(demo_service.Transaction).count(),
            db.query(demo_service.Block).count(),
            [str(account.balance) for account in db.query(Account).order_by(Account.id)],
        )

    for scenario_id in demo_service.SCENARIOS:
        assert demo_service.run_demo(scenario_id)["baseline_status"] == "VALID"

    with SessionLocal() as db:
        after = (
            db.query(User).count(),
            db.query(Account).count(),
            db.query(demo_service.Transaction).count(),
            db.query(demo_service.Block).count(),
            [str(account.balance) for account in db.query(Account).order_by(Account.id)],
        )
    assert after == before


def test_lab_page_and_execution_require_staff_role():
    _reset_database()
    customer = _create_user(UserRole.CUSTOMER)
    client = app.test_client()
    _login(client, customer)

    assert client.get("/security/lab").status_code == 403
    assert client.post("/api/security/lab/run/block-data").status_code == 403


def test_lab_routes_require_authentication_and_csrf():
    _reset_database()
    anonymous = app.test_client()
    assert anonymous.get("/api/security/lab/history").status_code == 401

    analyst = _create_user(UserRole.SECURITY_ANALYST)
    client = app.test_client()
    _login(client, analyst)
    assert client.get("/security/lab").status_code == 200
    assert client.post("/api/security/lab/run/block-data", csrf=False).status_code == 400
    assert client.post("/api/security/lab/run/not-allowlisted").status_code == 400


def test_verification_error_is_not_reported_as_detection(monkeypatch):
    def fail_validation(_db):
        raise RuntimeError("private internal detail")

    monkeypatch.setattr(demo_service, "validate_chain", fail_validation)
    result = demo_service.run_demo("transaction-amount")

    assert result["status"] == "VERIFICATION_ERROR"
    assert result["detected"] is False
    assert result["operation_completed"] is False
    assert "private internal detail" not in result["explanation"]


def test_unsupported_signature_provider_is_reported_as_unsupported(monkeypatch):
    def unsupported(*_args, **_kwargs):
        raise NotImplementedError("provider does not support this operation")

    monkeypatch.setattr(demo_service.CryptoSignatureService, "sign_transaction", unsupported)
    result = demo_service.run_demo("digital-signature")

    assert result["status"] == "UNSUPPORTED"
    assert result["detected"] is False
    assert result["operation_completed"] is False


def test_history_and_reset_endpoints_are_staff_only_and_keep_synthetic_results():
    _reset_database()
    analyst = _create_user(UserRole.SECURITY_ANALYST)
    client = app.test_client()
    _login(client, analyst)

    run_response = client.post("/api/security/lab/run/previous-hash")
    assert run_response.status_code == 200
    run_payload = run_response.get_json()
    assert run_payload["result"]["detected"] is True
    assert run_payload["summary"]["detected"] == 1
    assert "initiating_user_id" not in run_payload["results"][0]

    reset_response = client.post("/api/security/lab/reset")
    assert reset_response.status_code == 200
    assert reset_response.get_json()["results"] == []
