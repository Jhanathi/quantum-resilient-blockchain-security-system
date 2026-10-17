from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from threading import RLock
from typing import Any, Iterator
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database.database import Base
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.block import Block
from backend.models.transaction import RiskLevel, Transaction, TransactionStatus
from backend.models.user import User, UserRole
from backend.services.blockchain_service import (
    GENESIS_PREVIOUS_HASH,
    calculate_block_hash,
    validate_block,
    validate_chain,
)
from backend.services.crypto_service import (
    CryptoSignatureService,
    canonical_transaction_payload,
)

_HISTORY_LIMIT = 100
_history: list[dict[str, Any]] = []
_history_lock = RLock()

SCENARIOS: dict[str, dict[str, str]] = {
    "transaction-amount": {
        "name": "Transaction amount tampering",
        "description": "Change the amount in a demo transaction without changing its containing block hash.",
        "expected": "The block hash should no longer match its transaction data.",
    },
    "block-data": {
        "name": "Block data tampering",
        "description": "Change a demo block field without rebuilding the block hash.",
        "expected": "Block and chain validation should report inconsistent data.",
    },
    "previous-hash": {
        "name": "Previous-hash link tampering",
        "description": "Replace a non-genesis block's link to its predecessor.",
        "expected": "The previous-hash relationship and block integrity should fail validation.",
    },
    "digital-signature": {
        "name": "Digital-signature tampering",
        "description": "Change the amount covered by a demo ML-DSA signature without signing it again.",
        "expected": "The original signature should not verify against the changed payload.",
    },
    "recomputed-hash": {
        "name": "Recomputed hash demonstration",
        "description": "Change block data and recompute that block's hash without updating the next block.",
        "expected": "The next block's previous-hash link should remain invalid.",
    },
}

_DEMO_TIME = datetime(2024, 1, 1, tzinfo=timezone.utc)


@contextmanager
def _isolated_demo_database() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, future=True)
    try:
        with factory() as db:
            demo_user = User(
                id="00000000-0000-4000-8000-000000000012",
                name="Synthetic Security Lab User",
                username="security-lab-demo",
                email="security-lab-demo@example.invalid",
                password_hash="not-a-credential",
                role=UserRole.CUSTOMER,
                is_active=True,
            )
            sender = Account(
                id="00000000-0000-4000-8000-000000000021",
                user_id=demo_user.id,
                account_number="DEMO-ACCOUNT-001",
                account_type=AccountType.SAVINGS,
                balance=Decimal("10000.00"),
                status=AccountStatus.ACTIVE,
            )
            receiver = Account(
                id="00000000-0000-4000-8000-000000000022",
                user_id=demo_user.id,
                account_number="DEMO-ACCOUNT-002",
                account_type=AccountType.SAVINGS,
                balance=Decimal("10000.00"),
                status=AccountStatus.ACTIVE,
            )
            db.add_all([demo_user, sender, receiver])
            db.flush()
            yield db
    finally:
        engine.dispose()


def _new_demo_transaction(db: Session, *, transaction_id: str = "DEMO-TXN-001") -> Transaction:
    transaction = Transaction(
        id="00000000-0000-4000-8000-000000000031",
        transaction_id=transaction_id,
        sender_account_id="00000000-0000-4000-8000-000000000021",
        receiver_account_id="00000000-0000-4000-8000-000000000022",
        amount=Decimal("125.50"),
        currency="INR",
        description="Synthetic security lab transaction",
        status=TransactionStatus.COMPLETED,
        risk_level=RiskLevel.LOW,
        risk_score=Decimal("0.00"),
        aqrs_level=2,
        cryptographic_mode="ML-DSA-44",
        created_at=_DEMO_TIME,
        updated_at=_DEMO_TIME,
    )
    db.add(transaction)
    db.flush()
    return transaction


def _new_demo_chain(db: Session) -> tuple[Transaction, list[Block]]:
    transaction = _new_demo_transaction(db)
    genesis = Block(
        block_number=0,
        timestamp=_DEMO_TIME,
        previous_hash=GENESIS_PREVIOUS_HASH,
        block_hash="",
        transaction_count=0,
        block_size_bytes=0,
    )
    db.add(genesis)
    db.flush()
    genesis.block_hash = calculate_block_hash(genesis)
    db.flush()

    second = Block(
        block_number=1,
        timestamp=_DEMO_TIME,
        previous_hash=genesis.block_hash,
        block_hash="",
        transaction_count=1,
        block_size_bytes=0,
    )
    second.transactions.append(transaction)
    db.add(second)
    db.flush()
    second.block_hash = calculate_block_hash(second)
    db.flush()

    third = Block(
        block_number=2,
        timestamp=_DEMO_TIME,
        previous_hash=second.block_hash,
        block_hash="",
        transaction_count=0,
        block_size_bytes=0,
    )
    db.add(third)
    db.flush()
    third.block_hash = calculate_block_hash(third)
    db.flush()
    return transaction, [genesis, second, third]


def _result(
    *,
    scenario_id: str,
    baseline_status: str,
    post_status: str,
    detected: bool,
    operation_completed: bool,
    explanation: str,
    details: dict[str, Any],
) -> dict[str, Any]:
    scenario = SCENARIOS[scenario_id]
    return {
        "scenario_id": scenario_id,
        "name": scenario["name"],
        "description": scenario["description"],
        "expected_outcome": scenario["expected"],
        "baseline_status": baseline_status,
        "status": post_status,
        "post_tampering_status": post_status,
        "detected": detected,
        "operation_completed": operation_completed,
        "explanation": explanation,
        "details": details,
    }


def _run_chain_scenario(scenario_id: str) -> dict[str, Any]:
    with _isolated_demo_database() as db:
        transaction, blocks = _new_demo_chain(db)
        baseline = validate_chain(db)
        if not baseline["valid"]:
            return _result(
                scenario_id=scenario_id,
                baseline_status="INVALID",
                post_status="VERIFICATION_ERROR",
                detected=False,
                operation_completed=False,
                explanation="The isolated demo chain was not valid before tampering; no detection conclusion is reported.",
                details={"baseline_errors": baseline["errors"]},
            )

        if scenario_id == "transaction-amount":
            original = str(transaction.amount)
            transaction.amount = Decimal("126.50")
            db.flush()
            block_result = validate_block(db, blocks[1])
            chain_result = validate_chain(db)
            detected = not block_result["valid"] and not chain_result["valid"]
            return _result(
                scenario_id=scenario_id,
                baseline_status="VALID",
                post_status="INVALID" if not chain_result["valid"] else "VALID",
                detected=detected,
                operation_completed=True,
                explanation=(
                    "The transaction amount is included in the block's canonical data. "
                    "Changing it without rebuilding the stored block hash makes the calculated hash differ."
                    if detected
                    else "The verifier accepted the changed amount; this implementation did not detect this alteration."
                ),
                details={
                    "transaction_id": transaction.transaction_id,
                    "original_amount": original,
                    "modified_amount": str(transaction.amount),
                    "independent_transaction_hash": False,
                    "block_number": blocks[1].block_number,
                    "block_valid": block_result["valid"],
                    "calculated_hash_matches": block_result["calculated_hash"] == block_result["block_hash"],
                    "chain_errors": chain_result["errors"],
                },
            )

        if scenario_id == "block-data":
            block = blocks[1]
            original_count = block.transaction_count
            block.transaction_count += 1
            db.flush()
            block_result = validate_block(db, block)
            chain_result = validate_chain(db)
            detected = not block_result["valid"] and not chain_result["valid"]
            return _result(
                scenario_id=scenario_id,
                baseline_status="VALID",
                post_status="INVALID" if not chain_result["valid"] else "VALID",
                detected=detected,
                operation_completed=True,
                explanation=(
                    "The changed transaction count no longer matches the canonical block hash or actual transaction count."
                    if detected
                    else "The verifier accepted the changed block field; this implementation did not detect this alteration."
                ),
                details={
                    "block_number": block.block_number,
                    "original_transaction_count": original_count,
                    "modified_transaction_count": block.transaction_count,
                    "block_valid": block_result["valid"],
                    "transaction_count_matches": block_result["transaction_count"] == len(block.transactions),
                    "calculated_hash_matches": block_result["calculated_hash"] == block_result["block_hash"],
                    "chain_errors": chain_result["errors"],
                },
            )

        if scenario_id == "previous-hash":
            block = blocks[2]
            original_hash = block.previous_hash
            block.previous_hash = "f" * 64
            db.flush()
            block_result = validate_block(db, block)
            chain_result = validate_chain(db)
            detected = not block_result["previous_hash_valid"] and not chain_result["valid"]
            return _result(
                scenario_id=scenario_id,
                baseline_status="VALID",
                post_status="INVALID" if not chain_result["valid"] else "VALID",
                detected=detected,
                operation_completed=True,
                explanation=(
                    "Block 2 no longer points to block 1's stored hash, and its changed link also invalidates its own hash."
                    if detected
                    else "The verifier accepted the changed previous-hash link."
                ),
                details={
                    "block_number": block.block_number,
                    "previous_block_number": blocks[1].block_number,
                    "original_previous_hash": original_hash,
                    "modified_previous_hash": block.previous_hash,
                    "previous_hash_valid": block_result["previous_hash_valid"],
                    "block_valid": block_result["valid"],
                    "chain_errors": chain_result["errors"],
                },
            )

        if scenario_id == "recomputed-hash":
            changed_block = blocks[1]
            next_block = blocks[2]
            original_timestamp = changed_block.timestamp
            changed_block.timestamp = changed_block.timestamp + timedelta(seconds=1)
            db.flush()
            changed_block.block_hash = calculate_block_hash(changed_block)
            db.flush()
            changed_block_result = validate_block(db, changed_block)
            next_block_result = validate_block(db, next_block)
            chain_result = validate_chain(db)
            detected = (
                changed_block_result["valid"]
                and not next_block_result["previous_hash_valid"]
                and not chain_result["valid"]
            )
            return _result(
                scenario_id=scenario_id,
                baseline_status="VALID",
                post_status="INVALID" if not chain_result["valid"] else "VALID",
                detected=detected,
                operation_completed=True,
                explanation=(
                    "Recomputing block 1 makes that block's own hash consistent, but block 2 still references the old hash. "
                    "The full chain therefore remains invalid."
                    if detected
                    else "The verifier accepted the recomputed block without requiring its successor's link to match."
                ),
                details={
                    "recomputed_block_number": changed_block.block_number,
                    "original_timestamp": original_timestamp.isoformat(),
                    "modified_timestamp": changed_block.timestamp.isoformat(),
                    "recomputed_block_valid": changed_block_result["valid"],
                    "next_block_number": next_block.block_number,
                    "next_previous_hash_valid": next_block_result["previous_hash_valid"],
                    "next_block_valid": next_block_result["valid"],
                    "chain_errors": chain_result["errors"],
                },
            )

    raise ValueError("Unknown blockchain demonstration scenario.")


def _run_signature_scenario() -> dict[str, Any]:
    scenario_id = "digital-signature"
    with _isolated_demo_database() as db:
        transaction = _new_demo_transaction(db, transaction_id="DEMO-TXN-SIGNATURE")
        try:
            signing = CryptoSignatureService.sign_transaction(db, transaction.transaction_id)
            if not signing["valid"]:
                return _result(
                    scenario_id=scenario_id,
                    baseline_status="INVALID",
                    post_status="VERIFICATION_ERROR",
                    detected=False,
                    operation_completed=False,
                    explanation="The isolated transaction could not be signed and verified before tampering.",
                    details={"transaction_id": transaction.transaction_id},
                )
            baseline = CryptoSignatureService.verify_transaction_signature(db, transaction.id)
            if not baseline["valid"]:
                return _result(
                    scenario_id=scenario_id,
                    baseline_status="INVALID",
                    post_status="VERIFICATION_ERROR",
                    detected=False,
                    operation_completed=False,
                    explanation="The original demo signature did not verify; no tampering conclusion is reported.",
                    details={"transaction_id": transaction.transaction_id},
                )

            original_amount = str(transaction.amount)
            transaction.amount = Decimal("126.50")
            changed_payload = canonical_transaction_payload(transaction, transaction.aqrs_decision)
            post = CryptoSignatureService.verify_canonical_payload(db, transaction.id, changed_payload)
            detected = baseline["valid"] and not post["valid"]
            return _result(
                scenario_id=scenario_id,
                baseline_status="VALID",
                post_status="INVALID" if not post["valid"] else "VALID",
                detected=detected,
                operation_completed=True,
                explanation=(
                    "The signature verifies the original canonical transaction payload. "
                    "Changing the signed amount without a new signature causes ML-DSA verification to fail."
                    if detected
                    else "The verifier accepted the changed signed payload."
                ),
                details={
                    "transaction_id": transaction.transaction_id,
                    "algorithm": baseline["algorithm"],
                    "original_amount": original_amount,
                    "modified_amount": str(transaction.amount),
                    "original_signature_valid": baseline["valid"],
                    "modified_payload_signature_valid": post["valid"],
                },
            )
        except NotImplementedError:
            return _result(
                scenario_id=scenario_id,
                baseline_status="UNSUPPORTED",
                post_status="UNSUPPORTED",
                detected=False,
                operation_completed=False,
                explanation="The configured signature provider does not support this verification operation.",
                details={"transaction_id": transaction.transaction_id},
            )


def run_demo(scenario_id: str) -> dict[str, Any]:
    if scenario_id not in SCENARIOS:
        raise ValueError("Unsupported security demonstration scenario.")

    try:
        if scenario_id == "digital-signature":
            return _run_signature_scenario()
        return _run_chain_scenario(scenario_id)
    except NotImplementedError:
        return _result(
            scenario_id=scenario_id,
            baseline_status="UNSUPPORTED",
            post_status="UNSUPPORTED",
            detected=False,
            operation_completed=False,
            explanation="The current implementation does not support this verification operation.",
            details={},
        )
    except Exception:
        return _result(
            scenario_id=scenario_id,
            baseline_status="VERIFICATION_ERROR",
            post_status="VERIFICATION_ERROR",
            detected=False,
            operation_completed=False,
            explanation="Verification could not be completed. No tampering-detection result is claimed.",
            details={},
        )


def record_demo_result(result: dict[str, Any], user_id: str) -> dict[str, Any]:
    if result.get("scenario_id") not in SCENARIOS:
        raise ValueError("Unsupported security demonstration scenario.")
    record = {
        **deepcopy(result),
        "execution_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "initiating_user_id": user_id,
    }
    with _history_lock:
        _history.append(record)
        del _history[:-_HISTORY_LIMIT]
    return history_snapshot()


def _summary(results: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"detected": 0, "failed_to_detect": 0, "unsupported": 0, "errored": 0}
    for result in results:
        if result["detected"]:
            counts["detected"] += 1
        elif result["status"] == "UNSUPPORTED":
            counts["unsupported"] += 1
        elif result["status"] == "VERIFICATION_ERROR":
            counts["errored"] += 1
        else:
            counts["failed_to_detect"] += 1
    return counts


def history_snapshot() -> dict[str, Any]:
    with _history_lock:
        records = deepcopy(_history)
    latest_by_scenario: dict[str, dict[str, Any]] = {}
    for record in records:
        latest_by_scenario[record["scenario_id"]] = record
    latest_results = list(latest_by_scenario.values())
    public_history = [
        {
            "execution_id": record["execution_id"],
            "scenario_id": record["scenario_id"],
            "name": record["name"],
            "timestamp": record["timestamp"],
            "baseline_status": record["baseline_status"],
            "status": record["status"],
            "detected": record["detected"],
        }
        for record in reversed(records)
    ]
    return {
        "results": [
            {key: value for key, value in result.items() if key != "initiating_user_id"}
            for result in latest_results
        ],
        "history": public_history,
        "summary": _summary(latest_results),
    }


def reset_demo_history() -> dict[str, Any]:
    with _history_lock:
        _history.clear()
    return history_snapshot()


__all__ = [
    "SCENARIOS",
    "history_snapshot",
    "record_demo_result",
    "reset_demo_history",
    "run_demo",
]
