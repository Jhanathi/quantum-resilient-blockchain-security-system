from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from backend.database.database import DatabaseManager
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.aqrs_decision import AQRSDecision
from backend.models.block import Block
from backend.models.transaction import RiskLevel, Transaction, TransactionStatus
from backend.models.user import User, UserRole
from backend.services.blockchain_service import (
    GENESIS_PREVIOUS_HASH,
    add_transaction_to_ledger,
    calculate_block_hash,
    ensure_genesis_block,
    validate_chain,
)
from backend.services.crypto_service import CryptoSignatureService


@pytest.fixture
def db_session():
    manager = DatabaseManager("sqlite:///:memory:")
    manager.create_all()
    session = manager.SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _signed_transaction(db):
    user = User(name="Ledger User", username="ledger_user", email="ledger@example.com", password_hash="hash", role=UserRole.CUSTOMER)
    db.add(user)
    db.flush()
    sender = Account(user_id=user.id, account_number="LEDGER-S", account_type=AccountType.SAVINGS, balance=Decimal("1000.00"), currency="INR", status=AccountStatus.ACTIVE)
    receiver = Account(user_id=user.id, account_number="LEDGER-R", account_type=AccountType.CURRENT, balance=Decimal("100.00"), currency="INR", status=AccountStatus.ACTIVE)
    db.add_all([sender, receiver])
    db.flush()
    transaction = Transaction(
        transaction_id="TX-LEDGER-1",
        sender_account_id=sender.id,
        receiver_account_id=receiver.id,
        amount=Decimal("25.00"),
        currency="INR",
        status=TransactionStatus.COMPLETED,
        risk_level=RiskLevel.LOW,
        risk_score=Decimal("10.00"),
        aqrs_level=2,
        cryptographic_mode="ML-DSA-44",
    )
    db.add(transaction)
    db.flush()
    db.add(AQRSDecision(
        transaction_id=transaction.id,
        risk_score=Decimal("10.00"),
        risk_level=RiskLevel.LOW,
        selected_security_level=2,
        algorithm="ML-DSA-44",
        security_level="ML-DSA-44",
        decision_reason="Test decision",
        aqrs_score=Decimal("0.0100"),
    ))
    db.flush()
    CryptoSignatureService.sign_transaction(db, transaction.id)
    return transaction


def test_genesis_is_persistent_and_idempotent(db_session):
    first = ensure_genesis_block(db_session)
    second = ensure_genesis_block(db_session)

    assert first.id == second.id
    assert db_session.query(Block).filter_by(block_number=0).count() == 1
    assert first.block_index == 0
    assert first.previous_hash == GENESIS_PREVIOUS_HASH
    assert first.block_hash == calculate_block_hash(first)


def test_only_verified_completed_transactions_enter_ledger(db_session):
    transaction = _signed_transaction(db_session)
    block = add_transaction_to_ledger(db_session, transaction.id)

    assert block.block_index == 1
    assert block.previous_hash == db_session.query(Block).filter_by(block_number=0).one().block_hash
    assert transaction.block_id == block.id
    assert block.transaction_count == 1
    assert validate_chain(db_session)["valid"] is True

    with pytest.raises(ValueError, match="completed"):
        pending = Transaction(
            transaction_id="TX-LEDGER-PENDING",
            sender_account_id=transaction.sender_account_id,
            receiver_account_id=transaction.receiver_account_id,
            amount=Decimal("5.00"),
            status=TransactionStatus.PENDING,
        )
        db_session.add(pending)
        db_session.flush()
        add_transaction_to_ledger(db_session, pending.id)


def test_chain_validation_detects_block_tampering(db_session):
    transaction = _signed_transaction(db_session)
    block = add_transaction_to_ledger(db_session, transaction.id)
    db_session.commit()

    block.previous_hash = "f" * 64
    db_session.flush()
    result = validate_chain(db_session)

    assert result["valid"] is False
    assert result["errors"]


def test_chain_validation_detects_transaction_tampering(db_session):
    transaction = _signed_transaction(db_session)
    add_transaction_to_ledger(db_session, transaction.id)
    db_session.commit()

    transaction.amount = Decimal("99.00")
    db_session.flush()

    assert validate_chain(db_session)["valid"] is False


def test_chain_remains_valid_after_reloading_from_database(db_session):
    transaction = _signed_transaction(db_session)
    add_transaction_to_ledger(db_session, transaction.id)
    db_session.commit()

    reloaded_session = db_session.get_bind()
    from sqlalchemy.orm import Session

    with Session(reloaded_session) as fresh_session:
        result = validate_chain(fresh_session)
        assert result["valid"] is True
        assert result["block_count"] == 2
        assert fresh_session.query(Block).filter_by(block_number=1).one().transactions[0].transaction_id == transaction.transaction_id