from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from backend.models.audit_log import AuditLog
from backend.models.block import Block
from backend.models.deposit import Deposit
from backend.models.transaction import Transaction, TransactionStatus
from backend.services.crypto_service import CryptoSignatureService

GENESIS_PREVIOUS_HASH = "0" * 64


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _transaction_reference(transaction: Transaction) -> dict[str, Any]:
    signature = transaction.signature
    return {
        "id": transaction.id,
        "transaction_id": transaction.transaction_id,
        "sender_account_id": transaction.sender_account_id,
        "receiver_account_id": transaction.receiver_account_id,
        "amount": str(transaction.amount),
        "currency": transaction.currency,
        "status": transaction.status.value if getattr(transaction.status, "value", None) else str(transaction.status),
        "created_at": _as_utc_iso(transaction.created_at),
        "signature_id": signature.id if signature else None,
        "signature_hex": signature.signature_hex if signature else None,
        "public_key_hex": signature.public_key_hex if signature else None,
        "canonical_payload": signature.canonical_payload if signature else None,
    }


def _block_content(block: Block) -> dict[str, Any]:
    content = {
        "block_index": block.block_number,
        "timestamp": _as_utc_iso(block.timestamp),
        "previous_hash": block.previous_hash,
        "transaction_count": block.transaction_count,
        "transactions": [
            _transaction_reference(transaction)
            for transaction in sorted(block.transactions, key=lambda item: item.transaction_id)
        ],
    }
    if block.deposits:
        content["deposits"] = [
            {
                "transaction_id": deposit.transaction_id,
                "account_id": deposit.account_id,
                "amount": str(deposit.amount),
                "currency": deposit.currency,
                "status": deposit.status,
                "created_at": _as_utc_iso(deposit.created_at),
            }
            for deposit in sorted(block.deposits, key=lambda item: item.transaction_id)
        ]
    return content


def calculate_block_hash(block: Block) -> str:
    canonical = json.dumps(_block_content(block), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _block_size(block: Block) -> int:
    payload = {**_block_content(block), "block_hash": block.block_hash}
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def ensure_genesis_block(db: Session) -> Block:
    genesis = db.query(Block).filter_by(block_number=0).one_or_none()
    if genesis is not None:
        return genesis

    genesis = Block(
        block_number=0,
        timestamp=datetime(1970, 1, 1, tzinfo=timezone.utc),
        previous_hash=GENESIS_PREVIOUS_HASH,
        block_hash="",
        transaction_count=0,
        block_size_bytes=0,
    )
    db.add(genesis)
    db.flush()
    genesis.block_hash = calculate_block_hash(genesis)
    genesis.block_size_bytes = _block_size(genesis)
    db.flush()
    return genesis


def _get_transaction(db: Session, identifier: str) -> Transaction | None:
    return db.query(Transaction).filter(
        (Transaction.id == identifier) | (Transaction.transaction_id == identifier)
    ).one_or_none()


def add_transaction_to_ledger(db: Session, transaction_id: str, *, user_id: str | None = None) -> Block:
    transaction = _get_transaction(db, transaction_id)
    if transaction is None:
        raise ValueError("Transaction not found.")
    if transaction.block is not None:
        return transaction.block
    if transaction.status != TransactionStatus.COMPLETED:
        raise ValueError("Only completed transactions can be added to the ledger.")
    if transaction.aqrs_decision is None:
        raise ValueError("Transaction AQRS decision is required before ledger inclusion.")
    if transaction.signature is None or transaction.signature.verification_status != "VERIFIED":
        raise ValueError("A verified ML-DSA signature is required before ledger inclusion.")

    verification = CryptoSignatureService.verify_transaction_signature(db, transaction.id)
    if not verification["valid"]:
        raise ValueError("Transaction signature verification failed.")

    ensure_genesis_block(db)
    previous = db.query(Block).order_by(Block.block_number.desc()).first()
    assert previous is not None
    block = Block(
        block_number=previous.block_number + 1,
        timestamp=_utc_now(),
        previous_hash=previous.block_hash,
        block_hash="",
        transaction_count=1,
        block_size_bytes=0,
    )
    block.transactions.append(transaction)
    db.add(block)
    db.flush()
    block.block_hash = calculate_block_hash(block)
    block.block_size_bytes = _block_size(block)
    db.add(
        AuditLog(
            user_id=user_id,
            transaction_id=transaction.id,
            event_type="BLOCK_CREATED",
            status="success",
            message="Verified transaction added to the persistent tamper-evident ledger.",
            metadata_={
                "block_number": block.block_number,
                "block_hash": block.block_hash,
                "previous_hash": block.previous_hash,
            },
        )
    )
    db.flush()
    return block


def add_deposit_to_ledger(db: Session, deposit: Deposit, *, user_id: str | None = None) -> Block:
    if deposit.status != "COMPLETED":
        raise ValueError("Only completed deposits can be added to the ledger.")
    if deposit.block is not None:
        return deposit.block

    ensure_genesis_block(db)
    previous = db.query(Block).order_by(Block.block_number.desc()).first()
    assert previous is not None
    block = Block(
        block_number=previous.block_number + 1,
        timestamp=_utc_now(),
        previous_hash=previous.block_hash,
        block_hash="",
        transaction_count=1,
        block_size_bytes=0,
    )
    block.deposits.append(deposit)
    db.add(block)
    db.flush()
    block.block_hash = calculate_block_hash(block)
    block.block_size_bytes = _block_size(block)
    db.add(
        AuditLog(
            user_id=user_id,
            event_type="BLOCK_CREATED",
            status="success",
            message="Simulated deposit was added to the tamper-evident ledger.",
            metadata_={
                "block_number": block.block_number,
                "block_hash": block.block_hash,
                "previous_hash": block.previous_hash,
                "deposit_reference": deposit.transaction_id,
            },
        )
    )
    db.flush()
    return block


def validate_block(db: Session, block: Block) -> dict[str, Any]:
    calculated_hash = calculate_block_hash(block)
    previous = db.query(Block).filter_by(block_number=block.block_number - 1).one_or_none()
    previous_valid = (
        block.previous_hash == GENESIS_PREVIOUS_HASH
        if block.block_number == 0
        else previous is not None and block.previous_hash == previous.block_hash
    )
    entry_count = len(block.transactions) + len(block.deposits)
    valid = calculated_hash == block.block_hash and block.transaction_count == entry_count and previous_valid
    return {
        "block_number": block.block_number,
        "block_hash": block.block_hash,
        "calculated_hash": calculated_hash,
        "valid": valid,
        "previous_hash_valid": previous_valid,
        "transaction_count": block.transaction_count,
    }


def validate_chain(db: Session) -> dict[str, Any]:
    blocks = db.query(Block).order_by(Block.block_number.asc()).all()
    errors: list[str] = []
    if not blocks or blocks[0].block_number != 0:
        errors.append("Genesis block is missing.")
    for expected_index, block in enumerate(blocks):
        if block.block_number != expected_index:
            errors.append(f"Block index gap at {block.block_number}.")
        result = validate_block(db, block)
        if not result["valid"]:
            errors.append(f"Block {block.block_number} failed validation.")
    return {"valid": not errors, "block_count": len(blocks), "errors": errors}


def get_block(db: Session, block_number: int) -> Block | None:
    return db.query(Block).filter_by(block_number=block_number).one_or_none()


def get_chain(db: Session) -> list[Block]:
    return db.query(Block).order_by(Block.block_number.asc()).all()


def get_transaction_block(db: Session, transaction_id: str) -> Block | None:
    transaction = _get_transaction(db, transaction_id)
    return transaction.block if transaction else None


__all__ = [
    "GENESIS_PREVIOUS_HASH",
    "add_transaction_to_ledger",
    "add_deposit_to_ledger",
    "calculate_block_hash",
    "ensure_genesis_block",
    "get_block",
    "get_chain",
    "get_transaction_block",
    "validate_block",
    "validate_chain",
]