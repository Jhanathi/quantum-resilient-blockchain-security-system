from __future__ import annotations

import uuid
from decimal import Decimal, InvalidOperation

from sqlalchemy import update
from sqlalchemy.orm import Session

from backend.models.account import Account, AccountStatus
from backend.models.transaction import Transaction, TransactionStatus


class ValidationError(ValueError):
    pass


class AuthorizationError(PermissionError):
    pass


class InsufficientBalanceError(ValueError):
    pass


class TransactionService:
    @staticmethod
    def parse_amount(raw_amount: object) -> Decimal:
        if raw_amount is None or str(raw_amount).strip() == "":
            raise ValidationError("Transaction amount is required.")
        try:
            amount = Decimal(str(raw_amount))
        except (InvalidOperation, ValueError, TypeError) as exc:
            raise ValidationError("Transaction amount must be a valid decimal value.") from exc

        if not amount.is_finite():
            raise ValidationError("Transaction amount must be a valid decimal value.")
        if amount <= 0:
            raise ValidationError("Transaction amount must be greater than zero.")
        if amount > Decimal("1000000000000"):
            raise ValidationError("Transaction amount exceeds the allowed maximum.")
        try:
            rounded_amount = amount.quantize(Decimal("0.01"))
        except InvalidOperation as exc:
            raise ValidationError("Transaction amount has unsupported precision.") from exc
        if rounded_amount != amount:
            raise ValidationError("Transaction amount supports at most two decimal places.")
        return rounded_amount

    @staticmethod
    def validate_account_state(account: Account) -> None:
        if account.status != AccountStatus.ACTIVE:
            raise ValidationError(f"Account {account.account_number} is not active.")

    @staticmethod
    def apply_transfer_balances(
        db: Session,
        *,
        sender: Account,
        receiver: Account,
        amount: Decimal,
    ) -> None:
        if sender.id == receiver.id:
            raise ValidationError("Sender and receiver accounts must be different.")

        TransactionService.validate_account_state(sender)
        TransactionService.validate_account_state(receiver)
        if sender.currency != receiver.currency:
            raise ValidationError("Sender and recipient accounts must use the same currency.")

        debit = db.execute(
            update(Account)
            .where(
                Account.id == sender.id,
                Account.status == AccountStatus.ACTIVE,
                Account.balance >= amount,
            )
            .values(balance=Account.balance - amount)
            .execution_options(synchronize_session=False)
        )
        if debit.rowcount != 1:
            db.refresh(sender)
            TransactionService.validate_account_state(sender)
            if amount > sender.balance:
                raise InsufficientBalanceError("Insufficient balance for transfer.")
            raise ValidationError("Sender account changed during transfer. Please retry.")

        credit = db.execute(
            update(Account)
            .where(
                Account.id == receiver.id,
                Account.status == AccountStatus.ACTIVE,
            )
            .values(balance=Account.balance + amount)
            .execution_options(synchronize_session=False)
        )
        if credit.rowcount != 1:
            db.refresh(receiver)
            TransactionService.validate_account_state(receiver)
            raise ValidationError("Recipient account changed during transfer. Please retry.")

        db.refresh(sender)
        db.refresh(receiver)

    @staticmethod
    def apply_deposit_balance(
        db: Session,
        *,
        account: Account,
        user_id: str,
        amount: Decimal,
    ) -> None:
        credit = db.execute(
            update(Account)
            .where(
                Account.id == account.id,
                Account.user_id == user_id,
                Account.status == AccountStatus.ACTIVE,
            )
            .values(balance=Account.balance + amount)
            .execution_options(synchronize_session=False)
        )
        if credit.rowcount != 1:
            db.refresh(account)
            if account.user_id != user_id:
                raise AuthorizationError("You can only deposit into your own account.")
            TransactionService.validate_account_state(account)
            raise ValidationError("Account changed during deposit. Please retry.")
        db.refresh(account)

    @staticmethod
    def create_transfer(
        db: Session,
        *,
        sender: Account,
        receiver: Account,
        amount: Decimal,
        description: str | None = None,
    ) -> Transaction:
        if sender.id == receiver.id:
            raise ValidationError("Sender and receiver accounts must be different.")

        TransactionService.validate_account_state(sender)
        TransactionService.validate_account_state(receiver)

        TransactionService.apply_transfer_balances(
            db,
            sender=sender,
            receiver=receiver,
            amount=amount,
        )

        transaction = Transaction(
            transaction_id=f"TX-{uuid.uuid4().hex[:12].upper()}",
            sender_account_id=sender.id,
            receiver_account_id=receiver.id,
            amount=amount,
            currency=sender.currency or receiver.currency or "INR",
            description=description or "Funds transfer",
            status=TransactionStatus.COMPLETED,
        )
        db.add(transaction)
        db.flush()
        return transaction

    @staticmethod
    def get_transactions_for_user(db: Session, user_id: str) -> list[Transaction]:
        from backend.models.account import Account

        user_account_ids = [row[0] for row in db.query(Account.id).filter_by(user_id=user_id).all()]
        if not user_account_ids:
            return []
        return (
            db.query(Transaction)
            .filter(
                (Transaction.sender_account_id.in_(user_account_ids))
                | (Transaction.receiver_account_id.in_(user_account_ids))
            )
            .order_by(Transaction.created_at.desc())
            .all()
        )

    @staticmethod
    def get_transaction_by_identifier(db: Session, identifier: str) -> Transaction | None:
        return (
            db.query(Transaction)
            .filter((Transaction.id == identifier) | (Transaction.transaction_id == identifier))
            .one_or_none()
        )

    @staticmethod
    def get_transaction_for_user(db: Session, user_id: str, transaction_id: str) -> Transaction | None:
        from backend.services.account_service import AccountService

        tx = TransactionService.get_transaction_by_identifier(db, transaction_id)
        if tx is None:
            return None
        user_account_ids = AccountService.get_owned_account_ids(db, user_id)
        if tx.sender_account_id in user_account_ids or tx.receiver_account_id in user_account_ids:
            return tx
        return None
