from __future__ import annotations

import uuid
from decimal import Decimal
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.models.account import Account, AccountStatus, AccountType


class AccountService:
    @staticmethod
    def get_owned_account_ids(db: Session, user_id: str) -> set[str]:
        rows = db.query(Account.id).filter_by(user_id=user_id).all()
        return {row[0] for row in rows}

    @staticmethod
    def get_account_by_id(db: Session, account_id: str) -> Account | None:
        return db.get(Account, account_id)

    @staticmethod
    def get_account_by_number(db: Session, account_number: str) -> Account | None:
        return db.query(Account).filter_by(account_number=account_number).one_or_none()

    @staticmethod
    def get_account_by_identifier(
        db: Session,
        identifier: str,
        *,
        allow_id: bool = False,
    ) -> Account | None:
        account = AccountService.get_account_by_number(db, identifier)
        if account is None and allow_id:
            account = AccountService.get_account_by_id(db, identifier)
        return account

    @staticmethod
    def get_account_for_user(db: Session, user_id: str, account_id: str) -> Account | None:
        return db.query(Account).filter_by(id=account_id, user_id=user_id).first()

    @staticmethod
    def create_account(db: Session, user_id: str, account_type: AccountType) -> Account:
        for _ in range(5):
            account_number = f"INR-{uuid.uuid4().hex[:12].upper()}"
            if AccountService.get_account_by_number(db, account_number) is not None:
                continue
            account = Account(
                user_id=user_id,
                account_number=account_number,
                account_type=account_type,
                balance=Decimal("0.00"),
                currency="INR",
                status=AccountStatus.ACTIVE,
            )
            db.add(account)
            try:
                db.flush()
            except IntegrityError:
                db.rollback()
                continue
            return account
        raise RuntimeError("A unique account number could not be generated.")
