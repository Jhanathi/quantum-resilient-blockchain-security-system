from __future__ import annotations

from sqlalchemy.orm import Session

from backend.models.account import Account


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
