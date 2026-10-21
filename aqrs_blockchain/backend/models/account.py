from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, Enum as SAEnum, ForeignKey, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.database import Base

if TYPE_CHECKING:
    from backend.models.deposit import Deposit
    from backend.models.transaction import Transaction
    from backend.models.user import User


class AccountType(str, Enum):
    SAVINGS = "SAVINGS"
    CURRENT = "CURRENT"


class AccountStatus(str, Enum):
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    CLOSED = "CLOSED"


class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = (CheckConstraint("balance >= 0", name="ck_accounts_balance_non_negative"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    account_number: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    account_type: Mapped[AccountType] = mapped_column(SAEnum(AccountType), nullable=False)
    balance: Mapped[Decimal] = mapped_column(Numeric(15, 2), default=Decimal("0.00"), nullable=False)
    currency: Mapped[str] = mapped_column(String(10), default="INR", nullable=False)
    status: Mapped[AccountStatus] = mapped_column(SAEnum(AccountStatus), default=AccountStatus.ACTIVE, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    user: Mapped["User"] = relationship(back_populates="accounts")
    transactions_sent: Mapped[list["Transaction"]] = relationship(
        back_populates="sender_account",
        foreign_keys="Transaction.sender_account_id",
    )
    transactions_received: Mapped[list["Transaction"]] = relationship(
        back_populates="receiver_account",
        foreign_keys="Transaction.receiver_account_id",
    )
    deposits: Mapped[list["Deposit"]] = relationship(back_populates="account")

    def __repr__(self) -> str:
        return f"Account(id={self.id}, account_number={self.account_number!r}, balance={self.balance})"
