from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.database import Base

if TYPE_CHECKING:
    from backend.models.account import Account
    from backend.models.block import Block


class Deposit(Base):
    __tablename__ = "simulated_deposits"
    __table_args__ = (CheckConstraint("amount > 0", name="ck_simulated_deposits_amount_positive"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    transaction_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    block_id: Mapped[str | None] = mapped_column(ForeignKey("blocks.id"), nullable=True, index=True)
    amount: Mapped[Decimal] = mapped_column(Numeric(15, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="COMPLETED", nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="Simulated demo credit", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    account: Mapped["Account"] = relationship(back_populates="deposits")
    block: Mapped["Block | None"] = relationship(back_populates="deposits")

    @property
    def transaction_type(self) -> str:
        return "DEPOSIT"
