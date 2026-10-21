from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.database import Base

if TYPE_CHECKING:
    from backend.models.deposit import Deposit
    from backend.models.transaction import Transaction


class Block(Base):
    __tablename__ = "blocks"
    __table_args__ = (CheckConstraint("transaction_count >= 0", name="ck_blocks_transaction_count_non_negative"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    block_number: Mapped[int] = mapped_column(Integer, unique=True, nullable=False, index=True)
    previous_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    block_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    transaction_count: Mapped[int] = mapped_column(Integer, nullable=False)
    block_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    transactions: Mapped[list["Transaction"]] = relationship(back_populates="block")
    deposits: Mapped[list["Deposit"]] = relationship(back_populates="block")

    @property
    def block_index(self) -> int:
        return self.block_number

    def __repr__(self) -> str:
        return f"Block(id={self.id}, block_number={self.block_number}, hash={self.block_hash})"
