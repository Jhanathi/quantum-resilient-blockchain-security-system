from __future__ import annotations

import os
from decimal import Decimal

from sqlalchemy import select
from werkzeug.security import generate_password_hash

from backend.config import DATABASE_URL, PRODUCTION_DATABASE_PATH, is_production_database
from backend.database.database import SessionLocal, create_tables
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.transaction import RiskLevel, Transaction, TransactionStatus
from backend.models.user import User, UserRole


def seed_database(*, admin_password: str, customer_password: str, allow_production: bool = False) -> dict[str, int]:
    """Create development/demo entities for local database work.

    This is explicitly demo data and should not be used in production without an
    explicit opt-in.
    """
    target_url = os.getenv("DATABASE_URL", DATABASE_URL)
    if is_production_database(target_url) and not allow_production:
        raise RuntimeError(
            "Refusing to seed demo data in the production database. "
            "Set DATABASE_URL to a temporary SQLite database or pass allow_production=True for an explicit maintenance action."
        )

    for label, password in (("admin", admin_password), ("customer", customer_password)):
        if len(password) < 8 or not any(char.isupper() for char in password) or not any(char.islower() for char in password) or not any(char.isdigit() for char in password):
            raise ValueError(f"The {label} password must include at least 8 characters, uppercase, lowercase, and a number.")

    create_tables()
    session = SessionLocal()
    try:
        users = session.execute(select(User)).scalars().all()
        user_count = len(users)
        if user_count > 0:
            accounts = session.execute(select(Account)).scalars().count()
            transactions = session.execute(select(Transaction)).scalars().count()
            return {"users": user_count, "accounts": accounts, "transactions": transactions}

        admin = User(
            name="Admin User",
            username="admin",
            email="admin@example.com",
            password_hash=generate_password_hash(admin_password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        customer1 = User(
            name="Customer One",
            username="customer1",
            email="customer1@example.com",
            password_hash=generate_password_hash(customer_password),
            role=UserRole.CUSTOMER,
            is_active=True,
        )
        customer2 = User(
            name="Customer Two",
            username="customer2",
            email="customer2@example.com",
            password_hash=generate_password_hash(customer_password),
            role=UserRole.CUSTOMER,
            is_active=True,
        )
        session.add_all([admin, customer1, customer2])
        session.flush()

        acct1 = Account(
            user_id=customer1.id,
            account_number="INR-10001",
            account_type=AccountType.SAVINGS,
            balance=Decimal("25000.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        acct2 = Account(
            user_id=customer2.id,
            account_number="INR-10002",
            account_type=AccountType.CURRENT,
            balance=Decimal("15000.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        session.add_all([acct1, acct2])
        session.flush()

        tx1 = Transaction(
            transaction_id="TX-DEMO-001",
            sender_account_id=acct1.id,
            receiver_account_id=acct2.id,
            amount=Decimal("1250.00"),
            currency="INR",
            description="Demo customer transfer",
            status=TransactionStatus.SUCCESS,
            risk_level=RiskLevel.MEDIUM,
            risk_score=Decimal("42.50"),
            aqrs_level=3,
            cryptographic_mode="ML-DSA",
        )
        session.add(tx1)
        session.commit()

        return {"users": 3, "accounts": 2, "transactions": 1}
    finally:
        session.close()


__all__ = ["seed_database"]
