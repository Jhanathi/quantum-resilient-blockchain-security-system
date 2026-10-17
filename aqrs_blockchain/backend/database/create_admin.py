from __future__ import annotations

import argparse
import getpass
import re

from sqlalchemy import func
from werkzeug.security import generate_password_hash

from backend.database.database import SessionLocal, create_tables
from backend.models.account import Account
from backend.models.aqrs_decision import AQRSDecision
from backend.models.audit_log import AuditLog
from backend.models.block import Block
from backend.models.experiment import Experiment
from backend.models.signature import Signature
from backend.models.transaction import Transaction
from backend.models.user import User, UserRole
from backend.services.security_audit_service import record_security_event


def create_admin_account(name: str, email: str, username: str, password: str) -> None:
    name = name.strip()
    email = email.strip().lower()
    username = username.strip()
    if not name or not username or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("A name, username, and valid email address are required.")
    if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"\d", password):
        raise ValueError("Password must be at least 8 characters and include uppercase, lowercase, and numeric characters.")

    create_tables()
    with SessionLocal() as db:
        if db.query(User).filter(func.lower(User.email) == email).first() is not None:
            raise ValueError("An account with this email already exists.")
        if db.query(User).filter(func.lower(User.username) == username.lower()).first() is not None:
            raise ValueError("This username is already taken.")
        admin = User(
            name=name,
            email=email,
            username=username,
            password_hash=generate_password_hash(password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(admin)
        db.flush()
        record_security_event(
            db,
            event_type="ADMIN_ACCOUNT_CREATED",
            severity="HIGH",
            title="Administrator account created",
            description="The administrator provisioning utility created a privileged account.",
            outcome="SUCCESS",
            source="admin_cli",
            category="ACCESS_CONTROL",
            target_type="user",
            target_id=admin.id,
            metadata={"role": UserRole.ADMIN.value},
        )
        db.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an administrator account for this database.")
    parser.add_argument("--name", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--username", required=True)
    args = parser.parse_args()

    password = getpass.getpass("Administrator password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        parser.error("Passwords do not match.")
    try:
        create_admin_account(args.name, args.email, args.username, password)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"Administrator account created for {args.email.strip().lower()}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())