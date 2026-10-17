from __future__ import annotations

import re

from sqlalchemy.orm import Session
from werkzeug.security import check_password_hash, generate_password_hash

from backend.models.user import User


class InvalidCurrentPassword(Exception):
    pass


class PasswordPolicyError(ValueError):
    pass


def password_policy_error(password: str) -> str | None:
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"\d", password):
        return "Password must include uppercase, lowercase, and numeric characters."
    return None


def change_password(db: Session, user: User, current_password: str, new_password: str) -> None:
    try:
        current_password_valid = check_password_hash(user.password_hash, current_password)
    except (TypeError, ValueError):
        current_password_valid = False
    if not current_password_valid:
        raise InvalidCurrentPassword

    error = password_policy_error(new_password)
    if error:
        raise PasswordPolicyError(error)
    if check_password_hash(user.password_hash, new_password):
        raise PasswordPolicyError("New password must be different from the current password.")

    user.password_hash = generate_password_hash(new_password)
    user.auth_version += 1
    db.commit()


__all__ = ["InvalidCurrentPassword", "PasswordPolicyError", "change_password", "password_policy_error"]