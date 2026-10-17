from __future__ import annotations

from hashlib import sha256
from math import ceil
import time

from sqlalchemy import case, delete, select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from backend.database.database import SessionLocal
from backend.models.rate_limit_bucket import RateLimitBucket


class DatabaseRateLimitStore:
    """Atomic fixed-window limits persisted in the application's shared database."""

    @staticmethod
    def _digest(key: str) -> str:
        return sha256(key.encode("utf-8")).hexdigest()

    def consume(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        now: float,
    ) -> tuple[bool, int]:
        if limit < 1 or window_seconds < 1:
            raise ValueError("Rate-limit settings must be positive integers.")

        digest = self._digest(key)
        expired = RateLimitBucket.window_started_at <= now - window_seconds
        update_values = {
            "window_started_at": case(
                (expired, now),
                else_=RateLimitBucket.window_started_at,
            ),
            "count": case((expired, 1), else_=RateLimitBucket.count + 1),
        }

        for attempt in range(6):
            try:
                with SessionLocal() as db:
                    dialect = db.get_bind().dialect.name
                    values = {"key": digest, "window_started_at": now, "count": 1}
                    if dialect == "sqlite":
                        statement = sqlite_insert(RateLimitBucket).values(**values)
                        statement = statement.on_conflict_do_update(
                            index_elements=[RateLimitBucket.key],
                            set_=update_values,
                        ).returning(RateLimitBucket.count, RateLimitBucket.window_started_at)
                        count, window_started_at = db.execute(statement).one()
                    elif dialect == "postgresql":
                        statement = postgresql_insert(RateLimitBucket).values(**values)
                        statement = statement.on_conflict_do_update(
                            index_elements=[RateLimitBucket.key],
                            set_=update_values,
                        ).returning(RateLimitBucket.count, RateLimitBucket.window_started_at)
                        count, window_started_at = db.execute(statement).one()
                    elif dialect in {"mysql", "mariadb"}:
                        statement = mysql_insert(RateLimitBucket).values(**values)
                        statement = statement.on_duplicate_key_update(**update_values)
                        db.execute(statement)
                        bucket = db.execute(
                            select(RateLimitBucket).where(RateLimitBucket.key == digest)
                        ).scalar_one()
                        count = bucket.count
                        window_started_at = bucket.window_started_at
                    else:
                        raise RuntimeError(
                            f"Database-backed rate limiting is unsupported for dialect {dialect!r}."
                        )
                    db.commit()
                break
            except OperationalError as exc:
                if "database is locked" not in str(getattr(exc, "orig", exc)).lower() or attempt == 5:
                    raise
                time.sleep(0.01 * (attempt + 1))

        retry_after = max(1, ceil(window_seconds - (now - window_started_at)))
        return count <= limit, retry_after

    def clear(self, key: str) -> None:
        digest = self._digest(key)
        with SessionLocal() as db:
            db.execute(delete(RateLimitBucket).where(RateLimitBucket.key == digest))
            db.commit()
