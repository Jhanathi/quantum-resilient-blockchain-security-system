from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
import json
import re
from typing import Any, Mapping

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from backend.models.security_audit_event import SecurityAuditEvent

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
OUTCOMES = ("SUCCESS", "FAILURE", "BLOCKED")
DEMO_FILTERS = ("all", "operational", "demo")
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
MAX_EXPORT_ROWS = 10_000
MAX_METADATA_BYTES = 8192

_EVENT_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,79}$")
_CATEGORY_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,39}$")
_SOURCE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "credential",
    "private",
    "signingkey",
    "apikey",
    "authorization",
    "session",
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|authorization|private[_ -]?key|signing[_ -]?key|api[_ -]?key|session|cookie)"
    r"\s*[:=]\s*[^\s,;]+|\bBearer\s+[A-Za-z0-9._~+/=-]+"
)


class AuditFilterError(ValueError):
    pass


def _bounded_text(value: str, *, field: str, limit: int, required: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text.")
    cleaned = value.strip()
    cleaned = _SECRET_VALUE_RE.sub(
        lambda match: f"{match.group(1) or 'credential'}=[redacted]",
        cleaned,
    )
    if required and not cleaned:
        raise ValueError(f"{field} is required.")
    if len(cleaned) > limit:
        raise ValueError(f"{field} must be {limit} characters or fewer.")
    return cleaned


def _safe_json_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 5:
        return "[omitted: nested metadata limit]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        cleaned = _SECRET_VALUE_RE.sub(
            lambda match: f"{match.group(1) or 'credential'}=[redacted]",
            value,
        )
        return cleaned[:1000]
    if isinstance(value, (list, tuple)):
        return [_safe_json_value(item, depth=depth + 1) for item in value[:50]]
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in list(value.items())[:100]:
            if not isinstance(key, str):
                continue
            normalized = re.sub(r"[^a-z]", "", key.lower())
            if any(part in normalized for part in _SENSITIVE_KEY_PARTS):
                continue
            output[key[:100]] = _safe_json_value(item, depth=depth + 1)
        return output
    raise ValueError("Metadata must contain only JSON-compatible values.")


def sanitize_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise ValueError("Metadata must be an object.")
    sanitized = _safe_json_value(metadata)
    encoded = json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
        raise ValueError("Metadata exceeds the maximum allowed size.")
    return sanitized


def record_security_event(
    db: Session,
    *,
    event_type: str,
    severity: str,
    title: str,
    description: str,
    outcome: str,
    source: str,
    category: str | None = None,
    actor_id: str | None = None,
    actor_username: str | None = None,
    actor_email: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    correlation_id: str | None = None,
    is_demo: bool = False,
    metadata: Mapping[str, Any] | None = None,
    created_at: datetime | None = None,
) -> SecurityAuditEvent:
    event_type = _bounded_text(event_type, field="Event type", limit=80, required=True)
    severity = _bounded_text(severity, field="Severity", limit=16, required=True).upper()
    outcome = _bounded_text(outcome, field="Outcome", limit=16, required=True).upper()
    source = _bounded_text(source, field="Source", limit=80, required=True)
    category = _bounded_text(
        category or event_type.split("_", 1)[0],
        field="Category",
        limit=40,
        required=True,
    ).upper()
    if not _EVENT_TYPE_RE.fullmatch(event_type):
        raise ValueError("Event type has an invalid format.")
    if not _CATEGORY_RE.fullmatch(category):
        raise ValueError("Category has an invalid format.")
    if severity not in SEVERITIES:
        raise ValueError("Severity is not supported.")
    if outcome not in OUTCOMES:
        raise ValueError("Outcome is not supported.")
    if not _SOURCE_RE.fullmatch(source):
        raise ValueError("Source has an invalid format.")
    if not isinstance(is_demo, bool):
        raise ValueError("Demo marker must be boolean.")

    safe_metadata = sanitize_metadata(metadata)
    event = SecurityAuditEvent(
        event_type=event_type,
        category=category,
        severity=severity,
        title=_bounded_text(title, field="Title", limit=160, required=True),
        description=_bounded_text(description, field="Description", limit=2000, required=True),
        outcome=outcome,
        source=source,
        actor_id=_bounded_text(actor_id, field="Actor ID", limit=36) if actor_id else None,
        actor_username=_bounded_text(actor_username, field="Actor username", limit=80) if actor_username else None,
        actor_email=_bounded_text(actor_email, field="Actor email", limit=120) if actor_email else None,
        target_type=_bounded_text(target_type, field="Target type", limit=80) if target_type else None,
        target_id=_bounded_text(target_id, field="Target ID", limit=128) if target_id else None,
        correlation_id=_bounded_text(correlation_id, field="Correlation ID", limit=64) if correlation_id else None,
        is_demo=is_demo,
        metadata_=safe_metadata,
        created_at=created_at or datetime.now(timezone.utc),
    )
    db.add(event)
    return event


def parse_audit_filters(args: Mapping[str, Any]) -> dict[str, Any]:
    start_value = str(args.get("start_date", "")).strip()
    end_value = str(args.get("end_date", "")).strip()
    if any(value and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) for value in (start_value, end_value)):
        raise AuditFilterError("Dates must use YYYY-MM-DD format.")
    try:
        start_date = date.fromisoformat(start_value) if start_value else None
        end_date = date.fromisoformat(end_value) if end_value else None
    except ValueError as exc:
        raise AuditFilterError("Dates must use YYYY-MM-DD format.") from exc
    if end_date == date.max:
        raise AuditFilterError("End date is outside the supported range.")
    if start_date and end_date and start_date > end_date:
        raise AuditFilterError("Start date must not be after end date.")

    severity = str(args.get("severity", "")).strip().upper()
    outcome = str(args.get("outcome", "")).strip().upper()
    category = str(args.get("category", "")).strip().upper()
    event_type = str(args.get("event_type", "")).strip().upper()
    mode = str(args.get("mode", "all")).strip().lower() or "all"
    sort = str(args.get("sort", "desc")).strip().lower() or "desc"
    actor = str(args.get("actor", "")).strip()
    search = str(args.get("search", "")).strip()
    try:
        page = int(args.get("page", 1))
        page_size = int(args.get("page_size", DEFAULT_PAGE_SIZE))
    except (TypeError, ValueError) as exc:
        raise AuditFilterError("Page and page size must be integers.") from exc
    if page < 1:
        raise AuditFilterError("Page must be a positive integer.")
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise AuditFilterError(f"Page size must be between 1 and {MAX_PAGE_SIZE}.")
    if severity and severity not in SEVERITIES:
        raise AuditFilterError("Severity filter is not supported.")
    if outcome and outcome not in OUTCOMES:
        raise AuditFilterError("Outcome filter is not supported.")
    if category and not _CATEGORY_RE.fullmatch(category):
        raise AuditFilterError("Category filter has an invalid format.")
    if event_type and not _EVENT_TYPE_RE.fullmatch(event_type):
        raise AuditFilterError("Event type filter has an invalid format.")
    if mode not in DEMO_FILTERS:
        raise AuditFilterError("Mode filter must be all, operational, or demo.")
    if sort not in {"asc", "desc"}:
        raise AuditFilterError("Sort must be asc or desc.")
    if len(actor) > 120:
        raise AuditFilterError("Actor filter must be 120 characters or fewer.")
    if len(search) > 200:
        raise AuditFilterError("Search must be 200 characters or fewer.")

    return {
        "start": datetime.combine(start_date, time.min, tzinfo=timezone.utc) if start_date else None,
        "end": datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=timezone.utc) if end_date else None,
        "severity": severity or None,
        "outcome": outcome or None,
        "category": category or None,
        "event_type": event_type or None,
        "actor": actor or None,
        "search": search or None,
        "mode": mode,
        "sort": sort,
        "page": page,
        "page_size": page_size,
    }


def filtered_audit_query(db: Session, filters: Mapping[str, Any]):
    query = db.query(SecurityAuditEvent)
    if filters.get("start"):
        query = query.filter(SecurityAuditEvent.created_at >= filters["start"])
    if filters.get("end"):
        query = query.filter(SecurityAuditEvent.created_at < filters["end"])
    if filters.get("severity"):
        query = query.filter(SecurityAuditEvent.severity == filters["severity"])
    if filters.get("outcome"):
        query = query.filter(SecurityAuditEvent.outcome == filters["outcome"])
    if filters.get("category"):
        query = query.filter(SecurityAuditEvent.category == filters["category"])
    if filters.get("event_type"):
        query = query.filter(SecurityAuditEvent.event_type == filters["event_type"])
    if filters.get("actor"):
        pattern = f"%{filters['actor']}%"
        query = query.filter(
            or_(
                SecurityAuditEvent.actor_id.ilike(pattern),
                SecurityAuditEvent.actor_username.ilike(pattern),
                SecurityAuditEvent.actor_email.ilike(pattern),
            )
        )
    if filters.get("search"):
        pattern = f"%{filters['search']}%"
        query = query.filter(
            or_(
                SecurityAuditEvent.title.ilike(pattern),
                SecurityAuditEvent.description.ilike(pattern),
                SecurityAuditEvent.event_type.ilike(pattern),
            )
        )
    if filters.get("mode") == "demo":
        query = query.filter(SecurityAuditEvent.is_demo.is_(True))
    elif filters.get("mode") == "operational":
        query = query.filter(SecurityAuditEvent.is_demo.is_(False))
    return query


def serialize_event(event: SecurityAuditEvent, *, include_metadata: bool = True) -> dict[str, Any]:
    created_at = event.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    result = {
        "id": event.id,
        "event_type": event.event_type,
        "category": event.category,
        "severity": event.severity,
        "title": event.title,
        "description": event.description,
        "outcome": event.outcome,
        "source": event.source,
        "actor_id": event.actor_id,
        "actor_username": event.actor_username,
        "actor_email": event.actor_email,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "correlation_id": event.correlation_id,
        "is_demo": event.is_demo,
        "created_at": created_at.astimezone(timezone.utc).isoformat(),
    }
    if include_metadata:
        try:
            result["metadata"] = sanitize_metadata(event.metadata_ or {})
        except (TypeError, ValueError):
            result["metadata"] = {"_omitted": "Stored metadata is invalid or exceeds the safe display limit."}
    return result


def list_audit_events(db: Session, filters: Mapping[str, Any]) -> dict[str, Any]:
    query = filtered_audit_query(db, filters)
    total = int(query.order_by(None).count())
    sort_column = SecurityAuditEvent.created_at
    ordering = sort_column.asc() if filters["sort"] == "asc" else sort_column.desc()
    events = (
        query.order_by(ordering, SecurityAuditEvent.id.asc())
        .offset((filters["page"] - 1) * filters["page_size"])
        .limit(filters["page_size"])
        .all()
    )
    return {
        "events": [serialize_event(event) for event in events],
        "pagination": {
            "page": filters["page"],
            "page_size": filters["page_size"],
            "total": total,
            "pages": (total + filters["page_size"] - 1) // filters["page_size"],
        },
    }


def audit_dashboard_stats(db: Session) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)
    total = int(db.query(func.count(SecurityAuditEvent.id)).scalar() or 0)
    recent = int(
        db.query(func.count(SecurityAuditEvent.id))
        .filter(SecurityAuditEvent.created_at >= day_ago)
        .scalar()
        or 0
    )
    high_critical = int(
        db.query(func.count(SecurityAuditEvent.id))
        .filter(SecurityAuditEvent.severity.in_(("HIGH", "CRITICAL")))
        .scalar()
        or 0
    )
    failed_blocked = int(
        db.query(func.count(SecurityAuditEvent.id))
        .filter(SecurityAuditEvent.outcome.in_(("FAILURE", "BLOCKED")))
        .scalar()
        or 0
    )
    severity_rows = (
        db.query(SecurityAuditEvent.severity, func.count(SecurityAuditEvent.id))
        .group_by(SecurityAuditEvent.severity)
        .all()
    )
    category_rows = (
        db.query(SecurityAuditEvent.category, func.count(SecurityAuditEvent.id))
        .group_by(SecurityAuditEvent.category)
        .order_by(func.count(SecurityAuditEvent.id).desc(), SecurityAuditEvent.category.asc())
        .limit(12)
        .all()
    )
    recent_events = (
        db.query(SecurityAuditEvent)
        .order_by(SecurityAuditEvent.created_at.desc(), SecurityAuditEvent.id.asc())
        .limit(10)
        .all()
    )
    return {
        "total_events": total,
        "last_24_hours": recent,
        "high_critical": high_critical,
        "failed_or_blocked": failed_blocked,
        "severity_distribution": {severity: count for severity, count in severity_rows},
        "category_distribution": {category: count for category, count in category_rows},
        "demo_events": int(
            db.query(func.count(SecurityAuditEvent.id))
            .filter(SecurityAuditEvent.is_demo.is_(True))
            .scalar()
            or 0
        ),
        "operational_events": int(
            db.query(func.count(SecurityAuditEvent.id))
            .filter(SecurityAuditEvent.is_demo.is_(False))
            .scalar()
            or 0
        ),
        "recent_events": [serialize_event(event, include_metadata=False) for event in recent_events],
    }


def report_event_rows(db: Session, filters: Mapping[str, Any]) -> list[SecurityAuditEvent]:
    return (
        filtered_audit_query(db, filters)
        .order_by(SecurityAuditEvent.created_at.desc(), SecurityAuditEvent.id.asc())
        .limit(MAX_EXPORT_ROWS)
        .all()
    )


def report_event_count(db: Session, filters: Mapping[str, Any]) -> int:
    return int(filtered_audit_query(db, filters).order_by(None).count())


def event_categories(db: Session) -> list[str]:
    return [
        category
        for (category,) in db.query(SecurityAuditEvent.category)
        .distinct()
        .order_by(SecurityAuditEvent.category.asc())
        .all()
    ]


__all__ = [
    "AuditFilterError",
    "DEFAULT_PAGE_SIZE",
    "MAX_EXPORT_ROWS",
    "MAX_PAGE_SIZE",
    "OUTCOMES",
    "SEVERITIES",
    "audit_dashboard_stats",
    "event_categories",
    "list_audit_events",
    "parse_audit_filters",
    "record_security_event",
    "report_event_count",
    "report_event_rows",
    "sanitize_metadata",
    "serialize_event",
]
