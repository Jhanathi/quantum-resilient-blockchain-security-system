from __future__ import annotations

import csv
import hmac
import ipaddress
import io
import json
import os
import re
import secrets
import time
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps
from hashlib import sha256
from typing import Any, Dict, List

from flask import Flask, abort, g, jsonify, redirect, render_template, render_template_string, request, session, url_for
from flask_cors import CORS
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, OperationalError
from werkzeug.security import check_password_hash, generate_password_hash

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    def load_dotenv(*_args, **_kwargs):
        return False

from backend.config import BASE_DIR, resolve_app_config

load_dotenv(BASE_DIR / ".env", override=False)


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    config = resolve_app_config()
    app.config.from_mapping(
        APP_ENV=config["APP_ENV"],
        SECRET_KEY=config["SECRET_KEY"] or ("test-secret" if app.testing else None),
        DEBUG=bool(config["DEBUG"]),
        HOST=config["HOST"],
        PORT=config["PORT"],
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=bool(config["SESSION_COOKIE_SECURE"]) and not app.testing,
        SESSION_IDLE_TIMEOUT_SECONDS=int(config["SESSION_IDLE_TIMEOUT_SECONDS"]),
        SESSION_ABSOLUTE_TIMEOUT_SECONDS=int(config["SESSION_ABSOLUTE_TIMEOUT_SECONDS"]),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,
        JSON_SORT_KEYS=False,
        SESSION_COOKIE_NAME="session",
        AUTH_RATE_LIMIT=int(os.environ.get("AUTH_RATE_LIMIT", "5")),
        AUTH_RATE_WINDOW_SECONDS=int(os.environ.get("AUTH_RATE_WINDOW_SECONDS", "300")),
        REGISTRATION_RATE_LIMIT=int(os.environ.get("REGISTRATION_RATE_LIMIT", "10")),
        REGISTRATION_RATE_WINDOW_SECONDS=int(os.environ.get("REGISTRATION_RATE_WINDOW_SECONDS", "3600")),
        TRANSFER_RATE_LIMIT=int(os.environ.get("TRANSFER_RATE_LIMIT", "10")),
        TRANSFER_RATE_WINDOW_SECONDS=int(os.environ.get("TRANSFER_RATE_WINDOW_SECONDS", "60")),
        SENSITIVE_WRITE_RATE_LIMIT=int(os.environ.get("SENSITIVE_WRITE_RATE_LIMIT", "30")),
        SENSITIVE_WRITE_RATE_WINDOW_SECONDS=int(os.environ.get("SENSITIVE_WRITE_RATE_WINDOW_SECONDS", "60")),
        SECURITY_LAB_RATE_LIMIT=int(os.environ.get("SECURITY_LAB_RATE_LIMIT", "10")),
        SECURITY_LAB_RATE_WINDOW_SECONDS=int(os.environ.get("SECURITY_LAB_RATE_WINDOW_SECONDS", "60")),
        SECURITY_AUDIT_SIGNAL_LIMIT=int(os.environ.get("SECURITY_AUDIT_SIGNAL_LIMIT", "5")),
        SECURITY_AUDIT_SIGNAL_WINDOW_SECONDS=int(os.environ.get("SECURITY_AUDIT_SIGNAL_WINDOW_SECONDS", "60")),
        RATE_LIMIT_CLOCK=time.time,
        TRUSTED_PROXY_NETWORKS=tuple(
            ipaddress.ip_network(value.strip())
            for value in os.environ.get("TRUSTED_PROXY_CIDRS", "").split(",")
            if value.strip()
        ),
    )
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=app.config["SESSION_IDLE_TIMEOUT_SECONDS"])

    if app.testing:
        app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or "test-secret"
    elif not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY must be set in the environment before starting the application.")
    if app.config["APP_ENV"] == "production" and not app.config["SECRET_KEY"]:
        raise RuntimeError("Production configuration requires SECRET_KEY to be set before starting the application.")
    if app.config["APP_ENV"] == "production" and app.config["DEBUG"]:
        raise RuntimeError("Debug mode must remain disabled in production.")
    if test_config:
        app.config.update(test_config)
    if app.testing:
        app.config["SESSION_COOKIE_SECURE"] = False
    CORS(app)
    return app


app = create_app()


@app.get("/health")
@app.get("/healthz")
def health_check():
    return jsonify(
        {
            "status": "ok",
            "environment": app.config.get("APP_ENV", "development"),
            "debug": bool(app.config.get("DEBUG", False)),
            "database": os.environ.get("DATABASE_URL", "sqlite:///./pqbank.db"),
        }
    )


@app.after_request
def add_security_headers(response):
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-XSS-Protection", "0")
    if request.is_secure and app.config.get("SESSION_COOKIE_SECURE"):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

from backend.database.database import SessionLocal, create_tables
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.aqrs_decision import AQRSDecision
from backend.models.audit_log import AuditLog
from backend.models.idempotency_record import IdempotencyRecord
from backend.models.rate_limit_bucket import RateLimitBucket
from backend.models.security_audit_event import SecurityAuditEvent
from backend.models.transaction import Transaction, TransactionStatus
from backend.models.user import User, UserRole
from backend.services import (
    AccountService,
    AQRSDecisionService,
    AuthorizationError,
    CryptoSignatureService,
    InvalidCurrentPassword,
    InsufficientBalanceError,
    PasswordPolicyError,
    TransactionService,
    ValidationError,
    add_transaction_to_ledger,
    build_decision_for_amount,
    classify_transaction_risk,
    get_admin_overview,
    get_audit_logs,
    get_aqrs_analytics,
    get_algorithm_usage,
    get_blockchain_analytics,
    get_security_overview,
    get_signature_statistics,
    get_transactions,
    get_users,
    change_password,
    password_policy_error,
    RESEARCH_MODES,
    get_experiment,
    get_latest_experiment,
    list_experiments,
    run_experiment,
    serialize_experiment,
    select_security_level,
)
from backend.services.rate_limit_service import DatabaseRateLimitStore
from backend.services.security_demo_service import (
    SCENARIOS as SECURITY_LAB_SCENARIOS,
    history_snapshot as security_lab_history,
    record_demo_result,
    reset_demo_history,
    run_demo as run_security_demo,
)
from backend.services.security_audit_service import (
    AuditFilterError,
    MAX_EXPORT_ROWS,
    OUTCOMES as SECURITY_AUDIT_OUTCOMES,
    SEVERITIES as SECURITY_AUDIT_SEVERITIES,
    audit_dashboard_stats,
    event_categories,
    list_audit_events,
    parse_audit_filters,
    record_security_event,
    report_event_count,
    report_event_rows,
    serialize_event,
)

create_tables()
app.extensions["rate_limit_store"] = DatabaseRateLimitStore()


@app.before_request
def assign_request_correlation_id():
    g.correlation_id = uuid.uuid4().hex


@app.after_request
def add_request_correlation_id(response):
    correlation_id = getattr(g, "correlation_id", None)
    if correlation_id:
        response.headers.setdefault("X-Request-ID", correlation_id)
    return response


def _record_security_audit(
    event_type: str,
    severity: str,
    title: str,
    description: str,
    outcome: str,
    *,
    source: str,
    category: str | None = None,
    actor: User | None = None,
    actor_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    is_demo: bool = False,
    metadata: Dict[str, Any] | None = None,
) -> bool:
    try:
        with SessionLocal() as audit_db:
            record_security_event(
                audit_db,
                event_type=event_type,
                severity=severity,
                title=title,
                description=description,
                outcome=outcome,
                source=source,
                category=category,
                actor_id=actor.id if actor else actor_id,
                actor_username=actor.username if actor else None,
                actor_email=actor.email if actor else None,
                target_type=target_type,
                target_id=target_id,
                correlation_id=getattr(g, "correlation_id", None),
                is_demo=is_demo,
                metadata=metadata,
            )
            audit_db.commit()
        return True
    except Exception as exc:
        app.logger.error("Security audit event could not be persisted (%s)", type(exc).__name__)
        return False


def _allow_security_signal_audit(key: str) -> bool:
    try:
        store = app.config.get("RATE_LIMIT_STORE", app.extensions["rate_limit_store"])
        allowed, _ = store.consume(
            f"security-audit-signal:{key}",
            limit=app.config["SECURITY_AUDIT_SIGNAL_LIMIT"],
            window_seconds=app.config["SECURITY_AUDIT_SIGNAL_WINDOW_SECONDS"],
            now=float(app.config["RATE_LIMIT_CLOCK"]()),
        )
        return allowed
    except Exception as exc:
        app.logger.error("Security event audit throttling failed (%s)", type(exc).__name__)
        return False


with SessionLocal() as _startup_db:
    from backend.services.blockchain_service import ensure_genesis_block

    ensure_genesis_block(_startup_db)
    _startup_db.commit()


TRANSACTIONS: List[Dict[str, Any]] = []
BLOCKS: List[Dict[str, Any]] = []

ECDSA_SIGN_BASELINE_MS = 0.8
ECDSA_VERIFY_BASELINE_MS = 0.4
ECDSA_SIG_SIZE_BYTES = 71


def _session_clock() -> float:
    return float(app.config["SESSION_CLOCK"]())


app.config.setdefault("SESSION_CLOCK", time.time)


def _csrf_token() -> str:
    token = session.get("csrf_token")
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token() -> dict[str, str]:
    return {"csrf_token": _csrf_token()}


@app.before_request
def enforce_session_expiration():
    if not session.get("user_id"):
        return None

    now = _session_clock()
    issued_at = session.get("auth_issued_at")
    last_seen_at = session.get("auth_last_seen_at")
    absolute_timeout = app.config["SESSION_ABSOLUTE_TIMEOUT_SECONDS"]
    idle_timeout = app.config["SESSION_IDLE_TIMEOUT_SECONDS"]
    expired = (
        not isinstance(issued_at, (int, float))
        or not isinstance(last_seen_at, (int, float))
        or now - issued_at >= absolute_timeout
        or now - last_seen_at >= idle_timeout
    )
    if expired:
        expired_user_id = session.get("user_id")
        session.clear()
        _record_security_audit(
            "SESSION_EXPIRED",
            "LOW",
            "Authenticated session expired",
            "An authenticated session expired due to invalid, idle, or absolute timeout state.",
            "BLOCKED",
            source="session",
            category="AUTHENTICATION",
            actor_id=expired_user_id if isinstance(expired_user_id, str) else None,
        )
        if request.path.startswith("/api/"):
            return jsonify({"error": "Session expired. Please sign in again."}), 401
        return redirect(url_for("login_page"))

    session.permanent = True
    session["auth_last_seen_at"] = now
    return None


@app.before_request
def enforce_csrf_token():
    if request.method in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return None

    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if (
        not isinstance(expected, str)
        or not isinstance(supplied, str)
        or not hmac.compare_digest(expected, supplied)
    ):
        if _allow_security_signal_audit(f"csrf:{_client_ip()}"):
            _record_security_audit(
                "CSRF_VALIDATION_FAILED",
                "MEDIUM",
                "CSRF validation rejected a request",
                "A state-changing request did not include a valid session-bound CSRF token.",
                "BLOCKED",
                source="csrf",
                category="ACCESS_CONTROL",
                actor_id=session.get("user_id") if isinstance(session.get("user_id"), str) else None,
                metadata={"method": request.method, "path": request.path[:200]},
            )
        return jsonify({"error": "A valid CSRF token is required."}), 400
    return None


def _client_ip() -> str:
    remote = request.remote_addr or "unknown"
    networks = app.config["TRUSTED_PROXY_NETWORKS"]
    if not networks:
        return remote
    try:
        remote_address = ipaddress.ip_address(remote)
    except ValueError:
        return remote
    if not any(remote_address in network for network in networks):
        return remote

    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if not forwarded_for:
        return remote
    try:
        chain = [ipaddress.ip_address(value.strip()) for value in forwarded_for.split(",")]
    except ValueError:
        return remote
    chain.append(remote_address)
    while chain and any(chain[-1] in network for network in networks):
        chain.pop()
    return chain[-1].compressed if chain else remote


def _login_rate_limit_key(identity: str) -> str:
    return f"auth-login:{_client_ip()}:{identity.strip().lower()}"


def _rate_limit_for_request() -> tuple[str, int, int] | None:
    endpoint = request.endpoint
    client_ip = _client_ip()
    if endpoint == "login_user":
        payload = request.get_json(silent=True)
        identity = ""
        if isinstance(payload, dict):
            identity = str(payload.get("email") or payload.get("username") or "")
        return (
            _login_rate_limit_key(identity),
            app.config["AUTH_RATE_LIMIT"],
            app.config["AUTH_RATE_WINDOW_SECONDS"],
        )
    if endpoint == "register_user":
        return (
            f"auth-register:{client_ip}",
            app.config["REGISTRATION_RATE_LIMIT"],
            app.config["REGISTRATION_RATE_WINDOW_SECONDS"],
        )
    if endpoint == "create_transaction":
        actor = session.get("user_id") or client_ip
        return (
            f"money-transfer:{actor}",
            app.config["TRANSFER_RATE_LIMIT"],
            app.config["TRANSFER_RATE_WINDOW_SECONDS"],
        )
    if endpoint in {
        "security_audit_dashboard_api",
        "security_audit_api",
        "security_audit_events_api",
        "security_audit_event_detail_api",
        "export_security_audit_csv",
        "export_security_audit_json",
    }:
        actor = session.get("user_id") or client_ip
        return (
            f"security-audit-read:{actor}",
            app.config["SENSITIVE_WRITE_RATE_LIMIT"],
            app.config["SENSITIVE_WRITE_RATE_WINDOW_SECONDS"],
        )
    sensitive_write_endpoints = {
        "api_transaction",
        "api_sign_message",
        "api_verify_message",
        "sign_transaction_endpoint",
        "create_research_experiment_api",
        "change_password_api",
        "logout_user",
    }
    if (
        request.method not in {"GET", "HEAD", "OPTIONS"}
        and endpoint in {"run_security_lab_demo", "reset_security_lab"}
    ):
        actor = session.get("user_id") or client_ip
        return (
            f"security-lab:{actor}",
            app.config["SECURITY_LAB_RATE_LIMIT"],
            app.config["SECURITY_LAB_RATE_WINDOW_SECONDS"],
        )
    if request.method not in {"GET", "HEAD", "OPTIONS"} and endpoint in sensitive_write_endpoints:
        actor = session.get("user_id") or client_ip
        return (
            f"sensitive-write:{endpoint}:{actor}",
            app.config["SENSITIVE_WRITE_RATE_LIMIT"],
            app.config["SENSITIVE_WRITE_RATE_WINDOW_SECONDS"],
        )
    return None


@app.before_request
def enforce_shared_rate_limits():
    policy = _rate_limit_for_request()
    if policy is None:
        return None

    key, limit, window_seconds = policy
    store = app.config.get("RATE_LIMIT_STORE", app.extensions["rate_limit_store"])
    try:
        allowed, retry_after = store.consume(
            key,
            limit=limit,
            window_seconds=window_seconds,
            now=float(app.config["RATE_LIMIT_CLOCK"]()),
        )
    except Exception as exc:
        app.logger.error("Shared rate-limit storage failed (%s)", type(exc).__name__)
        return jsonify({"error": "Request protection is temporarily unavailable."}), 503
    if allowed:
        return None

    error = (
        "Too many failed login attempts. Please wait and try again later."
        if request.endpoint == "login_user"
        else "Rate limit exceeded. Please retry later."
    )
    response = jsonify({"error": error})
    response.status_code = 429
    response.headers["Retry-After"] = str(retry_after)
    rate_limit_actor = session.get("user_id") or _client_ip()
    if _allow_security_signal_audit(f"rate-limit:{rate_limit_actor}:{request.endpoint}"):
        _record_security_audit(
            "RATE_LIMIT_EXCEEDED",
            "MEDIUM",
            "Request rate limit exceeded",
            "A request was blocked after exceeding its configured rate limit.",
            "BLOCKED",
            source="rate_limit",
            category="ACCESS_CONTROL",
            actor_id=session.get("user_id") if isinstance(session.get("user_id"), str) else None,
            metadata={"endpoint": str(request.endpoint or "")[:100]},
        )
    return response


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def classify_risk(amount: float) -> str:
    return classify_transaction_risk(amount).value


def select_dilithium_level(risk_level: str) -> int:
    return select_security_level(risk_level)["selected_security_level"]


def dilithium_engine(level: int):
    if level == 2:
        return Dilithium2
    if level == 3:
        return Dilithium3
    return Dilithium5


def generate_tx_id() -> str:
    return f"TX{len(TRANSACTIONS) + 1:03d}"


def build_message(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_aqrs_score(level: int | str, sign_ms: float, verify_ms: float, sig_size: int) -> float:
    if level == "ecdsa":
        return 1.0
    security_bits = {2: 128, 3: 192, 5: 256}
    sign_ratio = sign_ms / ECDSA_SIGN_BASELINE_MS
    verify_ratio = verify_ms / ECDSA_VERIFY_BASELINE_MS
    size_ratio = sig_size / ECDSA_SIG_SIZE_BYTES
    overhead = (sign_ratio + verify_ratio + size_ratio) / 3.0
    return (security_bits[level] / 128.0) / overhead


def maybe_add_block() -> int | None:
    if len(TRANSACTIONS) % 5 != 0:
        return None
    previous_hash = BLOCKS[-1]["hash"] if BLOCKS else "GENESIS"
    tx_ids = [tx["transaction_id"] for tx in TRANSACTIONS[-5:]]
    block_hash = sha256(("".join(tx_ids) + previous_hash).encode("utf-8")).hexdigest()
    block_number = len(BLOCKS) + 1
    block = {
        "block_number": block_number,
        "transaction_count": 5,
        "hash": block_hash,
        "previous_hash": previous_hash,
        "timestamp": utc_now(),
        "transactions": tx_ids,
    }
    BLOCKS.append(block)
    return block_number


@app.get("/")
def index() -> Any:
    return render_template("login.html", page="login")


@app.get("/login")
def login_page() -> Any:
    return render_template("login.html", page="login")


@app.get("/register")
def register_page() -> Any:
    return render_template("register.html", page="register")


@app.get("/dashboard")
def dashboard_page() -> Any:
    if _current_user_from_session() is None:
        return redirect(url_for("login_page"))
    return render_template("dashboard.html", page="dashboard")


@app.get("/transfer")
def transfer_page() -> Any:
    if _current_user_from_session() is None:
        return redirect(url_for("login_page"))
    return render_template("transfer.html", page="transfer")


@app.get("/transactions")
def transactions_page() -> Any:
    if _current_user_from_session() is None:
        return redirect(url_for("login_page"))
    return render_template("transactions.html", page="transactions")


@app.get("/transaction/<transaction_id>")
def transaction_details_page(transaction_id: str) -> Any:
    user = _current_user_from_session()
    if user is None:
        return redirect(url_for("login_page"))
    with SessionLocal() as db:
        if TransactionService.get_transaction_for_user(db, user.id, transaction_id) is None:
            abort(404)
    return render_template("transaction_details.html", page="transaction-details", transaction_id=transaction_id)


@app.get("/account/security")
def account_security_page() -> Any:
    if _current_user_from_session() is None:
        return redirect(url_for("login_page"))
    return render_template("account_security.html", page="account-security")


@app.get("/research")
def research_page() -> Any:
    denied = _role_page(UserRole.ADMIN, UserRole.SECURITY_ANALYST)
    return denied or render_template("research.html", page="research", console="RESEARCH LAB")


@app.get("/research/legacy")
def legacy_research_page() -> Any:
    denied = _role_page(UserRole.ADMIN, UserRole.SECURITY_ANALYST)
    if denied:
        return denied
    legacy_html = (Path(app.root_path) / "index.html").read_text(encoding="utf-8")
    return render_template_string(legacy_html)


def _role_page(*roles: UserRole):
    user = _current_user_from_session()
    if user is None:
        _record_security_audit(
            "AUTHENTICATION_REQUIRED",
            "MEDIUM",
            "Unauthenticated page access denied",
            "A protected operations page required an authenticated session.",
            "BLOCKED",
            source="authorization",
            category="ACCESS_CONTROL",
            metadata={"path": request.path[:200]},
        )
        return redirect(url_for("login_page"))
    if user.role not in roles:
        _record_security_audit(
            "ROLE_ACCESS_DENIED",
            "MEDIUM",
            "Page access denied by role policy",
            "An authenticated user attempted to open a page without the required role.",
            "BLOCKED",
            source="authorization",
            category="ACCESS_CONTROL",
            actor=user,
            metadata={"path": request.path, "required_roles": [role.value for role in roles]},
        )
        abort(403)
    return None


@app.get("/admin")
def admin_page() -> Any:
    denied = _role_page(UserRole.ADMIN)
    return denied or render_template("admin.html", page="admin", console="ADMIN CONSOLE")


@app.get("/admin/users")
def admin_users_page() -> Any:
    denied = _role_page(UserRole.ADMIN)
    return denied or render_template("admin_users.html", page="admin-users", console="ADMIN CONSOLE")


@app.get("/admin/transactions")
def admin_transactions_page() -> Any:
    denied = _role_page(UserRole.ADMIN)
    return denied or render_template("admin_transactions.html", page="admin-transactions", console="ADMIN CONSOLE")


@app.get("/admin/audit")
def admin_audit_page() -> Any:
    denied = _role_page(UserRole.ADMIN)
    return denied or render_template("admin_audit.html", page="admin-audit", console="ADMIN CONSOLE")


@app.get("/security")
def security_page() -> Any:
    denied = _role_page(UserRole.ADMIN, UserRole.SECURITY_ANALYST)
    return denied or render_template("security.html", page="security", console="SECURITY OPERATIONS")


@app.get("/security/aqrs")
def security_aqrs_page() -> Any:
    denied = _role_page(UserRole.ADMIN, UserRole.SECURITY_ANALYST)
    return denied or render_template("security_aqrs.html", page="security-aqrs", console="SECURITY OPERATIONS")


@app.get("/security/blockchain")
def security_blockchain_page() -> Any:
    denied = _role_page(UserRole.ADMIN, UserRole.SECURITY_ANALYST)
    return denied or render_template("security_blockchain.html", page="security-blockchain", console="SECURITY OPERATIONS")


@app.get("/security/crypto")
def security_crypto_page() -> Any:
    denied = _role_page(UserRole.ADMIN, UserRole.SECURITY_ANALYST)
    return denied or render_template("security_crypto.html", page="security-crypto", console="SECURITY OPERATIONS")


@app.get("/security/audit")
def security_audit_page() -> Any:
    denied = _role_page(UserRole.ADMIN, UserRole.SECURITY_ANALYST)
    return denied or render_template(
        "security_audit.html",
        page="security-audit-reporting",
        console="SECURITY OPERATIONS",
        severities=SECURITY_AUDIT_SEVERITIES,
        outcomes=SECURITY_AUDIT_OUTCOMES,
    )


@app.get("/security/lab")
def security_lab_page() -> Any:
    denied = _role_page(UserRole.ADMIN, UserRole.SECURITY_ANALYST)
    return denied or render_template(
        "security_lab.html",
        page="security-lab",
        console="SECURITY OPERATIONS",
        scenarios=SECURITY_LAB_SCENARIOS,
    )


@app.post("/api/transaction")
def api_transaction() -> Any:
    payload = request.get_json(silent=True) or {}
    sender = str(payload.get("sender", "")).strip() or "Unknown"
    receiver = str(payload.get("receiver", "")).strip() or "Unknown"
    amount = float(payload.get("amount", 0) or 0)
    mode = payload.get("mode", "aqrs")

    risk_level = classify_risk(amount)

    if mode == "aqrs":
        dilithium_level = select_dilithium_level(risk_level)
        engine = dilithium_engine(dilithium_level)
        pk, sk = engine.keygen()
        tx_id = generate_tx_id()
        tx_payload = {
            "transaction_id": tx_id,
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "risk_level": risk_level,
            "mode": mode,
            "dilithium_level": dilithium_level,
            "timestamp": utc_now(),
        }
        message = build_message(tx_payload)
        start = time.perf_counter()
        signature = engine.sign(sk, message.encode("utf-8"))
        signing_time_ms = (time.perf_counter() - start) * 1000
        start = time.perf_counter()
        is_valid = engine.verify(pk, message.encode("utf-8"), signature)
        verification_time_ms = (time.perf_counter() - start) * 1000
        signature_size = len(signature)
        public_key_hex = pk.hex()
        signature_hex = signature.hex()
        aqrs_score = compute_aqrs_score(dilithium_level, signing_time_ms, verification_time_ms, signature_size)
    elif mode == "ecdsa":
        dilithium_level = None
        key = ec.generate_private_key(ec.SECP256K1())
        tx_id = generate_tx_id()
        tx_payload = {
            "transaction_id": tx_id,
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "risk_level": risk_level,
            "mode": mode,
            "dilithium_level": None,
            "timestamp": utc_now(),
        }
        message = build_message(tx_payload)
        start = time.perf_counter()
        signature = key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        signing_time_ms = (time.perf_counter() - start) * 1000
        public_key = key.public_key()
        start = time.perf_counter()
        public_key.verify(signature, message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        verification_time_ms = (time.perf_counter() - start) * 1000
        signature_size = len(signature)
        public_key_hex = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
        signature_hex = signature.hex()
        aqrs_score = compute_aqrs_score("ecdsa", signing_time_ms, verification_time_ms, signature_size)
        is_valid = True
    else:
        dilithium_level = {"dil2": 2, "dil3": 3, "dil5": 5}.get(mode, 2)
        engine = dilithium_engine(dilithium_level)
        pk, sk = engine.keygen()
        tx_id = generate_tx_id()
        tx_payload = {
            "transaction_id": tx_id,
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "risk_level": risk_level,
            "mode": mode,
            "dilithium_level": dilithium_level,
            "timestamp": utc_now(),
        }
        message = build_message(tx_payload)
        start = time.perf_counter()
        signature = engine.sign(sk, message.encode("utf-8"))
        signing_time_ms = (time.perf_counter() - start) * 1000
        start = time.perf_counter()
        is_valid = engine.verify(pk, message.encode("utf-8"), signature)
        verification_time_ms = (time.perf_counter() - start) * 1000
        signature_size = len(signature)
        public_key_hex = pk.hex()
        signature_hex = signature.hex()
        aqrs_score = compute_aqrs_score(dilithium_level, signing_time_ms, verification_time_ms, signature_size)

    block_number = maybe_add_block()

    tx_record = {
        "transaction_id": tx_id,
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "risk_level": risk_level,
        "mode": mode,
        "dilithium_level": dilithium_level,
        "signing_time_ms": round(signing_time_ms, 2),
        "verification_time_ms": round(verification_time_ms, 2),
        "signature_size_bytes": signature_size,
        "signature_hex": signature_hex[:64],
        "public_key_hex": public_key_hex[:64],
        "is_valid": bool(is_valid),
        "block_number": block_number,
        "timestamp": utc_now(),
        "aqrs_score": round(aqrs_score, 4),
    }
    TRANSACTIONS.append(tx_record)

    return jsonify(tx_record)


@app.post("/api/sign-message")
def api_sign_message() -> Any:
    payload = request.get_json(silent=True) or {}
    message = str(payload.get("message", ""))
    mode = payload.get("mode", "ecdsa")

    if mode == "ecdsa":
        key = ec.generate_private_key(ec.SECP256K1())
        start = time.perf_counter()
        signature = key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        signing_time_ms = (time.perf_counter() - start) * 1000
        public_key = key.public_key()
        public_key_hex = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
        return jsonify(
            {
                "signature_hex": signature.hex(),
                "public_key_hex": public_key_hex,
                "signing_time_ms": round(signing_time_ms, 2),
                "key_size_bytes": 64,
                "signature_size_bytes": len(signature),
            }
        )

    level = select_dilithium_level("MEDIUM")
    engine = dilithium_engine(level)
    pk, sk = engine.keygen()
    start = time.perf_counter()
    signature = engine.sign(sk, message.encode("utf-8"))
    signing_time_ms = (time.perf_counter() - start) * 1000

    return jsonify(
        {
            "signature_hex": signature.hex(),
            "public_key_hex": pk.hex(),
            "signing_time_ms": round(signing_time_ms, 2),
            "key_size_bytes": len(pk),
            "signature_size_bytes": len(signature),
        }
    )


@app.post("/api/verify-message")
def api_verify_message() -> Any:
    payload = request.get_json(silent=True) or {}
    message = str(payload.get("message", ""))
    signature_hex = str(payload.get("signature_hex", ""))
    public_key_hex = str(payload.get("public_key_hex", ""))
    mode = payload.get("mode", "ecdsa")

    try:
        signature = bytes.fromhex(signature_hex)
        public_key_bytes = bytes.fromhex(public_key_hex)
    except ValueError:
        return jsonify({"is_valid": False, "verification_time_ms": 0.0})

    if mode == "ecdsa":
        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)
            start = time.perf_counter()
            public_key.verify(signature, message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
            verification_time_ms = (time.perf_counter() - start) * 1000
            return jsonify({"is_valid": True, "verification_time_ms": round(verification_time_ms, 2)})
        except Exception:
            return jsonify({"is_valid": False, "verification_time_ms": 0.0})

    level = select_dilithium_level("MEDIUM")
    engine = dilithium_engine(level)
    start = time.perf_counter()
    is_valid = engine.verify(public_key_bytes, message.encode("utf-8"), signature)
    verification_time_ms = (time.perf_counter() - start) * 1000
    return jsonify({"is_valid": bool(is_valid), "verification_time_ms": round(verification_time_ms, 2)})


def _serialize_user(user: User | None) -> Dict[str, Any] | None:
    if user is None:
        return None
    return {
        "id": user.id,
        "name": user.name,
        "username": user.username,
        "email": user.email,
        "role": user.role.value if isinstance(user.role, UserRole) else str(user.role),
        "is_active": user.is_active,
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }


def _log_audit_event(
    user_id: str | None,
    event_type: str,
    status: str,
    message: str,
    *,
    metadata: Dict[str, Any] | None = None,
    transaction_id: str | None = None,
) -> None:
    try:
        with SessionLocal() as db:
            db.add(
                AuditLog(
                    user_id=user_id,
                    transaction_id=transaction_id,
                    event_type=event_type,
                    status=status,
                    message=message,
                    metadata_=metadata or {},
                )
            )
            db.commit()
    except Exception:
        pass


def _current_user_from_session() -> User | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    with SessionLocal() as db:
        user = db.get(User, user_id)
        if user is None or not user.is_active or session.get("auth_version") != user.auth_version:
            session.clear()
            return None
        return user


def require_auth(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        user = _current_user_from_session()
        if user is None:
            _record_security_audit(
                "AUTHENTICATION_REQUIRED",
                "MEDIUM",
                "Unauthenticated API access denied",
                "An API request required an authenticated session.",
                "BLOCKED",
                source="authorization",
                category="ACCESS_CONTROL",
                metadata={"path": request.path[:200]},
            )
            _log_audit_event(None, "unauthorized_access", "failure", "Authentication required")
            return jsonify({"error": "Authentication required."}), 401
        g.current_user = user
        return view_func(*args, **kwargs)

    return wrapper


def require_role(*allowed_roles: str):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None) or _current_user_from_session()
            if user is None:
                _log_audit_event(None, "unauthorized_access", "failure", "Authentication required for protected route")
                return jsonify({"error": "Authentication required."}), 401

            user_role = user.role.value if isinstance(user.role, UserRole) else str(user.role)
            if user_role not in allowed_roles:
                _record_security_audit(
                    "ROLE_ACCESS_DENIED",
                    "MEDIUM",
                    "API access denied by role policy",
                    "An authenticated user attempted an API action without the required role.",
                    "BLOCKED",
                    source="authorization",
                    category="ACCESS_CONTROL",
                    actor=user,
                    metadata={"path": request.path[:200], "required_roles": list(allowed_roles)},
                )
                _log_audit_event(
                    user.id,
                    "forbidden_access",
                    "forbidden",
                    "User attempted access without required role",
                    metadata={"required_roles": list(allowed_roles), "user_role": user_role},
                )
                return jsonify({"error": "Permission denied."}), 403

            g.current_user = user
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


@app.get("/api/transactions")
@require_auth
def api_transactions() -> Any:
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        transactions = TransactionService.get_transactions_for_user(db, user.id)
        serialized = []
        for tx in transactions:
            decision = tx.aqrs_decision
            if decision is None:
                decision_policy = build_decision_for_amount(tx.amount)
                security_level = decision_policy["security_level"]
                algorithm = decision_policy["algorithm"]
            else:
                security_level = decision.security_level
                algorithm = decision.algorithm
            serialized.append(
                {
                    "id": tx.id,
                    "transaction_id": tx.transaction_id,
                    "sender_account_id": tx.sender_account_id,
                    "receiver_account_id": tx.receiver_account_id,
                    "amount": str(tx.amount),
                    "currency": tx.currency,
                    "description": tx.description,
                    "status": tx.status.value if hasattr(tx.status, "value") else str(tx.status),
                    "risk_level": tx.risk_level.value if tx.risk_level else None,
                    "security_level": security_level,
                    "algorithm": algorithm,
                    "created_at": tx.created_at.isoformat() if tx.created_at else None,
                }
            )

    return jsonify({"transactions": serialized})


@app.post("/api/transactions")
@require_auth
def create_transaction() -> Any:
    user = getattr(g, "current_user")
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    idempotency_key = request.headers.get("Idempotency-Key", "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._~-]{16,128}", idempotency_key):
        return jsonify({"error": "A valid Idempotency-Key header is required."}), 400

    sender_account_id = str(payload.get("sender_account_id") or "").strip()
    has_account_number = "receiver_account_number" in payload
    receiver_identifier = payload.get("receiver_account_number") if has_account_number else payload.get("receiver_account_id")
    receiver_identifier = str(receiver_identifier or "").strip()
    raw_amount = payload.get("amount")
    description = payload.get("description")

    if not sender_account_id or not receiver_identifier:
        return jsonify({"error": "Sender account ID and recipient account number are required."}), 400
    if len(sender_account_id) > 36 or len(receiver_identifier) > (32 if has_account_number else 36):
        return jsonify({"error": "Invalid account identifier."}), 400
    if not re.fullmatch(r"[A-Za-z0-9-]+", receiver_identifier):
        return jsonify({"error": "Recipient account number is invalid."}), 400
    if description is not None and (not isinstance(description, str) or len(description) > 255):
        return jsonify({"error": "Description must be 255 characters or fewer."}), 400

    try:
        amount = TransactionService.parse_amount(raw_amount)
    except ValidationError as exc:
        _record_security_audit(
            "TRANSFER_REJECTED",
            "LOW",
            "Transfer request rejected",
            "A transfer request failed amount validation before processing.",
            "FAILURE",
            source="transaction",
            category="TRANSACTION",
            actor=user,
            metadata={"reason": str(exc)[:200]},
        )
        _log_audit_event(user.id, "TRANSACTION_REJECTED", "failure", str(exc), metadata={"sender_account_id": sender_account_id, "recipient_account_number": receiver_identifier, "amount": raw_amount})
        return jsonify({"error": str(exc)}), 400

    fingerprint_payload = {
        "sender_account_id": sender_account_id,
        "receiver_identifier": receiver_identifier,
        "amount": str(amount),
        "description": description or "",
    }
    request_fingerprint = sha256(
        json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    with SessionLocal() as db:
        idempotency_record = IdempotencyRecord(
            user_id=user.id,
            operation="transfer:create",
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
        )
        db.add(idempotency_record)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            with SessionLocal() as replay_db:
                existing_request = (
                    replay_db.query(IdempotencyRecord)
                    .filter_by(user_id=user.id, operation="transfer:create", idempotency_key=idempotency_key)
                    .one_or_none()
                )
                if existing_request is None:
                    _record_security_audit(
                        "IDEMPOTENCY_CONFLICT",
                        "MEDIUM",
                        "Transfer idempotency key conflict",
                        "A transfer request could not claim its idempotency key.",
                        "BLOCKED",
                        source="transaction",
                        category="TRANSACTION",
                        actor=user,
                    )
                    return jsonify({"error": "Transfer request could not be claimed. Retry with the same key."}), 409
                if existing_request.request_fingerprint != request_fingerprint:
                    _record_security_audit(
                        "IDEMPOTENCY_CONFLICT",
                        "MEDIUM",
                        "Transfer idempotency key reused",
                        "An idempotency key was presented for a different transfer payload.",
                        "BLOCKED",
                        source="transaction",
                        category="TRANSACTION",
                        actor=user,
                    )
                    return jsonify({"error": "Idempotency-Key was already used with a different transfer."}), 409
                if existing_request.response_json is None:
                    _record_security_audit(
                        "IDEMPOTENCY_CONFLICT",
                        "LOW",
                        "Duplicate transfer is still processing",
                        "A matching transfer request is already being processed.",
                        "BLOCKED",
                        source="transaction",
                        category="TRANSACTION",
                        actor=user,
                    )
                    return jsonify({"error": "This transfer request is still being processed. Retry with the same key."}), 409
                replay_response = jsonify(json.loads(existing_request.response_json))
                replay_response.headers["Idempotency-Replayed"] = "true"
                return replay_response
        except OperationalError as exc:
            db.rollback()
            if "database is locked" not in str(getattr(exc, "orig", exc)).lower():
                raise
            response = jsonify(
                {"error": "This transfer request is being processed. Retry with the same key."}
            )
            response.status_code = 409
            response.headers["Retry-After"] = "1"
            return response

        sender = (
            AccountService.get_account_for_user(db, user.id, sender_account_id)
            if user.role != UserRole.ADMIN
            else AccountService.get_account_by_id(db, sender_account_id)
        )
        receiver = AccountService.get_account_by_identifier(
            db,
            receiver_identifier,
            allow_id=not has_account_number,
        )

        if sender is None:
            other_sender = AccountService.get_account_by_id(db, sender_account_id)
            if other_sender is not None and user.role != UserRole.ADMIN:
                db.rollback()
                _record_security_audit(
                    "TRANSFER_AUTHORIZATION_DENIED",
                    "HIGH",
                    "Transfer from an unauthorized account blocked",
                    "A user attempted to transfer funds from an account they do not own.",
                    "BLOCKED",
                    source="transaction",
                    category="TRANSACTION",
                    actor=user,
                    target_type="account",
                    target_id=other_sender.id,
                )
                _log_audit_event(user.id, "TRANSACTION_REJECTED", "forbidden", "User attempted transfer from another user's account", metadata={"sender_account_id": other_sender.id, "request_user_id": user.id})
                return jsonify({"error": "You can only transfer from your own account."}), 403
            db.rollback()
            _record_security_audit(
                "TRANSFER_REJECTED",
                "LOW",
                "Transfer sender account unavailable",
                "A transfer could not find the authorized sender account.",
                "FAILURE",
                source="transaction",
                category="TRANSACTION",
                actor=user,
            )
            _log_audit_event(user.id, "TRANSACTION_REJECTED", "failure", "Missing sender account", metadata={"sender_account_id": sender_account_id})
            return jsonify({"error": "Sender account not found."}), 404
        if receiver is None:
            db.rollback()
            _record_security_audit(
                "TRANSFER_REJECTED",
                "LOW",
                "Transfer recipient account unavailable",
                "A transfer could not find its recipient account.",
                "FAILURE",
                source="transaction",
                category="TRANSACTION",
                actor=user,
            )
            _log_audit_event(user.id, "TRANSACTION_REJECTED", "failure", "Missing recipient account", metadata={"recipient_account_number": receiver_identifier})
            return jsonify({"error": "Account not found."}), 404

        if sender.id == receiver.id:
            db.rollback()
            _record_security_audit(
                "TRANSFER_REJECTED",
                "LOW",
                "Self-transfer request rejected",
                "A transfer cannot use the same account as sender and recipient.",
                "FAILURE",
                source="transaction",
                category="TRANSACTION",
                actor=user,
            )
            _log_audit_event(user.id, "TRANSACTION_REJECTED", "failure", "Sender and receiver cannot be the same account", metadata={"sender_account_id": sender.id, "receiver_account_id": receiver.id})
            return jsonify({"error": "Sender and receiver accounts must be different."}), 400

        try:
            TransactionService.apply_transfer_balances(
                db,
                sender=sender,
                receiver=receiver,
                amount=amount,
            )

            risk = classify_transaction_risk(amount)
            decision_policy = select_security_level(risk)

            txn = Transaction(
                transaction_id=f"TX-{uuid.uuid4().hex[:12].upper()}",
                sender_account_id=sender.id,
                receiver_account_id=receiver.id,
                amount=amount,
                currency=sender.currency or receiver.currency or "INR",
                description=description or f"Transfer from {sender.account_number} to {receiver.account_number}",
                status=TransactionStatus.COMPLETED,
                risk_level=risk,
                risk_score=Decimal("0.00"),
                aqrs_level=decision_policy["selected_security_level"],
                cryptographic_mode=decision_policy["algorithm"],
            )
            db.add(txn)
            db.flush()

            decision = AQRSDecisionService.evaluate_transaction(txn)
            db.add(decision)
            db.flush()

            _log_audit_event(
                user.id,
                "AQRS_DECISION_CREATED",
                "success",
                decision.decision_reason,
                metadata={
                    "transaction_id": txn.transaction_id,
                    "risk_level": decision.risk_level.value,
                    "security_level": decision.security_level,
                    "algorithm": decision.algorithm,
                    "selected_security_level": decision.selected_security_level,
                },
                transaction_id=txn.id,
            )

            try:
                signature_result = CryptoSignatureService.sign_transaction(db, txn.id)
                verification_result = CryptoSignatureService.verify_transaction_signature(db, txn.id)
                if not verification_result["valid"]:
                    raise ValueError("Transaction signature verification failed.")
                ledger_block = add_transaction_to_ledger(db, txn.id, user_id=user.id)
            except Exception as exc:
                db.rollback()
                app.logger.error("Transaction signing failed (%s)", type(exc).__name__)
                _log_audit_event(user.id, "CRYPTO_SIGNATURE_FAILED", "failure", "Transaction could not be signed securely.", metadata={"transaction_id": txn.transaction_id, "algorithm": decision.algorithm, "security_level": decision.security_level}, transaction_id=txn.id)
                return jsonify({"error": "Transaction could not be signed securely."}), 409

            response_payload = {
                "id": txn.id,
                "transaction_id": txn.transaction_id,
                "sender_account_id": txn.sender_account_id,
                "receiver_account_id": txn.receiver_account_id,
                "amount": str(txn.amount),
                "currency": txn.currency,
                "status": txn.status.value if hasattr(txn.status, "value") else str(txn.status),
                "description": txn.description,
                "risk_level": txn.risk_level.value if txn.risk_level else None,
                "security_level": decision.security_level,
                "algorithm": decision.algorithm,
                "signature_available": True,
                "signature_size_bytes": signature_result.get("signature_size_bytes", 0),
                "block_number": ledger_block.block_number,
                "block_hash": ledger_block.block_hash,
                "created_at": txn.created_at.isoformat() if txn.created_at else None,
            }
            result_payload = {
                "message": "Transaction completed successfully",
                "transaction": response_payload,
            }
            idempotency_record.response_json = json.dumps(
                result_payload,
                sort_keys=True,
                separators=(",", ":"),
            )
            db.commit()
            db.refresh(txn)
            db.refresh(decision)
            _record_security_audit(
                "TRANSFER_COMPLETED",
                "INFO",
                "Funds transfer completed",
                "An authenticated transfer completed and was committed to the ledger.",
                "SUCCESS",
                source="transaction",
                category="TRANSACTION",
                actor=user,
                target_type="transaction",
                target_id=txn.id,
                metadata={"transaction_id": txn.transaction_id, "block_number": ledger_block.block_number},
            )
            _log_audit_event(user.id, "TRANSACTION_CREATED", "success", "Transfer completed successfully", metadata={"transaction_id": txn.id, "sender_account_id": sender.id, "receiver_account_id": receiver.id, "amount": str(amount), "risk_level": risk.value, "security_level": decision.security_level}, transaction_id=txn.id)
            return jsonify(result_payload)
        except (ValidationError, InsufficientBalanceError, ValueError) as exc:
            db.rollback()
            _record_security_audit(
                "TRANSFER_REJECTED",
                "LOW",
                "Transfer rejected during processing",
                "A transfer failed validation or balance checks and was rolled back.",
                "FAILURE",
                source="transaction",
                category="TRANSACTION",
                actor=user,
                metadata={"reason": str(exc)[:200]},
            )
            _log_audit_event(user.id, "TRANSACTION_REJECTED", "failure", str(exc), metadata={"sender_account_id": sender.id, "receiver_account_id": receiver.id, "amount": str(amount)}, transaction_id=None)
            return jsonify({"error": str(exc)}), 400 if isinstance(exc, ValidationError) else 409
        except Exception as exc:
            db.rollback()
            app.logger.error("Transaction processing failed (%s)", type(exc).__name__)
            _record_security_audit(
                "TRANSFER_PROCESSING_FAILED",
                "HIGH",
                "Transfer processing failed",
                "A transfer failed unexpectedly and the transaction was rolled back.",
                "FAILURE",
                source="transaction",
                category="TRANSACTION",
                actor=user,
            )
            _log_audit_event(
                user.id,
                "TRANSACTION_REJECTED",
                "failure",
                "Transfer could not be completed.",
                metadata={"sender_account_id": sender.id, "receiver_account_id": receiver.id},
            )
            return jsonify({"error": "Transfer could not be completed."}), 500


@app.get("/api/transactions/<transaction_id>")
@require_auth
def get_transaction_by_id(transaction_id: str) -> Any:
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        txn = TransactionService.get_transaction_for_user(db, user.id, transaction_id)
        if txn is None:
            if user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
                txn = TransactionService.get_transaction_by_identifier(db, transaction_id)
            if txn is None:
                return jsonify({"error": "Transaction not found or access denied."}), 403 if user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST} else 404

        decision = txn.aqrs_decision or AQRSDecisionService.evaluate_transaction(txn)
        return jsonify(
            {
                "transaction": {
                    "id": txn.id,
                    "transaction_id": txn.transaction_id,
                    "sender_account_id": txn.sender_account_id,
                    "receiver_account_id": txn.receiver_account_id,
                    "amount": str(txn.amount),
                    "currency": txn.currency,
                    "description": txn.description,
                    "status": txn.status.value if hasattr(txn.status, "value") else str(txn.status),
                    "risk_level": txn.risk_level.value if txn.risk_level else None,
                    "security_level": decision.security_level,
                    "algorithm": decision.algorithm,
                    "created_at": txn.created_at.isoformat() if txn.created_at else None,
                }
            }
        )


@app.get("/api/transactions/<transaction_id>/security")
@require_auth
def get_transaction_security(transaction_id: str) -> Any:
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        txn = TransactionService.get_transaction_by_identifier(db, transaction_id)
        if txn is None:
            return jsonify({"error": "Transaction not found."}), 404

        if user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
            user_account_ids = {row[0] for row in db.query(Account.id).filter_by(user_id=user.id).all()}
            if txn.sender_account_id not in user_account_ids and txn.receiver_account_id not in user_account_ids:
                _log_audit_event(user.id, "AQRS_DECISION_FORBIDDEN", "forbidden", "User attempted to access another customer's security decision", metadata={"transaction_id": txn.id, "request_user_id": user.id})
                return jsonify({"error": "Access denied."}), 403

        decision = txn.aqrs_decision or AQRSDecisionService.evaluate_transaction(txn)
        if txn.aqrs_decision is None and decision.transaction_id == txn.id:
            db.add(decision)
            db.commit()
            db.refresh(decision)

        signature = txn.signature
        signature_available = signature is not None and bool(signature.signature_hex)
        return jsonify(
            {
                "transaction_id": txn.transaction_id,
                "risk_level": txn.risk_level.value if txn.risk_level else None,
                "security_level": decision.security_level,
                "algorithm": decision.algorithm,
                "selected_security_level": decision.selected_security_level,
                "compatibility_name": {
                    2: "DIL2",
                    3: "DIL3",
                    5: "DIL5",
                }.get(decision.selected_security_level, "DIL2"),
                "decision_reason": decision.decision_reason,
                "aqrs_score": str(decision.aqrs_score),
                "signature_available": signature_available,
                "signature_size": signature.signature_size_bytes if signature else 0,
                "verification_status": signature.verification_status if signature else "UNSIGNED",
            }
        )


@app.post("/api/transactions/<transaction_id>/sign")
@require_auth
def sign_transaction_endpoint(transaction_id: str) -> Any:
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        txn = TransactionService.get_transaction_for_user(db, user.id, transaction_id)
        if txn is None:
            if user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
                txn = TransactionService.get_transaction_by_identifier(db, transaction_id)
            if txn is None:
                return jsonify({"error": "Transaction not found or access denied."}), 404

        try:
            result = CryptoSignatureService.sign_transaction(db, txn.id)
            db.commit()
            _log_audit_event(user.id, "CRYPTO_SIGNATURE_CREATED", "success", "Signed transaction using ML-DSA", metadata={"transaction_id": txn.transaction_id, "algorithm": result["algorithm"], "security_level": result["security_level"]}, transaction_id=txn.id)
            return jsonify(result)
        except Exception as exc:
            db.rollback()
            app.logger.error("Transaction signing failed (%s)", type(exc).__name__)
            _log_audit_event(user.id, "CRYPTO_SIGNATURE_FAILED", "failure", "Transaction signing could not be completed.", metadata={"transaction_id": txn.transaction_id}, transaction_id=txn.id)
            return jsonify({"error": "Transaction signing could not be completed."}), 409


@app.get("/api/transactions/<transaction_id>/verify")
@require_auth
def verify_transaction_endpoint(transaction_id: str) -> Any:
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        txn = TransactionService.get_transaction_for_user(db, user.id, transaction_id)
        if txn is None:
            if user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
                txn = TransactionService.get_transaction_by_identifier(db, transaction_id)
            if txn is None:
                return jsonify({"error": "Transaction not found or access denied."}), 404

        try:
            result = CryptoSignatureService.verify_transaction_signature(db, txn.id)
            db.commit()
            return jsonify({
                "transaction_id": txn.transaction_id,
                "valid": result["valid"],
                "algorithm": result["algorithm"],
                "security_level": result["security_level"],
                "signature_size_bytes": result["signature_size_bytes"],
                "verification_time_ms": result["verification_time_ms"],
            })
        except Exception as exc:
            db.rollback()
            app.logger.error("Transaction signature verification failed (%s)", type(exc).__name__)
            _log_audit_event(
                user.id,
                "CRYPTO_VERIFICATION_FAILED",
                "failure",
                "Transaction signature verification could not be completed.",
                metadata={"transaction_id": txn.transaction_id},
                transaction_id=txn.id,
            )
            return jsonify({"error": "Transaction signature verification could not be completed."}), 409


def _serialize_block(block) -> Dict[str, Any]:
    return {
        "id": block.id,
        "block_index": block.block_number,
        "timestamp": block.timestamp.isoformat() if block.timestamp else None,
        "previous_hash": block.previous_hash,
        "block_hash": block.block_hash,
        "transaction_count": block.transaction_count,
        "block_size_bytes": block.block_size_bytes,
        "created_at": block.created_at.isoformat() if block.created_at else None,
        "transactions": [
            {
                "id": transaction.id,
                "transaction_id": transaction.transaction_id,
                "signature_id": transaction.signature.id if transaction.signature else None,
            }
            for transaction in block.transactions
        ],
    }


@app.get("/api/blockchain")
@require_auth
def get_blockchain() -> Any:
    user = getattr(g, "current_user")
    if user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        return jsonify({"error": "Access denied."}), 403
    from backend.services.blockchain_service import get_chain, validate_chain

    with SessionLocal() as db:
        return jsonify({"blocks": [_serialize_block(block) for block in get_chain(db)], "validation": validate_chain(db)})


@app.get("/api/blockchain/validate")
@require_auth
def validate_blockchain() -> Any:
    user = getattr(g, "current_user")
    if user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        return jsonify({"error": "Access denied."}), 403
    from backend.services.blockchain_service import validate_chain

    with SessionLocal() as db:
        result = validate_chain(db)
    _record_security_audit(
        "BLOCKCHAIN_INTEGRITY_CHECK",
        "INFO" if result["valid"] else "HIGH",
        "Blockchain integrity verification completed",
        "The persisted blockchain was checked using the configured block-hash and previous-hash validation rules.",
        "SUCCESS" if result["valid"] else "FAILURE",
        source="blockchain",
        category="INTEGRITY",
        actor=getattr(g, "current_user", None),
        metadata={"valid": result["valid"], "block_count": result["block_count"], "error_count": len(result["errors"])},
    )
    return jsonify(result)


@app.get("/api/blockchain/blocks/<int:block_number>")
@require_auth
def get_block_by_number(block_number: int) -> Any:
    user = getattr(g, "current_user")
    if user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        return jsonify({"error": "Access denied."}), 403
    from backend.services.blockchain_service import get_block, validate_block

    with SessionLocal() as db:
        block = get_block(db, block_number)
        if block is None:
            return jsonify({"error": "Block not found."}), 404
        return jsonify({"block": _serialize_block(block), "validation": validate_block(db, block)})


@app.get("/api/transactions/<transaction_id>/block")
@require_auth
def get_transaction_block(transaction_id: str) -> Any:
    user = getattr(g, "current_user")
    from backend.services.blockchain_service import get_transaction_block as find_transaction_block

    with SessionLocal() as db:
        txn = TransactionService.get_transaction_for_user(db, user.id, transaction_id)
        if txn is None and user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
            txn = TransactionService.get_transaction_by_identifier(db, transaction_id)
        if txn is None:
            return jsonify({"error": "Transaction not found or access denied."}), 404
        block = find_transaction_block(db, txn.id)
        if block is None:
            return jsonify({"error": "Transaction is not included in the ledger."}), 404
        return jsonify({"block": _serialize_block(block)})


@app.get("/api/security/aqrs/decisions")
@require_auth
def get_all_aqrs_decisions():
    user = getattr(g, "current_user")
    if user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        _log_audit_event(user.id, "AQRS_DECISION_FORBIDDEN", "forbidden", "Customer attempted to access system AQRS decisions", metadata={"user_role": user.role.value})
        return jsonify({"error": "Access denied."}), 403

    with SessionLocal() as db:
        decisions = db.query(AQRSDecision).order_by(AQRSDecision.created_at.desc()).all()

    return jsonify(
        {
            "decisions": [
                {
                    "id": d.id,
                    "transaction_id": d.transaction_id,
                    "risk_level": d.risk_level.value,
                    "selected_security_level": d.selected_security_level,
                    "security_level": d.security_level,
                    "algorithm": d.algorithm,
                    "compatibility_name": {
                        2: "DIL2",
                        3: "DIL3",
                        5: "DIL5",
                    }.get(d.selected_security_level, "DIL2"),
                    "decision_reason": d.decision_reason,
                    "aqrs_score": str(d.aqrs_score),
                    "created_at": d.created_at.isoformat() if d.created_at else None,
                }
                for d in decisions
            ]
        }
    )


@app.get("/api/blocks")
def api_blocks() -> Any:
    return jsonify(BLOCKS)


@app.get("/api/admin/overview")
@require_auth
@require_role(UserRole.ADMIN.value)
def admin_overview_api() -> Any:
    with SessionLocal() as db:
        return jsonify(get_admin_overview(db))


@app.get("/api/admin/users")
@require_auth
@require_role(UserRole.ADMIN.value)
def admin_users_api() -> Any:
    with SessionLocal() as db:
        return jsonify({"users": get_users(db)})


@app.get("/api/admin/transactions")
@require_auth
@require_role(UserRole.ADMIN.value)
def admin_transactions_api() -> Any:
    with SessionLocal() as db:
        return jsonify({"transactions": get_transactions(db)})


@app.get("/api/admin/audit")
@require_auth
@require_role(UserRole.ADMIN.value)
def admin_audit_api() -> Any:
    with SessionLocal() as db:
        return jsonify({"events": get_audit_logs(db)})


@app.get("/api/security/overview")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def security_overview_api() -> Any:
    with SessionLocal() as db:
        return jsonify(get_security_overview(db))


@app.get("/api/security/aqrs")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def security_aqrs_api() -> Any:
    with SessionLocal() as db:
        return jsonify(get_aqrs_analytics(db))


@app.get("/api/security/crypto")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def security_crypto_api() -> Any:
    with SessionLocal() as db:
        return jsonify({"algorithms": get_algorithm_usage(db), "signatures": get_signature_statistics(db)})


@app.get("/api/security/blockchain")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def security_blockchain_api() -> Any:
    with SessionLocal() as db:
        return jsonify(get_blockchain_analytics(db))


@app.get("/api/security/audit")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def security_audit_api() -> Any:
    with SessionLocal() as db:
        return jsonify({"events": get_audit_logs(db, security_only=True)})


@app.get("/api/security/audit/dashboard")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def security_audit_dashboard_api() -> Any:
    with SessionLocal() as db:
        return jsonify({
            "stats": audit_dashboard_stats(db),
            "categories": event_categories(db),
            "severities": list(SECURITY_AUDIT_SEVERITIES),
            "outcomes": list(SECURITY_AUDIT_OUTCOMES),
        })


@app.get("/api/security/audit/events")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def security_audit_events_api() -> Any:
    try:
        filters = parse_audit_filters(request.args)
    except AuditFilterError as exc:
        return jsonify({"error": str(exc)}), 400
    with SessionLocal() as db:
        return jsonify(list_audit_events(db, filters))


@app.get("/api/security/audit/events/<event_id>")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def security_audit_event_detail_api(event_id: str) -> Any:
    if len(event_id) > 36:
        return jsonify({"error": "Audit event not found."}), 404
    with SessionLocal() as db:
        event = db.get(SecurityAuditEvent, event_id)
        if event is None:
            return jsonify({"error": "Audit event not found."}), 404
        return jsonify({"event": serialize_event(event)})


def _audit_export_context() -> tuple[dict[str, Any] | None, Any | None]:
    try:
        return parse_audit_filters(request.args), None
    except AuditFilterError as exc:
        return None, (jsonify({"error": str(exc)}), 400)


def _audit_filter_report_value(filters: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value.isoformat() if isinstance(value, datetime) else value
        for key, value in filters.items()
    }


def _audit_csv_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


@app.get("/api/security/audit/export.csv")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def export_security_audit_csv() -> Any:
    filters, error = _audit_export_context()
    if error:
        return error
    with SessionLocal() as db:
        events = report_event_rows(db, filters)
        matching_event_count = report_event_count(db, filters)
        generated_at = datetime.now(timezone.utc)
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["generated_at", generated_at.isoformat()])
        writer.writerow(["matching_event_count", matching_event_count])
        writer.writerow(["exported_event_count", len(events)])
        writer.writerow(["selected_filters", json.dumps(_audit_filter_report_value(filters), sort_keys=True)])
        writer.writerow([])
        writer.writerow([
            "event_id", "timestamp", "event_type", "category", "severity", "title",
            "description", "actor_id", "actor_username", "actor_email", "outcome",
            "source", "target_type", "target_id", "correlation_id", "is_demo", "metadata",
        ])
        for event in events:
            row = serialize_event(event)
            writer.writerow([
                _audit_csv_cell(row[key])
                for key in (
                    "id", "created_at", "event_type", "category", "severity", "title",
                    "description", "actor_id", "actor_username", "actor_email", "outcome",
                    "source", "target_type", "target_id", "correlation_id", "is_demo", "metadata",
                )
            ])
        _record_security_audit(
            "AUDIT_REPORT_EXPORTED",
            "INFO",
            "Security audit CSV report generated",
            "An authorized user generated a bounded CSV export of security audit events.",
            "SUCCESS",
            source="security_audit",
            category="AUDIT",
            actor=g.current_user,
            metadata={"format": "csv", "matching_event_count": matching_event_count, "exported_event_count": len(events), "selected_filters": _audit_filter_report_value(filters)},
        )
    from flask import Response

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="pqbank-security-audit.csv"'},
    )


@app.get("/api/security/audit/export.json")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def export_security_audit_json() -> Any:
    filters, error = _audit_export_context()
    if error:
        return error
    with SessionLocal() as db:
        events = report_event_rows(db, filters)
        matching_event_count = report_event_count(db, filters)
        generated_at = datetime.now(timezone.utc)
        report = {
            "generated_at": generated_at.isoformat(),
            "selected_filters": _audit_filter_report_value(filters),
            "matching_event_count": matching_event_count,
            "exported_event_count": len(events),
            "maximum_export_rows": MAX_EXPORT_ROWS,
            "events": [serialize_event(event) for event in events],
        }
        _record_security_audit(
            "AUDIT_REPORT_EXPORTED",
            "INFO",
            "Security audit JSON report generated",
            "An authorized user generated a bounded JSON export of security audit events.",
            "SUCCESS",
            source="security_audit",
            category="AUDIT",
            actor=g.current_user,
            metadata={"format": "json", "matching_event_count": matching_event_count, "exported_event_count": len(events), "selected_filters": _audit_filter_report_value(filters)},
        )
    from flask import Response

    return Response(
        json.dumps(report, ensure_ascii=False, separators=(",", ":"), allow_nan=False),
        mimetype="application/json",
        headers={"Content-Disposition": 'attachment; filename="pqbank-security-audit.json"'},
    )


@app.get("/api/security/lab/history")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def security_lab_history_api() -> Any:
    return jsonify(security_lab_history())


@app.post("/api/security/lab/run/<scenario_id>")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def run_security_lab_demo(scenario_id: str) -> Any:
    if scenario_id not in SECURITY_LAB_SCENARIOS:
        return jsonify({"error": "Unsupported security demonstration scenario."}), 400
    result = run_security_demo(scenario_id)
    if result["status"] == "VERIFICATION_ERROR":
        app.logger.error("Security lab verification failed for %s", scenario_id)
    _record_security_audit(
        "SECURITY_LAB_SCENARIO_RUN",
        "INFO" if result["status"] in {"VALID", "INVALID"} else "LOW",
        "Security lab simulation completed" if result["operation_completed"] else "Security lab simulation did not complete",
        "A controlled Module 12 demonstration ran against isolated synthetic data; this is not a production incident.",
        "SUCCESS" if result["operation_completed"] else "FAILURE",
        source="security_lab",
        category="DEMO",
        actor=g.current_user,
        target_type="demo_scenario",
        target_id=scenario_id,
        is_demo=True,
        metadata={
            "scenario_id": scenario_id,
            "baseline_status": result["baseline_status"],
            "post_tampering_status": result["status"],
            "tampering_detected": result["detected"],
        },
    )
    history = record_demo_result(result, g.current_user.id)
    return jsonify({"result": result, **history})


@app.post("/api/security/lab/reset")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def reset_security_lab() -> Any:
    _record_security_audit(
        "SECURITY_LAB_RESET",
        "INFO",
        "Security lab history reset",
        "Process-local Module 12 demonstration history was cleared; no production data was changed.",
        "SUCCESS",
        source="security_lab",
        category="DEMO",
        actor=g.current_user,
        target_type="demo_history",
        is_demo=True,
    )
    return jsonify({"message": "Demo history cleared. The next run starts from a fresh isolated baseline.", **reset_demo_history()})


@app.get("/api/research/experiments")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def research_experiments_api() -> Any:
    with SessionLocal() as db:
        return jsonify({"experiments": [serialize_experiment(experiment) for experiment in list_experiments(db)], "modes": list(RESEARCH_MODES)})


@app.get("/api/research/experiments/<experiment_id>")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def research_experiment_api(experiment_id: str) -> Any:
    with SessionLocal() as db:
        experiment = get_experiment(db, experiment_id)
        if experiment is None:
            return jsonify({"error": "Experiment not found."}), 404
        return jsonify({"experiment": serialize_experiment(experiment)})


@app.post("/api/research/experiments")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def create_research_experiment_api() -> Any:
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    try:
        transaction_count = payload.get("transaction_count", 100)
        if type(transaction_count) is not int:
            raise ValueError("transaction_count must be an integer.")
        seed = payload.get("seed")
        if seed is not None and type(seed) is not int:
            raise ValueError("seed must be an integer.")
        modes = payload.get("modes")
        if modes is not None and (
            not isinstance(modes, list) or any(not isinstance(mode, str) for mode in modes)
        ):
            raise ValueError("modes must be a list.")
        with SessionLocal() as db:
            experiment = run_experiment(db, transaction_count=transaction_count, seed=seed, modes=modes)
            return jsonify({"experiment": serialize_experiment(experiment)}), 201
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "The research experiment failed."}), 500


@app.get("/api/research/results")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def research_results_api() -> Any:
    with SessionLocal() as db:
        experiment = get_latest_experiment(db)
        if experiment is None:
            return jsonify({"error": "No completed research experiment is available."}), 404
        return jsonify({"experiment": serialize_experiment(experiment)})


@app.get("/api/research/compare")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def research_compare_api() -> Any:
    with SessionLocal() as db:
        experiment = get_latest_experiment(db)
        if experiment is None:
            return jsonify({"error": "No completed research experiment is available."}), 404
        return jsonify({"experiment_id": experiment.id, "experiment_name": experiment.experiment_name, "modes": list(RESEARCH_MODES), "results": [
            {
                "mode": result.mode,
                "average_signing_time_ms": result.average_signing_time_ms,
                "average_verification_time_ms": result.average_verification_time_ms,
                "average_signature_size_bytes": result.average_signature_size_bytes,
                "throughput_tps": result.throughput_tps,
                "blockchain_size_bytes": result.blockchain_size_bytes,
                "aqrs_score": result.aqrs_score,
            }
            for result in sorted(experiment.results, key=lambda item: RESEARCH_MODES.index(item.mode))
        ]})


@app.get("/api/research/experiments/<experiment_id>/export.csv")
@require_auth
@require_role(UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value)
def export_research_csv(experiment_id: str) -> Any:
    with SessionLocal() as db:
        experiment = get_experiment(db, experiment_id)
        if experiment is None:
            return jsonify({"error": "Experiment not found."}), 404
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["mode", "average_signing_time_ms", "average_verification_time_ms", "average_signature_size_bytes", "throughput_tps", "blockchain_size_bytes", "aqrs_score"])
        writer.writeheader()
        for result in experiment.results:
            writer.writerow({field: getattr(result, field) for field in writer.fieldnames})
        from flask import Response

        return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={experiment.experiment_name}.csv"})


@app.post("/api/auth/register")
def register_user():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    name = str(payload.get("name", "")).strip()
    email = str(payload.get("email", "")).strip().lower()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    requested_role = str(payload.get("role", "")).strip().upper()

    if not name or not email or not password:
        return jsonify({"error": "Name, email, and password are required."}), 400
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "A valid email address is required."}), 400
    if not username:
        username = email.split("@", 1)[0].strip()
    username = username.strip()
    password_error = password_policy_error(password)
    if password_error:
        return jsonify({"error": password_error}), 400
    if requested_role and requested_role not in {"CUSTOMER"}:
        return jsonify({"error": "Public registration creates CUSTOMER accounts only."}), 400

    with SessionLocal() as db:
        if db.query(User).filter(func.lower(User.email) == email).first() is not None:
            _record_security_audit(
                "REGISTRATION_REJECTED",
                "LOW",
                "Registration rejected for duplicate email",
                "A registration request used an email address that already exists.",
                "BLOCKED",
                source="authentication",
                category="AUTHENTICATION",
            )
            _log_audit_event(None, "registration_failed", "conflict", "Duplicate email registration attempt", metadata={"email": email})
            return jsonify({"error": "An account with this email already exists."}), 409
        if db.query(User).filter(func.lower(User.username) == username.lower()).first() is not None:
            _record_security_audit(
                "REGISTRATION_REJECTED",
                "LOW",
                "Registration rejected for duplicate username",
                "A registration request used a username that already exists.",
                "BLOCKED",
                source="authentication",
                category="AUTHENTICATION",
            )
            _log_audit_event(None, "registration_failed", "conflict", "Duplicate username registration attempt", metadata={"username": username})
            return jsonify({"error": "This username is already taken."}), 409

        user = User(
            name=name,
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=UserRole.CUSTOMER,
            is_active=True,
        )
        try:
            db.add(user)
            db.flush()

            account_number = f"INR-{uuid.uuid4().hex[:12].upper()}"
            account = Account(
                user_id=user.id,
                account_number=account_number,
                account_type=AccountType.SAVINGS,
                balance=Decimal("10000.00"),
                currency="INR",
                status=AccountStatus.ACTIVE,
            )
            db.add(account)
            db.commit()
            db.refresh(user)
        except Exception as exc:
            db.rollback()
            app.logger.error("Registration transaction failed (%s)", type(exc).__name__)
            _record_security_audit(
                "ACCOUNT_CREATION_FAILED",
                "MEDIUM",
                "Account registration failed",
                "A registration transaction could not be committed.",
                "FAILURE",
                source="authentication",
                category="ACCOUNT",
            )
            return jsonify({"error": "Registration could not be completed."}), 500

        _record_security_audit(
            "ACCOUNT_CREATED",
            "INFO",
            "Customer account created",
            "A customer registered successfully and received an initial account.",
            "SUCCESS",
            source="authentication",
            category="ACCOUNT",
            actor=user,
            target_type="user",
            target_id=user.id,
        )
        _log_audit_event(user.id, "registration_success", "success", "User registered successfully", metadata={"username": username, "role": user.role.value, "account_number": account.account_number})
        return jsonify({"message": "User registered successfully.", "user": _serialize_user(user)}), 201


@app.post("/api/auth/login")
def login_user():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    email = str(payload.get("email", "")).strip().lower()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))

    identity = email or username
    if not password or (not email and not username):
        return jsonify({"error": "Email/username and password are required."}), 400

    username = username.strip()
    with SessionLocal() as db:
        user = None
        if email:
            user = db.query(User).filter(func.lower(User.email) == email).first()
        if user is None and username:
            user = db.query(User).filter(func.lower(User.username) == username.lower()).first()

        try:
            password_valid = user is not None and check_password_hash(user.password_hash, password)
        except (TypeError, ValueError):
            app.logger.error("Authentication refused because a stored password hash is invalid.")
            password_valid = False

        if not password_valid:
            _record_security_audit(
                "LOGIN_FAILED",
                "MEDIUM",
                "Login attempt failed",
                "The supplied account identity and password did not authenticate.",
                "FAILURE",
                source="authentication",
                category="AUTHENTICATION",
            )
            _log_audit_event(None, "login_failed", "failure", "Failed login attempt", metadata={"email": email or username})
            return jsonify({"error": "Invalid credentials."}), 401
        if not user.is_active:
            _record_security_audit(
                "LOGIN_BLOCKED_INACTIVE_ACCOUNT",
                "MEDIUM",
                "Login blocked for inactive account",
                "Authentication succeeded for an account that is inactive, so session creation was denied.",
                "BLOCKED",
                source="authentication",
                category="AUTHENTICATION",
                actor=user,
            )
            _log_audit_event(user.id, "login_failed", "failure", "Inactive account login attempt", metadata={"email": user.email})
            return jsonify({"error": "This account is inactive."}), 401

        user.last_login = datetime.now(timezone.utc)
        db.add(user)
        db.commit()
        rate_limit_store = app.config.get("RATE_LIMIT_STORE", app.extensions["rate_limit_store"])
        rate_limit_store.clear(_login_rate_limit_key(identity))
        session.clear()
        now = _session_clock()
        session["user_id"] = user.id
        session["user_role"] = user.role.value
        session["auth_version"] = user.auth_version
        session["auth_issued_at"] = now
        session["auth_last_seen_at"] = now
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True

        _record_security_audit(
            "LOGIN_SUCCEEDED",
            "INFO",
            "User signed in",
            "An account authenticated and a new session was established.",
            "SUCCESS",
            source="authentication",
            category="AUTHENTICATION",
            actor=user,
        )
        _log_audit_event(user.id, "login_success", "success", "User logged in successfully", metadata={"username": user.username})
        return jsonify({"message": "Login successful.", "user": _serialize_user(user)})


@app.post("/api/auth/password")
@require_auth
def change_password_api() -> Any:
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    current_password = str(payload.get("current_password", ""))
    new_password = str(payload.get("new_password", ""))
    confirm_password = str(payload.get("confirm_password", ""))
    if not current_password or not new_password or not confirm_password:
        _log_audit_event(g.current_user.id, "password_change_failed", "failure", "Required password-change fields were missing")
        return jsonify({"error": "Current, new, and confirmed passwords are required."}), 400
    if new_password != confirm_password:
        _log_audit_event(g.current_user.id, "password_change_failed", "failure", "New password confirmation did not match")
        return jsonify({"error": "New password and confirmation do not match."}), 400

    user_id = g.current_user.id
    with SessionLocal() as db:
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            session.clear()
            return jsonify({"error": "Authentication required."}), 401
        try:
            change_password(db, user, current_password, new_password)
        except InvalidCurrentPassword:
            _record_security_audit(
                "PASSWORD_CHANGE_REJECTED",
                "MEDIUM",
                "Password change rejected",
                "The current password did not verify; account credentials were not changed.",
                "FAILURE",
                source="authentication",
                category="AUTHENTICATION",
                actor=user,
            )
            _log_audit_event(user.id, "password_change_failed", "failure", "Current password verification failed", metadata={"username": user.username})
            return jsonify({"error": "Current password is incorrect."}), 401
        except PasswordPolicyError as exc:
            _record_security_audit(
                "PASSWORD_CHANGE_REJECTED",
                "LOW",
                "Password change rejected by policy",
                "The requested new password did not satisfy account password policy.",
                "FAILURE",
                source="authentication",
                category="AUTHENTICATION",
                actor=user,
            )
            _log_audit_event(user.id, "password_change_failed", "failure", "New password did not meet policy", metadata={"username": user.username})
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            db.rollback()
            app.logger.error("Password change failed (%s)", type(exc).__name__)
            _log_audit_event(user.id, "password_change_failed", "failure", "Password change could not be completed", metadata={"username": user.username})
            return jsonify({"error": "Password change could not be completed."}), 500

        _record_security_audit(
            "PASSWORD_CHANGED",
            "INFO",
            "Account password changed",
            "The authenticated user changed their password and existing sessions were revoked.",
            "SUCCESS",
            source="authentication",
            category="AUTHENTICATION",
            actor=user,
        )
        _log_audit_event(user.id, "password_changed", "success", "Password changed; all sessions revoked", metadata={"username": user.username})
        session.clear()
        return jsonify({"message": "Password changed. Sign in again with your new password."})


@app.post("/api/auth/logout")
@require_auth
def logout_user():
    user = getattr(g, "current_user")
    _record_security_audit(
        "LOGOUT_SUCCEEDED",
        "INFO",
        "User signed out",
        "The authenticated user ended the current session.",
        "SUCCESS",
        source="authentication",
        category="AUTHENTICATION",
        actor=user,
    )
    _log_audit_event(user.id, "logout", "success", "User logged out", metadata={"username": user.username})
    session.clear()
    return jsonify({"message": "Logged out successfully."})


@app.get("/api/auth/me")
@require_auth
def current_user_profile():
    user = getattr(g, "current_user")
    return jsonify({"user": _serialize_user(user)})


@app.get("/api/admin/test")
@require_auth
@require_role(UserRole.ADMIN.value)
def admin_test_endpoint():
    user = getattr(g, "current_user")
    return jsonify({"message": "Admin access granted.", "user": _serialize_user(user)})


@app.get("/api/security/test")
@require_auth
@require_role(UserRole.SECURITY_ANALYST.value)
def security_test_endpoint():
    user = getattr(g, "current_user")
    return jsonify({"message": "Security access granted.", "user": _serialize_user(user)})


@app.get("/api/users/me/accounts")
@require_auth
def my_accounts():
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        accounts = db.query(Account).filter_by(user_id=user.id).all()
    return jsonify({"accounts": [{"id": acc.id, "account_number": acc.account_number, "account_type": acc.account_type.value if hasattr(acc.account_type, "value") else str(acc.account_type), "balance": str(acc.balance), "currency": acc.currency, "status": acc.status.value if hasattr(acc.status, "value") else str(acc.status)} for acc in accounts]})


@app.get("/api/accounts/<account_id>")
@require_auth
def get_account_by_id(account_id: str):
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        account = db.get(Account, account_id)
        if account is None:
            return jsonify({"error": "Account not found."}), 404
        if user.role != UserRole.ADMIN and account.user_id != user.id:
            _log_audit_event(
                user.id,
                "forbidden_account_access",
                "forbidden",
                "User attempted access to another user's account",
                metadata={"account_id": account.id, "owner_user_id": account.user_id, "request_user_id": user.id},
            )
            return jsonify({"error": "Account access denied."}), 403

        return jsonify(
            {
                "account": {
                    "id": account.id,
                    "user_id": account.user_id,
                    "account_number": account.account_number,
                    "account_type": account.account_type.value,
                    "balance": str(account.balance),
                    "currency": account.currency,
                    "status": account.status.value,
                }
            }
        )


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").strip().lower() in {"1", "true", "yes", "on"}
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
