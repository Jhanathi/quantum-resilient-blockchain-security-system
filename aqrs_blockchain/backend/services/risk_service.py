from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from backend.models.aqrs_decision import AQRSDecision
from backend.models.transaction import RiskLevel

_SECURITY_POLICY = {
    RiskLevel.LOW: {
        "selected_security_level": 2,
        "security_level": "ML-DSA-44",
        "algorithm": "ML-DSA-44",
        "compatibility_name": "DIL2",
        "decision_reason": "LOW-risk transaction selected ML-DSA-44 according to AQRS policy.",
        "aqrs_score": Decimal("0.0146"),
    },
    RiskLevel.MEDIUM: {
        "selected_security_level": 3,
        "security_level": "ML-DSA-65",
        "algorithm": "ML-DSA-65",
        "compatibility_name": "DIL3",
        "decision_reason": "MEDIUM-risk transaction selected ML-DSA-65 according to AQRS policy.",
        "aqrs_score": Decimal("0.0148"),
    },
    RiskLevel.HIGH: {
        "selected_security_level": 5,
        "security_level": "ML-DSA-87",
        "algorithm": "ML-DSA-87",
        "compatibility_name": "DIL5",
        "decision_reason": "HIGH-risk transaction selected ML-DSA-87 according to AQRS policy.",
        "aqrs_score": Decimal("0.0116"),
    },
}


def _coerce_decimal(amount: Any) -> Decimal:
    if amount is None:
        raise ValueError("Transaction amount is required.")
    try:
        value = Decimal(str(amount))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError("Transaction amount must be a valid decimal value.") from exc
    if not value.is_finite():
        raise ValueError("Transaction amount must be a valid decimal value.")
    return value


def classify_transaction_risk(amount: Any) -> RiskLevel:
    value = _coerce_decimal(amount)
    if value < Decimal("1000"):
        return RiskLevel.LOW
    if value < Decimal("100000"):
        return RiskLevel.MEDIUM
    return RiskLevel.HIGH


def select_security_level(risk_level: RiskLevel | str) -> dict[str, Any]:
    normalized = risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level).upper()
    try:
        risk = RiskLevel(normalized)
    except ValueError as exc:
        raise ValueError(f"Unknown risk level '{risk_level}'.") from exc
    return dict(_SECURITY_POLICY[risk])


def build_decision_for_amount(amount: Any) -> dict[str, Any]:
    risk = classify_transaction_risk(amount)
    policy = select_security_level(risk)
    return {
        "risk_level": risk.value,
        "security_level": policy["security_level"],
        "algorithm": policy["algorithm"],
        "compatibility_name": policy["compatibility_name"],
        "selected_security_level": policy["selected_security_level"],
        "decision_reason": policy["decision_reason"],
        "aqrs_score": str(policy["aqrs_score"]),
    }


class AQRSDecisionService:
    @staticmethod
    def evaluate_transaction(transaction) -> AQRSDecision:
        risk = classify_transaction_risk(transaction.amount)
        policy = select_security_level(risk)
        return AQRSDecision(
            transaction_id=transaction.id,
            risk_score=Decimal("0.00"),
            risk_level=risk,
            selected_security_level=policy["selected_security_level"],
            algorithm=policy["algorithm"],
            security_level=policy["security_level"],
            decision_reason=policy["decision_reason"],
            aqrs_score=policy["aqrs_score"],
        )

    @staticmethod
    def serialize_decision(decision: AQRSDecision) -> dict[str, Any]:
        return {
            "id": decision.id,
            "transaction_id": decision.transaction_id,
            "risk_level": decision.risk_level.value if hasattr(decision.risk_level, "value") else str(decision.risk_level),
            "selected_security_level": decision.selected_security_level,
            "security_level": decision.security_level,
            "algorithm": decision.algorithm,
            "compatibility_name": {
                2: "DIL2",
                3: "DIL3",
                5: "DIL5",
            }.get(decision.selected_security_level, "DIL2"),
            "decision_reason": decision.decision_reason,
            "aqrs_score": str(decision.aqrs_score),
            "created_at": decision.created_at.isoformat() if decision.created_at else None,
        }
