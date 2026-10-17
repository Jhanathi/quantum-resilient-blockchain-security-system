from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from aqrs_calculator import compute_all_aqrs_scores
from backend.models.experiment import Experiment, ExperimentResult
from simulation import run_simulation
from transaction_generator import generate_transactions

RESEARCH_MODES = ("ECDSA", "DIL2", "DIL3", "DIL5", "AQRS")


def _serialize_result(result: ExperimentResult) -> dict[str, Any]:
    return {
        "mode": result.mode,
        "average_signing_time_ms": result.average_signing_time_ms,
        "average_verification_time_ms": result.average_verification_time_ms,
        "average_signature_size_bytes": result.average_signature_size_bytes,
        "throughput_tps": result.throughput_tps,
        "blockchain_size_bytes": result.blockchain_size_bytes,
        "aqrs_score": result.aqrs_score,
    }


def serialize_experiment(experiment: Experiment) -> dict[str, Any]:
    return {
        "id": experiment.id,
        "experiment_name": experiment.experiment_name,
        "transaction_count": experiment.transaction_count,
        "configuration": experiment.configuration or {},
        "created_at": experiment.created_at.isoformat() if experiment.created_at else None,
        "status": experiment.status,
        "results": [_serialize_result(result) for result in sorted(experiment.results, key=lambda item: RESEARCH_MODES.index(item.mode) if item.mode in RESEARCH_MODES else 99)],
    }


def _validate_config(transaction_count: int, seed: int | None, modes: list[str] | None) -> tuple[int, int | None, list[str]]:
    if type(transaction_count) is not int or transaction_count < 1 or transaction_count > 1000:
        raise ValueError("transaction_count must be between 1 and 1000.")
    if seed is not None and type(seed) is not int:
        raise ValueError("seed must be an integer.")
    selected_modes = list(RESEARCH_MODES if modes is None else modes)
    if not selected_modes or any(mode not in RESEARCH_MODES for mode in selected_modes):
        raise ValueError(f"modes must contain only: {', '.join(RESEARCH_MODES)}.")
    if "ECDSA" not in selected_modes:
        raise ValueError("ECDSA is required as the AQRS comparison baseline.")
    if len(set(selected_modes)) != len(selected_modes):
        raise ValueError("modes must not contain duplicates.")
    return transaction_count, seed, selected_modes


def run_experiment(db: Session, *, transaction_count: int = 100, seed: int | None = None, modes: list[str] | None = None) -> Experiment:
    transaction_count, seed, selected_modes = _validate_config(transaction_count, seed, modes)
    experiment = Experiment(
        experiment_name=f"research-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}",
        transaction_count=transaction_count,
        configuration={"transaction_count": transaction_count, "seed": seed, "modes": selected_modes, "input": "transaction_generator"},
        status="RUNNING",
    )
    db.add(experiment)
    db.commit()

    random_state = random.getstate()
    try:
        if seed is not None:
            random.seed(seed)
        transactions = generate_transactions(transaction_count)
        all_results = {mode: run_simulation(mode, transactions) for mode in selected_modes}
        aqrs_scores = compute_all_aqrs_scores(all_results)
        for mode in selected_modes:
            result = all_results[mode]
            db.add(ExperimentResult(
                experiment_id=experiment.id,
                mode=mode,
                average_signing_time_ms=float(result["average_signing_time_ms"]),
                average_verification_time_ms=float(result["average_verification_time_ms"]),
                average_signature_size_bytes=float(result["average_signature_size_bytes"]),
                throughput_tps=float(result["throughput_tps"]),
                blockchain_size_bytes=int(result["total_chain_size_bytes"]),
                aqrs_score=float(aqrs_scores.get(mode, 0.0)),
            ))
        experiment.status = "COMPLETED"
        db.commit()
        db.refresh(experiment)
        return experiment
    except Exception:
        db.rollback()
        experiment.status = "FAILED"
        db.add(experiment)
        db.commit()
        raise
    finally:
        random.setstate(random_state)


def get_latest_experiment(db: Session) -> Experiment | None:
    return db.query(Experiment).filter_by(status="COMPLETED").order_by(Experiment.created_at.desc()).first()


def get_experiment(db: Session, experiment_id: str) -> Experiment | None:
    return db.get(Experiment, experiment_id)


def list_experiments(db: Session) -> list[Experiment]:
    return db.query(Experiment).order_by(Experiment.created_at.desc()).limit(100).all()


__all__ = ["RESEARCH_MODES", "get_experiment", "get_latest_experiment", "list_experiments", "run_experiment", "serialize_experiment"]