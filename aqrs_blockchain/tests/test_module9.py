from __future__ import annotations

import math

import pytest

from app import app
from backend.database.database import DatabaseManager
from backend.models import Account, AQRSDecision, AuditLog, Block, Experiment, ExperimentResult, Signature, Transaction, User
from backend.services import research_service
from backend.services.research_service import RESEARCH_MODES, get_latest_experiment, run_experiment, serialize_experiment


@pytest.fixture
def db_session():
    manager = DatabaseManager("sqlite:///:memory:")
    manager.create_all()
    session = manager.SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_experiment_execution_persists_all_modes_and_metrics(db_session):
    experiment = run_experiment(db_session, transaction_count=4, seed=42)

    assert experiment.status == "COMPLETED"
    assert experiment.transaction_count == 4
    assert experiment.configuration["seed"] == 42
    assert experiment.configuration["modes"] == list(RESEARCH_MODES)
    assert {result.mode for result in experiment.results} == set(RESEARCH_MODES)
    assert all(result.average_signing_time_ms > 0 for result in experiment.results)
    assert all(result.average_verification_time_ms > 0 for result in experiment.results)
    assert all(result.average_signature_size_bytes > 0 for result in experiment.results)
    assert all(result.throughput_tps > 0 for result in experiment.results)
    assert all(
        math.isfinite(metric)
        for result in experiment.results
        for metric in (
            result.average_signing_time_ms,
            result.average_verification_time_ms,
            result.average_signature_size_bytes,
            result.throughput_tps,
            result.aqrs_score,
        )
    )
    assert db_session.query(Experiment).count() == 1
    assert db_session.query(ExperimentResult).count() == 5


def test_experiment_result_retrieval_and_reproducible_configuration(db_session):
    first = run_experiment(db_session, transaction_count=3, seed=7)
    second = run_experiment(db_session, transaction_count=3, seed=7)

    latest = get_latest_experiment(db_session)
    assert latest.id == second.id
    assert first.configuration == second.configuration
    assert [result.mode for result in second.results] == list(RESEARCH_MODES)
    payload = serialize_experiment(latest)
    assert payload["id"] == second.id
    assert "private_key" not in str(payload).lower()
    assert "secret_key" not in str(payload).lower()


def test_research_endpoints_require_authorized_session():
    app.config["TESTING"] = True
    client = app.test_client()

    assert client.get("/research").status_code == 302
    assert client.get("/api/research/experiments").status_code == 401
    assert client.get("/api/research/results").status_code == 401
    assert client.get("/api/research/compare").status_code == 401


def test_research_page_and_static_assets_are_registered():
    app.config["TESTING"] = True
    client = app.test_client()
    assert client.get("/research").status_code in {200, 302}
    assert client.get("/static/css/research.css").status_code == 200
    assert client.get("/static/js/research.js").status_code == 200


@pytest.mark.parametrize(
    ("transaction_count", "seed", "modes"),
    [
        (0, None, None),
        (1001, None, None),
        (1.5, None, None),
        (1, True, None),
        (1, None, []),
        (1, None, ["NOT-A-MODE"]),
        (1, None, ["DIL2"]),
        (1, None, ["ECDSA", "ECDSA"]),
    ],
)
def test_invalid_research_configuration_is_rejected_without_persisting_experiment(
    db_session, transaction_count, seed, modes
):
    with pytest.raises(ValueError):
        run_experiment(
            db_session,
            transaction_count=transaction_count,
            seed=seed,
            modes=modes,
        )
    assert db_session.query(Experiment).count() == 0


def test_failed_research_run_is_persisted_as_failed_not_completed(db_session, monkeypatch):
    def fail_run(_mode, _transactions):
        raise RuntimeError("synthetic benchmark failure")

    monkeypatch.setattr(research_service, "run_simulation", fail_run)
    with pytest.raises(RuntimeError, match="synthetic benchmark failure"):
        run_experiment(db_session, transaction_count=1, seed=42)

    failed = db_session.query(Experiment).one()
    assert failed.status == "FAILED"
    assert db_session.query(ExperimentResult).filter_by(experiment_id=failed.id).count() == 0
