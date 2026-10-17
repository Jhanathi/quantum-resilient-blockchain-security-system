from __future__ import annotations

import csv
from pathlib import Path

from app import app


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_FILE = PROJECT_ROOT / "docs" / "API_ENDPOINTS.csv"
REQUIRED_COLUMNS = {
    "methods",
    "path",
    "endpoint",
    "purpose",
    "authentication",
    "required_role",
    "csrf",
    "rate_limit",
    "input_format",
    "important_response_codes",
    "relevant_test_file",
}


def load_inventory() -> list[dict[str, str]]:
    with INVENTORY_FILE.open(encoding="utf-8", newline="") as inventory_file:
        reader = csv.DictReader(inventory_file)
        assert REQUIRED_COLUMNS <= set(reader.fieldnames or [])
        return list(reader)


def test_inventory_exactly_matches_the_registered_flask_route_map():
    rows = load_inventory()
    inventory_routes = [
        (row["methods"], row["path"], row["endpoint"])
        for row in rows
    ]
    actual_routes = [
        (
            "|".join(sorted(rule.methods or ())),
            rule.rule,
            rule.endpoint,
        )
        for rule in app.url_map.iter_rules()
    ]

    assert len(inventory_routes) == len(set(inventory_routes))
    assert set(inventory_routes) == set(actual_routes)
    assert all(all(row[column].strip() for column in REQUIRED_COLUMNS) for row in rows)


def test_state_changing_routes_are_csrf_and_rate_limit_reviewed():
    rows = load_inventory()
    for row in rows:
        methods = set(row["methods"].split("|"))
        if "POST" in methods or "PUT" in methods or "PATCH" in methods or "DELETE" in methods:
            assert row["csrf"] == "Required"
            assert "per " in row["rate_limit"]
        else:
            assert row["csrf"] == "Not applicable"

    assert "enforce_csrf_token" in {
        hook.__name__ for hook in app.before_request_funcs.get(None, [])
    }


def test_static_endpoint_cannot_serve_project_files_outside_asset_directory():
    client = app.test_client()
    assert client.get("/static/js/app.js").status_code == 200
    assert client.get("/app.py").status_code == 404
    assert client.get("/pqbank.db").status_code == 404
    assert client.get("/static/../app.py").status_code == 404
