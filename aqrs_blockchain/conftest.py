import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("TEST_DATABASE_URL", f"sqlite:///{(ROOT / 'test_pqbank.db').resolve()}")


def _sqlite_path(database_url: str) -> Path | None:
    prefix = "sqlite:///"
    if not database_url.startswith(prefix) or database_url.startswith("sqlite:///:memory:"):
        return None
    filename = database_url[len(prefix):].split("?", 1)[0]
    path = Path(filename)
    return path.resolve() if path.is_absolute() else (ROOT / path).resolve()


test_database_url = os.environ["TEST_DATABASE_URL"].strip()
test_database_path = _sqlite_path(test_database_url)
production_database_path = (ROOT / "pqbank.db").resolve()
if test_database_url.startswith("sqlite") and test_database_path == production_database_path:
    raise RuntimeError("Refusing to run tests against the real application database.")
if not test_database_url.startswith("sqlite"):
    raise RuntimeError("Tests require an isolated SQLite TEST_DATABASE_URL.")

database_url = os.environ.get("DATABASE_URL")
if database_url:
    database_path = _sqlite_path(database_url.strip())
    if database_url.strip() != test_database_url and database_path != test_database_path:
        raise RuntimeError(
            "Refusing to run tests with DATABASE_URL different from TEST_DATABASE_URL. "
            "Configure both variables to the same isolated SQLite database."
        )
else:
    os.environ["DATABASE_URL"] = test_database_url
