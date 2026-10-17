import pytest

from backend.config import DATABASE_URL, PRODUCTION_DATABASE_PATH, TEST_DATABASE_PATH, TEST_DATABASE_URL
from backend.database.database import DatabaseManager, engine, is_production_database


def test_test_database_is_isolated():
    assert str(engine.url.database).lower() == str(TEST_DATABASE_PATH).lower()
    assert TEST_DATABASE_PATH != PRODUCTION_DATABASE_PATH
    assert not is_production_database(DATABASE_URL)
    assert DATABASE_URL == TEST_DATABASE_URL


def test_database_manager_rejects_production_database():
    with pytest.raises(RuntimeError, match="real application database"):
        DatabaseManager("sqlite:///./pqbank.db")


def test_production_database_path_alias_is_detected():
    url = f"sqlite:///{PRODUCTION_DATABASE_PATH.as_posix()}"
    assert is_production_database(url)


def test_test_database_is_not_the_live_database_file():
    assert engine.url.database is not None
    assert engine.url.database != str(PRODUCTION_DATABASE_PATH)
