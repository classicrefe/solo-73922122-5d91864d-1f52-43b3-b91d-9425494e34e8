import pytest
from fastapi.testclient import TestClient

from app.db import connect, init_db


@pytest.fixture
def conn():
    """In-memory SQLite connection with schema (single connection)."""
    connection = connect(":memory:")
    init_db(connection)
    yield connection
    connection.close()


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "api-test.db"
    monkeypatch.setenv("LICENSE_CHECK_DB", str(db_file))
    setup = connect(str(db_file))
    init_db(setup)
    setup.close()

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
