"""
NetSecureX - Pytest fixtures

Sets up an isolated, disposable SQLite database (a temp file, not the real
instance/netsecurex.db) and known test credentials BEFORE importing the app
module, since app.py reads its configuration from the environment at import
time. Every test function gets fresh, empty tables.
"""

import os
import sys
import tempfile

import pytest

# --- Configure the environment BEFORE importing app.py -------------------
# A real temp file (not sqlite:///:memory:) so the same database is visible
# across the multiple connections Flask-SQLAlchemy may open per test.
_db_fd, _db_path = tempfile.mkstemp(suffix=".db")

os.environ["NSX_DATABASE_URL"] = f"sqlite:///{_db_path}"
os.environ["NSX_SECRET_KEY"] = "test-secret-key"
os.environ["NSX_ADMIN_USERNAME"] = "testadmin"
os.environ["NSX_ADMIN_PASSWORD"] = "testpass123"
os.environ["NSX_DEBUG"] = "false"
os.environ["NSX_MAX_LOGIN_ATTEMPTS"] = "3"
os.environ["NSX_LOGIN_LOCKOUT_SECONDS"] = "300"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app as netsecurex_app  # noqa: E402  (must follow env setup above)
from models import db as _db  # noqa: E402


@pytest.fixture()
def flask_app():
    application = netsecurex_app.app
    application.config["TESTING"] = True
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(flask_app):
    return flask_app.test_client()


@pytest.fixture()
def logged_in_client(client):
    """A test client that has already authenticated as the test admin."""
    client.post(
        "/login",
        data={"username": "testadmin", "password": "testpass123"},
        follow_redirects=True,
    )
    return client


@pytest.fixture(autouse=True)
def _reset_login_attempts():
    """Prevent brute-force lockout state from one test bleeding into another."""
    netsecurex_app.LOGIN_ATTEMPTS.clear()
    yield
    netsecurex_app.LOGIN_ATTEMPTS.clear()


def pytest_sessionfinish(session, exitstatus):
    try:
        os.close(_db_fd)
        os.remove(_db_path)
    except OSError:
        pass
