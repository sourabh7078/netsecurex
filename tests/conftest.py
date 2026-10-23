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
os.environ["NSX_ENABLE_SCHEDULER"] = "false"   # no background thread in tests
os.environ["NSX_UDP_SCAN"] = "false"           # no real UDP traffic in tests
os.environ["NSX_UDP_PROBES"] = "snmp"          # only the SNMP probe is ever available
os.environ["NSX_CSRF"] = "false"               # forms in tests post without tokens; CSRF has its own tests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app as netsecurex_app  # noqa: E402  (must follow env setup above)
from models import db as _db  # noqa: E402
from models import User, ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402


@pytest.fixture()
def flask_app():
    application = netsecurex_app.app
    application.config["TESTING"] = True
    with application.app_context():
        _db.create_all()
        netsecurex_app.bootstrap_users()
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


@pytest.fixture()
def make_user():
    """Create an account with the given role; returns a logged-in test client factory."""
    def _make(username, password, role):
        _db.session.add(User(username=username, password_hash=generate_password_hash(password),
                             role=role, is_active=True))
        _db.session.commit()

    return _make


def login_as(client, username, password):
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=True)


def pytest_sessionfinish(session, exitstatus):
    try:
        os.close(_db_fd)
        os.remove(_db_path)
    except OSError:
        pass
