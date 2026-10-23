"""Roles, account management, and the database-backed lockout."""
import app as netsecurex_app
from models import db, User, LoginAttempt, ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN
from conftest import login_as

PASSWORD = "a-long-password-1"


def test_bootstrap_creates_admin_once(flask_app):
    admin = User.query.filter_by(username="testadmin").one()
    assert admin.role == ROLE_ADMIN and admin.is_active
    netsecurex_app.bootstrap_users()          # second call must not duplicate
    assert User.query.count() == 1


def test_viewer_cannot_start_a_scan(client, make_user):
    make_user("viewer1", PASSWORD, ROLE_VIEWER)
    login_as(client, "viewer1", PASSWORD)
    resp = client.get("/scan/new")
    assert resp.status_code == 403
    resp = client.post("/scan/new", data={"target": "10.0.0.1", "authorized": "on"})
    assert resp.status_code == 403


def test_viewer_can_see_dashboard(client, make_user):
    make_user("viewer2", PASSWORD, ROLE_VIEWER)
    login_as(client, "viewer2", PASSWORD)
    assert client.get("/").status_code == 200


def test_analyst_can_reach_scan_form(client, make_user):
    make_user("analyst1", PASSWORD, ROLE_ANALYST)
    login_as(client, "analyst1", PASSWORD)
    assert client.get("/scan/new").status_code == 200


def test_analyst_cannot_manage_users(client, make_user):
    make_user("analyst2", PASSWORD, ROLE_ANALYST)
    login_as(client, "analyst2", PASSWORD)
    assert client.get("/admin/users").status_code == 403


def test_admin_creates_user_with_validation(client):
    login_as(client, "testadmin", "testpass123")
    client.post("/admin/users/new", data={"username": "ab", "password": PASSWORD, "role": "viewer"})
    assert User.query.filter_by(username="ab").first() is None         # too short
    client.post("/admin/users/new", data={"username": "newuser", "password": "short", "role": "viewer"})
    assert User.query.filter_by(username="newuser").first() is None    # password too short
    client.post("/admin/users/new", data={"username": "newuser", "password": PASSWORD, "role": "viewer"})
    created = User.query.filter_by(username="newuser").one()
    assert created.role == ROLE_VIEWER
    assert created.password_hash != PASSWORD                            # stored hashed


def test_cannot_disable_yourself(client):
    login_as(client, "testadmin", "testpass123")
    me = User.query.filter_by(username="testadmin").one()
    client.post(f"/admin/users/{me.id}/toggle")
    assert User.query.get(me.id).is_active is True


def test_last_active_admin_cannot_be_demoted(client, make_user):
    make_user("second", PASSWORD, ROLE_ADMIN)
    login_as(client, "second", PASSWORD)
    first = User.query.filter_by(username="testadmin").one()
    # Two active admins: demoting the other one is allowed.
    client.post(f"/admin/users/{first.id}/role", data={"role": "viewer"})
    assert User.query.get(first.id).role == ROLE_VIEWER
    # Now 'second' is the only active admin: demoting it must be refused.
    second = User.query.filter_by(username="second").one()
    client.post(f"/admin/users/{second.id}/role", data={"role": "viewer"})
    assert User.query.get(second.id).role == ROLE_ADMIN


def test_disabled_user_cannot_log_in(client, make_user):
    make_user("gone", PASSWORD, ROLE_ANALYST)
    user = User.query.filter_by(username="gone").one()
    user.is_active = False
    db.session.commit()
    resp = login_as(client, "gone", PASSWORD)
    assert b"Invalid credentials" in resp.data


def test_lockout_state_is_stored_in_the_database(client):
    for _ in range(3):
        client.post("/login", data={"username": "testadmin", "password": "wrong"})
    row = db.session.get(LoginAttempt, "127.0.0.1")
    assert row is not None and row.failures == 3 and row.locked_until is not None
    assert client.post("/login", data={"username": "testadmin", "password": "testpass123"}).status_code == 429


def test_successful_login_clears_lockout_row(client):
    client.post("/login", data={"username": "testadmin", "password": "wrong"})
    client.post("/login", data={"username": "testadmin", "password": "testpass123"})
    assert db.session.get(LoginAttempt, "127.0.0.1") is None
