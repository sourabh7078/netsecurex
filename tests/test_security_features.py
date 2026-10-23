"""Security features: CSRF, two-factor sign-in, password reset, audit log,
scan ownership and sharing, and the local Chart.js bundle."""
import os
import re
import time
from datetime import datetime, timedelta

import app as netsecurex_app
import totp
from models import db, User, Scan, ScanShare, AuditEvent, PasswordResetToken, ROLE_ANALYST, ROLE_VIEWER
from werkzeug.security import generate_password_hash
from conftest import login_as

PASSWORD = "a-long-password-1"
ROOT = os.path.join(os.path.dirname(__file__), "..")


def _csrf(client):
    client.get("/login")
    with client.session_transaction() as sess:
        return sess["csrf_token"]


def _user(username, role=ROLE_ANALYST, password=PASSWORD):
    user = User(username=username, password_hash=generate_password_hash(password), role=role, is_active=True)
    db.session.add(user)
    db.session.commit()
    return user


def _scan(owner, target):
    scan = Scan(target_range=target, start_time=datetime.utcnow(), status="completed", owner=owner)
    db.session.add(scan)
    db.session.commit()
    return scan


# ---------------------------------------------------------------- CSRF
def test_csrf_blocks_post_without_token(flask_app, client):
    flask_app.config["CSRF_ENABLED"] = True
    try:
        resp = client.post("/login", data={"username": "testadmin", "password": "testpass123"})
        assert resp.status_code == 400
        assert b"expired" in resp.data.lower()
    finally:
        flask_app.config["CSRF_ENABLED"] = False


def test_csrf_accepts_matching_token(flask_app, client):
    flask_app.config["CSRF_ENABLED"] = True
    try:
        token = _csrf(client)
        resp = client.post("/login", data={"username": "testadmin", "password": "testpass123",
                                           "csrf_token": token})
        assert resp.status_code == 302
    finally:
        flask_app.config["CSRF_ENABLED"] = False


def test_csrf_rejects_wrong_token(flask_app, client):
    flask_app.config["CSRF_ENABLED"] = True
    try:
        _csrf(client)
        resp = client.post("/login", data={"username": "testadmin", "password": "testpass123",
                                           "csrf_token": "forged"})
        assert resp.status_code == 400
    finally:
        flask_app.config["CSRF_ENABLED"] = False


# ---------------------------------------------------------------- two-factor
def test_two_factor_enrolment_then_sign_in(flask_app, client):
    login_as(client, "testadmin", "testpass123")
    client.post("/account/security/2fa/start")
    with client.session_transaction() as sess:
        secret = sess["totp_pending"]
    code = totp.totp_at(secret, time.time())
    client.post("/account/security/2fa/enable", data={"code": code})
    assert User.query.filter_by(username="testadmin").one().totp_enabled is True

    client.get("/logout")
    resp = client.post("/login", data={"username": "testadmin", "password": "testpass123"})
    assert resp.status_code == 302 and "/login/2fa" in resp.headers["Location"]

    resp = client.post("/login/2fa", data={"code": totp.totp_at(secret, time.time())})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/")


def test_two_factor_wrong_code_is_refused(flask_app, client):
    user = User.query.filter_by(username="testadmin").one()
    user.totp_secret = totp.generate_secret()
    user.totp_enabled = True
    db.session.commit()
    client.post("/login", data={"username": "testadmin", "password": "testpass123"})
    resp = client.post("/login/2fa", data={"code": "000000"}, follow_redirects=True)
    # Either the wrong code is refused, or (1 in a million) the random secret yields 000000.
    with client.session_transaction() as sess:
        signed_in = bool(sess.get("logged_in"))
    assert not signed_in or totp.totp_at(user.totp_secret, time.time()) == "000000"


def test_two_factor_page_requires_pending_sign_in(client):
    resp = client.get("/login/2fa")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


# ---------------------------------------------------------------- password reset
def test_admin_issues_reset_link_and_user_sets_password(flask_app, client, make_user):
    make_user("resetme", PASSWORD, ROLE_ANALYST)
    target = User.query.filter_by(username="resetme").one()
    login_as(client, "testadmin", "testpass123")
    resp = client.post(f"/admin/users/{target.id}/reset", follow_redirects=True)
    token = re.search(r"/reset/([A-Za-z0-9_\-]+)", resp.get_data(as_text=True)).group(1)
    client.get("/logout")

    assert client.get(f"/reset/{token}").status_code == 200
    resp = client.post(f"/reset/{token}", data={"password": "brand-new-password-2", "confirm": "brand-new-password-2"})
    assert resp.status_code == 302
    assert client.post(f"/reset/{token}", data={"password": "x" * 12, "confirm": "x" * 12}).status_code == 400

    client.get("/logout")
    fresh = login_as(client, "resetme", "brand-new-password-2")
    assert b"Invalid credentials" not in fresh.data


def test_reset_link_cannot_be_used_twice(flask_app, client, make_user):
    make_user("twice", PASSWORD, ROLE_ANALYST)
    user = User.query.filter_by(username="twice").one()
    token = "one-time-token-abc"
    flask_app.test_client()  # ensure app is initialised
    db.session.add(PasswordResetToken(user_id=user.id, token_hash=netsecurex_app._hash_token(token),
                                      expires_at=datetime.utcnow() + timedelta(minutes=5)))
    db.session.commit()
    assert client.post(f"/reset/{token}", data={"password": "a-new-long-password", "confirm": "a-new-long-password"}).status_code == 302
    assert client.get(f"/reset/{token}").status_code == 400


def test_expired_reset_link_is_rejected(flask_app, client, make_user):
    make_user("late", PASSWORD, ROLE_ANALYST)
    user = User.query.filter_by(username="late").one()
    token = "expired-token-xyz"
    db.session.add(PasswordResetToken(user_id=user.id, token_hash=netsecurex_app._hash_token(token),
                                      expires_at=datetime.utcnow() - timedelta(minutes=1)))
    db.session.commit()
    assert client.get(f"/reset/{token}").status_code == 400


# ---------------------------------------------------------------- audit log
def test_audit_records_sign_in_and_failure(flask_app, client):
    client.post("/login", data={"username": "testadmin", "password": "wrong"})
    login_as(client, "testadmin", "testpass123")
    actions = {e.action for e in AuditEvent.query.all()}
    assert "auth.failed" in actions and "auth.login" in actions


def test_audit_page_is_admin_only(client, make_user):
    make_user("auditor", PASSWORD, ROLE_ANALYST)
    login_as(client, "auditor", PASSWORD)
    assert client.get("/admin/audit").status_code == 403


def test_audit_page_lists_events_for_admin(client):
    login_as(client, "testadmin", "testpass123")
    client.post("/admin/users/new", data={"username": "newperson", "password": PASSWORD, "role": "viewer"})
    html = client.get("/admin/audit").get_data(as_text=True)
    assert "user.create" in html and "newperson" in html


# ---------------------------------------------------------------- scan ownership and sharing
def test_analyst_sees_only_own_scans(client, make_user):
    alice_scan = _scan("alice", "10.1.1.1")
    bob_scan = _scan("bob", "10.2.2.2")
    make_user("alice", PASSWORD, ROLE_ANALYST)
    login_as(client, "alice", PASSWORD)
    listing = client.get("/history").get_data(as_text=True)
    assert "10.1.1.1" in listing and "10.2.2.2" not in listing
    assert client.get(f"/scan/{bob_scan.id}").status_code == 403
    assert client.get(f"/scan/{alice_scan.id}").status_code == 200


def test_viewer_sees_every_scan(client, make_user):
    _scan("bob", "10.4.4.4")
    make_user("watcher", PASSWORD, ROLE_VIEWER)
    login_as(client, "watcher", PASSWORD)
    assert "10.4.4.4" in client.get("/history").get_data(as_text=True)


def test_owner_shares_scan_with_analyst(client, make_user):
    make_user("owner", PASSWORD, ROLE_ANALYST)
    make_user("guest", PASSWORD, ROLE_ANALYST)
    scan = _scan("owner", "10.5.5.5")
    login_as(client, "owner", PASSWORD)
    client.post(f"/scan/{scan.id}/share", data={"username": "guest"})
    assert ScanShare.query.filter_by(scan_id=scan.id, username="guest").first() is not None
    client.get("/logout")
    login_as(client, "guest", PASSWORD)
    assert client.get(f"/scan/{scan.id}").status_code == 200


def test_non_owner_cannot_share(client, make_user):
    make_user("owner2", PASSWORD, ROLE_ANALYST)
    make_user("other", PASSWORD, ROLE_ANALYST)
    scan = _scan("owner2", "10.6.6.6")
    login_as(client, "other", PASSWORD)
    resp = client.post(f"/scan/{scan.id}/share", data={"username": "other"})
    assert resp.status_code == 403


def test_new_scan_records_its_owner(flask_app, client, make_user, monkeypatch):
    captured = {}

    def fake_create(target, authorized, owner=""):
        captured["owner"] = owner
        return Scan(id=999, target_range=target, owner=owner), None

    monkeypatch.setattr(netsecurex_app, "_validate_and_create_scan", fake_create)
    make_user("starter", PASSWORD, ROLE_ANALYST)
    login_as(client, "starter", PASSWORD)
    client.post("/scan/new", data={"target": "10.7.7.7", "authorized": "on"})
    assert captured["owner"] == "starter"


# ---------------------------------------------------------------- static assets
def test_chart_js_is_bundled_locally():
    assert os.path.exists(os.path.join(ROOT, "static", "vendor", "chart.umd.min.js"))
    base = open(os.path.join(ROOT, "templates", "base.html"), encoding="utf-8").read()
    assert "cdnjs" not in base and "vendor/chart.umd.min.js" in base
