"""
Tests for the dashboard authentication flow, using Flask's test client
against an isolated test database (see conftest.py).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestDashboardAuth:
    def test_dashboard_redirects_when_not_logged_in(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_login_with_correct_credentials_succeeds(self, client):
        resp = client.post(
            "/login",
            data={"username": "testadmin", "password": "testpass123"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data or b"NetSecureX" in resp.data

    def test_login_with_wrong_password_fails(self, client):
        resp = client.post(
            "/login",
            data={"username": "testadmin", "password": "wrongpassword"},
            follow_redirects=True,
        )
        assert b"Invalid credentials" in resp.data

    def test_logged_in_client_can_reach_dashboard(self, logged_in_client):
        resp = logged_in_client.get("/")
        assert resp.status_code == 200


class TestBruteForceLockout:
    def test_lockout_after_max_failed_attempts(self, client):
        # conftest.py sets NSX_MAX_LOGIN_ATTEMPTS=3 for the test environment
        for _ in range(3):
            client.post("/login", data={"username": "testadmin", "password": "wrong"})

        # 4th attempt (even with correct credentials) should now be blocked
        resp = client.post(
            "/login",
            data={"username": "testadmin", "password": "testpass123"},
        )
        assert resp.status_code == 429

    def test_successful_login_clears_failure_count(self, client):
        client.post("/login", data={"username": "testadmin", "password": "wrong"})
        client.post("/login", data={"username": "testadmin", "password": "wrong"})
        # Succeed before hitting the limit
        resp = client.post(
            "/login",
            data={"username": "testadmin", "password": "testpass123"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        # Failure count should be reset now -- two more wrong attempts
        # should NOT trigger lockout (would need 3 fresh failures)
        r1 = client.post("/login", data={"username": "testadmin", "password": "wrong"})
        assert r1.status_code == 200  # not locked out yet
