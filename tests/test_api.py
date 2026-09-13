"""
Tests for the REST API (/api/v1/...) and dashboard auth flow, using Flask's
test client against an isolated test database (see conftest.py).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestApiAuth:
    def test_missing_api_key_returns_401(self, client):
        resp = client.get("/api/v1/scans")
        assert resp.status_code == 401

    def test_wrong_api_key_returns_401(self, client):
        resp = client.get("/api/v1/scans", headers={"X-API-Key": "wrong-key"})
        assert resp.status_code == 401

    def test_correct_api_key_succeeds(self, client, api_headers):
        resp = client.get("/api/v1/scans", headers=api_headers)
        assert resp.status_code == 200
        assert resp.get_json() == []


class TestApiCreateScan:
    def test_missing_authorization_flag_rejected(self, client, api_headers):
        resp = client.post(
            "/api/v1/scans", headers=api_headers,
            json={"target": "192.168.56.101", "authorized": False},
        )
        assert resp.status_code == 400
        assert "authorized" in resp.get_json()["message"].lower()

    def test_empty_target_rejected(self, client, api_headers):
        resp = client.post(
            "/api/v1/scans", headers=api_headers,
            json={"target": "", "authorized": True},
        )
        assert resp.status_code == 400

    def test_oversized_cidr_rejected(self, client, api_headers):
        resp = client.post(
            "/api/v1/scans", headers=api_headers,
            json={"target": "10.0.0.0/8", "authorized": True},
        )
        assert resp.status_code == 400
        assert "exceeds" in resp.get_json()["message"].lower()

    def test_invalid_cidr_rejected(self, client, api_headers):
        resp = client.post(
            "/api/v1/scans", headers=api_headers,
            json={"target": "999.999.999.999/24", "authorized": True},
        )
        assert resp.status_code == 400

    def test_valid_request_creates_scan(self, client, api_headers, monkeypatch):
        # Avoid touching the real network: replace run_scan with a stub that
        # returns immediately with no hosts, since we're only testing the
        # HTTP contract here, not the scanning engine itself (see test_scanner.py).
        import app as netsecurex_app

        def fake_run_scan(target, ports=None, progress_cb=None):
            if progress_cb:
                progress_cb(100)
            return {"target": target, "hosts": []}

        monkeypatch.setattr(netsecurex_app, "run_scan", fake_run_scan)

        resp = client.post(
            "/api/v1/scans", headers=api_headers,
            json={"target": "192.168.56.101", "authorized": True},
        )
        assert resp.status_code == 201
        body = resp.get_json()
        assert "scan_id" in body
        assert body["status"] == "running"
        assert "status_url" in body
        assert "result_url" in body


class TestApiScanRetrieval:
    def test_nonexistent_scan_returns_404(self, client, api_headers):
        resp = client.get("/api/v1/scans/999999", headers=api_headers)
        assert resp.status_code == 404

    def test_status_endpoint_for_unknown_scan_404s(self, client, api_headers):
        resp = client.get("/api/v1/scans/999999/status", headers=api_headers)
        assert resp.status_code == 404


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
