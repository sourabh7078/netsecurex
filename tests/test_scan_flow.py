"""End-to-end scan persistence: source tags, change alerts, and the changes page."""
from datetime import datetime, timedelta

import app as netsecurex_app
import alerts
from models import db, Scan, Host, Port, Vulnerability, RiskScore
from conftest import login_as


def _stub_scan_result(target, ports=None, progress_cb=None):
    return {"target": target, "hosts": [{
        "ip": "10.0.0.1", "hostname": "", "os_guess": "Linux",
        "ports": [{"port": 21, "protocol": "tcp", "state": "open", "service": "ftp",
                   "version": "vsFTPd 2.3.4", "banner": "",
                   "vulnerabilities": [
                       {"cve_id": "CVE-2011-2523", "cvss_score": 9.8, "severity": "Critical",
                        "description": "backdoor", "source": "offline-db"},
                       {"cve_id": "CVE-2024-0001", "cvss_score": 9.1, "severity": "Critical",
                        "description": "from NVD", "source": "live-nvd"},
                   ]}],
    }]}


def _run(flask_app, scan, target):
    netsecurex_app.SCAN_STATE[scan.id] = {"status": "running", "progress": 0}
    netsecurex_app._execute_scan(flask_app.app_context(), scan.id, target)
    # _execute_scan commits in its own app context; drop this context's stale copies.
    db.session.expire_all()


def test_scan_stores_source_tag_per_finding(flask_app, monkeypatch):
    monkeypatch.setattr(netsecurex_app, "run_scan", _stub_scan_result)
    monkeypatch.setattr(alerts, "dispatch", lambda payload: [])
    scan = Scan(target_range="10.0.0.1", start_time=datetime.utcnow(), status="running")
    db.session.add(scan)
    db.session.commit()
    _run(flask_app, scan, "10.0.0.1")
    sources = {v.cve_id: v.source for v in Vulnerability.query.all()}
    assert sources == {"CVE-2011-2523": "offline-db", "CVE-2024-0001": "live-nvd"}
    assert db.session.get(Scan, scan.id).status == "completed"


def test_first_scan_alerts_on_every_critical(flask_app, monkeypatch):
    monkeypatch.setattr(netsecurex_app, "run_scan", _stub_scan_result)
    sent = []
    monkeypatch.setattr(alerts, "dispatch", lambda payload: sent.append(payload) or ["webhook"])
    scan = Scan(target_range="10.0.0.1", start_time=datetime.utcnow(), status="running")
    db.session.add(scan)
    db.session.commit()
    _run(flask_app, scan, "10.0.0.1")
    assert len(sent) == 1 and sent[0]["count"] == 2


def test_second_scan_alerts_only_on_new_criticals(flask_app, monkeypatch):
    monkeypatch.setattr(netsecurex_app, "run_scan", _stub_scan_result)
    sent = []
    monkeypatch.setattr(alerts, "dispatch", lambda payload: sent.append(payload) or ["webhook"])
    first = Scan(target_range="10.0.0.1", start_time=datetime.utcnow() - timedelta(hours=1), status="running")
    db.session.add(first)
    db.session.commit()
    _run(flask_app, first, "10.0.0.1")
    sent.clear()
    second = Scan(target_range="10.0.0.1", start_time=datetime.utcnow(), status="running")
    db.session.add(second)
    db.session.commit()
    _run(flask_app, second, "10.0.0.1")
    assert sent == []          # same two criticals as before: nothing new to report


def test_failed_alert_does_not_fail_the_scan(flask_app, monkeypatch):
    monkeypatch.setattr(netsecurex_app, "run_scan", _stub_scan_result)

    def boom(payload):
        raise RuntimeError("alert channel exploded")

    monkeypatch.setattr(alerts, "dispatch", boom)
    scan = Scan(target_range="10.0.0.1", start_time=datetime.utcnow(), status="running")
    db.session.add(scan)
    db.session.commit()
    _run(flask_app, scan, "10.0.0.1")
    assert db.session.get(Scan, scan.id).status == "completed"


def test_changes_page_without_previous_scan(client, flask_app, make_user):
    scan = Scan(target_range="10.9.9.9", start_time=datetime.utcnow(), status="completed")
    db.session.add(scan)
    db.session.commit()
    login_as(client, "testadmin", "testpass123")
    resp = client.get(f"/scan/{scan.id}/changes")
    assert resp.status_code == 200
    assert b"no earlier completed scan" in resp.data.lower()


def test_changes_page_shows_differences(client, flask_app, monkeypatch):
    monkeypatch.setattr(netsecurex_app, "run_scan", _stub_scan_result)
    monkeypatch.setattr(alerts, "dispatch", lambda payload: [])
    old = Scan(target_range="10.0.0.1", start_time=datetime.utcnow() - timedelta(hours=2), status="completed")
    db.session.add(old)
    db.session.commit()
    old_host = Host(scan_id=old.id, ip="10.0.0.1", os_guess="Linux", status="up")
    db.session.add(old_host)
    db.session.commit()
    db.session.add(RiskScore(host_id=old_host.id, score=3.0, category="Low"))
    db.session.commit()
    new = Scan(target_range="10.0.0.1", start_time=datetime.utcnow(), status="running")
    db.session.add(new)
    db.session.commit()
    _run(flask_app, new, "10.0.0.1")
    login_as(client, "testadmin", "testpass123")
    resp = client.get(f"/scan/{new.id}/changes")
    assert resp.status_code == 200
    assert b"CVE-2011-2523" in resp.data
    assert b"Compared with scan" in resp.data


def test_result_page_shows_source_badges(client, flask_app, monkeypatch):
    monkeypatch.setattr(netsecurex_app, "run_scan", _stub_scan_result)
    monkeypatch.setattr(alerts, "dispatch", lambda payload: [])
    scan = Scan(target_range="10.0.0.1", start_time=datetime.utcnow(), status="running")
    db.session.add(scan)
    db.session.commit()
    _run(flask_app, scan, "10.0.0.1")
    login_as(client, "testadmin", "testpass123")
    html = client.get(f"/scan/{scan.id}").get_data(as_text=True)
    assert "live NVD" in html and "offline" in html
