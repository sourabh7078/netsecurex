"""Scheduled scans: due checks, authorization, interval bounds, and single-run guard."""
from datetime import datetime, timedelta

import app as netsecurex_app
from models import db, Scan, Schedule, ROLE_ANALYST
from conftest import login_as


def _stub_start(target, owner="", label="web"):
    scan = Scan(target_range=target, start_time=datetime.utcnow(), status="running", owner=owner)
    db.session.add(scan)
    db.session.commit()
    return scan


def test_due_schedule_starts_a_scan_and_reschedules(flask_app, monkeypatch):
    monkeypatch.setattr(netsecurex_app, "_start_scan", _stub_start)
    now = datetime.utcnow()
    sched = Schedule(target_range="10.0.0.0/30", interval_minutes=60, enabled=True,
                     next_run_at=now - timedelta(minutes=1))
    db.session.add(sched)
    db.session.commit()
    started = netsecurex_app._run_due_schedules(now)
    assert len(started) == 1
    sched = db.session.get(Schedule, sched.id)
    assert sched.last_scan_id == started[0]
    assert sched.next_run_at == now + timedelta(minutes=60)


def test_future_schedule_does_not_run(flask_app, monkeypatch):
    monkeypatch.setattr(netsecurex_app, "_start_scan", _stub_start)
    now = datetime.utcnow()
    db.session.add(Schedule(target_range="10.0.0.0/30", interval_minutes=60, enabled=True,
                            next_run_at=now + timedelta(hours=1)))
    db.session.commit()
    assert netsecurex_app._run_due_schedules(now) == []


def test_disabled_schedule_does_not_run(flask_app, monkeypatch):
    monkeypatch.setattr(netsecurex_app, "_start_scan", _stub_start)
    now = datetime.utcnow()
    db.session.add(Schedule(target_range="10.0.0.0/30", interval_minutes=60, enabled=False,
                            next_run_at=now - timedelta(minutes=5)))
    db.session.commit()
    assert netsecurex_app._run_due_schedules(now) == []


def test_running_scan_postpones_instead_of_overlapping(flask_app, monkeypatch):
    monkeypatch.setattr(netsecurex_app, "_start_scan", _stub_start)
    now = datetime.utcnow()
    running = Scan(target_range="10.0.0.0/30", start_time=now, status="running")
    db.session.add(running)
    db.session.commit()
    sched = Schedule(target_range="10.0.0.0/30", interval_minutes=60, enabled=True,
                     next_run_at=now - timedelta(minutes=1), last_scan_id=running.id)
    db.session.add(sched)
    db.session.commit()
    assert netsecurex_app._run_due_schedules(now) == []
    assert db.session.get(Schedule, sched.id).next_run_at == now + timedelta(minutes=1)


def test_schedule_form_requires_authorization(client, make_user):
    make_user("analyst3", "a-long-password-1", ROLE_ANALYST)
    login_as(client, "analyst3", "a-long-password-1")
    client.post("/schedules/new", data={"target": "10.0.0.0/30", "interval_minutes": "60"})
    assert Schedule.query.count() == 0


def test_schedule_interval_bounds_enforced(client, make_user):
    make_user("analyst4", "a-long-password-1", ROLE_ANALYST)
    login_as(client, "analyst4", "a-long-password-1")
    client.post("/schedules/new", data={"target": "10.0.0.0/30", "interval_minutes": "5", "authorized": "on"})
    assert Schedule.query.count() == 0
    client.post("/schedules/new", data={"target": "10.0.0.0/30", "interval_minutes": "60", "authorized": "on"})
    assert Schedule.query.count() == 1
