"""
NetSecureX - Database Models
SQLite (default) or MySQL via SQLAlchemy.

Scan tables:
    scans(id, target_range, start_time, end_time, status, owner)
    hosts, ports, vulnerabilities (with source), risk_scores
    scan_shares(id, scan_id, username)                 -- analysts see scans shared with them

Account and automation tables:
    users(id, username, password_hash, role, is_active, created_at,
          totp_secret, totp_enabled)
    login_attempts(ip, failures, locked_until)          -- shared brute-force state
    schedules(id, target_range, interval_minutes, enabled, created_by, ...)
    password_reset_tokens(id, user_id, token_hash, expires_at, used)
    audit_events(id, timestamp, username, ip, action, target, detail)
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

ROLE_VIEWER = "viewer"
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"
ROLES = (ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN)


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_range = db.Column(db.String(255), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default="running")  # running | completed | failed
    owner = db.Column(db.String(64), default="")           # username that started the scan

    hosts = db.relationship("Host", backref="scan", cascade="all, delete-orphan")
    shares = db.relationship("ScanShare", backref="scan", cascade="all, delete-orphan")

    @property
    def duration_seconds(self):
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None


class ScanShare(db.Model):
    __tablename__ = "scan_shares"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    username = db.Column(db.String(64), nullable=False)
    __table_args__ = (db.UniqueConstraint("scan_id", "username", name="uq_scan_share"),)


class Host(db.Model):
    __tablename__ = "hosts"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(255), default="")
    os_guess = db.Column(db.String(120), default="Unknown")
    status = db.Column(db.String(20), default="up")

    ports = db.relationship("Port", backref="host", cascade="all, delete-orphan")
    risk_scores = db.relationship("RiskScore", backref="host", cascade="all, delete-orphan")

    @property
    def latest_risk(self):
        if self.risk_scores:
            return sorted(self.risk_scores, key=lambda r: r.computed_at)[-1]
        return None


class Port(db.Model):
    __tablename__ = "ports"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False)
    port_no = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default="tcp")
    service = db.Column(db.String(80), default="unknown")
    version = db.Column(db.String(120), default="")
    state = db.Column(db.String(20), default="open")

    vulnerabilities = db.relationship("Vulnerability", backref="port", cascade="all, delete-orphan")


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    port_id = db.Column(db.Integer, db.ForeignKey("ports.id"), nullable=False)
    cve_id = db.Column(db.String(30), default="N/A")
    cvss_score = db.Column(db.Float, default=0.0)
    description = db.Column(db.Text, default="")
    severity = db.Column(db.String(20), default="Low")
    # "offline-db" (curated signatures), "live-nvd" (live lookup), or "nvd-feed" (local feed)
    source = db.Column(db.String(20), default="offline-db")


class RiskScore(db.Model):
    __tablename__ = "risk_scores"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False)
    score = db.Column(db.Float, default=0.0)
    category = db.Column(db.String(20), default="Low")
    computed_at = db.Column(db.DateTime, default=datetime.utcnow)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=ROLE_ANALYST)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    ip = db.Column(db.String(45), primary_key=True)
    failures = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)


class Schedule(db.Model):
    __tablename__ = "schedules"

    id = db.Column(db.Integer, primary_key=True)
    target_range = db.Column(db.String(255), nullable=False)
    interval_minutes = db.Column(db.Integer, nullable=False, default=1440)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.String(64), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    next_run_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_scan_id = db.Column(db.Integer, nullable=True)


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token_hash = db.Column(db.String(64), nullable=False, unique=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, nullable=False, default=False)


class AuditEvent(db.Model):
    __tablename__ = "audit_events"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    username = db.Column(db.String(64), default="")
    ip = db.Column(db.String(45), default="")
    action = db.Column(db.String(64), nullable=False)
    target = db.Column(db.String(255), default="")
    detail = db.Column(db.Text, default="")
