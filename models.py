"""
NetSecureX - Database Models
SQLite via SQLAlchemy. Schema:

scans(id, target_range, start_time, end_time, status)
hosts(id, scan_id, ip, hostname, os_guess, status)
ports(id, host_id, port_no, protocol, service, version, state)
vulnerabilities(id, port_id, cve_id, cvss_score, description, severity)
risk_scores(id, host_id, score, category, computed_at)
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_range = db.Column(db.String(255), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default="running")  # running | completed | failed

    hosts = db.relationship("Host", backref="scan", cascade="all, delete-orphan")

    @property
    def duration_seconds(self):
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None


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

    vulnerabilities = db.relationship(
        "Vulnerability", backref="port", cascade="all, delete-orphan"
    )


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    port_id = db.Column(db.Integer, db.ForeignKey("ports.id"), nullable=False)
    cve_id = db.Column(db.String(30), default="N/A")
    cvss_score = db.Column(db.Float, default=0.0)
    description = db.Column(db.Text, default="")
    severity = db.Column(db.String(20), default="Low")  # Critical/High/Medium/Low


class RiskScore(db.Model):
    __tablename__ = "risk_scores"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False)
    score = db.Column(db.Float, default=0.0)
    category = db.Column(db.String(20), default="Low")  # Critical/High/Medium/Low
    computed_at = db.Column(db.DateTime, default=datetime.utcnow)
