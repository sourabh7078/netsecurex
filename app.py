"""
NetSecureX - Intelligent Network Vulnerability Scanner & Security Dashboard
Main Flask application: routes, auth, scan orchestration.

Run: python app.py
Default login: admin / admin123  (change in production!)
"""

import os
import threading
import ipaddress
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file
)

from models import db, Scan, Host, Port, Vulnerability
from scanner import run_scan
from risk_engine import compute_host_risk, compute_scan_summary
from report_generator import generate_report

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("NSX_SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "instance", "netsecurex.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

# In-memory demo credential store (swap for a real users table + hashing in production)
DEMO_USER = {"username": "admin", "password": "admin123"}

# Track in-progress scans: scan_id -> {"status": ..., "progress": ...}
SCAN_STATE = {}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def login_required(view):
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEMO_USER["username"] and password == DEMO_USER["password"]:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard / history
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    recent_scans = Scan.query.order_by(Scan.start_time.desc()).limit(10).all()
    total_hosts = Host.query.count()
    total_vulns = Vulnerability.query.count()
    critical_vulns = Vulnerability.query.filter_by(severity="Critical").count()
    return render_template(
        "dashboard.html",
        scans=recent_scans,
        total_hosts=total_hosts,
        total_vulns=total_vulns,
        critical_vulns=critical_vulns,
    )


@app.route("/history")
@login_required
def history():
    scans = Scan.query.order_by(Scan.start_time.desc()).all()
    return render_template("history.html", scans=scans)


# ---------------------------------------------------------------------------
# New scan (with authorization gate)
# ---------------------------------------------------------------------------

@app.route("/scan/new", methods=["GET", "POST"])
@login_required
def new_scan():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        authorized = request.form.get("authorized") == "on"

        if not authorized:
            flash("You must confirm you are authorized to scan this target.", "error")
            return redirect(url_for("new_scan"))

        try:
            # Accept single IP, CIDR range, or hostname
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
            else:
                ipaddress.ip_address(target)
        except ValueError:
            pass  # allow hostnames through; scanner.py will resolve/validate

        scan = Scan(
            target_range=target,
            start_time=datetime.utcnow(),
            status="running",
        )
        db.session.add(scan)
        db.session.commit()

        SCAN_STATE[scan.id] = {"status": "running", "progress": 0}

        thread = threading.Thread(
            target=_execute_scan,
            args=(app.app_context(), scan.id, target),
            daemon=True,
        )
        thread.start()

        return redirect(url_for("scan_progress", scan_id=scan.id))

    return render_template("new_scan.html")


def _execute_scan(app_context, scan_id, target):
    with app_context:
        try:
            def progress_cb(pct):
                SCAN_STATE[scan_id]["progress"] = pct

            results = run_scan(target, progress_cb=progress_cb)

            scan = Scan.query.get(scan_id)
            for host_data in results["hosts"]:
                host = Host(
                    scan_id=scan.id,
                    ip=host_data["ip"],
                    hostname=host_data.get("hostname", ""),
                    os_guess=host_data.get("os_guess", "Unknown"),
                    status="up",
                )
                db.session.add(host)
                db.session.flush()  # get host.id

                for port_data in host_data["ports"]:
                    port = Port(
                        host_id=host.id,
                        port_no=port_data["port"],
                        protocol=port_data.get("protocol", "tcp"),
                        service=port_data.get("service", "unknown"),
                        version=port_data.get("version", ""),
                        state=port_data.get("state", "open"),
                    )
                    db.session.add(port)
                    db.session.flush()

                    for vuln in port_data.get("vulnerabilities", []):
                        v = Vulnerability(
                            port_id=port.id,
                            cve_id=vuln["cve_id"],
                            cvss_score=vuln["cvss_score"],
                            description=vuln["description"],
                            severity=vuln["severity"],
                        )
                        db.session.add(v)

                db.session.commit()
                compute_host_risk(host.id)

            scan.status = "completed"
            scan.end_time = datetime.utcnow()
            db.session.commit()

            SCAN_STATE[scan_id]["status"] = "completed"
            SCAN_STATE[scan_id]["progress"] = 100

        except Exception as exc:  # pragma: no cover - defensive
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = "failed"
                scan.end_time = datetime.utcnow()
                db.session.commit()
            SCAN_STATE[scan_id]["status"] = "failed"
            SCAN_STATE[scan_id]["error"] = str(exc)


@app.route("/scan/<int:scan_id>/progress")
@login_required
def scan_progress(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return render_template("scan_progress.html", scan=scan)


@app.route("/api/scan/<int:scan_id>/status")
@login_required
def api_scan_status(scan_id):
    state = SCAN_STATE.get(scan_id, {"status": "unknown", "progress": 0})
    return jsonify(state)


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------

@app.route("/scan/<int:scan_id>")
@login_required
def scan_result(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    summary = compute_scan_summary(scan_id)
    return render_template("scan_result.html", scan=scan, summary=summary)


@app.route("/scan/<int:scan_id>/report")
@login_required
def download_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    filepath = generate_report(scan_id)
    filename = f"NetSecureX_Report_Scan{scan_id}.docx"
    return send_file(filepath, as_attachment=True, download_name=filename)


# ---------------------------------------------------------------------------
# API for dashboard charts
# ---------------------------------------------------------------------------

@app.route("/api/charts/severity")
@login_required
def api_severity_chart():
    from sqlalchemy import func
    rows = (
        db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )
    data = {sev: count for sev, count in rows}
    return jsonify(data)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)
