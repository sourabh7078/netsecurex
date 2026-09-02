"""
NetSecureX - Intelligent Network Vulnerability Scanner & Security Dashboard
Main Flask application: routes, auth, scan orchestration.

Run: python app.py
Default login: admin / admin123  (change via NSX_ADMIN_USERNAME / NSX_ADMIN_PASSWORD)

Environment variables (all optional -- see README.md for the full table):
    NSX_SECRET_KEY        Flask session secret. MUST be set to a random value in production.
    NSX_DATABASE_URL      SQLAlchemy URI. Defaults to a local SQLite file.
                           Set this to use XAMPP's MySQL instead, e.g.
                           mysql+pymysql://root:@localhost:3306/netsecurex
    NSX_ADMIN_USERNAME    Dashboard login username. Default: admin
    NSX_ADMIN_PASSWORD    Dashboard login password. Default: admin123
    NSX_HOST              Interface to bind to. Default: 0.0.0.0
    NSX_PORT              Port to listen on. Default: 5000
    NSX_DEBUG             "true"/"1" to enable Flask debug mode. Default: false
    NSX_MAX_SCAN_HOSTS    Safety cap on hosts per CIDR scan. Default: 1024 (a /22)
    NSX_API_KEY            REST API key. Auto-generated (and logged) per run if unset.
    NSX_USE_NMAP           "true"/"1" to use real Nmap (if installed) instead of the
                           built-in pure-Python scanner. See scanner.py for details.
"""

import os
import logging
import threading
import ipaddress
import secrets
from functools import wraps
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash

# python-dotenv is optional -- if present, load a local .env file for convenience.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from models import db, Scan, Host, Port, Vulnerability
from scanner import run_scan
from risk_engine import compute_host_risk, compute_scan_summary
from report_generator import generate_report

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _env_bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("netsecurex")

# ---------------------------------------------------------------------------
# App & configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)

DEBUG_MODE = _env_bool("NSX_DEBUG", default=False)
_default_secret = "dev-secret-change-me"
app.config["SECRET_KEY"] = os.environ.get("NSX_SECRET_KEY", _default_secret)

if app.config["SECRET_KEY"] == _default_secret and not DEBUG_MODE:
    log.warning(
        "NSX_SECRET_KEY is not set -- using the insecure default. "
        "Set a random NSX_SECRET_KEY before exposing this app beyond localhost."
    )

# Database: SQLite by default (zero-config, ideal for a quick demo/viva).
# To use XAMPP's MySQL instead, set NSX_DATABASE_URL, e.g.:
#   Windows (cmd):        set NSX_DATABASE_URL=mysql+pymysql://root:@localhost:3306/netsecurex
#   macOS/Linux (bash):   export NSX_DATABASE_URL="mysql+pymysql://root:@localhost:3306/netsecurex"
# Make sure MySQL is running in the XAMPP control panel and the 'netsecurex' database
# has already been created (e.g. via phpMyAdmin) before starting the app.
# Requires: pip install PyMySQL   (already listed in requirements.txt)
_default_sqlite_uri = "sqlite:///" + os.path.join(BASE_DIR, "instance", "netsecurex.db")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("NSX_DATABASE_URL", _default_sqlite_uri)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

db.init_app(app)

# Safety cap: refuse to enumerate absurdly large ranges (e.g. a /8) from the UI.
# A /22 (1024 addresses) is already generous for a lab/demo network.
MAX_SCAN_HOSTS = int(os.environ.get("NSX_MAX_SCAN_HOSTS", "1024"))

# Demo credential store: a single hashed admin credential, configurable via env vars.
# Swap this for a real users table if you need more than one analyst account.
ADMIN_USERNAME = os.environ.get("NSX_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get("NSX_ADMIN_PASSWORD", "admin123")
)

# REST API key (separate from the dashboard login) for programmatic access --
# see the "REST API" section in README.md. Generated randomly per process if
# not set, so the API is still usable out of the box but the key changes on
# every restart unless NSX_API_KEY is explicitly configured.
_default_api_key = None
API_KEY = os.environ.get("NSX_API_KEY")
if not API_KEY:
    _default_api_key = secrets.token_hex(16)
    API_KEY = _default_api_key

# Track in-progress scans: scan_id -> {"status": ..., "progress": ...}
SCAN_STATE = {}


# ---------------------------------------------------------------------------
# Security headers (sensible defaults for a security-focused tool)
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def server_error(e):
    log.exception("Unhandled server error: %s", e)
    return render_template("error.html", code=500, message="Something went wrong."), 500


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


def api_key_required(view):
    """Auth for the JSON REST API (/api/v1/...), separate from the dashboard
    session login. Callers must send a valid key in the X-API-Key header."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        provided = request.headers.get("X-API-Key", "")
        if not provided or not secrets.compare_digest(provided, API_KEY):
            return jsonify({"error": "unauthorized", "message": "Missing or invalid X-API-Key header"}), 401
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        valid = (
            username == ADMIN_USERNAME
            and check_password_hash(ADMIN_PASSWORD_HASH, password)
        )
        if valid:
            session["logged_in"] = True
            session["username"] = username
            log.info("Successful login for user '%s'", username)
            return redirect(url_for("dashboard"))
        log.warning("Failed login attempt for username '%s'", username)
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

# ---------------------------------------------------------------------------
# Shared scan-creation logic (used by both the web form and the REST API)
# ---------------------------------------------------------------------------

def _validate_and_create_scan(target, authorized):
    """Validates a scan request and, if valid, creates the Scan row and
    kicks off the background scan thread. Returns (scan, error_message) --
    exactly one of the two will be None."""
    target = (target or "").strip()

    if not target or len(target) > 253:
        return None, "Please provide a valid target (IP, hostname, or CIDR range)."

    if not authorized:
        return None, "You must confirm you are authorized to scan this target."

    # Reject CIDR ranges larger than the configured safety cap, so a typo
    # like "10.0.0.0/8" can't accidentally kick off a scan of 16M addresses.
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses > MAX_SCAN_HOSTS:
                return None, (
                    f"That range has {network.num_addresses} addresses, which exceeds "
                    f"the configured safety limit of {MAX_SCAN_HOSTS}. Use a smaller "
                    f"CIDR block (e.g. /22 or smaller)."
                )
        except ValueError:
            return None, "That doesn't look like a valid CIDR range."

    scan = Scan(
        target_range=target,
        start_time=datetime.utcnow(),
        status="running",
    )
    db.session.add(scan)
    db.session.commit()

    SCAN_STATE[scan.id] = {"status": "running", "progress": 0}
    log.info("Starting scan #%s against target '%s'", scan.id, target)

    thread = threading.Thread(
        target=_execute_scan,
        args=(app.app_context(), scan.id, target),
        daemon=True,
    )
    thread.start()

    return scan, None


@app.route("/scan/new", methods=["GET", "POST"])
@login_required
def new_scan():
    if request.method == "POST":
        target = request.form.get("target", "")
        authorized = request.form.get("authorized") == "on"

        scan, error = _validate_and_create_scan(target, authorized)
        if error:
            flash(error, "error")
            return redirect(url_for("new_scan"))

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
            log.info("Scan #%s completed: %d host(s) found", scan_id, len(results["hosts"]))

        except Exception as exc:  # pragma: no cover - defensive
            log.exception("Scan #%s failed", scan_id)
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
    try:
        filepath = generate_report(scan_id)
    except Exception:
        log.exception("Report generation failed for scan #%s", scan_id)
        flash("Report generation failed. Please try again.", "error")
        return redirect(url_for("scan_result", scan_id=scan_id))
    filename = f"NetSecureX_Report_Scan{scan_id}.docx"
    return send_file(filepath, as_attachment=True, download_name=filename)


# ---------------------------------------------------------------------------
# REST API (v1) -- programmatic access, separate from the web dashboard.
# Auth: send header  X-API-Key: <key>   (see README.md "REST API" section)
# ---------------------------------------------------------------------------

def _serialize_vuln(v):
    return {
        "cve_id": v.cve_id,
        "cvss_score": v.cvss_score,
        "description": v.description,
        "severity": v.severity,
    }


def _serialize_port(p):
    return {
        "port": p.port_no,
        "protocol": p.protocol,
        "service": p.service,
        "version": p.version,
        "state": p.state,
        "vulnerabilities": [_serialize_vuln(v) for v in p.vulnerabilities],
    }


def _serialize_host(h):
    latest = h.latest_risk
    return {
        "ip": h.ip,
        "hostname": h.hostname,
        "os_guess": h.os_guess,
        "risk_score": latest.score if latest else None,
        "risk_category": latest.category if latest else None,
        "ports": [_serialize_port(p) for p in h.ports],
    }


def _serialize_scan(s, include_hosts=False):
    data = {
        "id": s.id,
        "target_range": s.target_range,
        "status": s.status,
        "start_time": s.start_time.isoformat() if s.start_time else None,
        "end_time": s.end_time.isoformat() if s.end_time else None,
        "duration_seconds": s.duration_seconds,
    }
    if include_hosts:
        data["hosts"] = [_serialize_host(h) for h in s.hosts]
    return data


@app.route("/api/v1/scans", methods=["POST"])
@api_key_required
def api_create_scan():
    """Start a new scan. Body: {"target": "192.168.56.101", "authorized": true}"""
    data = request.get_json(silent=True) or {}
    scan, error = _validate_and_create_scan(data.get("target"), bool(data.get("authorized")))
    if error:
        return jsonify({"error": "invalid_request", "message": error}), 400

    return jsonify({
        "scan_id": scan.id,
        "status": scan.status,
        "status_url": url_for("api_get_scan_status", scan_id=scan.id, _external=True),
        "result_url": url_for("api_get_scan", scan_id=scan.id, _external=True),
    }), 201


@app.route("/api/v1/scans", methods=["GET"])
@api_key_required
def api_list_scans():
    """List recent scans (summary only, no host/port detail)."""
    limit = min(int(request.args.get("limit", 20)), 100)
    scans = Scan.query.order_by(Scan.start_time.desc()).limit(limit).all()
    return jsonify([_serialize_scan(s) for s in scans])


@app.route("/api/v1/scans/<int:scan_id>", methods=["GET"])
@api_key_required
def api_get_scan(scan_id):
    """Full scan detail: hosts, ports, vulnerabilities, and risk scores."""
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(_serialize_scan(scan, include_hosts=True))


@app.route("/api/v1/scans/<int:scan_id>/status", methods=["GET"])
@api_key_required
def api_get_scan_status(scan_id):
    """Lightweight polling endpoint: {"status": "running", "progress": 42}"""
    Scan.query.get_or_404(scan_id)  # 404 if the scan doesn't exist
    state = SCAN_STATE.get(scan_id, {"status": "unknown", "progress": 0})
    return jsonify(state)


@app.route("/api/v1/scans/<int:scan_id>/report", methods=["GET"])
@api_key_required
def api_download_report(scan_id):
    """Download the auto-generated .docx report for a completed scan."""
    Scan.query.get_or_404(scan_id)
    try:
        filepath = generate_report(scan_id)
    except Exception:
        log.exception("API report generation failed for scan #%s", scan_id)
        return jsonify({"error": "report_generation_failed"}), 500
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

    active_db = app.config["SQLALCHEMY_DATABASE_URI"].split("://")[0]
    log.info("NetSecureX using database backend: %s", active_db)
    if active_db.startswith("mysql"):
        log.info("Connected to MySQL (e.g. via XAMPP) -- check phpMyAdmin to view live tables.")

    if _default_api_key:
        log.warning(
            "NSX_API_KEY not set -- generated a random key for this session: %s "
            "(set NSX_API_KEY to keep it stable across restarts)", _default_api_key
        )
    log.info("REST API available at /api/v1/scans (send header X-API-Key: <key>)")

    host = os.environ.get("NSX_HOST", "0.0.0.0")
    port = int(os.environ.get("NSX_PORT", "5000"))
    log.info("Starting NetSecureX on http://%s:%s (debug=%s)", host, port, DEBUG_MODE)
    app.run(debug=DEBUG_MODE, host=host, port=port)
