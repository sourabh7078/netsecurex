"""
NetSecureX - Intelligent Network Vulnerability Scanner & Security Dashboard
Main Flask application: routes, accounts and roles, two-factor sign-in,
password reset, CSRF protection, scan ownership and sharing, schedules,
change reports, alerts, and the audit log.

Run: python app.py
On first start, an administrator account is created from NSX_ADMIN_USERNAME /
NSX_ADMIN_PASSWORD (defaults admin / admin123). Change the password before use
beyond a private lab.

Environment variables (all optional -- see README.md for the full table):
    NSX_SECRET_KEY, NSX_DATABASE_URL, NSX_ADMIN_USERNAME, NSX_ADMIN_PASSWORD,
    NSX_HOST, NSX_PORT, NSX_DEBUG, NSX_MAX_SCAN_HOSTS, NSX_MAX_LOGIN_ATTEMPTS,
    NSX_LOGIN_LOCKOUT_SECONDS, NSX_SESSION_TIMEOUT_MINUTES,
    NSX_SESSION_COOKIE_SECURE, NSX_CSRF (default true), NSX_ENABLE_SCHEDULER,
    NSX_USE_NMAP, NSX_USE_LIVE_CVE, NSX_NVD_FEED_PATH, NSX_UDP_SCAN, NSX_UDP_PROBES
    Alert channels (webhook and e-mail) are documented in alerts.py.
"""

import ipaddress
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file, has_request_context,
)
from sqlalchemy import or_, text, inspect as sa_inspect
from werkzeug.security import generate_password_hash, check_password_hash

try:  # optional: load a local .env file
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from models import (
    db, Scan, ScanShare, Host, Port, Vulnerability, User, LoginAttempt, Schedule,
    PasswordResetToken, AuditEvent,
    ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN, ROLES,
)
from scanner import run_scan
from risk_engine import compute_host_risk, compute_scan_summary, get_risk_trend
from report_generator import generate_report
from nmap_output import build_nmap_style_output
from changes import snapshot_scan, diff_snapshots, find_new_critical
import alerts
import totp


def _env_bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("netsecurex")

# ---------------------------------------------------------------- configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

DEBUG_MODE = _env_bool("NSX_DEBUG", default=False)
_default_secret = "dev-secret-change-me"
app.config["SECRET_KEY"] = os.environ.get("NSX_SECRET_KEY", _default_secret)
if app.config["SECRET_KEY"] == _default_secret and not DEBUG_MODE:
    log.warning("NSX_SECRET_KEY is not set -- using the insecure default. "
                "Set a random NSX_SECRET_KEY before exposing this app beyond localhost.")

_default_sqlite_uri = "sqlite:///" + os.path.join(BASE_DIR, "instance", "netsecurex.db")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("NSX_DATABASE_URL", _default_sqlite_uri)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = _env_bool("NSX_SESSION_COOKIE_SECURE", default=False)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    minutes=int(os.environ.get("NSX_SESSION_TIMEOUT_MINUTES", "60")))
app.config["CSRF_ENABLED"] = _env_bool("NSX_CSRF", default=True)

db.init_app(app)

MAX_SCAN_HOSTS = int(os.environ.get("NSX_MAX_SCAN_HOSTS", "1024"))
MAX_LOGIN_ATTEMPTS = int(os.environ.get("NSX_MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("NSX_LOGIN_LOCKOUT_SECONDS", "300"))
RESET_TOKEN_MINUTES = 30
MIN_INTERVAL, MAX_INTERVAL = 15, 10080
MIN_PASSWORD_LENGTH = 10
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")

ROLE_RANK = {ROLE_VIEWER: 1, ROLE_ANALYST: 2, ROLE_ADMIN: 3}

SCAN_STATE = {}  # scan_id -> {"status": ..., "progress": ...}  (one worker process)


# ---------------------------------------------------------------- database setup
def _add_column_if_missing(table, column, ddl):
    insp = sa_inspect(db.engine)
    if insp.has_table(table):
        cols = {c["name"] for c in insp.get_columns(table)}
        if column not in cols:
            db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
            db.session.commit()
            log.info("Added column %s.%s", table, column)


def _migrate_schema():
    """Add columns introduced after a database was first created. create_all()
    builds new tables but does not alter existing ones."""
    _add_column_if_missing("vulnerabilities", "source", "VARCHAR(20) DEFAULT 'offline-db'")
    _add_column_if_missing("scans", "owner", "VARCHAR(64) DEFAULT ''")
    _add_column_if_missing("users", "totp_secret", "VARCHAR(64)")
    _add_column_if_missing("users", "totp_enabled", "BOOLEAN DEFAULT 0")


def bootstrap_users():
    """Create the first administrator if the users table is empty."""
    if User.query.count() == 0:
        username = os.environ.get("NSX_ADMIN_USERNAME", "admin")
        password = os.environ.get("NSX_ADMIN_PASSWORD", "admin123")
        db.session.add(User(username=username,
                            password_hash=generate_password_hash(password),
                            role=ROLE_ADMIN, is_active=True))
        db.session.commit()
        log.info("Created initial administrator '%s'", username)


def init_database():
    db.create_all()
    _migrate_schema()
    bootstrap_users()


# ---------------------------------------------------------------- audit log
def audit(action, target="", detail="", username=None):
    """Record an audit event. Safe to call outside a request (for example from
    the scheduler): the user name is then taken from the argument."""
    if username is None:
        username = session.get("username", "") if has_request_context() else "system"
    ip = _client_ip() if has_request_context() else ""
    try:
        db.session.add(AuditEvent(username=username or "", ip=ip, action=action,
                                  target=str(target)[:255], detail=str(detail)[:2000]))
        db.session.commit()
    except Exception:
        db.session.rollback()
        log.exception("Could not write audit event %s", action)


# ---------------------------------------------------------------- lockout (shared)
def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def _is_locked_out(ip):
    row = db.session.get(LoginAttempt, ip)
    if row is None or row.locked_until is None:
        return False, 0
    remaining = (row.locked_until - datetime.utcnow()).total_seconds()
    if remaining <= 0:
        db.session.delete(row)
        db.session.commit()
        return False, 0
    return True, int(remaining)


def _record_login_failure(ip):
    row = db.session.get(LoginAttempt, ip)
    if row is None:
        row = LoginAttempt(ip=ip, failures=0)
        db.session.add(row)
    row.failures += 1
    if row.failures >= MAX_LOGIN_ATTEMPTS:
        row.locked_until = datetime.utcnow() + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)
        log.warning("IP %s locked out for %ss after %d failed logins",
                    ip, LOGIN_LOCKOUT_SECONDS, row.failures)
    db.session.commit()


def _clear_login_failures(ip):
    row = db.session.get(LoginAttempt, ip)
    if row is not None:
        db.session.delete(row)
        db.session.commit()


# ---------------------------------------------------------------- CSRF
def _csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.before_request
def csrf_protect():
    if not app.config.get("CSRF_ENABLED", True):
        return None
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken", "")
        expected = session.get("csrf_token", "")
        if not expected or not sent or not secrets.compare_digest(sent, expected):
            log.warning("CSRF check failed for %s from %s", request.path, _client_ip())
            return render_template("error.html", code=400,
                                   message="This form has expired. Reload the page and try again."), 400
    return None


# ---------------------------------------------------------------- headers, errors
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


@app.context_processor
def inject_globals():
    role = session.get("role")
    return {
        "can_scan": ROLE_RANK.get(role, 0) >= ROLE_RANK[ROLE_ANALYST],
        "is_admin": role == ROLE_ADMIN,
        "csrf_token": _csrf_token,
    }


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403,
                           message="Your role does not allow this action."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def server_error(e):
    log.exception("Unhandled server error: %s", e)
    return render_template("error.html", code=500, message="Something went wrong."), 500


# ---------------------------------------------------------------- auth decorators
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(minimum):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect(url_for("login"))
            if ROLE_RANK.get(session.get("role"), 0) < ROLE_RANK[minimum]:
                return render_template("error.html", code=403,
                                       message="Your role does not allow this action."), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def _active_admin_count():
    return User.query.filter_by(role=ROLE_ADMIN, is_active=True).count()


# ---------------------------------------------------------------- scan visibility
def _visible_scans():
    """Scans the signed-in user may see. Analysts see their own scans and scans
    shared with them. Viewers and administrators see all scans."""
    if session.get("role") != ROLE_ANALYST:
        return Scan.query
    username = session.get("username", "")
    shared = db.session.query(ScanShare.scan_id).filter(ScanShare.username == username)
    return Scan.query.filter(or_(Scan.owner == username, Scan.id.in_(shared)))


def _can_view_scan(scan):
    if session.get("role") != ROLE_ANALYST:
        return True
    username = session.get("username", "")
    if scan.owner == username:
        return True
    return ScanShare.query.filter_by(scan_id=scan.id, username=username).first() is not None


def _can_manage_scan(scan):
    return session.get("role") == ROLE_ADMIN or scan.owner == session.get("username")


def _get_viewable_scan_or_403(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if not _can_view_scan(scan):
        return None
    return scan


# ---------------------------------------------------------------- sign-in
def _complete_login(user, ip):
    _clear_login_failures(ip)
    session.permanent = True
    session["logged_in"] = True
    session["user_id"] = user.id
    session["username"] = user.username
    session["role"] = user.role
    session["csrf_token"] = secrets.token_urlsafe(32)   # rotate on sign-in
    session.pop("pending_2fa", None)
    audit("auth.login", username=user.username)
    log.info("Successful login for '%s' (%s)", user.username, user.role)
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = _client_ip()
        locked, remaining = _is_locked_out(ip)
        if locked:
            log.warning("Blocked login from locked-out IP %s (%ss remaining)", ip, remaining)
            flash(f"Too many failed attempts. Try again in {remaining} seconds.", "error")
            return render_template("login.html"), 429

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        valid = bool(user and user.is_active and check_password_hash(user.password_hash, password))
        if valid and user.totp_enabled:
            session["pending_2fa"] = user.id
            return redirect(url_for("login_2fa"))
        if valid:
            return _complete_login(user, ip)

        _record_login_failure(ip)
        audit("auth.failed", target=username, detail="password")
        log.warning("Failed login for username '%s' from %s", username, ip)
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    user_id = session.get("pending_2fa")
    if not user_id:
        return redirect(url_for("login"))
    user = db.session.get(User, user_id)
    if user is None or not user.is_active or not user.totp_enabled:
        session.pop("pending_2fa", None)
        return redirect(url_for("login"))
    ip = _client_ip()
    if request.method == "POST":
        locked, remaining = _is_locked_out(ip)
        if locked:
            flash(f"Too many failed attempts. Try again in {remaining} seconds.", "error")
            return render_template("login_2fa.html"), 429
        if totp.verify(user.totp_secret, request.form.get("code", "").strip()):
            return _complete_login(user, ip)
        _record_login_failure(ip)
        audit("auth.failed", target=user.username, detail="two-factor code")
        flash("That code is not valid. Check your authenticator app and try again.", "error")
    return render_template("login_2fa.html")


@app.route("/logout")
def logout():
    if session.get("logged_in"):
        audit("auth.logout")
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- security settings (2FA)
@app.route("/account/security")
@login_required
def security():
    user = User.query.get_or_404(session["user_id"])
    pending = session.get("totp_pending") if not user.totp_enabled else None
    uri = totp.provisioning_uri(pending, user.username) if pending else None
    return render_template("security.html", user=user, pending=pending, uri=uri)


@app.route("/account/security/2fa/start", methods=["POST"])
@login_required
def security_2fa_start():
    user = User.query.get_or_404(session["user_id"])
    if user.totp_enabled:
        flash("Two-factor sign-in is already on.", "error")
        return redirect(url_for("security"))
    session["totp_pending"] = totp.generate_secret()
    return redirect(url_for("security"))


@app.route("/account/security/2fa/enable", methods=["POST"])
@login_required
def security_2fa_enable():
    user = User.query.get_or_404(session["user_id"])
    pending = session.get("totp_pending")
    if user.totp_enabled or not pending:
        return redirect(url_for("security"))
    if totp.verify(pending, request.form.get("code", "").strip()):
        user.totp_secret = pending
        user.totp_enabled = True
        db.session.commit()
        session.pop("totp_pending", None)
        audit("auth.2fa_enabled")
        flash("Two-factor sign-in is now on. You will need a code at each sign-in.", "success")
    else:
        flash("That code did not match. Try the code shown now in your authenticator app.", "error")
    return redirect(url_for("security"))


@app.route("/account/security/2fa/disable", methods=["POST"])
@login_required
def security_2fa_disable():
    user = User.query.get_or_404(session["user_id"])
    if totp.verify(user.totp_secret, request.form.get("code", "").strip()):
        user.totp_secret = None
        user.totp_enabled = False
        db.session.commit()
        audit("auth.2fa_disabled")
        flash("Two-factor sign-in is now off.", "success")
    else:
        flash("That code did not match.", "error")
    return redirect(url_for("security"))


# ---------------------------------------------------------------- password reset
def _hash_token(token):
    import hashlib
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    record = PasswordResetToken.query.filter_by(token_hash=_hash_token(token)).first()
    if record is None or record.used or record.expires_at < datetime.utcnow():
        return render_template("error.html", code=400,
                               message="This reset link is invalid or has expired. Ask an administrator for a new one."), 400
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(password) < MIN_PASSWORD_LENGTH:
            flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", "error")
        elif password != confirm:
            flash("The two passwords do not match.", "error")
        else:
            user = db.session.get(User, record.user_id)
            user.password_hash = generate_password_hash(password)
            record.used = True
            db.session.commit()
            audit("auth.password_reset_used", target=user.username, username=user.username)
            flash("Your password has been changed. Sign in with the new password.", "success")
            return redirect(url_for("login"))
    return render_template("reset.html", token=token)


@app.route("/admin/users/<int:user_id>/reset", methods=["POST"])
@role_required(ROLE_ADMIN)
def user_issue_reset(user_id):
    user = User.query.get_or_404(user_id)
    token = secrets.token_urlsafe(24)
    db.session.add(PasswordResetToken(user_id=user.id, token_hash=_hash_token(token),
                                      expires_at=datetime.utcnow() + timedelta(minutes=RESET_TOKEN_MINUTES)))
    db.session.commit()
    audit("auth.password_reset_issued", target=user.username)
    link = url_for("reset_password", token=token, _external=True)
    flash(f"Reset link for '{user.username}' (valid {RESET_TOKEN_MINUTES} minutes, shown once): {link}", "success")
    return redirect(url_for("users"))


# ---------------------------------------------------------------- dashboard, history
@app.route("/")
@login_required
def dashboard():
    recent = _visible_scans().order_by(Scan.start_time.desc()).limit(10).all()
    return render_template(
        "dashboard.html",
        scans=recent,
        total_hosts=Host.query.count(),
        total_vulns=Vulnerability.query.count(),
        critical_vulns=Vulnerability.query.filter_by(severity="Critical").count(),
    )


@app.route("/history")
@login_required
def history():
    scans = _visible_scans().order_by(Scan.start_time.desc()).all()
    return render_template("history.html", scans=scans)


# ---------------------------------------------------------------- scan creation
def _validate_target(target, authorized):
    """Return (normalised_target, error). error is None when the request is valid."""
    target = (target or "").strip()
    if not target or len(target) > 253:
        return None, "Please provide a valid target (IP, hostname, or CIDR range)."
    if not authorized:
        return None, "You must confirm you are authorized to scan this target."
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return None, "That doesn't look like a valid CIDR range."
        if network.num_addresses > MAX_SCAN_HOSTS:
            return None, (f"That range has {network.num_addresses} addresses, which exceeds the "
                          f"configured limit of {MAX_SCAN_HOSTS}. Use a smaller CIDR block.")
    return target, None


def _start_scan(target, owner="", label="web"):
    scan = Scan(target_range=target, start_time=datetime.utcnow(), status="running", owner=owner or "")
    db.session.add(scan)
    db.session.commit()
    SCAN_STATE[scan.id] = {"status": "running", "progress": 0}
    log.info("Starting scan #%s against '%s' (%s, owner %s)", scan.id, target, label, owner or "-")
    threading.Thread(target=_execute_scan, args=(app.app_context(), scan.id, target),
                     daemon=True).start()
    return scan


def _validate_and_create_scan(target, authorized, owner=""):
    """Validate and start a scan. Returns (scan, error); exactly one is None."""
    target, error = _validate_target(target, authorized)
    if error:
        return None, error
    return _start_scan(target, owner=owner), None


@app.route("/scan/new", methods=["GET", "POST"])
@role_required(ROLE_ANALYST)
def new_scan():
    if request.method == "POST":
        scan, error = _validate_and_create_scan(
            request.form.get("target", ""), request.form.get("authorized") == "on",
            owner=session.get("username", ""))
        if error:
            flash(error, "error")
            return redirect(url_for("new_scan"))
        audit("scan.start", target=scan.target_range, detail=f"scan #{scan.id}")
        return redirect(url_for("scan_progress", scan_id=scan.id))
    return render_template("new_scan.html")


# ---------------------------------------------------------------- scan execution
def _previous_completed_scan(scan):
    return (Scan.query
            .filter(Scan.target_range == scan.target_range,
                    Scan.status == "completed",
                    Scan.id != scan.id,
                    Scan.start_time < scan.start_time)
            .order_by(Scan.start_time.desc())
            .first())


def _alert_on_new_critical(scan):
    previous = _previous_completed_scan(scan)
    new_critical = find_new_critical(
        snapshot_scan(previous) if previous else None,
        snapshot_scan(scan),
    )
    if new_critical:
        channels = alerts.dispatch(alerts.build_payload(scan.target_range, scan.id, new_critical))
        log.info("Scan #%s: %d new Critical finding(s); alerts sent via %s",
                 scan.id, len(new_critical), channels or "no configured channel")


def _execute_scan(app_context, scan_id, target):
    with app_context:
        try:
            def progress_cb(pct):
                SCAN_STATE[scan_id]["progress"] = pct

            results = run_scan(target, progress_cb=progress_cb)

            scan = db.session.get(Scan, scan_id)
            for host_data in results["hosts"]:
                host = Host(scan_id=scan.id, ip=host_data["ip"],
                            hostname=host_data.get("hostname", ""),
                            os_guess=host_data.get("os_guess", "Unknown"), status="up")
                db.session.add(host)
                db.session.flush()

                for port_data in host_data["ports"]:
                    port = Port(host_id=host.id,
                                port_no=port_data["port"],
                                protocol=port_data.get("protocol", "tcp"),
                                service=port_data.get("service", "unknown"),
                                version=port_data.get("version", ""),
                                state=port_data.get("state", "open"))
                    db.session.add(port)
                    db.session.flush()

                    for vuln in port_data.get("vulnerabilities", []):
                        db.session.add(Vulnerability(
                            port_id=port.id,
                            cve_id=vuln["cve_id"],
                            cvss_score=vuln["cvss_score"],
                            description=vuln["description"],
                            severity=vuln["severity"],
                            source=vuln.get("source", "offline-db"),
                        ))

                db.session.commit()
                compute_host_risk(host.id)

            scan.status = "completed"
            scan.end_time = datetime.utcnow()
            db.session.commit()
            SCAN_STATE[scan_id]["status"] = "completed"
            SCAN_STATE[scan_id]["progress"] = 100
            log.info("Scan #%s completed: %d host(s)", scan_id, len(results["hosts"]))

            try:
                _alert_on_new_critical(scan)
            except Exception:
                log.exception("Change alert check failed for scan #%s", scan_id)

        except Exception as exc:
            log.exception("Scan #%s failed", scan_id)
            db.session.rollback()
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.end_time = datetime.utcnow()
                db.session.commit()
            SCAN_STATE[scan_id]["status"] = "failed"
            SCAN_STATE[scan_id]["error"] = str(exc)


@app.route("/scan/<int:scan_id>/progress")
@login_required
def scan_progress(scan_id):
    scan = _get_viewable_scan_or_403(scan_id)
    if scan is None:
        return render_template("error.html", code=403, message="You can only view scans you own or that were shared with you."), 403
    return render_template("scan_progress.html", scan=scan)


@app.route("/api/scan/<int:scan_id>/status")
@login_required
def api_scan_status(scan_id):
    scan = _get_viewable_scan_or_403(scan_id)
    if scan is None:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(SCAN_STATE.get(scan_id, {"status": "unknown", "progress": 0}))


# ---------------------------------------------------------------- results, changes, sharing
@app.route("/scan/<int:scan_id>")
@login_required
def scan_result(scan_id):
    scan = _get_viewable_scan_or_403(scan_id)
    if scan is None:
        return render_template("error.html", code=403, message="You can only view scans you own or that were shared with you."), 403
    summary = compute_scan_summary(scan_id)
    terminal_lines = build_nmap_style_output(scan, summary["host_rows"]) if summary else []
    previous = _previous_completed_scan(scan)
    shares = sorted(s.username for s in scan.shares)
    return render_template("scan_result.html", scan=scan, summary=summary,
                           terminal_lines=terminal_lines, has_previous=previous is not None,
                           can_manage=_can_manage_scan(scan), shares=shares)


@app.route("/scan/<int:scan_id>/changes")
@login_required
def scan_changes(scan_id):
    scan = _get_viewable_scan_or_403(scan_id)
    if scan is None:
        return render_template("error.html", code=403, message="You can only view scans you own or that were shared with you."), 403
    previous = _previous_completed_scan(scan)
    diff = None
    if previous is not None:
        diff = diff_snapshots(snapshot_scan(previous), snapshot_scan(scan))
    return render_template("changes.html", scan=scan, previous=previous, diff=diff)


@app.route("/scan/<int:scan_id>/share", methods=["POST"])
@login_required
def scan_share(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if not _can_manage_scan(scan):
        return render_template("error.html", code=403, message="Only the owner or an administrator can share this scan."), 403
    username = request.form.get("username", "").strip()
    target = User.query.filter_by(username=username, is_active=True).first()
    if target is None:
        flash("No active user has that name.", "error")
    elif target.username == scan.owner:
        flash("The owner already has access.", "error")
    elif ScanShare.query.filter_by(scan_id=scan.id, username=target.username).first():
        flash(f"The scan is already shared with {target.username}.", "error")
    else:
        db.session.add(ScanShare(scan_id=scan.id, username=target.username))
        db.session.commit()
        audit("scan.shared", target=f"scan #{scan.id}", detail=f"shared with {target.username}")
        flash(f"Scan shared with {target.username}.", "success")
    return redirect(url_for("scan_result", scan_id=scan.id))


@app.route("/scan/<int:scan_id>/unshare/<username>", methods=["POST"])
@login_required
def scan_unshare(scan_id, username):
    scan = Scan.query.get_or_404(scan_id)
    if not _can_manage_scan(scan):
        return render_template("error.html", code=403, message="Only the owner or an administrator can change sharing."), 403
    share = ScanShare.query.filter_by(scan_id=scan.id, username=username).first()
    if share:
        db.session.delete(share)
        db.session.commit()
        audit("scan.unshared", target=f"scan #{scan.id}", detail=f"removed {username}")
    return redirect(url_for("scan_result", scan_id=scan.id))


@app.route("/scan/<int:scan_id>/report")
@login_required
def download_report(scan_id):
    scan = _get_viewable_scan_or_403(scan_id)
    if scan is None:
        return render_template("error.html", code=403, message="You can only download reports for scans you can view."), 403
    try:
        filepath = generate_report(scan_id)
    except Exception:
        log.exception("Report generation failed for scan #%s", scan_id)
        flash("Report generation failed. Please try again.", "error")
        return redirect(url_for("scan_result", scan_id=scan_id))
    audit("report.download", target=f"scan #{scan_id}")
    return send_file(filepath, as_attachment=True,
                     download_name=f"NetSecureX_Report_Scan{scan_id}.docx")


# ---------------------------------------------------------------- schedules
def _run_due_schedules(now=None):
    """Start a scan for every enabled schedule whose time has come. Returns the
    list of scan ids started. A schedule whose previous scan is still running
    is postponed by one minute rather than run in parallel."""
    now = now or datetime.utcnow()
    started = []
    due = Schedule.query.filter(Schedule.enabled.is_(True), Schedule.next_run_at <= now).all()
    for sched in due:
        previous = db.session.get(Scan, sched.last_scan_id) if sched.last_scan_id else None
        if previous is not None and previous.status == "running":
            sched.next_run_at = now + timedelta(minutes=1)
            continue
        scan = _start_scan(sched.target_range, owner=sched.created_by, label=f"schedule #{sched.id}")
        sched.last_scan_id = scan.id
        sched.next_run_at = now + timedelta(minutes=sched.interval_minutes)
        started.append(scan.id)
        audit("schedule.run", target=sched.target_range, detail=f"schedule #{sched.id}, scan #{scan.id}",
              username=sched.created_by or "system")
    db.session.commit()
    return started


def _can_manage_schedule(sched):
    return session.get("role") == ROLE_ADMIN or sched.created_by == session.get("username")


@app.route("/schedules")
@login_required
def schedules():
    items = Schedule.query.order_by(Schedule.id.desc()).all()
    return render_template("schedules.html", schedules=items,
                           min_interval=MIN_INTERVAL, max_interval=MAX_INTERVAL)


@app.route("/schedules/new", methods=["POST"])
@role_required(ROLE_ANALYST)
def schedule_create():
    target, error = _validate_target(request.form.get("target", ""),
                                     request.form.get("authorized") == "on")
    try:
        interval = int(request.form.get("interval_minutes", "1440"))
    except ValueError:
        interval, error = 0, error or "Interval must be a whole number of minutes."
    if not error and not (MIN_INTERVAL <= interval <= MAX_INTERVAL):
        error = f"Interval must be between {MIN_INTERVAL} and {MAX_INTERVAL} minutes."
    if error:
        flash(error, "error")
        return redirect(url_for("schedules"))
    sched = Schedule(target_range=target, interval_minutes=interval, enabled=True,
                     created_by=session.get("username", ""), next_run_at=datetime.utcnow())
    db.session.add(sched)
    db.session.commit()
    audit("schedule.create", target=target, detail=f"every {interval} minutes")
    flash("Schedule created. The first scan starts within a minute.", "success")
    return redirect(url_for("schedules"))


@app.route("/schedules/<int:sched_id>/toggle", methods=["POST"])
@role_required(ROLE_ANALYST)
def schedule_toggle(sched_id):
    sched = Schedule.query.get_or_404(sched_id)
    if not _can_manage_schedule(sched):
        return render_template("error.html", code=403, message="You can only change schedules you created."), 403
    sched.enabled = not sched.enabled
    if sched.enabled:
        sched.next_run_at = datetime.utcnow()
    db.session.commit()
    audit("schedule.pause" if not sched.enabled else "schedule.resume", target=sched.target_range)
    return redirect(url_for("schedules"))


@app.route("/schedules/<int:sched_id>/delete", methods=["POST"])
@role_required(ROLE_ANALYST)
def schedule_delete(sched_id):
    sched = Schedule.query.get_or_404(sched_id)
    if not _can_manage_schedule(sched):
        return render_template("error.html", code=403, message="You can only delete schedules you created."), 403
    audit("schedule.delete", target=sched.target_range)
    db.session.delete(sched)
    db.session.commit()
    return redirect(url_for("schedules"))


# ---------------------------------------------------------------- user management
@app.route("/admin/users")
@role_required(ROLE_ADMIN)
def users():
    return render_template("users.html", users=User.query.order_by(User.id).all(), roles=ROLES)


@app.route("/admin/users/new", methods=["POST"])
@role_required(ROLE_ADMIN)
def user_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", ROLE_ANALYST)
    if not USERNAME_RE.match(username):
        flash("Username must be 3-64 characters: letters, digits, dot, dash, underscore.", "error")
    elif len(password) < MIN_PASSWORD_LENGTH:
        flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", "error")
    elif role not in ROLES:
        flash("Unknown role.", "error")
    elif User.query.filter_by(username=username).first():
        flash("That username already exists.", "error")
    else:
        db.session.add(User(username=username, password_hash=generate_password_hash(password),
                            role=role, is_active=True))
        db.session.commit()
        audit("user.create", target=username, detail=f"role {role}")
        flash(f"User '{username}' created as {role}.", "success")
    return redirect(url_for("users"))


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@role_required(ROLE_ADMIN)
def user_set_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get("role", "")
    if new_role not in ROLES:
        flash("Unknown role.", "error")
    elif user.role == ROLE_ADMIN and new_role != ROLE_ADMIN and user.is_active and _active_admin_count() <= 1:
        flash("At least one active administrator must remain.", "error")
    else:
        old = user.role
        user.role = new_role
        if user.id == session.get("user_id"):
            session["role"] = new_role
        db.session.commit()
        audit("user.role", target=user.username, detail=f"{old} -> {new_role}")
        flash(f"'{user.username}' is now {new_role}.", "success")
    return redirect(url_for("users"))


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@role_required(ROLE_ADMIN)
def user_toggle(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == session.get("user_id") and user.is_active:
        flash("You cannot deactivate your own account.", "error")
    elif user.is_active and user.role == ROLE_ADMIN and _active_admin_count() <= 1:
        flash("At least one active administrator must remain.", "error")
    else:
        user.is_active = not user.is_active
        db.session.commit()
        audit("user.enable" if user.is_active else "user.disable", target=user.username)
        flash(f"'{user.username}' is now {'active' if user.is_active else 'disabled'}.", "success")
    return redirect(url_for("users"))


# ---------------------------------------------------------------- audit log
@app.route("/admin/audit")
@role_required(ROLE_ADMIN)
def audit_log():
    username = request.args.get("user", "").strip()
    limit = min(max(int(request.args.get("limit", 200)), 1), 1000)
    query = AuditEvent.query
    if username:
        query = query.filter(AuditEvent.username == username)
    events = query.order_by(AuditEvent.id.desc()).limit(limit).all()
    return render_template("audit.html", events=events, username=username, limit=limit)


# ---------------------------------------------------------------- chart endpoints
@app.route("/api/charts/severity")
@login_required
def api_severity_chart():
    from sqlalchemy import func
    rows = (db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
            .group_by(Vulnerability.severity).all())
    return jsonify({sev: count for sev, count in rows})


@app.route("/api/charts/trend")
@login_required
def api_risk_trend():
    limit = min(int(request.args.get("limit", 20)), 100)
    return jsonify(get_risk_trend(limit=limit))


# ---------------------------------------------------------------- background scheduler
def _scheduler_loop(interval_seconds=30):
    while True:
        try:
            with app.app_context():
                _run_due_schedules()
        except Exception:
            log.exception("Scheduler tick failed")
        time.sleep(interval_seconds)


def start_scheduler():
    if _env_bool("NSX_ENABLE_SCHEDULER", default=True):
        threading.Thread(target=_scheduler_loop, daemon=True, name="nsx-scheduler").start()
        log.info("Scheduler started")


# ---------------------------------------------------------------- startup
with app.app_context():
    try:
        init_database()
    except Exception:
        log.exception("Database initialisation failed; check NSX_DATABASE_URL")

# Started at import time so that gunicorn (which never runs __main__) also runs
# scheduled scans. Tests set NSX_ENABLE_SCHEDULER=false.
start_scheduler()

if __name__ == "__main__":
    host = os.environ.get("NSX_HOST", "0.0.0.0")
    port = int(os.environ.get("NSX_PORT", "5000"))
    log.info("NetSecureX on http://%s:%s (database: %s)", host, port,
             app.config["SQLALCHEMY_DATABASE_URI"].split("://")[0])
    app.run(debug=DEBUG_MODE, host=host, port=port)
