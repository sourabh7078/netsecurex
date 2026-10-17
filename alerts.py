"""
NetSecureX - Alerts for new Critical findings

Two optional channels, both configured through environment variables:

  Webhook:  NSX_ALERT_WEBHOOK_URL
            Receives a JSON POST with the alert payload.

  E-mail:   NSX_ALERT_EMAIL_TO  (recipient; required to enable e-mail)
            NSX_SMTP_HOST, NSX_SMTP_PORT (default 587)
            NSX_SMTP_USER, NSX_SMTP_PASSWORD (optional, for login)
            NSX_SMTP_FROM (default: the SMTP user or netsecurex@localhost)
            NSX_SMTP_STARTTLS (default true)

dispatch() never raises. An alert that cannot be delivered is logged, and
the scan that produced it still completes.
"""

import json
import logging
import os
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage

log = logging.getLogger("netsecurex.alerts")


def _env(name, default=""):
    return os.environ.get(name, default)


def build_payload(target, scan_id, findings):
    return {
        "event": "new_critical_findings",
        "target": target,
        "scan_id": scan_id,
        "count": len(findings),
        "findings": findings,
    }


def _plain_text(payload):
    lines = [
        f"NetSecureX found {payload['count']} new Critical finding(s) on {payload['target']} "
        f"(scan #{payload['scan_id']}).",
        "",
    ]
    for f in payload["findings"]:
        lines.append(f"- {f['ip']} port {f['port']} ({f['service']}): {f['cve']} "
                     f"CVSS {f['cvss']} [{f.get('source', 'offline-db')}]")
    lines.append("")
    lines.append("Only scan systems you own or are authorized to test.")
    return "\n".join(lines)


def send_webhook(url, payload, timeout=5):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "NetSecureX/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status


def send_email(payload, to_addr, smtp_host, smtp_port, user, password, from_addr,
               starttls=True, timeout=10):
    message = EmailMessage()
    message["Subject"] = f"NetSecureX: {payload['count']} new Critical finding(s) on {payload['target']}"
    message["From"] = from_addr
    message["To"] = to_addr
    message.set_content(_plain_text(payload))
    with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout) as server:
        if starttls:
            server.starttls(context=ssl.create_default_context())
        if user:
            server.login(user, password)
        server.send_message(message)


def dispatch(payload):
    """Send the payload to every configured channel. Returns the list of
    channels that succeeded. Never raises."""
    sent = []

    url = _env("NSX_ALERT_WEBHOOK_URL")
    if url:
        try:
            send_webhook(url, payload)
            sent.append("webhook")
        except Exception:
            log.exception("Webhook alert failed for scan #%s", payload.get("scan_id"))

    to_addr = _env("NSX_ALERT_EMAIL_TO")
    smtp_host = _env("NSX_SMTP_HOST")
    if to_addr and smtp_host:
        try:
            user = _env("NSX_SMTP_USER")
            send_email(
                payload,
                to_addr=to_addr,
                smtp_host=smtp_host,
                smtp_port=int(_env("NSX_SMTP_PORT", "587")),
                user=user,
                password=_env("NSX_SMTP_PASSWORD"),
                from_addr=_env("NSX_SMTP_FROM", user or "netsecurex@localhost"),
                starttls=_env("NSX_SMTP_STARTTLS", "true").strip().lower() in ("1", "true", "yes", "on"),
            )
            sent.append("email")
        except Exception:
            log.exception("E-mail alert failed for scan #%s", payload.get("scan_id"))

    return sent
