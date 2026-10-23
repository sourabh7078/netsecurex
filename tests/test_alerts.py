"""Alert payloads and delivery. No real network or mail server is contacted."""
import json

import alerts

PAYLOAD = alerts.build_payload("10.0.0.0/30", 9, [
    {"ip": "10.0.0.1", "port": "21/tcp", "service": "ftp", "cve": "CVE-2011-2523",
     "severity": "Critical", "cvss": 9.8, "source": "offline-db"},
])


def _clear_env(monkeypatch):
    for name in ("NSX_ALERT_WEBHOOK_URL", "NSX_ALERT_EMAIL_TO", "NSX_SMTP_HOST"):
        monkeypatch.delenv(name, raising=False)


def test_payload_shape():
    assert PAYLOAD["event"] == "new_critical_findings"
    assert PAYLOAD["count"] == 1 and PAYLOAD["scan_id"] == 9


def test_plain_text_mentions_target_and_cve():
    text = alerts._plain_text(PAYLOAD)
    assert "10.0.0.0/30" in text and "CVE-2011-2523" in text


def test_dispatch_with_nothing_configured_sends_nothing(monkeypatch):
    _clear_env(monkeypatch)
    assert alerts.dispatch(PAYLOAD) == []


def test_webhook_receives_json(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("NSX_ALERT_WEBHOOK_URL", "https://hooks.example.test/nsx")
    captured = {}

    class _Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode())
        captured["method"] = request.get_method()
        return _Resp()

    monkeypatch.setattr(alerts.urllib.request, "urlopen", fake_urlopen)
    assert alerts.dispatch(PAYLOAD) == ["webhook"]
    assert captured["method"] == "POST"
    assert captured["body"]["count"] == 1


def test_webhook_failure_is_logged_not_raised(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("NSX_ALERT_WEBHOOK_URL", "https://hooks.example.test/down")

    def boom(*a, **k):
        raise OSError("unreachable")

    monkeypatch.setattr(alerts.urllib.request, "urlopen", boom)
    assert alerts.dispatch(PAYLOAD) == []   # no exception escapes


def test_email_sent_when_configured(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("NSX_ALERT_EMAIL_TO", "analyst@example.test")
    monkeypatch.setenv("NSX_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("NSX_SMTP_PORT", "2525")
    monkeypatch.setenv("NSX_SMTP_STARTTLS", "false")
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent["server"] = (host, port)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, context=None): sent["tls"] = True
        def login(self, u, p): sent["login"] = u
        def send_message(self, msg):
            sent["subject"] = msg["Subject"]
            sent["to"] = msg["To"]

    monkeypatch.setattr(alerts.smtplib, "SMTP", FakeSMTP)
    assert alerts.dispatch(PAYLOAD) == ["email"]
    assert sent["server"] == ("smtp.example.test", 2525)
    assert "tls" not in sent                      # STARTTLS disabled by configuration
    assert sent["to"] == "analyst@example.test"
    assert "1 new Critical" in sent["subject"]


def test_email_failure_is_logged_not_raised(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("NSX_ALERT_EMAIL_TO", "a@example.test")
    monkeypatch.setenv("NSX_SMTP_HOST", "smtp.example.test")

    class Broken:
        def __init__(self, *a, **k): raise OSError("refused")

    monkeypatch.setattr(alerts.smtplib, "SMTP", Broken)
    assert alerts.dispatch(PAYLOAD) == []
