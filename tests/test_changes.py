"""Change detection between scans, on plain snapshots and on stand-in objects."""
from changes import snapshot_scan, diff_snapshots, find_new_critical


def _snap(hosts):
    return {"scan_id": 0, "target": "t", "hosts": hosts}


def _port(service, findings=None):
    return {"service": service, "findings": findings or {}}


def _finding(cve, severity, cvss=9.0, source="offline-db"):
    return {"cve": cve, "severity": severity, "cvss": cvss, "source": source}


BEFORE = _snap({
    "10.0.0.1": {"risk": 5.0, "ports": {
        "21/tcp": _port("ftp", {"CVE-A|High": _finding("CVE-A", "High", 7.5)}),
        "80/tcp": _port("http"),
    }},
    "10.0.0.2": {"risk": 2.0, "ports": {"22/tcp": _port("ssh")}},
})

AFTER = _snap({
    "10.0.0.1": {"risk": 9.8, "ports": {
        "21/tcp": _port("ftp", {"CVE-B|Critical": _finding("CVE-B", "Critical", 9.8, "live-nvd")}),
        "3306/tcp": _port("mysql"),
    }},
    "10.0.0.3": {"risk": 1.0, "ports": {}},
})


def test_diff_detects_new_and_removed_hosts():
    d = diff_snapshots(BEFORE, AFTER)
    assert d["new_hosts"] == ["10.0.0.3"]
    assert d["removed_hosts"] == ["10.0.0.2"]


def test_diff_detects_port_changes():
    d = diff_snapshots(BEFORE, AFTER)
    assert {"ip": "10.0.0.1", "port": "3306/tcp", "service": "mysql"} in d["new_ports"]
    assert {"ip": "10.0.0.1", "port": "80/tcp", "service": "http"} in d["closed_ports"]


def test_diff_detects_finding_changes():
    d = diff_snapshots(BEFORE, AFTER)
    assert [f["cve"] for f in d["new_findings"]] == ["CVE-B"]
    assert [f["cve"] for f in d["resolved_findings"]] == ["CVE-A"]


def test_diff_detects_risk_change():
    d = diff_snapshots(BEFORE, AFTER)
    assert {"ip": "10.0.0.1", "before": 5.0, "after": 9.8} in d["risk_changes"]


def test_identical_snapshots_have_no_changes():
    d = diff_snapshots(BEFORE, BEFORE)
    assert all(not v for v in d.values())


def test_new_findings_on_a_new_port_are_reported():
    before = _snap({"10.0.0.1": {"risk": 0, "ports": {}}})
    after = _snap({"10.0.0.1": {"risk": 0, "ports": {
        "445/tcp": _port("microsoft-ds", {"CVE-X|High": _finding("CVE-X", "High")})}}})
    d = diff_snapshots(before, after)
    assert [f["cve"] for f in d["new_findings"]] == ["CVE-X"]


def test_find_new_critical_ignores_existing_criticals():
    before = _snap({"10.0.0.1": {"risk": 9, "ports": {
        "21/tcp": _port("ftp", {"CVE-Z|Critical": _finding("CVE-Z", "Critical")})}}})
    after = _snap({"10.0.0.1": {"risk": 9, "ports": {
        "21/tcp": _port("ftp", {"CVE-Z|Critical": _finding("CVE-Z", "Critical"),
                                "CVE-Y|Critical": _finding("CVE-Y", "Critical")})}}})
    new = find_new_critical(before, after)
    assert [n["cve"] for n in new] == ["CVE-Y"]


def test_find_new_critical_with_no_previous_scan_returns_all_criticals():
    new = find_new_critical(None, AFTER)
    assert [n["cve"] for n in new] == ["CVE-B"]
    assert new[0]["source"] == "live-nvd"


def test_find_new_critical_ignores_high_and_medium():
    after = _snap({"10.0.0.1": {"risk": 5, "ports": {
        "21/tcp": _port("ftp", {"CVE-H|High": _finding("CVE-H", "High")})}}})
    assert find_new_critical(None, after) == []


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_snapshot_scan_reads_orm_like_objects():
    v = _Obj(cve_id="CVE-Q", severity="Critical", cvss_score=9.8, source="live-nvd")
    port = _Obj(port_no=21, protocol="tcp", service="ftp", vulnerabilities=[v])
    risk = _Obj(score=9.8)
    host = _Obj(ip="10.0.0.1", ports=[port], latest_risk=risk)
    scan = _Obj(id=7, target_range="10.0.0.0/30", hosts=[host])
    snap = snapshot_scan(scan)
    assert snap["hosts"]["10.0.0.1"]["risk"] == 9.8
    assert "21/tcp" in snap["hosts"]["10.0.0.1"]["ports"]
    assert snap["hosts"]["10.0.0.1"]["ports"]["21/tcp"]["findings"]["CVE-Q|Critical"]["source"] == "live-nvd"
