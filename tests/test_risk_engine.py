"""
Tests for risk_engine.py -- CVSS-weighted risk scoring and scan summaries.
Requires the Flask app + database fixtures from conftest.py.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models import db, Scan, Host, Port, Vulnerability  # noqa: E402
from risk_engine import compute_host_risk, compute_scan_summary  # noqa: E402


def _make_scan_with_host(target="192.168.56.101"):
    """Helper: creates a Scan + Host, returns (scan, host) with both
    already committed so they have IDs. Ports/vulns are added by the
    caller before calling compute_host_risk()."""
    scan = Scan(target_range=target, status="running")
    db.session.add(scan)
    db.session.commit()

    host = Host(scan_id=scan.id, ip=target, os_guess="Likely Linux/Unix", status="up")
    db.session.add(host)
    db.session.commit()

    return scan, host


class TestComputeHostRisk:
    def test_single_critical_internet_facing_port(self, flask_app):
        scan, host = _make_scan_with_host()
        port = Port(host_id=host.id, port_no=21, protocol="tcp", service="ftp", state="open")
        db.session.add(port)
        db.session.commit()

        vuln = Vulnerability(port_id=port.id, cve_id="CVE-2011-2523",
                              cvss_score=9.8, severity="Critical",
                              description="vsftpd backdoor")
        db.session.add(vuln)
        db.session.commit()

        risk = compute_host_risk(host.id)

        # host_risk = (9.8 * 1.5) / 1 open port = 14.7, clamped to 10.0
        assert risk.score == 10.0
        assert risk.category == "Critical"

    def test_no_vulnerabilities_scores_zero(self, flask_app):
        scan, host = _make_scan_with_host()
        port = Port(host_id=host.id, port_no=80, protocol="tcp", service="http", state="open")
        db.session.add(port)
        db.session.commit()

        risk = compute_host_risk(host.id)

        assert risk.score == 0.0
        assert risk.category == "Low"

    def test_internal_only_port_uses_lower_exposure_weight(self, flask_app):
        scan, host = _make_scan_with_host()
        # Port 3306 (mysql) is NOT in INTERNET_FACING_PORTS -> weight 1.0
        port = Port(host_id=host.id, port_no=3306, protocol="tcp", service="mysql", state="open")
        db.session.add(port)
        db.session.commit()

        vuln = Vulnerability(port_id=port.id, cve_id="CVE-TEST",
                              cvss_score=8.0, severity="High", description="test")
        db.session.add(vuln)
        db.session.commit()

        risk = compute_host_risk(host.id)

        # (8.0 * 1.0) / 1 = 8.0, not (8.0 * 1.5) = 12.0/clamped-10
        assert risk.score == 8.0
        assert risk.category == "High"

    def test_multiple_open_ports_normalizes_score(self, flask_app):
        scan, host = _make_scan_with_host()
        # Two ports, only one vulnerable -- normalization by port count
        # should keep the score from being as high as a single-port host
        # with the same finding.
        p1 = Port(host_id=host.id, port_no=21, protocol="tcp", service="ftp", state="open")
        p2 = Port(host_id=host.id, port_no=22, protocol="tcp", service="ssh", state="open")
        db.session.add_all([p1, p2])
        db.session.commit()

        vuln = Vulnerability(port_id=p1.id, cve_id="CVE-TEST", cvss_score=8.0,
                              severity="High", description="test")
        db.session.add(vuln)
        db.session.commit()

        risk = compute_host_risk(host.id)

        # (8.0 * 1.5) / 2 open ports = 6.0
        assert risk.score == 6.0
        assert risk.category == "Medium"

    def test_nonexistent_host_returns_none(self, flask_app):
        assert compute_host_risk(999999) is None


class TestComputeScanSummary:
    def test_aggregates_severity_counts_correctly(self, flask_app):
        scan, host = _make_scan_with_host()
        port = Port(host_id=host.id, port_no=21, protocol="tcp", service="ftp", state="open")
        db.session.add(port)
        db.session.commit()

        v1 = Vulnerability(port_id=port.id, cve_id="CVE-1", cvss_score=9.8,
                            severity="Critical", description="a")
        v2 = Vulnerability(port_id=port.id, cve_id="CVE-2", cvss_score=5.0,
                            severity="Medium", description="b")
        db.session.add_all([v1, v2])
        db.session.commit()
        compute_host_risk(host.id)

        summary = compute_scan_summary(scan.id)

        assert summary["host_count"] == 1
        assert summary["open_port_count"] == 1
        assert summary["vuln_count"] == 2
        assert summary["severity_counts"]["Critical"] == 1
        assert summary["severity_counts"]["Medium"] == 1

    def test_host_rows_sorted_by_risk_descending(self, flask_app):
        scan = Scan(target_range="192.168.56.0/24", status="completed")
        db.session.add(scan)
        db.session.commit()

        low_host = Host(scan_id=scan.id, ip="192.168.56.1", os_guess="Unknown", status="up")
        high_host = Host(scan_id=scan.id, ip="192.168.56.2", os_guess="Unknown", status="up")
        db.session.add_all([low_host, high_host])
        db.session.commit()

        low_port = Port(host_id=low_host.id, port_no=80, protocol="tcp", service="http", state="open")
        high_port = Port(host_id=high_host.id, port_no=21, protocol="tcp", service="ftp", state="open")
        db.session.add_all([low_port, high_port])
        db.session.commit()

        high_vuln = Vulnerability(port_id=high_port.id, cve_id="CVE-X", cvss_score=9.8,
                                   severity="Critical", description="critical finding")
        db.session.add(high_vuln)
        db.session.commit()

        compute_host_risk(low_host.id)
        compute_host_risk(high_host.id)

        summary = compute_scan_summary(scan.id)

        assert summary["host_rows"][0]["host"].ip == "192.168.56.2"  # higher risk first
        assert summary["host_rows"][1]["host"].ip == "192.168.56.1"

    def test_nonexistent_scan_returns_none(self, flask_app):
        assert compute_scan_summary(999999) is None
