"""
Tests for scanner.py -- vulnerability matching, OS guessing, and version
parsing. These are pure functions with no Flask app or database dependency,
so they run fast and in complete isolation.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scanner  # noqa: E402


class TestVulnDatabase:
    def test_loads_successfully(self):
        assert len(scanner.VULN_DB) > 0

    def test_every_signature_has_required_fields(self):
        required = {"service", "cve_id", "cvss_score", "severity", "description"}
        for sig in scanner.VULN_DB:
            missing = required - sig.keys()
            assert not missing, f"Signature missing fields {missing}: {sig}"

    def test_severity_values_are_valid(self):
        valid = {"Critical", "High", "Medium", "Low"}
        for sig in scanner.VULN_DB:
            assert sig["severity"] in valid


class TestMatchVulnerabilities:
    def test_vsftpd_backdoor_detected_as_critical(self):
        matches = scanner.match_vulnerabilities("ftp", "vsFTPd 2.3.4", 21)
        cve_ids = [m["cve_id"] for m in matches]
        assert "CVE-2011-2523" in cve_ids
        backdoor = next(m for m in matches if m["cve_id"] == "CVE-2011-2523")
        assert backdoor["severity"] == "Critical"

    def test_generic_ftp_still_flagged_medium(self):
        matches = scanner.match_vulnerabilities("ftp", "ProFTPD 1.3.5", 21)
        assert any(m["severity"] in ("Medium", "Low") for m in matches)

    def test_telnet_always_flagged_even_with_no_version(self):
        matches = scanner.match_vulnerabilities("telnet", "", 23)
        assert len(matches) >= 1
        assert matches[0]["severity"] in ("Medium", "High")

    def test_unmatched_service_returns_empty(self):
        matches = scanner.match_vulnerabilities("some-made-up-service", "1.0", 9999)
        assert matches == []

    def test_samba_usermap_script_critical(self):
        matches = scanner.match_vulnerabilities("microsoft-ds", "Samba 3.0.20-Debian", 445)
        cve_ids = [m["cve_id"] for m in matches]
        assert "CVE-2007-2447" in cve_ids

    def test_ingreslock_backdoor_always_critical(self):
        matches = scanner.match_vulnerabilities("ingreslock", "", 1524)
        assert len(matches) == 1
        assert matches[0]["severity"] == "Critical"

    def test_port_mismatch_does_not_match(self):
        # A signature scoped to port 1524 should not fire if somehow the
        # service name matched on a different port.
        matches = scanner.match_vulnerabilities("ingreslock", "", 9999)
        assert matches == []


class TestGuessOS:
    def test_rdp_port_guesses_windows(self):
        ports = [{"port": 3389, "service": "rdp", "banner": ""}]
        result = scanner.guess_os("10.0.0.5", ports)
        assert "Windows" in result

    def test_openssh_banner_guesses_linux(self):
        ports = [{"port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_7.2p2"}]
        result = scanner.guess_os("10.0.0.6", ports)
        assert "Linux" in result

    def test_smb_ports_guess_windows(self):
        ports = [
            {"port": 445, "service": "microsoft-ds", "banner": ""},
            {"port": 139, "service": "netbios-ssn", "banner": ""},
        ]
        result = scanner.guess_os("10.0.0.7", ports)
        assert "Windows" in result

    def test_no_useful_signals_returns_unknown(self):
        ports = [{"port": 9999, "service": "unknown", "banner": ""}]
        result = scanner.guess_os("10.0.0.8", ports)
        assert result == "Unknown"


class TestServiceMap:
    def test_common_ports_are_named(self):
        assert scanner.SERVICE_MAP[80] == "http"
        assert scanner.SERVICE_MAP[22] == "ssh"
        assert scanner.SERVICE_MAP[1524] == "ingreslock"
        assert scanner.SERVICE_MAP[3632] == "distccd"

    def test_new_service_ports_are_named(self):
        assert scanner.SERVICE_MAP[6379] == "redis"
        assert scanner.SERVICE_MAP[27017] == "mongodb"
        assert scanner.SERVICE_MAP[9200] == "elasticsearch"
        assert scanner.SERVICE_MAP[2375] == "docker-api"
        assert scanner.SERVICE_MAP[5984] == "couchdb"

    def test_common_ports_list_matches_service_map_coverage(self):
        # Every port we scan by default should have a human-readable name,
        # or the dashboard will show "unknown" for well-known services.
        unnamed = [p for p in scanner.COMMON_PORTS if p not in scanner.SERVICE_MAP]
        assert unnamed == [], f"Ports with no SERVICE_MAP entry: {unnamed}"


class TestNewVulnSignatures:
    def test_redis_unauthenticated_critical(self):
        matches = scanner.match_vulnerabilities("redis", "", 6379)
        assert any(m["severity"] == "Critical" for m in matches)

    def test_docker_api_exposed_critical(self):
        matches = scanner.match_vulnerabilities("docker-api", "", 2375)
        assert any(m["severity"] == "Critical" for m in matches)

    def test_jenkins_matches_on_http_proxy_service_with_version(self):
        # Jenkins commonly runs on 8080, which SERVICE_MAP names "http-proxy" --
        # the signature must target that service name, not a bespoke "jenkins" one.
        matches = scanner.match_vulnerabilities("http-proxy", "Jenkins 2.440", 8080)
        assert any(m["cve_id"] == "CVE-2024-23897" for m in matches)

    def test_mongodb_no_auth_flagged(self):
        matches = scanner.match_vulnerabilities("mongodb", "", 27017)
        assert len(matches) >= 1


class TestRunScanConcurrency:
    """Covers the multi-host parallel scanning path added for CIDR ranges
    (see scanner.run_scan). Network calls are mocked so these run offline."""

    def test_single_host_uses_fine_grained_progress(self, monkeypatch):
        progress_calls = []
        monkeypatch.setattr(scanner, "discover_hosts", lambda target, progress_cb=None: ["10.0.0.1"])
        monkeypatch.setattr(scanner, "scan_ports", lambda ip, ports=None, progress_cb=None,
                             progress_offset=30, progress_span=60: [])
        monkeypatch.setattr(scanner, "guess_os", lambda ip, ports: "Unknown")

        result = scanner.run_scan("10.0.0.1", progress_cb=progress_calls.append)

        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["ip"] == "10.0.0.1"
        assert 100 in progress_calls

    def test_multi_host_scans_all_and_sorts_by_ip(self, monkeypatch):
        monkeypatch.setattr(scanner, "discover_hosts",
                             lambda target, progress_cb=None: ["10.0.0.3", "10.0.0.1", "10.0.0.2"])
        monkeypatch.setattr(scanner, "_scan_one_host",
                             lambda ip, ports: {"ip": ip, "hostname": "", "os_guess": "Unknown", "ports": []})

        result = scanner.run_scan("10.0.0.0/24")

        ips = [h["ip"] for h in result["hosts"]]
        assert ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        assert len(result["hosts"]) == 3

    def test_multi_host_reports_progress_to_completion(self, monkeypatch):
        progress_calls = []
        monkeypatch.setattr(scanner, "discover_hosts",
                             lambda target, progress_cb=None: ["10.0.0.1", "10.0.0.2"])
        monkeypatch.setattr(scanner, "_scan_one_host",
                             lambda ip, ports: {"ip": ip, "hostname": "", "os_guess": "Unknown", "ports": []})

        scanner.run_scan("10.0.0.0/30", progress_cb=progress_calls.append)

        assert 100 in progress_calls

    def test_no_live_hosts_returns_empty_and_completes_progress(self, monkeypatch):
        progress_calls = []
        monkeypatch.setattr(scanner, "discover_hosts", lambda target, progress_cb=None: [])

        result = scanner.run_scan("10.0.0.0/24", progress_cb=progress_calls.append)

        assert result["hosts"] == []
        assert 100 in progress_calls
