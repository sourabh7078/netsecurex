"""Local NVD feed, the feed importer, and the DNS and NTP probes (no network)."""
import struct

import cve_lookup
import udp_probe as u
import importlib.util
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _load_importer():
    spec = importlib.util.spec_from_file_location("import_nvd_feed",
                                                  os.path.join(ROOT, "tools", "import_nvd_feed.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FEED = [
    {"cve_id": "CVE-2021-1111", "cvss_score": 9.8, "severity": "Critical",
     "description": "Example daemon 2.3.4 allows remote command execution."},
    {"cve_id": "CVE-2020-2222", "cvss_score": 5.0, "severity": "Medium",
     "description": "Example daemon 2.9.0 leaks memory."},
]


def test_feed_matches_by_version_words(monkeypatch):
    monkeypatch.setattr(cve_lookup, "_feed", [])
    cve_lookup.set_feed(FEED)
    found = cve_lookup.feed_matches("example", "Example daemon 2.3.4")
    assert [f["cve_id"] for f in found] == ["CVE-2021-1111"]
    assert found[0]["source"] == "nvd-feed"


def test_feed_requires_a_version(monkeypatch):
    cve_lookup.set_feed(FEED)
    assert cve_lookup.feed_matches("example", "") == []


def test_merge_adds_feed_result_and_keeps_offline_first(monkeypatch):
    monkeypatch.setattr(cve_lookup, "USE_LIVE_CVE", False)
    cve_lookup.set_feed(FEED)
    offline = [{"cve_id": "CVE-OFFLINE", "cvss_score": 7.5, "severity": "High", "description": "x"}]
    merged = cve_lookup.merge_with_offline(list(offline), "example", "Example daemon 2.3.4")
    assert [m["cve_id"] for m in merged] == ["CVE-OFFLINE", "CVE-2021-1111"]
    assert merged[0]["source"] == "offline-db" and merged[1]["source"] == "nvd-feed"


def test_merge_deduplicates_feed_against_offline(monkeypatch):
    monkeypatch.setattr(cve_lookup, "USE_LIVE_CVE", False)
    cve_lookup.set_feed(FEED)
    offline = [{"cve_id": "CVE-2021-1111", "cvss_score": 9.8, "severity": "Critical", "description": "x"}]
    merged = cve_lookup.merge_with_offline(list(offline), "example", "Example daemon 2.3.4")
    assert [m["cve_id"] for m in merged] == ["CVE-2021-1111"]


def test_importer_converts_nvd_payload():
    importer = _load_importer()
    payload = {"vulnerabilities": [{"cve": {
        "id": "CVE-2024-9999",
        "descriptions": [{"lang": "en", "value": "Example flaw."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}]},
    }}, {"cve": {"descriptions": [], "metrics": {}}}]}
    records = importer.convert(payload)
    assert len(records) == 1
    assert records[0] == {"cve_id": "CVE-2024-9999", "cvss_score": 8.1,
                          "severity": "High", "description": "Example flaw."}


def test_dns_query_bytes_are_well_formed():
    query = u.build_dns_version_query(txid=0x1234)
    assert query[:2] == b"\x12\x34"                     # transaction id
    assert struct.unpack(">H", query[4:6])[0] == 1      # one question
    assert query.endswith(b"\x00\x10\x00\x03")          # TXT, class CH
    assert b"\x07version\x04bind\x00" in query


def _dns_reply(txid, version_text):
    header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    question = b"\x07version\x04bind\x00" + struct.pack(">HH", 16, 3)
    txt = bytes([len(version_text)]) + version_text.encode()
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 16, 3, 0, len(txt)) + txt
    return header + question + answer


def test_dns_reply_parses_version():
    reply = _dns_reply(0x1234, "9.18.1")
    assert u.parse_dns_response(reply, txid=0x1234) == {"version": "9.18.1"}


def test_dns_reply_with_wrong_id_is_ignored():
    assert u.parse_dns_response(_dns_reply(0x9999, "x"), txid=0x1234) is None


def test_dns_garbage_is_ignored():
    assert u.parse_dns_response(b"\x00\x01", txid=0x1234) is None


def test_ntp_request_and_reply():
    req = u.build_ntp_request()
    assert len(req) == 48 and req[0] == 0x1B
    server_reply = bytes([0x1C, 2]) + b"\x00" * 46      # mode 4 (server), stratum 2
    assert u.parse_ntp_response(server_reply) == {"stratum": 2}
    assert u.parse_ntp_response(req) is None            # a client request is not a reply
    assert u.parse_ntp_response(b"\x1c") is None        # too short
