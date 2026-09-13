"""
Tests for cve_lookup.py. NSX_USE_LIVE_CVE is disabled by default in the test
environment, so these tests verify the safe-by-default behavior and the
pure helper functions -- they deliberately do NOT make real network calls.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cve_lookup  # noqa: E402


class TestDisabledByDefault:
    def test_feature_flag_is_off_by_default(self):
        # conftest.py does not set NSX_USE_LIVE_CVE, so it must default False.
        assert cve_lookup.USE_LIVE_CVE is False

    def test_lookup_returns_empty_when_disabled(self):
        result = cve_lookup.lookup_live_cves("ftp", "vsFTPd 2.3.4")
        assert result == []

    def test_merge_passes_through_offline_matches_unchanged_when_disabled(self):
        offline = [{"cve_id": "CVE-2011-2523", "cvss_score": 9.8,
                    "severity": "Critical", "description": "backdoor"}]
        result = cve_lookup.merge_with_offline(offline, "ftp", "vsFTPd 2.3.4")
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2011-2523"
        assert result[0]["source"] == "offline-db"  # tagged even when live is off


class TestScoreToSeverity:
    def test_critical_boundary(self):
        assert cve_lookup._score_to_severity(9.0) == "Critical"
        assert cve_lookup._score_to_severity(10.0) == "Critical"

    def test_high_boundary(self):
        assert cve_lookup._score_to_severity(7.0) == "High"
        assert cve_lookup._score_to_severity(8.9) == "High"

    def test_medium_boundary(self):
        assert cve_lookup._score_to_severity(4.0) == "Medium"
        assert cve_lookup._score_to_severity(6.9) == "Medium"

    def test_low_boundary(self):
        assert cve_lookup._score_to_severity(0.0) == "Low"
        assert cve_lookup._score_to_severity(3.9) == "Low"


class TestCache:
    def test_cache_roundtrip(self):
        cve_lookup._cache_set("test-key", [{"cve_id": "CVE-TEST"}])
        result = cve_lookup._cache_get("test-key")
        assert result == [{"cve_id": "CVE-TEST"}]

    def test_cache_miss_returns_none(self):
        assert cve_lookup._cache_get("never-set-this-key") is None

    def test_cache_expiry(self, monkeypatch):
        import time
        cve_lookup._cache_set("expiring-key", [{"cve_id": "CVE-OLD"}])
        # Simulate time passing beyond CACHE_TTL_SECONDS. Capture the real
        # time.time() first -- patching it in place and then calling it
        # from within its own replacement would recurse infinitely.
        real_now = time.time()
        monkeypatch.setattr(time, "time", lambda: real_now + cve_lookup.CACHE_TTL_SECONDS + 10)
        assert cve_lookup._cache_get("expiring-key") is None


class TestLookupRequiresVersionSignal:
    def test_empty_version_returns_empty_even_if_enabled(self, monkeypatch):
        monkeypatch.setattr(cve_lookup, "USE_LIVE_CVE", True)
        result = cve_lookup.lookup_live_cves("http", "")
        assert result == []
