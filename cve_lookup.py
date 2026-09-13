"""
NetSecureX - Live CVE Lookup (Optional)

Supplements the offline vuln_db.json signatures with live results from the
NVD (National Vulnerability Database) REST API, when explicitly enabled.
Uses only the Python standard library (urllib) -- no extra pip dependency.

Enable with:
    NSX_USE_LIVE_CVE=true

Optional tuning:
    NSX_NVD_API_KEY       Free from https://nvd.nist.gov/developers/request-an-api-key
                          Raises the NVD rate limit from 5 requests/30s to 50/30s.
    NSX_NVD_TIMEOUT       Per-request timeout in seconds. Default: 5
    NSX_NVD_CACHE_TTL     How long (seconds) to cache a lookup before re-querying.
                          Default: 3600 (1 hour) -- avoids hammering NVD with the
                          same service/version query across repeated scans.

Design notes:
  - This is strictly additive: the offline vuln_db.json signatures always run
    first and are never removed. Live results are merged in on top, deduped
    by CVE ID, and clearly tagged with "source": "live-nvd" so the report and
    dashboard can (optionally) distinguish them.
  - Every failure mode (disabled, no network, timeout, rate-limited, malformed
    response) returns an empty list rather than raising -- a scan must never
    fail just because the live lookup didn't work. This also means the
    behavior is identical whether you're offline, rate-limited, or simply
    have the feature turned off; callers don't need to care which.
  - Results are cached in memory per (service, version) pair for the lifetime
    of the process, so a single scan hitting the same service on multiple
    hosts only queries NVD once per unique service/version combination.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESULTS = 3


def _env_bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


USE_LIVE_CVE = _env_bool("NSX_USE_LIVE_CVE", default=False)
NVD_API_KEY = os.environ.get("NSX_NVD_API_KEY", "")
REQUEST_TIMEOUT = float(os.environ.get("NSX_NVD_TIMEOUT", "5"))
CACHE_TTL_SECONDS = int(os.environ.get("NSX_NVD_CACHE_TTL", "3600"))

# In-memory cache: "service|version" (lowercased) -> (cached_at_epoch, results)
_cache = {}


def _cache_get(key):
    entry = _cache.get(key)
    if not entry:
        return None
    cached_at, data = entry
    if time.time() - cached_at > CACHE_TTL_SECONDS:
        _cache.pop(key, None)
        return None
    return data


def _cache_set(key, data):
    _cache[key] = (time.time(), data)


def _score_to_severity(score):
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _extract_score(metrics):
    """NVD returns CVSS under one of several keys depending on which version
    of the scoring system was used for that CVE. Prefer the newest available."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError, ValueError):
                continue
    return 0.0


def _extract_description(cve):
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")[:400]
    return ""


def lookup_live_cves(service, version):
    """Query NVD for CVEs matching a service/version keyword search.

    Returns a list of dicts in the same shape as offline vuln_db.json
    entries (cve_id, cvss_score, description, severity), each additionally
    tagged with "source": "live-nvd". Returns [] on any failure or if the
    feature is disabled -- callers should treat this exactly like "no
    additional matches found", never as an error condition.
    """
    if not USE_LIVE_CVE:
        return []

    keyword = f"{service} {version}".strip()
    if not keyword or not version:
        # Querying on service name alone (e.g. just "http") is too broad and
        # burns rate-limit budget on noise -- require some version signal.
        return []

    cache_key = keyword.lower()
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    params = {"keywordSearch": keyword, "resultsPerPage": str(MAX_RESULTS)}
    url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": "NetSecureX/1.0 (academic project; NVD API client)"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            ValueError, OSError):
        # Covers: no network, DNS failure, connection timeout, HTTP 403/429
        # (rate limit), and malformed/non-JSON responses. Fail quiet, fall
        # back to offline-only results for this service/version.
        return []

    results = []
    for item in payload.get("vulnerabilities", [])[:MAX_RESULTS]:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        score = _extract_score(cve.get("metrics", {}))
        results.append({
            "cve_id": cve_id,
            "cvss_score": score,
            "description": _extract_description(cve) or "No description available from NVD.",
            "severity": _score_to_severity(score),
            "source": "live-nvd",
        })

    _cache_set(cache_key, results)
    return results


def merge_with_offline(offline_matches, service, version):
    """Combine offline signature matches with live NVD results, deduped by
    CVE ID (offline entries win on conflict, since they're curated for this
    project's demo targets). Offline-only entries are tagged "source":
    "offline-db" for consistency with the live results' tagging."""
    for m in offline_matches:
        m.setdefault("source", "offline-db")

    if not USE_LIVE_CVE:
        return offline_matches

    live_matches = lookup_live_cves(service, version)
    known_ids = {m["cve_id"] for m in offline_matches if m.get("cve_id") not in (None, "N/A")}

    combined = list(offline_matches)
    for lv in live_matches:
        if lv["cve_id"] not in known_ids:
            combined.append(lv)
            known_ids.add(lv["cve_id"])

    return combined
