"""
Convert an NVD CVE 2.0 JSON file into the local feed NetSecureX reads.

Download the feed from https://nvd.nist.gov (the CVE API 2.0 JSON, or the
yearly data feeds), then run:

    python tools/import_nvd_feed.py nvd-cve.json netsecurex-feed.json
    set NSX_NVD_FEED_PATH=netsecurex-feed.json        (Windows)
    export NSX_NVD_FEED_PATH=netsecurex-feed.json     (Linux/macOS)

Only the fields NetSecureX uses are kept: identifier, CVSS base score,
severity, and the English description.
"""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from cve_lookup import _extract_score, _score_to_severity, _extract_description  # noqa: E402


def convert(payload):
    """Turn an NVD 2.0 payload (dict) into a list of feed records."""
    records = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        score = _extract_score(cve.get("metrics", {}))
        records.append({
            "cve_id": cve_id,
            "cvss_score": score,
            "severity": _score_to_severity(score),
            "description": _extract_description(cve) or "No description available.",
        })
    return records


def main(argv):
    if len(argv) != 3:
        print("usage: import_nvd_feed.py <nvd-cve.json> <feed-out.json>")
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        records = convert(json.load(fh))
    with open(argv[2], "w", encoding="utf-8") as fh:
        json.dump(records, fh)
    print(f"wrote {len(records)} records to {argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
