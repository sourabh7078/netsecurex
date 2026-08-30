"""
NetSecureX - Risk Scoring Engine

Formula (per host):
    host_risk = SUM(vuln_cvss_score * exposure_weight) / normalization_factor

    exposure_weight = 1.5  if port is considered "internet-facing"
                       1.0  otherwise (internal-only service)
    normalization_factor = number of open ports on the host (capped at 1 minimum)
                            -- keeps hosts with many benign open ports from being
                               unfairly penalised vs. a host with one severe issue.

Severity bands (applied to the final normalized host score, 0-10 scale):
    Critical : 9.0 - 10.0
    High     : 7.0 - 8.9
    Medium   : 4.0 - 6.9
    Low      : 0.0 - 3.9
"""

from datetime import datetime
from models import db, Host, Port, Vulnerability, RiskScore

# Ports conventionally exposed to the public internet in a typical deployment
INTERNET_FACING_PORTS = {80, 443, 21, 25, 22, 8080, 8443}

EXPOSURE_WEIGHT_PUBLIC = 1.5
EXPOSURE_WEIGHT_INTERNAL = 1.0


def _severity_band(score):
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def compute_host_risk(host_id):
    host = Host.query.get(host_id)
    if not host:
        return None

    weighted_sum = 0.0
    open_port_count = max(len(host.ports), 1)

    for port in host.ports:
        exposure_weight = (
            EXPOSURE_WEIGHT_PUBLIC if port.port_no in INTERNET_FACING_PORTS
            else EXPOSURE_WEIGHT_INTERNAL
        )
        for vuln in port.vulnerabilities:
            weighted_sum += vuln.cvss_score * exposure_weight

    raw_score = weighted_sum / open_port_count
    # Clamp to a 0-10 scale for readability alongside CVSS
    normalized_score = min(raw_score, 10.0)

    risk = RiskScore(
        host_id=host.id,
        score=round(normalized_score, 2),
        category=_severity_band(normalized_score),
        computed_at=datetime.utcnow(),
    )
    db.session.add(risk)
    db.session.commit()
    return risk


def compute_scan_summary(scan_id):
    from models import Scan
    scan = Scan.query.get(scan_id)
    if not scan:
        return None

    summary = {
        "host_count": len(scan.hosts),
        "open_port_count": 0,
        "vuln_count": 0,
        "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "host_rows": [],
        "network_risk_score": 0.0,
    }

    total_host_score = 0.0

    for host in scan.hosts:
        summary["open_port_count"] += len(host.ports)
        host_vulns = []
        for port in host.ports:
            for v in port.vulnerabilities:
                host_vulns.append(v)
                summary["vuln_count"] += 1
                summary["severity_counts"][v.severity] = (
                    summary["severity_counts"].get(v.severity, 0) + 1
                )

        latest = host.latest_risk
        risk_score = latest.score if latest else 0.0
        risk_category = latest.category if latest else "Low"
        total_host_score += risk_score

        summary["host_rows"].append({
            "host": host,
            "risk_score": risk_score,
            "risk_category": risk_category,
            "vuln_count": len(host_vulns),
        })

    if scan.hosts:
        summary["network_risk_score"] = round(total_host_score / len(scan.hosts), 2)

    summary["host_rows"].sort(key=lambda r: r["risk_score"], reverse=True)

    return summary
