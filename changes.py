"""
NetSecureX - Change detection between scans

Two pure helpers:
  snapshot_scan(scan)              -> plain dict describing a scan
  diff_snapshots(before, after)    -> what changed between two snapshots
  find_new_critical(before, after) -> Critical findings that are new

Keeping these functions free of database calls makes them easy to test.
snapshot_scan only reads attributes, so it works on ORM objects or on
simple stand-ins in tests.
"""

CRITICAL = "Critical"


def _finding_key(cve_id, severity):
    return f"{cve_id}|{severity}"


def snapshot_scan(scan):
    """Plain-dict view of a scan: hosts, their risk, their ports and findings."""
    hosts = {}
    for host in scan.hosts:
        latest = host.latest_risk
        ports = {}
        for port in host.ports:
            findings = {}
            for v in port.vulnerabilities:
                findings[_finding_key(v.cve_id, v.severity)] = {
                    "cve": v.cve_id,
                    "severity": v.severity,
                    "cvss": v.cvss_score,
                    "source": getattr(v, "source", "offline-db") or "offline-db",
                }
            ports[f"{port.port_no}/{port.protocol}"] = {
                "service": port.service,
                "findings": findings,
            }
        hosts[host.ip] = {"risk": latest.score if latest else 0.0, "ports": ports}
    return {"scan_id": scan.id, "target": scan.target_range, "hosts": hosts}


def diff_snapshots(before, after):
    """Changes from `before` to `after`. Returns a dict of lists."""
    bh, ah = before["hosts"], after["hosts"]
    result = {
        "new_hosts": sorted(set(ah) - set(bh)),
        "removed_hosts": sorted(set(bh) - set(ah)),
        "new_ports": [],
        "closed_ports": [],
        "new_findings": [],
        "resolved_findings": [],
        "risk_changes": [],
    }

    for ip in sorted(set(ah) & set(bh)):
        bp, ap = bh[ip]["ports"], ah[ip]["ports"]
        for pk in sorted(set(ap) - set(bp)):
            result["new_ports"].append({"ip": ip, "port": pk, "service": ap[pk]["service"]})
            for fk in sorted(ap[pk]["findings"]):
                result["new_findings"].append({"ip": ip, "port": pk, **ap[pk]["findings"][fk]})
        for pk in sorted(set(bp) - set(ap)):
            result["closed_ports"].append({"ip": ip, "port": pk, "service": bp[pk]["service"]})
            for fk in sorted(bp[pk]["findings"]):
                result["resolved_findings"].append({"ip": ip, "port": pk, **bp[pk]["findings"][fk]})
        for pk in sorted(set(ap) & set(bp)):
            bf, af = bp[pk]["findings"], ap[pk]["findings"]
            for fk in sorted(set(af) - set(bf)):
                result["new_findings"].append({"ip": ip, "port": pk, **af[fk]})
            for fk in sorted(set(bf) - set(af)):
                result["resolved_findings"].append({"ip": ip, "port": pk, **bf[fk]})
        if bh[ip]["risk"] != ah[ip]["risk"]:
            result["risk_changes"].append({"ip": ip, "before": bh[ip]["risk"], "after": ah[ip]["risk"]})

    for ip in sorted(set(ah) - set(bh)):
        for pk in sorted(ah[ip]["ports"]):
            result["new_ports"].append({"ip": ip, "port": pk, "service": ah[ip]["ports"][pk]["service"]})
            for fk in sorted(ah[ip]["ports"][pk]["findings"]):
                result["new_findings"].append({"ip": ip, "port": pk, **ah[ip]["ports"][pk]["findings"][fk]})

    return result


def find_new_critical(before, after):
    """Critical findings present in `after` but not in `before`.
    If `before` is None (no earlier scan of this target), every Critical
    finding counts as new."""
    seen = set()
    if before:
        for ip, host in before["hosts"].items():
            for pk, port in host["ports"].items():
                for fk, f in port["findings"].items():
                    if f["severity"] == CRITICAL:
                        seen.add((ip, pk, fk))

    new = []
    for ip, host in after["hosts"].items():
        for pk, port in host["ports"].items():
            for fk, f in port["findings"].items():
                if f["severity"] == CRITICAL and (ip, pk, fk) not in seen:
                    new.append({
                        "ip": ip,
                        "port": pk,
                        "service": port["service"],
                        "cve": f["cve"],
                        "severity": f["severity"],
                        "cvss": f["cvss"],
                        "source": f.get("source", "offline-db"),
                    })
    return sorted(new, key=lambda x: (x["ip"], x["port"], x["cve"]))
