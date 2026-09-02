"""
NetSecureX - Nmap/Zenmap-Style Output Formatter

Renders a scan's stored results (hosts, ports, services, OS guess) back out
as classic Nmap terminal-style text -- the same look as Zenmap's "Nmap
Output" tab -- for display in the web dashboard. This is purely a
presentation layer: it re-formats data already collected by scanner.py /
risk_engine.py, it does not perform a second scan.
"""

from datetime import datetime


def _format_port_line(port):
    """One line per port, e.g.:  80/tcp   open   http   Apache httpd 2.4.7"""
    state = port.state or "open"
    service = port.service or "unknown"
    version = f"  {port.version}" if port.version else ""
    return {
        "text": f"{port.port_no}/{port.protocol:<4} {state:<10} {service:<16}{version}",
        "state": state,
    }


def build_nmap_style_output(scan, host_rows):
    """Returns a list of {"text": str, "style": "header"|"open"|"filtered"|
    "closed"|"detail"|"plain"} line dicts -- ready for the template to
    color-code exactly like Zenmap's syntax-highlighted output pane."""
    lines = []

    def add(text, style="plain"):
        lines.append({"text": text, "style": style})

    started = scan.start_time.strftime("%a %b %d %H:%M:%S %Y") if scan.start_time else "unknown"
    add(f"Starting Nmap-style scan at {started}", "detail")
    add(f"NetSecureX scan report for target: {scan.target_range}", "detail")
    add("", "plain")

    if not host_rows:
        add("No live hosts found in the specified range.", "filtered")
        return lines

    for row in host_rows:
        host = row["host"]
        label = f"{host.hostname} ({host.ip})" if host.hostname else host.ip
        add(f"Nmap-style scan report for {label}", "header")
        add("Host is up.", "open")
        add("", "plain")

        if host.ports:
            add(f"{'PORT':<11}{'STATE':<11}{'SERVICE':<17}VERSION", "detail")
            for port in host.ports:
                pl = _format_port_line(port)
                style = "open" if pl["state"] == "open" else (
                    "filtered" if pl["state"] == "filtered" else "closed"
                )
                add(pl["text"], style)
        else:
            add("No open ports found among scanned ports.", "filtered")

        add("", "plain")
        add(f"Device type: general purpose", "detail")
        add(f"Running: {host.os_guess}", "detail")
        add(f"OS details: {host.os_guess}", "detail")

        latest = host.latest_risk
        if latest:
            add(f"Risk Score: {latest.score} / 10  ({latest.category})", "detail")

        vuln_count = sum(len(p.vulnerabilities) for p in host.ports)
        if vuln_count:
            add(f"Vulnerabilities matched: {vuln_count} finding(s) -- see report for CVE detail.", "filtered")

        add("", "plain")

    add(f"NetSecureX done: {len(host_rows)} host(s) scanned.", "detail")
    if scan.duration_seconds:
        add(f"Scan completed in {scan.duration_seconds:.2f} seconds.", "detail")

    return lines
