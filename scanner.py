"""
NetSecureX - Scanning Engine
Pure-Python implementation (standard library sockets + threading) by default,
so the tool runs without root/administrator privileges or a system Nmap
install. Real Nmap integration (via the python-nmap wrapper) is available as
an optional, auto-detected upgrade: if the 'nmap' binary is on PATH and the
python-nmap package is installed, set NSX_USE_NMAP=true to get Nmap's more
accurate service/version detection and OS fingerprinting (-O), with the
pure-Python scanner used as an automatic per-host fallback if Nmap fails or
lacks the privileges OS detection requires.

Modules implemented here:
  1. Host discovery      -> discover_hosts()
  2. Port scanning        -> scan_ports()            (pure Python)
                              nmap_scan_host()         (optional, real Nmap)
  3. Banner grabbing      -> grab_banner()
  4. OS fingerprinting    -> guess_os()               (heuristic fallback)
                              nmap_scan_host()'s -O    (real fingerprinting)
  5. Vulnerability match  -> match_vulnerabilities() (local signature DB)
"""

import ipaddress
import json
import os
import shutil
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Optional real-Nmap integration
# ---------------------------------------------------------------------------
# Enabled only if ALL of these are true:
#   1. NSX_USE_NMAP=true is set in the environment
#   2. the 'nmap' binary is found on PATH
#   3. the python-nmap package is importable
# Any check failing silently falls back to the pure-Python scanner below, so
# the app never crashes just because Nmap isn't installed.
def _env_bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


_NMAP_REQUESTED = _env_bool("NSX_USE_NMAP", default=False)
_NMAP_BINARY_FOUND = shutil.which("nmap") is not None

try:
    import nmap as _python_nmap
    _NMAP_MODULE_AVAILABLE = True
except ImportError:
    _python_nmap = None
    _NMAP_MODULE_AVAILABLE = False

USE_NMAP = _NMAP_REQUESTED and _NMAP_BINARY_FOUND and _NMAP_MODULE_AVAILABLE

NMAP_OS_TIMEOUT = os.environ.get("NSX_NMAP_TIMEOUT", "30s")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
VULN_DB_PATH = os.path.join(BASE_DIR, "vuln_db.json")

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

CONNECT_TIMEOUT = 0.6
BANNER_TIMEOUT = 1.0
MAX_WORKERS_HOSTS = 50
MAX_WORKERS_PORTS = 100


def _load_vuln_db():
    with open(VULN_DB_PATH, "r") as f:
        return json.load(f)


VULN_DB = _load_vuln_db()


# ---------------------------------------------------------------------------
# 1. Host discovery
# ---------------------------------------------------------------------------

def _tcp_probe_alive(ip, ports=(80, 443, 22, 445, 139)):
    """Fallback 'is host alive' check using TCP connect attempts,
    since raw ICMP sockets usually need root."""
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                result = s.connect_ex((ip, port))
                if result == 0:
                    return True
        except (socket.timeout, socket.error):
            continue
    return False


def discover_hosts(target, progress_cb=None):
    """Expand target (single IP, hostname, or CIDR) into a list of live hosts."""
    live_hosts = []

    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        candidates = [str(ip) for ip in network.hosts()]
    else:
        try:
            resolved = socket.gethostbyname(target)
            candidates = [resolved]
        except socket.gaierror:
            candidates = [target]

    total = len(candidates)
    checked = 0
    lock = threading.Lock()

    def check(ip):
        nonlocal checked
        alive = _tcp_probe_alive(ip)
        with lock:
            checked += 1
            if progress_cb:
                progress_cb(int((checked / total) * 30))  # discovery = first 30%
        return ip, alive

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_HOSTS) as executor:
        futures = [executor.submit(check, ip) for ip in candidates]
        for future in as_completed(futures):
            ip, alive = future.result()
            if alive:
                live_hosts.append(ip)

    return sorted(live_hosts, key=lambda ip: socket.inet_aton(ip))


# ---------------------------------------------------------------------------
# 2 & 3. Port scanning + banner grabbing
# ---------------------------------------------------------------------------

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT)
            s.connect((ip, port))
            # Some services (HTTP) need a nudge before they respond
            if port in (80, 8080, 8443, 443):
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                except OSError:
                    pass
            data = s.recv(256)
            return data.decode(errors="ignore").strip()
    except (socket.timeout, socket.error, OSError):
        return ""


SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1723: "pptp", 3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-proxy",
    8443: "https-alt",
}


def _parse_version(banner, port):
    """Very lightweight version extraction from a raw banner string."""
    if not banner:
        return ""
    banner = banner.split("\n")[0].strip()
    return banner[:120]


def scan_ports(ip, ports=None, progress_cb=None, progress_offset=30, progress_span=60):
    ports = ports or COMMON_PORTS
    open_ports = []
    total = len(ports)
    done = 0
    lock = threading.Lock()

    def check_port(port):
        nonlocal done
        result = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(CONNECT_TIMEOUT)
                if s.connect_ex((ip, port)) == 0:
                    banner = grab_banner(ip, port)
                    service = SERVICE_MAP.get(port, "unknown")
                    version = _parse_version(banner, port)
                    result = {
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service,
                        "version": version,
                        "banner": banner,
                    }
        except (socket.timeout, socket.error, OSError):
            result = None
        with lock:
            done += 1
            if progress_cb:
                pct = progress_offset + int((done / total) * progress_span)
                progress_cb(pct)
        return result

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_PORTS) as executor:
        futures = [executor.submit(check_port, p) for p in ports]
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    return sorted(open_ports, key=lambda p: p["port"])


# ---------------------------------------------------------------------------
# 2b. Real Nmap scanning (optional -- used only when USE_NMAP is True)
# ---------------------------------------------------------------------------

def nmap_scan_host(ip, ports=None):
    """Scan a single host using the real 'nmap' binary via python-nmap,
    returning the same shape as scan_ports() plus an OS guess, so callers
    don't need to know whether Nmap or the pure-Python path produced it.

    Attempts service/version detection (-sV) always, and OS fingerprinting
    (-O) opportunistically -- OS detection requires elevated privileges
    (root/Administrator) and raw-socket access, so it's wrapped separately
    and simply omitted (not fatal) if it fails.

    Raises on any hard failure so the caller (run_scan) can fall back to
    the pure-Python scanner for that host.
    """
    ports = ports or COMMON_PORTS
    port_str = ",".join(str(p) for p in ports)

    scanner = _python_nmap.PortScanner()
    scanner.scan(
        hosts=ip,
        ports=port_str,
        arguments=f"-sV --host-timeout {NMAP_OS_TIMEOUT} -T4",
    )

    if ip not in scanner.all_hosts():
        return {"ports": [], "os_guess": "Unknown"}

    host_info = scanner[ip]
    open_ports = []
    for proto in host_info.all_protocols():
        for port_no, pdata in host_info[proto].items():
            if pdata.get("state") != "open":
                continue
            product = pdata.get("product", "")
            version = pdata.get("version", "")
            version_str = f"{product} {version}".strip() or pdata.get("extrainfo", "")
            open_ports.append({
                "port": int(port_no),
                "protocol": proto,
                "state": "open",
                "service": pdata.get("name", "unknown") or "unknown",
                "version": version_str[:120],
                "banner": version_str[:120],
            })
    open_ports.sort(key=lambda p: p["port"])

    # OS fingerprinting: best-effort, requires -O + privileges. Try it in a
    # separate pass so a permissions failure here doesn't discard the
    # perfectly good port results gathered above.
    os_guess = "Unknown"
    try:
        os_scanner = _python_nmap.PortScanner()
        os_scanner.scan(hosts=ip, arguments=f"-O --host-timeout {NMAP_OS_TIMEOUT}")
        matches = os_scanner[ip].get("osmatch", []) if ip in os_scanner.all_hosts() else []
        if matches:
            os_guess = matches[0].get("name", "Unknown")
    except Exception:
        # Common without root/Administrator privileges -- not fatal.
        os_guess = "Unknown (requires elevated privileges for -O)"

    return {"ports": open_ports, "os_guess": os_guess}


# ---------------------------------------------------------------------------
# 4. OS fingerprinting (best-effort heuristic, no raw sockets required)
# ---------------------------------------------------------------------------

def guess_os(ip, open_ports):
    """Heuristic OS guess based on open port fingerprints & banners.
    This is intentionally conservative -- real OS fingerprinting (Nmap -O)
    needs raw sockets / root, out of scope for the pure-Python fallback."""
    service_names = {p["service"] for p in open_ports}
    banners = " ".join(p.get("banner", "") for p in open_ports).lower()

    if 3389 in [p["port"] for p in open_ports] or "microsoft-ds" in service_names:
        return "Likely Windows"
    if "openssh" in banners:
        return "Likely Linux/Unix"
    if 445 in [p["port"] for p in open_ports] and 139 in [p["port"] for p in open_ports]:
        return "Likely Windows (SMB)"
    if 22 in [p["port"] for p in open_ports]:
        return "Likely Linux/Unix"
    return "Unknown"


# ---------------------------------------------------------------------------
# 5. Vulnerability matching against local signature DB
# ---------------------------------------------------------------------------

def match_vulnerabilities(service, version, port):
    """Match a detected service/version/port against vuln_db.json signatures.
    Signature match is substring-based on service name and, if present,
    a version-fragment; this keeps the demo self-contained (no live CVE
    API dependency) while remaining easy to extend with a real NVD feed."""
    matches = []
    banner_lower = (version or "").lower()

    for sig in VULN_DB:
        if sig["service"].lower() != service.lower():
            continue
        version_fragment = sig.get("version_contains", "")
        port_match = sig.get("port") in (None, port)
        if not port_match:
            continue
        if version_fragment and version_fragment.lower() not in banner_lower:
            # Signature requires a specific version substring that wasn't seen
            continue
        matches.append({
            "cve_id": sig["cve_id"],
            "cvss_score": sig["cvss_score"],
            "description": sig["description"],
            "severity": sig["severity"],
        })

    # Always flag plaintext/legacy protocols as at least a Low/Medium finding
    if service in ("telnet", "ftp") and not matches:
        matches.append({
            "cve_id": "N/A",
            "cvss_score": 5.0,
            "description": f"{service.upper()} transmits credentials/data in cleartext.",
            "severity": "Medium",
        })

    return matches


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_scan(target, ports=None, progress_cb=None):
    """Full pipeline: discovery -> port scan -> banner -> OS guess -> vuln match."""
    def cb(pct):
        if progress_cb:
            progress_cb(min(pct, 99))

    live_hosts = discover_hosts(target, progress_cb=cb)
    results = {"target": target, "hosts": []}

    if not live_hosts:
        if progress_cb:
            progress_cb(100)
        return results

    per_host_span = 60 / max(len(live_hosts), 1)

    for idx, ip in enumerate(live_hosts):
        offset = 30 + idx * per_host_span

        open_ports, os_guess = None, None

        if USE_NMAP:
            try:
                nmap_result = nmap_scan_host(ip, ports=ports)
                open_ports = nmap_result["ports"]
                os_guess = nmap_result["os_guess"]
                if progress_cb:
                    cb(int(offset + per_host_span))
            except Exception:
                # Real Nmap failed for this host (not installed correctly,
                # permissions, host unreachable via Nmap, etc.) -- fall back
                # to the pure-Python scanner below rather than losing the host.
                open_ports, os_guess = None, None

        if open_ports is None:
            open_ports = scan_ports(
                ip, ports=ports, progress_cb=cb,
                progress_offset=int(offset), progress_span=int(per_host_span),
            )
            os_guess = guess_os(ip, open_ports)

        for p in open_ports:
            p["vulnerabilities"] = match_vulnerabilities(p["service"], p.get("version", ""), p["port"])

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            hostname = ""

        results["hosts"].append({
            "ip": ip,
            "hostname": hostname,
            "os_guess": os_guess,
            "ports": open_ports,
        })

    if progress_cb:
        progress_cb(100)

    return results
