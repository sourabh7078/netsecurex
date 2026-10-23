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

import cve_lookup
from udp_probe import udp_port_results

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

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 512, 513, 514, 993, 995, 1099, 1524, 1723,
    2049, 3000, 3306, 3389, 3632, 5432, 5900, 5984, 6000,
    6379, 6667, 6697, 8009, 8080, 8180, 8443, 9090, 9200,
    9418, 11211, 27017, 2375,
]
# The 512/513/514/1099/1524/2049/3632/5432/6000/6667/6697/8009/8180 additions
# above cover Metasploitable2's full known-vulnerable service set (rexec/
# rlogin/rsh, Java RMI, the "ingreslock" root-shell backdoor, NFS, distccd,
# PostgreSQL, X11, UnrealIRCd, AJP, and the Tomcat manager) so a demo scan
# against it surfaces the classic teaching CVEs out of the box.
#
# 3000/5984/6379/9090/9200/9418/11211/27017/2375 extend coverage to common
# modern misconfigurations seen in real-world exposures: Grafana, CouchDB,
# Redis, Prometheus, Elasticsearch, the git daemon protocol, Memcached,
# MongoDB, and the unauthenticated Docker Engine API.
#
# Note: SNMP (default port 161) is UDP-based; this scanner is TCP-only, so
# it isn't included here even though vuln_db.json carries an SNMP signature
# for documentation/extensibility -- UDP scanning is tracked as future scope.

CONNECT_TIMEOUT = float(os.environ.get("NSX_CONNECT_TIMEOUT", "0.6"))
BANNER_TIMEOUT = float(os.environ.get("NSX_BANNER_TIMEOUT", "1.0"))
MAX_WORKERS_HOSTS = int(os.environ.get("NSX_MAX_WORKERS_HOSTS", "50"))
MAX_WORKERS_PORTS = int(os.environ.get("NSX_MAX_WORKERS_PORTS", "100"))
# How many hosts to port-scan CONCURRENTLY when a target expands to multiple
# live hosts (a CIDR range). Each of those concurrent host-scans still uses
# its own internal MAX_WORKERS_PORTS thread pool for that host's ports, so
# total in-flight sockets can reach roughly MAX_CONCURRENT_HOSTS x
# MAX_WORKERS_PORTS -- tune both down together on a resource-constrained
# machine. A single-target scan (one IP, no "/") always uses the original
# fine-grained per-port progress path regardless of this setting.
MAX_CONCURRENT_HOSTS = int(os.environ.get("NSX_MAX_CONCURRENT_HOSTS", "8"))


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
    143: "imap", 443: "https", 445: "microsoft-ds", 512: "exec", 513: "login",
    514: "shell", 993: "imaps", 995: "pop3s", 1099: "java-rmi",
    1524: "ingreslock", 1723: "pptp", 2049: "nfs", 2375: "docker-api",
    3000: "http", 3306: "mysql", 3389: "rdp", 3632: "distccd",
    5432: "postgresql", 5900: "vnc", 5984: "couchdb", 6000: "X11",
    6379: "redis", 6667: "irc", 6697: "ircs", 8009: "ajp13",
    8080: "http-proxy", 8180: "http-tomcat", 8443: "https-alt",
    9090: "http", 9200: "elasticsearch", 9418: "git", 11211: "memcached",
    27017: "mongodb",
    161: "snmp",
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
    """Match a detected service/version/port against vuln_db.json signatures,
    then (if NSX_USE_LIVE_CVE=true) supplement with a live NVD lookup via
    cve_lookup.py. The offline signature match below is completely
    self-contained and always runs first, regardless of network
    availability -- live results are purely additive and deduped by CVE ID."""
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

    return cve_lookup.merge_with_offline(matches, service, version)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _scan_one_host(ip, ports):
    """Scan a single host (Nmap-if-enabled, else pure-Python fallback) and
    return its full result dict, including vulnerability matches. Used by
    both the single-target path and the concurrent multi-host path below --
    no progress_cb here, since per-port progress isn't meaningful once
    several hosts are being scanned in parallel."""
    open_ports, os_guess = None, None

    if USE_NMAP:
        try:
            nmap_result = nmap_scan_host(ip, ports=ports)
            open_ports = nmap_result["ports"]
            os_guess = nmap_result["os_guess"]
        except Exception:
            open_ports, os_guess = None, None

    if open_ports is None:
        open_ports = scan_ports(ip, ports=ports)
        open_ports = sorted(open_ports + udp_port_results(ip), key=lambda p: p["port"])
        os_guess = guess_os(ip, open_ports)

    for p in open_ports:
        p["vulnerabilities"] = match_vulnerabilities(p["service"], p.get("version", ""), p["port"])

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        hostname = ""

    return {"ip": ip, "hostname": hostname, "os_guess": os_guess, "ports": open_ports}


def run_scan(target, ports=None, progress_cb=None):
    """Full pipeline: discovery -> port scan -> banner -> OS guess -> vuln match.

    A single-target scan (one IP/hostname) uses the original sequential path
    with fine-grained per-port progress reporting. A CIDR range that expands
    to multiple live hosts instead scans up to MAX_CONCURRENT_HOSTS of them
    in parallel -- much faster on larger networks -- reporting progress per
    completed host instead of per port.
    """
    def cb(pct):
        if progress_cb:
            progress_cb(min(pct, 99))

    live_hosts = discover_hosts(target, progress_cb=cb)
    results = {"target": target, "hosts": []}

    if not live_hosts:
        if progress_cb:
            progress_cb(100)
        return results

    if len(live_hosts) == 1:
        # Common case (a single IP/hostname target): keep the original
        # fine-grained, per-port progress reporting for a smooth progress bar.
        ip = live_hosts[0]
        open_ports, os_guess = None, None

        if USE_NMAP:
            try:
                nmap_result = nmap_scan_host(ip, ports=ports)
                open_ports = nmap_result["ports"]
                os_guess = nmap_result["os_guess"]
                cb(90)
            except Exception:
                open_ports, os_guess = None, None

        if open_ports is None:
            open_ports = scan_ports(ip, ports=ports, progress_cb=cb, progress_offset=30, progress_span=60)
            open_ports = sorted(open_ports + udp_port_results(ip), key=lambda p: p["port"])
            os_guess = guess_os(ip, open_ports)

        for p in open_ports:
            p["vulnerabilities"] = match_vulnerabilities(p["service"], p.get("version", ""), p["port"])

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            hostname = ""

        results["hosts"].append({"ip": ip, "hostname": hostname, "os_guess": os_guess, "ports": open_ports})

    else:
        # Multiple live hosts (a CIDR range): scan them concurrently rather
        # than one at a time, bounded by MAX_CONCURRENT_HOSTS so a large /22
        # doesn't try to open thousands of sockets at once.
        total = len(live_hosts)
        completed = 0
        lock = threading.Lock()

        def _task(ip):
            return _scan_one_host(ip, ports)

        with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_HOSTS, total)) as executor:
            future_to_ip = {executor.submit(_task, ip): ip for ip in live_hosts}
            for future in as_completed(future_to_ip):
                host_result = future.result()
                results["hosts"].append(host_result)
                with lock:
                    completed += 1
                    cb(30 + int((completed / total) * 60))

        # Concurrent completion order is nondeterministic -- sort back into
        # numeric IP order so results display consistently regardless of
        # which host happened to finish first.
        results["hosts"].sort(key=lambda h: socket.inet_aton(h["ip"]))

    if progress_cb:
        progress_cb(100)

    return results
