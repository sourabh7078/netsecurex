# 🛡️ NetSecureX

### Intelligent Network Vulnerability Scanner & Security Dashboard

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-black)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Academic%20Project-orange)

## Overview
NetSecureX is a Flask-based web platform that discovers hosts on an
authorized network, scans for open ports and services, matches findings
against a local vulnerability signature database, computes a CVSS-weighted
risk score, stores full scan history in SQLite, and generates a
professional Word (.docx) security report per scan.

This project extends the earlier **NetGuard** prototype (basic Flask + Nmap
scanner) into a full platform with persistence, risk intelligence, and
automated reporting.

## Features
- **Host Discovery** — TCP-based reachability probing across a single IP, hostname, or CIDR range
- **Multithreaded Port Scanning** — pure Python (stdlib sockets), no root/Nmap binary required
- **Optional Real Nmap Integration** — auto-detected upgrade path for more accurate service/version + OS detection, with automatic per-host fallback to the pure-Python scanner
- **Banner Grabbing & Service Detection** — lightweight fingerprinting of common services
- **Heuristic OS Fingerprinting** — best-effort OS guess from port/banner signatures (or real `-O` fingerprinting when using Nmap)
- **Offline Vulnerability Matching** — local JSON signature DB (`vuln_db.json`), no live API dependency required
- **Optional Live NVD/CVE Lookup** — supplements the offline database with real-time CVE data from the National Vulnerability Database when enabled, with automatic fallback to offline-only results on any network failure
- **CVSS-Weighted Risk Scoring** — per-host and network-wide risk scores with severity bands
- **Persistent Scan History** — SQLite (or MySQL/XAMPP) via SQLAlchemy (scans, hosts, ports, vulnerabilities, risk_scores)
- **Web Dashboard** — login-gated, live scan progress, severity charts (Chart.js), scan history, and a risk-trend-over-time chart across your scan history
- **Zenmap-Style Terminal Output** — a "Nmap Output" tab on every scan result, rendering findings as classic color-coded Nmap terminal text (green for open ports, orange for filtered, blue for OS/network details) alongside the structured Findings table
- **REST API** — JSON endpoints (API-key authenticated) to start scans, poll status, fetch results, and download reports programmatically
- **Automated Report Generation** — one-click `.docx` report: executive summary, methodology, findings, risk matrix, recommendations
- **Authorization Gate** — every scan requires an explicit confirmation of authorization before it runs, enforced identically in both the web form and the REST API
- **Automated Test Suite** — pytest coverage for the scanning engine, risk scoring, and REST API
- **Docker Support** — one-command `docker compose up` for a fully containerized run

## Tech Stack
| Layer | Technology |
|---|---|
| Backend | Flask + Flask-SQLAlchemy |
| Database | SQLite |
| Scanning | Python stdlib `socket` + `concurrent.futures` (threaded) |
| Frontend | Jinja2 templates + Chart.js |
| Reporting | `python-docx` |

## Project Structure
```
netsecurex/
├── app.py                 # Flask routes, auth, scan orchestration
├── models.py               # SQLAlchemy models (Scan, Host, Port, Vulnerability, RiskScore)
├── scanner.py               # Discovery, port scan, banner grab, OS guess, vuln match
├── risk_engine.py            # CVSS-weighted risk scoring + trend aggregation
├── report_generator.py        # python-docx report builder
├── nmap_output.py              # Zenmap-style terminal output formatter
├── cve_lookup.py                # Optional live NVD/CVE lookup
├── vuln_db.json               # Offline vulnerability signature database
├── requirements.txt
├── requirements-dev.txt        # Testing dependencies (pytest)
├── pytest.ini
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── LICENSE                    # MIT License + responsible-use notice
├── .gitignore                 # Excludes venv, __pycache__, DB, generated reports
├── templates/                 # login, dashboard, new_scan, scan_progress, scan_result, history, error
├── static/css/style.css       # Dark SOC-themed dashboard styling
├── tests/                      # pytest suite (scanner, risk engine, API, CVE lookup)
├── reports/                   # Generated per-scan .docx reports land here (gitignored)
├── instance/                  # SQLite DB created here at runtime (gitignored)
└── deploy/                    # Production deployment configs
    ├── netsecurex.service      # systemd unit (gunicorn + auto-restart)
    └── nginx_netsecurex.conf   # Nginx reverse proxy config
```

## Installation

### Prerequisites
- Python 3.9 or later
- `pip` (Python package manager)
- Git (to clone the repository)
- A lab/test target to scan — e.g. [Metasploitable2](https://sourceforge.net/projects/metasploitable/) running in VirtualBox/VMware, or any host you own/are authorized to test

### 1. Clone the repository
```bash
git clone https://github.com/sourabh7078/NetSecureX.git
cd NetSecureX
```
(If you're setting this up from the delivered source archive instead of GitHub, just `cd` into the extracted `netsecurex/` folder.)

### 2. Create and activate a virtual environment
```bash
python -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows (PowerShell)
venv\Scripts\Activate.ps1

# Windows (cmd.exe)
venv\Scripts\activate.bat
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the application
```bash
python app.py
```
The first run automatically creates the SQLite database at `instance/netsecurex.db`.

### 5. Open the dashboard
Navigate to **http://localhost:5000** and log in with:
```
Username: admin
Password: admin123
```
⚠️ These are the defaults. Set `NSX_ADMIN_USERNAME` / `NSX_ADMIN_PASSWORD` (see Environment Variables below) to change them — passwords are hashed with Werkzeug's `generate_password_hash` before being compared, never stored or checked in plaintext.

## Running with Docker
For a one-command run with no manual venv/dependency setup:
```bash
docker compose up --build
```
Then open **http://localhost:5000** — same login as above. Stop it with `docker compose down`.

Real secrets go in a `.env` file in the project root (auto-loaded by Docker Compose):
```
NSX_SECRET_KEY=some-random-string
NSX_ADMIN_USERNAME=admin
NSX_ADMIN_PASSWORD=change-me
NSX_API_KEY=some-random-string
```
`instance/` (the SQLite DB) and `reports/` (generated `.docx` reports) are bind-mounted back to your host, so scan history and reports survive a rebuild or `docker compose down`. Want MySQL instead of SQLite inside Docker too? `docker-compose.yml` has a commented-out `mysql` service — uncomment it and point `NSX_DATABASE_URL` at it (see the comments in that file for the exact connection string).

To build and run without Compose:
```bash
docker build -t netsecurex .
docker run -d -p 5000:5000 -e NSX_SECRET_KEY=change-me --name netsecurex netsecurex
```

## Testing
A pytest suite covers the scanning engine, risk scoring, and REST API (`tests/`):
```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest
```
- `test_scanner.py` — vulnerability signature matching, OS guessing, service name mapping (no database needed, runs fast)
- `test_cve_lookup.py` — the optional live-CVE module's safe-by-default behavior, caching, and severity mapping (no network calls made during tests)
- `test_risk_engine.py` — CVSS-weighted scoring formula and scan summary aggregation, against a disposable temp-file SQLite database
- `test_api.py` — REST API authentication, input validation (authorization flag, CIDR safety cap), and the brute-force login lockout, using Flask's test client

Tests use a temporary database file (never your real `instance/netsecurex.db`) and mock the actual network scanning calls, so the full suite runs offline in seconds with no lab VMs required.

## Environment Variables
All configuration is optional — sensible defaults are used for local demo/viva purposes. Set these as OS environment variables, or drop them in a `.env` file in the project root (auto-loaded via `python-dotenv` if installed):

| Variable | Default | Purpose |
|---|---|---|
| `NSX_SECRET_KEY` | *(insecure dev key)* | Flask session signing key. **Set this to a random value** before exposing the app beyond localhost. |
| `NSX_DATABASE_URL` | local SQLite file | SQLAlchemy connection URI. Set to a MySQL URI to use XAMPP (see below). |
| `NSX_ADMIN_USERNAME` | `admin` | Dashboard login username. |
| `NSX_ADMIN_PASSWORD` | `admin123` | Dashboard login password (hashed in memory at startup, never stored in plaintext). |
| `NSX_HOST` | `0.0.0.0` | Interface the Flask server binds to. |
| `NSX_PORT` | `5000` | Port the Flask server listens on. |
| `NSX_DEBUG` | `false` | Set to `true`/`1` to enable Flask's debug mode (auto-reload, interactive tracebacks). Keep `false` outside local development. |
| `NSX_MAX_SCAN_HOSTS` | `1024` | Safety cap on how many addresses a single CIDR scan may cover (protects against an accidental `/8`-sized scan). |
| `NSX_API_KEY` | *(random, regenerated per run)* | REST API authentication key. Set this to keep it stable across restarts. |
| `NSX_USE_NMAP` | `false` | Set to `true`/`1` to use real Nmap (if installed) instead of the built-in pure-Python scanner. |
| `NSX_MAX_LOGIN_ATTEMPTS` | `5` | Failed dashboard logins from one IP before it's temporarily locked out. |
| `NSX_LOGIN_LOCKOUT_SECONDS` | `300` | How long (seconds) a locked-out IP must wait before trying again. |
| `NSX_SESSION_TIMEOUT_MINUTES` | `60` | Dashboard session idle timeout, in minutes. |
| `NSX_SESSION_COOKIE_SECURE` | `false` | Set to `true`/`1` to require HTTPS for the session cookie (enable once served over HTTPS). |
| `NSX_USE_LIVE_CVE` | `false` | Set to `true`/`1` to supplement offline signature matches with live NVD lookups. |
| `NSX_NVD_API_KEY` | *(none)* | Optional. Free from nvd.nist.gov — raises the NVD rate limit from 5 to 50 requests/30s. |
| `NSX_NVD_TIMEOUT` | `5` | Per-request timeout (seconds) for NVD API calls. |
| `NSX_NVD_CACHE_TTL` | `3600` | How long (seconds) a live CVE lookup is cached before re-querying NVD. |

Example `.env` file:
```
NSX_SECRET_KEY=change-this-to-a-random-string
NSX_ADMIN_USERNAME=analyst
NSX_ADMIN_PASSWORD=a-much-stronger-password
NSX_DEBUG=false
```

## Security Notes
This project was built for academic demonstration, but includes a few practical hardening touches worth calling out in a viva:
- **Password hashing** — the dashboard login credential is hashed with Werkzeug's PBKDF2-based `generate_password_hash`/`check_password_hash`, not compared in plaintext.
- **Brute-force login protection** — after `NSX_MAX_LOGIN_ATTEMPTS` (default 5) failed logins, an IP is locked out for `NSX_LOGIN_LOCKOUT_SECONDS` (default 300s) and gets a `429 Too Many Requests` response instead of another password attempt. Tracked in memory per-IP; a successful login clears the counter.
- **Hardened session cookies** — `HttpOnly` (JavaScript can't read the cookie, blunting XSS-based session theft), `SameSite=Lax` (not sent on most cross-site requests, blunting CSRF), and an idle timeout (`NSX_SESSION_TIMEOUT_MINUTES`, default 60). `Secure` (HTTPS-only) is off by default since the dev server runs over plain HTTP locally — turn it on via `NSX_SESSION_COOKIE_SECURE=true` once deployed behind HTTPS.
- **Security headers** — every response sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: same-origin`.
- **CIDR safety cap** — scans are capped at `NSX_MAX_SCAN_HOSTS` addresses (default 1024, i.e. a /22) so a typo like `10.0.0.0/8` can't trigger a 16-million-address scan.
- **Authorization gate** — every scan requires an explicit on-screen confirmation before it runs (see [Legal & Ethical Notice](#legal--ethical-notice)).
- **Structured logging** — logins (including the client IP), lockouts, scan starts/completions/failures, and unhandled server errors are logged via Python's `logging` module instead of stray `print()` calls.
- Still **not** production-hardened: there's a single shared admin account, the login lockout is in-memory only (resets on restart, and doesn't share state across multiple worker processes), and the Flask development server is single-process. See "Running in Production" below if you need more than a local demo.

## Running in Production
The built-in `python app.py` uses Flask's development server, which is fine for a local demo but not recommended for real deployment. For anything beyond localhost:
```bash
# Linux/macOS
pip install gunicorn
gunicorn -w 1 -b 127.0.0.1:5000 app:app

# Windows (gunicorn doesn't support Windows natively)
pip install waitress
waitress-serve --port=5000 app:app
```
⚠️ Use `-w 1` (a single worker), not more. Live scan progress (`SCAN_STATE`) is tracked in memory — multiple gunicorn workers would each keep their own separate copy, so a scan started on one worker wouldn't be visible from another, making the progress bar look stuck.

Also set `NSX_SECRET_KEY` to a random value and keep `NSX_DEBUG=false` (the default) in any environment beyond your own machine.

## Deploying to a Public VPS (Nginx + systemd)
For a real "always-on" deployment (rather than just running `python app.py` in a terminal), put Nginx in front of gunicorn as a reverse proxy, keep the app itself running via `systemd`, and add free HTTPS. Ready-to-use config files are included in `deploy/`.

⚠️ **Before going further: read this.** Once this app has a public IP, whoever holds the login can point it at *any* address on the internet. You — as the server owner — are legally responsible for what gets scanned from your machine. Keep credentials private even if your code is public on GitHub, and only deploy this somewhere you're comfortable being accountable for.

1. **Get a small VPS** — DigitalOcean, AWS Lightsail, or Linode all offer a $4–6/month Ubuntu 22.04 box, which is plenty. Note its public IP.
2. **Install prerequisites and copy the project:**
   ```bash
   sudo apt update && sudo apt install python3-venv python3-pip nginx -y
   # copy your netsecurex/ folder to /opt/netsecurex (scp, git clone, etc.)
   cd /opt/netsecurex
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt gunicorn
   ```
3. **Create a dedicated, unprivileged user to run it** — never run a network-facing app as root:
   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin netsecurex
   sudo chown -R netsecurex:netsecurex /opt/netsecurex
   ```
4. **Set real production secrets** in `/opt/netsecurex/.env` — see the [Environment Variables](#environment-variables) table above. At minimum: `NSX_SECRET_KEY`, `NSX_ADMIN_USERNAME`, `NSX_ADMIN_PASSWORD`, `NSX_API_KEY`, and (after step 6) `NSX_SESSION_COOKIE_SECURE=true`.
5. **Install the systemd service** (keeps the app running, auto-restarts on crash/reboot):
   ```bash
   sudo cp deploy/netsecurex.service /etc/systemd/system/netsecurex.service
   sudo systemctl daemon-reload
   sudo systemctl enable netsecurex
   sudo systemctl start netsecurex
   sudo systemctl status netsecurex        # confirm it's running
   sudo journalctl -u netsecurex -f        # follow logs live
   ```
6. **Install the Nginx reverse proxy config:**
   ```bash
   sudo cp deploy/nginx_netsecurex.conf /etc/nginx/sites-available/netsecurex
   # edit the file first: replace "yourdomain.com" with your actual domain
   sudo ln -s /etc/nginx/sites-available/netsecurex /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```
7. **Add free HTTPS via Let's Encrypt** (requires a domain pointed at your VPS's IP):
   ```bash
   sudo apt install certbot python3-certbot-nginx -y
   sudo certbot --nginx -d yourdomain.com
   ```
   This automatically edits the Nginx config to add the SSL block and an HTTP→HTTPS redirect. Afterward, set `NSX_SESSION_COOKIE_SECURE=true` in your `.env` and restart: `sudo systemctl restart netsecurex`.
8. **Firewall everything except web traffic:**
   ```bash
   sudo apt install ufw -y
   sudo ufw allow 22/tcp     # SSH
   sudo ufw allow 80/tcp     # HTTP (redirects to HTTPS)
   sudo ufw allow 443/tcp    # HTTPS
   sudo ufw enable
   ```
   This blocks direct access to gunicorn's port 5000 from outside — only Nginx (via the loopback interface) can reach it.

## Using XAMPP / MySQL Instead of SQLite
By default NetSecureX uses SQLite (zero-config, ideal for a quick demo). If your lab environment already has **XAMPP** set up and you'd prefer MySQL:

1. Open the **XAMPP Control Panel** and click **Start** next to MySQL. (Apache isn't needed — Flask runs its own dev server on port 5000.)
2. Go to **http://localhost/phpmyadmin**, click **New**, name the database `netsecurex` (collation `utf8mb4_general_ci`), and click **Create**.
3. Install the MySQL driver in your virtual environment:
   ```bash
   pip install PyMySQL
   ```
   (already included in `requirements.txt`)
4. Set the `NSX_DATABASE_URL` environment variable before running the app:
   ```bash
   # Windows (cmd.exe)
   set NSX_DATABASE_URL=mysql+pymysql://root:@localhost:3306/netsecurex

   # macOS / Linux (bash)
   export NSX_DATABASE_URL="mysql+pymysql://root:@localhost:3306/netsecurex"
   ```
5. Run the app as usual:
   ```bash
   python app.py
   ```
   The console will print which database backend is active. On first run, the five tables (`scans`, `hosts`, `ports`, `vulnerabilities`, `risk_scores`) are created automatically inside the `netsecurex` database — verify this anytime under phpMyAdmin → **Structure**.
6. **Tip for the viva:** keep a phpMyAdmin tab open on the `hosts` or `vulnerabilities` table and refresh it while a scan runs, to show data being written live.

If `NSX_DATABASE_URL` isn't set, the app falls back to SQLite automatically — no code changes needed to switch back.

## Using Real Nmap Instead of the Built-in Scanner
By default, NetSecureX uses a pure-Python scanner (stdlib sockets + threading) so it runs anywhere without extra installs or elevated privileges. If you have the real **Nmap** binary available, you can opt into it for more accurate service/version detection and OS fingerprinting:

1. Install Nmap itself (not just the Python wrapper): [nmap.org/download](https://nmap.org/download.html). On Windows, use the official installer; on Kali/Debian/Ubuntu, `sudo apt install nmap`.
2. Install the Python wrapper:
   ```bash
   pip install python-nmap
   ```
3. Enable it:
   ```bash
   # Windows (cmd)
   set NSX_USE_NMAP=true

   # macOS/Linux (bash)
   export NSX_USE_NMAP=true
   ```
4. Run the app as usual: `python app.py`.

**How the fallback works:** `scanner.py` checks three things before using real Nmap — `NSX_USE_NMAP=true` is set, the `nmap` binary is found on your system `PATH`, and the `python-nmap` package is importable. If any of those fail, or if Nmap itself errors out on a specific host, that host is automatically scanned with the built-in pure-Python scanner instead — a scan never fails outright just because Nmap isn't available.

**About OS fingerprinting (`-O`):** real OS detection needs raw-socket access, which requires running as **Administrator** (Windows) or with `sudo` (Linux/macOS). Without elevated privileges, Nmap's service/version detection (`-sV`) still works normally, but the OS guess falls back to `"Unknown (requires elevated privileges for -O)"`.

## Using Live NVD/CVE Lookup
By default, vulnerability matching is entirely offline (`vuln_db.json`) — reliable for demos, but limited to the signatures curated into that file. Optionally, `cve_lookup.py` can supplement those offline matches with real-time results from the **National Vulnerability Database (NVD)** REST API, using only the Python standard library (`urllib`) — no extra package to install.

**Enable it:**
```bash
# Windows (cmd)
set NSX_USE_LIVE_CVE=true

# macOS/Linux (bash)
export NSX_USE_LIVE_CVE=true
```
Optionally set `NSX_NVD_API_KEY` (free from [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)) to raise NVD's rate limit from 5 to 50 requests per 30 seconds — useful if you're scanning many distinct services in one session.

**How it behaves:**
- Offline signatures always run first and are never removed or overridden — live results are purely additive, merged in and deduped by CVE ID.
- A live lookup only fires when a service *and* a version string were actually detected (querying on a bare service name like `"http"` with no version is too broad and wastes rate-limit budget on noise).
- Results are cached in memory per service/version pair for `NSX_NVD_CACHE_TTL` seconds (default 1 hour), so scanning the same service across many hosts in one session doesn't re-query NVD each time.
- **Every failure mode is silent and safe**: disabled, no network, DNS failure, timeout, NVD rate-limiting (HTTP 429), or a malformed response all simply return no additional results — a scan never fails or hangs because the live lookup didn't work. This is deliberate: for a live viva demo, you don't want an internet hiccup breaking your scan.
- Findings are tagged `"source": "offline-db"` or `"source": "live-nvd"` internally, so the two can be told apart if you extend the report/dashboard to display it.

## REST API
In addition to the web dashboard, NetSecureX exposes a small JSON REST API for programmatic use (scripts, CI pipelines, other tools) — authenticated separately from the dashboard login via an API key.

**Getting your API key:** set `NSX_API_KEY` yourself, or just start the app and check the console — if you haven't set one, a random key is generated and printed on every startup (it changes each restart unless you set `NSX_API_KEY` explicitly).

All API requests must include the header: `X-API-Key: <your-key>`

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scans` | Start a new scan. Body: `{"target": "192.168.56.101", "authorized": true}` |
| `GET` | `/api/v1/scans` | List recent scans (add `?limit=50` to change the default of 20). |
| `GET` | `/api/v1/scans/<id>` | Full scan detail — hosts, ports, vulnerabilities, risk scores. |
| `GET` | `/api/v1/scans/<id>/status` | Lightweight polling: `{"status": "running", "progress": 42}` |
| `GET` | `/api/v1/scans/<id>/report` | Download the generated `.docx` report for a completed scan. |

Example with `curl`:
```bash
# Start a scan
curl -X POST http://localhost:5000/api/v1/scans \
  -H "X-API-Key: your-key-here" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.56.101", "authorized": true}'

# Poll status
curl http://localhost:5000/api/v1/scans/1/status -H "X-API-Key: your-key-here"

# Get full results once completed
curl http://localhost:5000/api/v1/scans/1 -H "X-API-Key: your-key-here"

# Download the report
curl http://localhost:5000/api/v1/scans/1/report -H "X-API-Key: your-key-here" -o report.docx
```
The same authorization rules apply as the web form: requests without `"authorized": true` are rejected, and CIDR ranges larger than `NSX_MAX_SCAN_HOSTS` are refused with a `400` response.

## Publishing to GitHub
If you're pushing this project to your own GitHub repository:
```bash
git init
git add .
git commit -m "Initial commit: NetSecureX v1.0"
git branch -M main
git remote add origin https://github.com/<your-username>/NetSecureX.git
git push -u origin main
```
The included `.gitignore` already excludes `__pycache__/`, virtual environments, the runtime SQLite database, and generated per-scan reports, so only source code is tracked. The `LICENSE` file (MIT, with an added responsible-use notice) is picked up automatically by GitHub's license detector once pushed.

## Demo / Viva Strategy
1. Set up **Metasploitable2** (or any intentionally vulnerable VM) on an
   isolated host-only/NAT network alongside your scanning host. See "Setting
   Up a Local Scan Lab" below for the full VM networking walkthrough.
2. In NetSecureX, start a new scan against the Metasploitable2 IP (or the
   subnet CIDR to demonstrate multi-host discovery).
3. Show the live progress bar, then the populated dashboard: open ports,
   services, CVEs, and per-host risk scores.
4. Download and open the generated `.docx` report live.
5. **Before/after demo:** stop a service or open a new port on the VM,
   re-scan, and show the new finding appear — a strong talking point for
   "scan history and trend comparison."

## Setting Up a Local Scan Lab (Kali + Metasploitable2)
1. Create a **Host-Only network** (VirtualBox: File → Host Network Manager → Create; VMware: use the built-in Host-Only VMnet). This isolates the lab from your real network.
2. Attach both your Kali VM and Metasploitable2 VM to that same host-only network (Settings → Network → Attached to: Host-Only Adapter).
3. Start Metasploitable2, log in (`msfadmin` / `msfadmin`), run `ifconfig eth0` and note its IP (e.g. `192.168.56.101`).
4. Start Kali (or just use your physical host machine — either works, since both are on the host-only network), run `ip a` / `ipconfig` to find your own IP, and confirm connectivity with `ping 192.168.56.101`.
5. Run NetSecureX as usual (`python app.py`) and scan the Metasploitable2 IP from the dashboard.

**Default scanned ports (34 total)** now cover Metasploitable2's full known-vulnerable service set out of the box: 21 (ftp), 22 (ssh), 23 (telnet), 25 (smtp), 53 (dns), 80 (http), 110 (pop3), 111 (rpcbind), 135 (msrpc), 139/445 (samba), 143 (imap), 443 (https), 512/513/514 (rexec/rlogin/rsh), 993/995 (imaps/pop3s), 1099 (Java RMI), 1524 (ingreslock backdoor), 1723 (pptp), 2049 (nfs), 3306 (mysql), 3389 (rdp), 3632 (distccd), 5432 (postgresql), 5900 (vnc), 6000 (X11), 6667/6697 (irc), 8009 (ajp13), 8080 (http-proxy), 8180 (tomcat), 8443 (https-alt). A default scan against Metasploitable2 now typically surfaces 5–6 Critical findings, including the vsFTPd backdoor, the Samba `usermap_script` RCE, the `ingreslock` root-shell backdoor, distccd RCE, and the UnrealIRCd trojan backdoor — good breadth for a viva demo.

⚠️ **Never attach Metasploitable2 to a Bridged or NAT network.** It's intentionally full of unpatched vulnerabilities — keep it strictly on an isolated host-only network so nothing else on your LAN is exposed to it.

## Adding a Windows Target: Server 2019 (Optional Third Lab Host)
A Windows machine rounds out the lab nicely — it lets you demonstrate NetSecureX's OS-fingerprinting and Windows-specific signatures (SMB/EternalBlue, RDP/BlueKeep) against a real Windows target rather than only Linux ones.

1. **Download the free evaluation ISO** from `microsoft.com/evalcenter` (search "Windows Server 2019") — genuinely free, 180-day trial, no product key needed, just an email address.
2. **Create the VM:** VirtualBox → New → Type: Windows, Version: Windows 2019 (64-bit), 4GB+ RAM, 40GB+ disk. Attach the ISO under Settings → Storage before first boot.
3. **Install:** choose "Windows Server 2019 Standard Evaluation (Desktop Experience)" (the GUI edition), custom install, set the Administrator password when prompted.
4. **Network it the same way as the others:** Settings → Network → Adapter 1 → Host-Only Adapter → the same adapter (e.g. `vboxnet0`) your Kali/Metasploitable VMs use.
5. **Give it something to scan:** a bare install has almost nothing open. In Server Manager → Add Roles and Features, install **Web Server (IIS)** (opens 80/443) and/or **File and Storage Services → File Server** (opens SMB 139/445). RDP (3389) is typically enabled by default.
6. **Find its IP:** `ipconfig` in a Command Prompt/PowerShell on the Server 2019 VM — look for the address on the same `192.168.56.x` range.
7. **Scan it:** same as any other target — `ping` to confirm reachability from Kali, then enter the IP in NetSecureX's New Scan page.

**Realistic expectation:** Microsoft's evaluation ISO ships current on patches, so it won't have the same volume of Critical CVEs as Metasploitable2/3 out of the box — you'll mainly see IIS/SMB/RDP correctly identified with our existing signatures (CVE-2019-0708 for RDP, CVE-2017-0144 for SMB) flagging *potential* risk rather than confirmed unpatched exploits. That's still a legitimate, useful demo point: it shows the tool correctly fingerprinting a Windows host and applying the right signature set, distinct from the Linux-only findings on the Metasploitable boxes.

⚠️ **Keep this on the host-only network too, and never expose it to the public internet.** Unlike deploying the NetSecureX *application* itself (covered in "Deploying to a Public VPS" below, which is safe because it's just a login-gated web app), publicly exposing a Windows Server — especially one running RDP/SMB, and especially if you intentionally weaken its configuration for demo purposes — gets found and attacked by automated internet scanners within hours, and you are liable for whatever it's used for afterward. If you need remote access to *demonstrate* NetSecureX (e.g., for a remote viva), deploy the app on a VPS as described below and keep all scan *targets* strictly on your local, isolated lab network.

## Risk Scoring Formula
```
host_risk = Σ (vuln_cvss_score × exposure_weight) / open_port_count
exposure_weight = 1.5 (internet-facing port) | 1.0 (internal-only)
Severity bands: Critical 9.0–10.0 | High 7.0–8.9 | Medium 4.0–6.9 | Low 0.0–3.9
```

## Legal & Ethical Notice
NetSecureX is intended **only** for scanning networks and hosts you own or
have explicit written authorization to test. The application enforces an
authorization checkbox before every scan, but this is a UX safeguard, not a
legal one — the operator remains responsible for ensuring authorization.
Unauthorized network scanning may violate computer misuse laws.

## License
This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details. The license includes an additional notice restricting use to authorized systems only; see the [Legal & Ethical Notice](#legal--ethical-notice) above.

## Future Scope
- Email/webhook alerting on new Critical findings
- Role-based multi-analyst accounts with hashed credentials
- Displaying live-CVE vs. offline-signature source tags in the report/dashboard (currently tracked internally via `"source"` but not yet surfaced in the UI)
