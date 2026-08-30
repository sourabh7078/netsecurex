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
- **Banner Grabbing & Service Detection** — lightweight fingerprinting of common services
- **Heuristic OS Fingerprinting** — best-effort OS guess from port/banner signatures
- **Offline Vulnerability Matching** — local JSON signature DB (`vuln_db.json`), no live API dependency
- **CVSS-Weighted Risk Scoring** — per-host and network-wide risk scores with severity bands
- **Persistent Scan History** — SQLite via SQLAlchemy (scans, hosts, ports, vulnerabilities, risk_scores)
- **Web Dashboard** — login-gated, live scan progress, severity charts (Chart.js), scan history
- **Automated Report Generation** — one-click `.docx` report: executive summary, methodology, findings, risk matrix, recommendations
- **Authorization Gate** — every scan requires an explicit on-screen confirmation of authorization before it runs

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
├── risk_engine.py            # CVSS-weighted risk scoring
├── report_generator.py        # python-docx report builder
├── vuln_db.json               # Offline vulnerability signature database
├── requirements.txt
├── LICENSE                    # MIT License + responsible-use notice
├── .gitignore                 # Excludes venv, __pycache__, DB, generated reports
├── templates/                 # login, dashboard, new_scan, scan_progress, scan_result, history, error
├── static/css/style.css       # Dark SOC-themed dashboard styling
├── reports/                   # Generated per-scan .docx reports land here (gitignored)
└── instance/                  # SQLite DB created here at runtime (gitignored)
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
- **Security headers** — every response sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: same-origin`.
- **CIDR safety cap** — scans are capped at `NSX_MAX_SCAN_HOSTS` addresses (default 1024, i.e. a /22) so a typo like `10.0.0.0/8` can't trigger a 16-million-address scan.
- **Authorization gate** — every scan requires an explicit on-screen confirmation before it runs (see [Legal & Ethical Notice](#legal--ethical-notice)).
- **Structured logging** — logins, scan starts/completions/failures, and unhandled server errors are logged via Python's `logging` module instead of stray `print()` calls.
- Still **not** production-hardened: there's a single shared admin account with no rate-limiting on login attempts, and the Flask development server is single-process. See "Running in Production" below if you need more than a local demo.

## Running in Production
The built-in `python app.py` uses Flask's development server, which is fine for a local demo but not recommended for real deployment. For anything beyond localhost:
```bash
# Linux/macOS
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Windows (gunicorn doesn't support Windows natively)
pip install waitress
waitress-serve --port=5000 app:app
```
Also set `NSX_SECRET_KEY` to a random value and keep `NSX_DEBUG=false` (the default) in any environment beyond your own machine.

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
   isolated host-only/NAT network alongside your scanning host.
2. In NetSecureX, start a new scan against the Metasploitable2 IP (or the
   subnet CIDR to demonstrate multi-host discovery).
3. Show the live progress bar, then the populated dashboard: open ports,
   services, CVEs, and per-host risk scores.
4. Download and open the generated `.docx` report live.
5. **Before/after demo:** stop a service or open a new port on the VM,
   re-scan, and show the new finding appear — a strong talking point for
   "scan history and trend comparison."

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
- Live NVD/CVE API integration (currently offline signature DB by design, for
  demo reliability without network/API-key dependencies)
- Real Nmap SYN scanning + `-O` OS fingerprinting when run with elevated privileges
- Scan diffing / trend dashboards across historical scans
- Email/webhook alerting on new Critical findings
- Role-based multi-analyst accounts with hashed credentials
