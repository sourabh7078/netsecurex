# 🛡️ NetSecureX

### Intelligent Network Vulnerability Scanner & Security Dashboard
**MCA Final Year Project** — Cybersecurity Specialization

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
├── templates/                 # login, dashboard, new_scan, scan_progress, scan_result, history
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
⚠️ Change `DEMO_USER` in `app.py` (and add password hashing) before any use beyond local academic demonstration.

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
