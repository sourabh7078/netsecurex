"""
Seed a demonstration database for screenshots and demos.

Creates two completed scans of 192.168.56.0/24 (so the change report has
content), one schedule, and three accounts. The data is invented for
demonstration; it is not a record of any real scan.

Usage (from the project folder):
    python tools/seed_demo.py path/to/demo.db
"""
import os
import sys
from datetime import datetime, timedelta

db_path = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "demo.db")
os.environ.update({
    "NSX_DATABASE_URL": "sqlite:///" + db_path.replace("\\", "/"),
    "NSX_ADMIN_USERNAME": "demo", "NSX_ADMIN_PASSWORD": "demo-password-1",
    "NSX_SECRET_KEY": "demo-secret", "NSX_ENABLE_SCHEDULER": "false", "NSX_UDP_SCAN": "false",
})
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from werkzeug.security import generate_password_hash
import app as A
from models import db, Scan, Host, Port, Vulnerability, User, Schedule, ROLE_ANALYST, ROLE_VIEWER
from risk_engine import compute_host_risk


def make_scan(target, when, hosts):
    scan = Scan(target_range=target, start_time=when, end_time=when + timedelta(seconds=52), status="completed")
    db.session.add(scan)
    db.session.commit()
    for ip, name, os_guess, ports in hosts:
        host = Host(scan_id=scan.id, ip=ip, hostname=name, os_guess=os_guess, status="up")
        db.session.add(host)
        db.session.flush()
        for pno, proto, svc, ver, vulns in ports:
            port = Port(host_id=host.id, port_no=pno, protocol=proto, service=svc, version=ver, state="open")
            db.session.add(port)
            db.session.flush()
            for cve, cvss, sev, desc, src in vulns:
                db.session.add(Vulnerability(port_id=port.id, cve_id=cve, cvss_score=cvss,
                                             severity=sev, description=desc, source=src))
        db.session.commit()
        compute_host_risk(host.id)
    return scan


with A.app.app_context():
    db.create_all()
    A.bootstrap_users()
    now = datetime(2026, 10, 10, 9, 0, 0)
    target = "192.168.56.0/24"
    a = make_scan(target, now - timedelta(hours=3), [
        ("192.168.56.101", "metasploitable.localdomain", "Likely Linux/Unix", [
            (21, "tcp", "ftp", "vsFTPd 2.3.4", [("CVE-2011-2523", 9.8, "Critical", "vsftpd 2.3.4 backdoor allows command execution", "offline-db"),
                                                ("N/A", 5.3, "Medium", "FTP sends credentials in cleartext", "offline-db")]),
            (22, "tcp", "ssh", "OpenSSH 4.7p1", []),
            (80, "tcp", "http", "Apache/2.2.8", []),
            (445, "tcp", "microsoft-ds", "Samba 3.0.20-Debian", [("CVE-2007-2447", 10.0, "Critical", "Samba usermap_script command execution", "offline-db")]),
        ]),
        ("192.168.56.102", "WIN-SRV2019", "Likely Windows", [
            (445, "tcp", "microsoft-ds", "SMB", [("CVE-2017-0144", 8.1, "High", "SMBv1 EternalBlue exposure", "offline-db")]),
            (3389, "tcp", "rdp", "", [("CVE-2019-0708", 9.8, "Critical", "RDP BlueKeep pre-authentication RCE if unpatched", "offline-db")]),
        ]),
    ])
    b = make_scan(target, now, [
        ("192.168.56.101", "metasploitable.localdomain", "Likely Linux/Unix", [
            (21, "tcp", "ftp", "vsFTPd 2.3.4", [("CVE-2011-2523", 9.8, "Critical", "vsftpd 2.3.4 backdoor allows command execution", "offline-db"),
                                                ("N/A", 5.3, "Medium", "FTP sends credentials in cleartext", "offline-db")]),
            (22, "tcp", "ssh", "OpenSSH 4.7p1", []),
            (445, "tcp", "microsoft-ds", "Samba 3.0.20-Debian", [("CVE-2007-2447", 10.0, "Critical", "Samba usermap_script command execution", "offline-db")]),
            (1524, "tcp", "ingreslock", "", [("N/A", 10.0, "Critical", "ingreslock root-shell backdoor", "offline-db")]),
            (6379, "tcp", "redis", "", [("CVE-2022-0543", 10.0, "Critical", "Redis Lua sandbox escape allows remote code execution", "offline-db")]),
        ]),
        ("192.168.56.102", "WIN-SRV2019", "Likely Windows", [
            (445, "tcp", "microsoft-ds", "SMB", [("CVE-2017-0144", 8.1, "High", "SMBv1 EternalBlue exposure", "offline-db")]),
            (3389, "tcp", "rdp", "", [("CVE-2019-0708", 9.8, "Critical", "RDP BlueKeep pre-authentication RCE if unpatched", "offline-db")]),
        ]),
        ("192.168.56.103", "dev-box", "Likely Linux/Unix", [
            (22, "tcp", "ssh", "OpenSSH 8.9p1", [("CVE-2023-38408", 9.8, "Critical", "ssh-agent remote code execution in OpenSSH up to 9.3p2", "live-nvd")]),
        ]),
    ])
    db.session.add(User(username="analyst1", password_hash=generate_password_hash("analyst-pass-1"), role=ROLE_ANALYST, is_active=True))
    db.session.add(User(username="viewer1", password_hash=generate_password_hash("viewer-pass-1"), role=ROLE_VIEWER, is_active=True))
    db.session.add(Schedule(target_range=target, interval_minutes=1440, enabled=True, created_by="analyst1",
                            next_run_at=now + timedelta(days=1), last_scan_id=b.id))
    db.session.commit()
    print(f"Seeded {db_path}: scan {a.id} and scan {b.id}. Sign in as demo / demo-password-1.")
