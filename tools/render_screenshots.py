"""
Render screenshots of the running application from a seeded demo database.

Requires wkhtmltoimage on the PATH (apt install wkhtmltopdf, or the installer from wkhtmltopdf.org).

Usage (from the project folder):
    python tools/seed_demo.py demo.db
    python tools/render_screenshots.py demo.db screenshots/
"""
import os
import subprocess
import sys

db_path = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "demo.db")
out_dir = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else "screenshots")
os.makedirs(out_dir, exist_ok=True)
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
os.environ.update({
    "NSX_DATABASE_URL": "sqlite:///" + db_path.replace("\\", "/"),
    "NSX_ADMIN_USERNAME": "demo", "NSX_ADMIN_PASSWORD": "demo-password-1",
    "NSX_SECRET_KEY": "demo-secret", "NSX_ENABLE_SCHEDULER": "false", "NSX_UDP_SCAN": "false",
})
sys.path.insert(0, ROOT)
import app as A

CSS = "file:///" + os.path.join(ROOT, "static", "css", "style.css").replace("\\", "/")


def shot(html, name, width=1200):
    html_path = os.path.join(out_dir, name + ".html")
    html = html.replace("/static/css/style.css", CSS)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    png = os.path.join(out_dir, name + ".png")
    subprocess.run(["wkhtmltoimage", "--enable-local-file-access", "--disable-javascript",
                    "--width", str(width), "--quality", "92", "-q", html_path, png],
                   check=False, capture_output=True, timeout=120)
    os.remove(html_path)
    print("wrote", png, os.path.exists(png))


client = A.app.test_client()
shot(client.get("/login").get_data(as_text=True), "01_login", 900)
client.post("/login", data={"username": "demo", "password": "demo-password-1"})
shot(client.get("/scan/2").get_data(as_text=True), "02_scan_findings")
term = client.get("/scan/2").get_data(as_text=True)
term = term.replace('<div id="findings-view" class="zenmap-tab-panel">',
                    '<div id="findings-view" class="zenmap-tab-panel" style="display:none;">', 1)
term = term.replace('<div id="terminal-view" class="zenmap-tab-panel" style="display:none;">',
                    '<div id="terminal-view" class="zenmap-tab-panel" style="display:block;">', 1)
shot(term, "03_scan_nmap_output")
shot(client.get("/scan/2/changes").get_data(as_text=True), "04_change_report")
shot(client.get("/schedules").get_data(as_text=True), "05_schedules")
shot(client.get("/admin/users").get_data(as_text=True), "06_users")
shot(client.get("/history").get_data(as_text=True), "07_history")
