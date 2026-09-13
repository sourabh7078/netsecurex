# NetSecureX - Dockerfile
#
# Builds a container image running the app via gunicorn. Uses a single
# worker (-w 1) intentionally -- see the note in deploy/netsecurex.service
# and README.md's "Running in Production" section: live scan progress
# (SCAN_STATE) is tracked in memory, so multiple workers would each keep
# their own separate copy of it.
#
# BUILD:
#   docker build -t netsecurex .
#
# RUN (standalone, without docker-compose):
#   docker run -d -p 5000:5000 \
#     -e NSX_SECRET_KEY=change-me \
#     -e NSX_ADMIN_PASSWORD=change-me \
#     -v netsecurex_instance:/app/instance \
#     -v netsecurex_reports:/app/reports \
#     --name netsecurex netsecurex
#
# Prefer `docker compose up --build` instead (see docker-compose.yml) --
# it wires up the environment variables and volumes for you.

FROM python:3.11-slim

WORKDIR /app

# Uncomment if you want the real Nmap binary available inside the container
# for NSX_USE_NMAP=true (the pure-Python scanner needs nothing extra):
# RUN apt-get update \
#     && apt-get install -y --no-install-recommends nmap \
#     && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

# Created at build time so the volumes mounted over them (see
# docker-compose.yml) start from an existing, correctly-permissioned path
# rather than Docker auto-creating them as root-owned directories.
RUN mkdir -p instance reports

EXPOSE 5000

ENV NSX_HOST=0.0.0.0 \
    NSX_PORT=5000 \
    NSX_DEBUG=false

# --timeout 120: larger CIDR scans can take a while; don't let gunicorn kill
# the worker mid-scan on the default 30s timeout.
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:5000", "--timeout", "120", "app:app"]
