# SPDX-License-Identifier: GPL-3.0-or-later
# ── Docker CLI (client only) ─────────────────────────────────────
# We only need the docker *client* to control the resolver via the mounted
# socket — NOT the full docker.io engine (which added ~600 MB). The CLI is a
# static binary we copy from the official image.
FROM docker:cli AS dockercli

FROM python:3.11-slim

LABEL org.opencontainers.image.title="Certificate Resolver UI"
LABEL org.opencontainers.image.source="https://github.com/mluettermann/certificate-resolver-ui"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"

WORKDIR /app

# System dependencies: openssl is used to read certificate expiry dates.
# --no-install-recommends avoids pulling unnecessary extra packages.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

# Docker CLI client (~50 MB) instead of the full docker.io engine.
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

# Python deps
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/app.py .
COPY app/gunicorn.conf.py .
COPY app/templates/ templates/
COPY app/static/ static/

RUN mkdir -p /data /logs

EXPOSE 5000

# Production WSGI server. All settings (bind, workers, rotating log files,
# stdout = status only) live in gunicorn.conf.py.
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
