# Certificate Resolver UI

Web interface for the [Certificate Resolver](https://github.com/mluettermann/certificate_resolver) — a Flask app to manage wildcard certificates, deployment targets, and users, secured with login + two-factor authentication.

This repository builds the **`certificate-resolver-ui`** image. The container is **deployed as part of the resolver stack** (the `cert-ui` service in the resolver's `docker-compose.yml`); it is not run on its own in production.

---

## Features

- **Login + 2FA (TOTP)** with one-time backup codes (downloadable, shown once); forced password change on first login.
- **Roles:** `admin` (full access), `technician` (issue/renew, edit targets, delete domains), `viewer` (read-only).
- **Domain Setup:** register domains, issue/renew certificates with live output, view status & expiry, delete domains.
- **Deploy Setup:** edit `cert-targets.yml` per domain with a service picker (nginx, Apache, Traefik, nginx Proxy Manager → SSH; IIS → SFTP drop).
- **Administration:** user management and an audit log of UI actions.
- **Hardening:** CSRF protection, `HttpOnly`/`SameSite`/optional `Secure` cookies, idle session timeout, brute-force lockout, real client IP via `X-Forwarded-For`.

It controls the resolver container via the mounted Docker socket (`docker exec`) and shares its data (certificates, acme-dns credentials, `cert-targets.yml`).

---

## How it runs

- **Production:** prebuilt images are published to `ghcr.io/mluettermann/certificate-resolver-ui` by GitHub Actions and pulled by the resolver stack. The `cert-ui` service mounts the Docker socket, the shared data, and the log folder, and sits behind Traefik for TLS. See the [resolver README](https://github.com/mluettermann/certificate_resolver#deployment) for full deployment.
- **WSGI server:** gunicorn (`gunicorn.conf.py`), binding `[::]:5000` (dual-stack). Access logs go to rotating files; stdout shows status only.

---

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | — | Flask session secret — **required**, the app refuses to start without it (`openssl rand -hex 32`) |
| `ADMIN_USERNAME` | `admin` | Initial admin account |
| `ADMIN_PASSWORD` | empty | Initial password (empty → random, printed once to the log) |
| `SECURE_COOKIES` | `false` | Send session cookie only over HTTPS (set `true` behind TLS) |
| `TRUST_PROXY` | `true` | Honor `X-Forwarded-For` for the real client IP |
| `PROXY_HOPS` | `1` | Number of proxies in front |
| `SESSION_TIMEOUT_MINUTES` | `30` | Idle logout |
| `LOGIN_MAX_ATTEMPTS` / `LOGIN_LOCKOUT_MINUTES` | `5` / `15` | Brute-force lockout |
| `RESOLVER_CONTAINER` | `certificate-resolver` | Name of the resolver container to control |
| `DATA_DIR` | `/data` | App state: `users.json`, `audit.log`, `login_attempts.json` |
| `LOG_DIR` | `/logs` | Access/error logs (rotating) |
| `CERT_DIR` | `/data/certs` | Certificates to read (mounted from the resolver) |
| `CREDS_FILE` | `/data/acmedns-credentials.json` | acme-dns credentials to read |
| `TARGETS_FILE` | `/data/cert-targets.yml` | Distribution config (read + write) |
| `LOG_MAX_BYTES` / `LOG_BACKUPS` | `10 MB` / `5` | Log rotation |

In the resolver stack these are set with the `UI_` prefix (e.g. `UI_SECRET_KEY`); see the resolver's `docker-compose.yml`.

---

## Local development

```bash
cd app
pip install -r requirements.txt
DATA_DIR=./data ADMIN_PASSWORD=admin SECRET_KEY=dev python app.py
# → http://localhost:5000  (Flask dev server; production uses gunicorn)
```

The standalone `docker-compose.yml` in this repo is for isolated testing only (`docker compose up --build`, needs a running resolver container) — for real use, deploy via the resolver stack.

---

## Project structure

```
.
├── docker-compose.yml           # standalone test only
├── Dockerfile                   # builds the image (docker CLI + gunicorn)
├── .env-example
├── .github/workflows/           # builds and publishes the image to GHCR
└── app/
    ├── app.py                   # Flask application
    ├── gunicorn.conf.py         # WSGI server + rotating log config
    ├── requirements.txt
    ├── static/                  # favicon
    └── templates/               # login, twofa, twofa_setup, backup_codes,
                                 # dashboard, change_password, admin_users, audit
```

---

## Security

The UI mounts the Docker socket and can trigger certificate issuance and deployment to all configured targets. Please read [SECURITY.md](SECURITY.md) before exposing it.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
