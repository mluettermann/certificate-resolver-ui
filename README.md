# Certificate Resolver UI

Web interface for the [Certificate Resolver](https://github.com/mluettermann/certificate_resolver) — a Flask app to manage wildcard certificates, deployment targets, and users, secured with login + two-factor authentication.

This repository builds the **`certificate-resolver-ui`** image. The UI is **optional**: the resolver works on its own via the CLI. The UI runs as its own stack next to the resolver, on the same Docker host.

---

## Features

- **Login + 2FA (TOTP)** with one-time backup codes (downloadable, shown once); forced password change on first login.
- **Roles:** `admin` (full access), `technician` (issue/renew, edit targets, delete domains), `viewer` (read-only).
- **Domain Setup:** register domains, issue/renew certificates with live output, view status & expiry, delete domains.
- **Deploy Setup:** edit `cert-targets.yml` per domain with a service picker (nginx, Apache, Traefik, nginx Proxy Manager → SSH; IIS → SFTP drop; Proxmox VE). SSH targets have an optional *Address family* (`any` / `inet` / `inet6`) — use `inet6` when a host's IPv4 only reaches an HTTP(S) proxy. Target types without a form (e.g. `windows-ssh`, `esxi`) are shown read-only and saved back unchanged; fields the form doesn't know are preserved as well.
- **Administration:** user management and an audit log of UI actions.
- **Hardening:** CSRF protection, `HttpOnly`/`SameSite`/optional `Secure` cookies, idle session timeout, brute-force lockout, real client IP via `X-Forwarded-For`.

It controls the resolver container via the mounted Docker socket (`docker exec`) and shares its data (certificates, acme-dns credentials, `cert-targets.yml`).

---

## How it runs

- **Image:** prebuilt images are published to `ghcr.io/mluettermann/certificate-resolver-ui` by GitHub Actions. To build it yourself: `docker build -t ghcr.io/mluettermann/certificate-resolver-ui:latest .`
- **Stack:** the `docker-compose.yml` in this repo is the deployment. It mounts the Docker socket, the resolver's shared data and the log folder; a reverse proxy of your choice (Traefik, Caddy, nginx — see `deploy/`) provides TLS.
- **WSGI server:** gunicorn (`gunicorn.conf.py`), binding `[::]:5000` (dual-stack). Access logs go to rotating files; stdout shows status only.

---

## Deployment

**Prerequisite:** the [resolver](https://github.com/mluettermann/certificate_resolver#deployment) is installed and running on the same host (its `bootstrap.sh` already creates `DATA_ROOT/ui-data/`).

### 1. Configure

```bash
git clone https://github.com/mluettermann/certificate-resolver-ui.git
cd certificate-resolver-ui
cp .env-example .env        # same DATA_ROOT / LOG_ROOT as the resolver
sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$(openssl rand -hex 32)/" .env
```

### 2. Choose how the UI is reached

The base `docker-compose.yml` contains **no reverse proxy** and binds the UI to `127.0.0.1:5050` only, so it is never exposed unencrypted by accident. Put a TLS reverse proxy in front of it:

| Variant | Files | Start |
|---|---|---|
| **Traefik** (labels) | [`deploy/traefik/docker-compose.traefik.yml`](deploy/traefik/docker-compose.traefik.yml) | `docker compose -f docker-compose.yml -f deploy/traefik/docker-compose.traefik.yml up -d` |
| **Caddy** on the host | [`deploy/caddy/Caddyfile`](deploy/caddy/Caddyfile) | `docker compose up -d`, add the site block to your Caddyfile |
| **nginx** on the host | [`deploy/nginx/cert-ui.conf`](deploy/nginx/cert-ui.conf) | `docker compose up -d`, add the server block to nginx |
| **Caddy / nginx / NPM as a container** | [`deploy/proxy-network/docker-compose.proxy-network.yml`](deploy/proxy-network/docker-compose.proxy-network.yml) + the config above | `docker compose -f docker-compose.yml -f deploy/proxy-network/docker-compose.proxy-network.yml up -d`, upstream `certificate-resolver-ui:5000` |
| **No proxy** (admin only) | — | `docker compose up -d`, then `ssh -L 5050:127.0.0.1:5050 <host>` and open `http://localhost:5050` |

For every TLS variant set `SECURE_COOKIES=true` in `.env`. Traefik additionally needs `DOMAIN` (and optionally `TRAEFIK_NETWORK` / `TRAEFIK_ENTRYPOINT`); the container-proxy variant needs `PROXY_NETWORK`.

The proxy's TLS certificate can come from the resolver itself — deliver it with an `ssh` target in `cert-targets.yml`. That also works for a UI that is only reachable internally.

**Portainer:** create the stack from this Git repository with *Compose path* `docker-compose.yml`; for Traefik or a container proxy add the matching override file under *Additional paths*. Set the variables from `.env-example` as stack environment variables.

### 3. First login

On first start the UI creates an `admin` account. If `ADMIN_PASSWORD` is not set, a random password is generated and printed once — retrieve it with:

```bash
docker compose logs cert-ui | grep -A2 "Initial admin"
```

A password change and 2FA setup are enforced on first login.
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

The container paths (`DATA_DIR`, `LOG_DIR`, `CERT_DIR`, `CREDS_FILE`, `TARGETS_FILE`) are already set in `docker-compose.yml`; on the host side you only set `DATA_ROOT`, `LOG_ROOT` (and, depending on the proxy variant, `DOMAIN` / `PROXY_NETWORK`) in `.env`.

---

## Local development

```bash
cd app
pip install -r requirements.txt
DATA_DIR=./data ADMIN_PASSWORD=admin SECRET_KEY=dev python app.py
# → http://localhost:5000  (Flask dev server; production uses gunicorn)
```

To test a locally built image, build it with `docker build` (see above) and start the stack as usual (needs a running resolver container on the same host).

---

## Troubleshooting

**UI not reachable behind Traefik:** verify `DOMAIN` is set, and that both Traefik and `cert-ui` share the `traefik_proxy` network. Test the backend directly:
```bash
docker run --rm --network traefik_proxy curlimages/curl -s http://certificate-resolver-ui:5000/health
```

**nginx/Caddy: live output of issue/renew only appears at the end:** response buffering is on — keep `proxy_buffering off` (nginx) / `flush_interval -1` (Caddy) from the example configs.

**Login loops back to the login page:** `SECURE_COOKIES=true` but the UI is opened over plain HTTP (or the other way round behind TLS: keep it `true`).

**Actions fail with "No such container":** `RESOLVER_CONTAINER` must match the resolver's `container_name` (default `certificate-resolver`), and the resolver must be running.

---

## Project structure

```
.
├── docker-compose.yml           # base stack (no proxy, 127.0.0.1:5050)
├── deploy/
│   ├── traefik/                 # override: Traefik labels + network
│   ├── caddy/                   # Caddyfile site block
│   ├── nginx/                   # nginx server block
│   └── proxy-network/           # override: join a containerized proxy's network
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

## Versions & updates

Releases follow [Semantic Versioning](https://semver.org/) and are created automatically by [release-please](https://github.com/googleapis/release-please) from the commit history; see [CHANGELOG.md](CHANGELOG.md) and the GitHub releases. Every release publishes these image tags:

| Tag | Meaning |
|---|---|
| `1.2.3` | exactly this release |
| `1.2` | newest patch release of 1.2 |
| `1` | newest 1.x release — **default in `docker-compose.yml`** |
| `latest` | newest release, including breaking major versions |
| `edge` | current `main` branch, untested |

The compose file uses `${UI_TAG:-1}`, so automatic updaters such as Watchtower pick up fixes and new features, but never a breaking major release. Set `UI_TAG` in `.env` to pin something else.

### Compatibility

| UI | Resolver |
|---|---|
| 1.x | ≥ 1.0 |

### Contributing: commit messages

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) — they decide the next version number:

| Prefix | Example | Release |
|---|---|---|
| `fix:` | `fix: handle empty cert-targets.yml` | patch (1.0.**1**) |
| `feat:` | `feat: add proxmox backup server target` | minor (1.**1**.0) |
| `feat!:` / `BREAKING CHANGE:` footer | `feat!: rename UI_SECRET_KEY` | major (**2**.0.0) |
| `docs:`, `chore:`, `ci:`, `refactor:` | `docs: fix typo` | no release |

---

## Security

The UI mounts the Docker socket and can trigger certificate issuance and deployment to all configured targets. Please read [SECURITY.md](SECURITY.md) before exposing it.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
