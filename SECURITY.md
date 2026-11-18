# Security

This UI is part of the [Certificate Resolver](https://github.com/mluettermann/certificate_resolver) stack. Please also read the resolver's [SECURITY.md](https://github.com/mluettermann/certificate_resolver/blob/main/SECURITY.md).

## What the UI can do

- It mounts the **Docker socket** (`/var/run/docker.sock`) to control the resolver container. Access to the socket is equivalent to root on the Docker host.
- It can **issue, renew and delete certificates** and **edit `cert-targets.yml`**, which controls where certificates and private keys are deployed.
- It reads the **acme-dns credentials** of all registered domains.

## Recommendations

- Serve the UI **only behind TLS** (Traefik, Caddy or nginx — see `deploy/`) and set `SECURE_COOKIES=true`. The base compose binds it to `127.0.0.1` only; keep it that way unless you know why.
- Preferably restrict access to a **VPN or internal network**; do not expose it directly to the internet.
- Use a strong, random `SECRET_KEY` (`openssl rand -hex 32`). The app refuses to start without one.
- Enable **2FA for every user**, give users the lowest role they need (`viewer` / `technician` / `admin`), and review the audit log regularly.
- Keep the UI's data folder (`users.json`, `audit.log`) out of backups that others can read — it contains password hashes and 2FA secrets.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting instead: *Security → Report a vulnerability* in this repository.
