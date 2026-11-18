# SPDX-License-Identifier: GPL-3.0-or-later
from flask import Flask, render_template, request, redirect, session, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
import subprocess, os, json, datetime, bcrypt, pyotp, secrets, string, base64, re, hmac, fcntl
from dateutil import parser
import qrcode
import yaml
from io import BytesIO
from datetime import timedelta

# ───────── CONFIG (all values can be overridden via environment) ─────────
# A single data directory; all files live underneath it.
DATA_DIR = os.environ.get("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)

# Name of the cert-resolver container (used for docker exec)
DOCKER_CONTAINER = os.environ.get("RESOLVER_CONTAINER", "certificate-resolver")

CERT_DIR     = os.environ.get("CERT_DIR",     os.path.join(DATA_DIR, "certs"))
USERS_FILE   = os.environ.get("USERS_FILE",   os.path.join(DATA_DIR, "users.json"))
AUDIT_FILE   = os.environ.get("AUDIT_FILE",   os.path.join(DATA_DIR, "audit.log"))
CREDS_FILE   = os.environ.get("CREDS_FILE",   os.path.join(DATA_DIR, "acmedns-credentials.json"))
TARGETS_FILE = os.environ.get("TARGETS_FILE", os.path.join(DATA_DIR, "cert-targets.yml"))

app = Flask(__name__)
_secret = os.environ.get("SECRET_KEY", "")
if _secret in ("", "change-me", "supersecretkey"):
    raise RuntimeError(
        "SECRET_KEY is not set (or still the example value). "
        "Generate one with: openssl rand -hex 32"
    )
app.secret_key = _secret

# Idle session timeout in minutes (configurable). After this much inactivity
# the user is logged out and must sign in again.
SESSION_TIMEOUT_MIN = int(os.environ.get("SESSION_TIMEOUT_MINUTES", "30"))
app.permanent_session_lifetime = timedelta(minutes=SESSION_TIMEOUT_MIN)

# ── Session cookie hardening ─────────────────────────────────────
# Secure=True requires HTTPS; enable it (SECURE_COOKIES=true) once the UI
# is served via TLS, otherwise the browser drops the cookie over plain HTTP.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SECURE_COOKIES", "false").lower() in ("1", "true", "yes"),
)

# ── Trust the reverse proxy (Traefik) for the real client IP/scheme ──
# Behind a proxy, request.remote_addr is the proxy. ProxyFix rewrites it from
# X-Forwarded-For so logs and IP-based logic see the real client. PROXY_HOPS =
# number of trusted proxies in front (1 = just Traefik). Disable with
# TRUST_PROXY=false if the app is exposed directly without a proxy.
if os.environ.get("TRUST_PROXY", "true").lower() in ("1", "true", "yes"):
    _hops = int(os.environ.get("PROXY_HOPS", "1"))
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_hops, x_proto=_hops, x_host=_hops, x_port=_hops)


# ───────── Idle session timeout ─────────
@app.before_request
def enforce_session_timeout():
    # Runs before CSRF so an expired session redirects cleanly instead of 400.
    user = session.get("user")
    if not user:
        return
    now = int(datetime.datetime.utcnow().timestamp())
    last = session.get("last_active", now)
    if now - last > SESSION_TIMEOUT_MIN * 60:
        session.clear()
        # Page navigations get a redirect with a message; fetch/XHR get 401
        # so the frontend can react.
        is_page = (request.headers.get("Sec-Fetch-Mode") == "navigate"
                   or "text/html" in request.headers.get("Accept", ""))
        if is_page:
            return redirect("/?expired=1")
        return "Session expired", 401
    session["last_active"] = now


# ───────── CSRF protection ─────────
def generate_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.context_processor
def _inject_csrf():
    # Makes csrf_token() available in all templates.
    return {"csrf_token": generate_csrf}


@app.before_request
def csrf_protect():
    # Validate a CSRF token for all state-changing requests. Browsers send it
    # via a hidden form field (forms) or the X-CSRFToken header (fetch/XHR).
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    token = session.get("csrf_token")
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
    if not token or not sent or not hmac.compare_digest(token, sent):
        return "CSRF validation failed", 400


@app.before_request
def refresh_session():
    if "user" in session:
        session.permanent = True


@app.before_request
def enforce_password_change():
    # Redirect logged-in users who must change their password to /change-password.
    user = session.get("user")
    if not user or not user.get("must_change_password"):
        return
    allowed = {"/change-password", "/logout", "/backup-codes"}
    if request.path in allowed or request.path.startswith("/static"):
        return
    return redirect("/change-password")


# ───────── USERS ─────────
def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE) as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def ensure_default_admin():
    users = load_users()

    admin_user = os.environ.get("ADMIN_USERNAME", "admin")

    if any(u["username"] == admin_user for u in users):
        return

    # Password from the environment - or, if not set, generate a secure
    # random password (NO well-known default anymore).
    admin_pw = os.environ.get("ADMIN_PASSWORD")
    generated = False
    if not admin_pw:
        alphabet = string.ascii_letters + string.digits
        admin_pw = "".join(secrets.choice(alphabet) for _ in range(20))
        generated = True

    default_user = {
        "username": admin_user,
        "password": bcrypt.hashpw(admin_pw.encode(), bcrypt.gensalt()).decode(),
        "role": "admin",
        "otp_secret": None,
        "backup_codes": [],
        "must_change_password": True,
    }

    users.append(default_user)
    save_users(users)

    print("=" * 64, flush=True)
    print(f"  Initial admin account created: {admin_user}", flush=True)
    if generated:
        print(f"  Generated password: {admin_pw}", flush=True)
        print("  >>> WRITE THIS DOWN NOW - it is shown only ONCE! <<<", flush=True)
    else:
        print("  Password: from ADMIN_PASSWORD (environment)", flush=True)
    print("  A password change is required on first login.", flush=True)
    print("=" * 64, flush=True)


def auth(username, password):
    for u in load_users():
        if u["username"] == username:
            if bcrypt.checkpw(password.encode(), u["password"].encode()):
                return u
    return None


# ───────── BACKUP CODES ─────────
def generate_backup_codes():
    codes = []
    for _ in range(8):
        code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        codes.append(code[:4] + "-" + code[4:])
    return codes


def hash_backup_codes(codes):
    return [bcrypt.hashpw(c.encode(), bcrypt.gensalt()).decode() for c in codes]


def verify_backup_code(user, code):
    for i, hashed in enumerate(user.get("backup_codes", [])):
        if bcrypt.checkpw(code.encode(), hashed.encode()):
            del user["backup_codes"][i]

            users = load_users()
            for u in users:
                if u["username"] == user["username"]:
                    u["backup_codes"] = user["backup_codes"]

            save_users(users)
            return True
    return False


# ───────── AUDIT ─────────
def audit(action, target=""):
    user = session.get("user", {}).get("username", "system")
    os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)

    with open(AUDIT_FILE, "a") as f:
        f.write(f"{datetime.datetime.utcnow().isoformat()} | {user} | {action} | {target}\n")


# ───────── UTILS ─────────
def run_stream(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in p.stdout:
        yield line


def get_domains():
    if not os.path.exists(CREDS_FILE):
        return []
    with open(CREDS_FILE) as f:
        data = json.load(f)
    return [d.replace("_acme-challenge.", "") for d in data.keys()]


def get_expiry(domain):
    cert_path = f"{CERT_DIR}/{domain}/cert.pem"

    if not os.path.exists(cert_path):
        return None

    out = subprocess.getoutput(f"openssl x509 -enddate -noout -in {cert_path}")

    try:
        expiry = parser.parse(out.split("=")[1])

        # openssl prints "... GMT", so dateutil returns a timezone-aware
        # datetime. Normalise to naive UTC for a clean subtraction.
        if expiry.tzinfo is not None:
            expiry = expiry.astimezone(datetime.timezone.utc).replace(tzinfo=None)

        days = (expiry - datetime.datetime.utcnow()).days

        status = "ok"
        if days < 30:
            status = "warning"
        if days < 7:
            status = "critical"

        return {"expiry": expiry.isoformat(), "days": days, "status": status}
    except Exception:
        return None


def get_last_renew(domain):
    cert_path = f"{CERT_DIR}/{domain}/cert.pem"
    if not os.path.exists(cert_path):
        return None

    ts = os.path.getmtime(cert_path)
    return datetime.datetime.utcfromtimestamp(ts).isoformat()


def daemon_status():
    try:
        output = subprocess.getoutput(f"docker exec {DOCKER_CONTAINER} ps aux")

        if not output.strip():
            return {"running": False}

        text = output.lower()

        if "renewal-daemon.sh" in text:
            return {"running": True, "type": "daemon"}

        if "acme.sh" in text and "--cron" in text:
            return {"running": True, "type": "cron"}

        return {"running": False}
    except:
        return {"running": False}


def require_role(roles):
    user = session.get("user")
    return user and user["role"] in roles


# ───────── Brute-force throttle ─────────
# Cross-process counter (gunicorn runs multiple workers) stored in a small
# JSON file guarded by an flock. Keyed per account; spans password + 2FA and
# resets only on a fully successful login.
ATTEMPTS_FILE = os.environ.get("LOGIN_ATTEMPTS_FILE", os.path.join(DATA_DIR, "login_attempts.json"))
LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCKOUT_MIN = int(os.environ.get("LOGIN_LOCKOUT_MINUTES", "15"))


def _now():
    return int(datetime.datetime.utcnow().timestamp())


def _with_attempts(mutator):
    os.makedirs(os.path.dirname(ATTEMPTS_FILE), exist_ok=True)
    with open(ATTEMPTS_FILE, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.seek(0)
            raw = f.read().strip()
            data = json.loads(raw) if raw else {}
            result = mutator(data)
            f.seek(0)
            f.truncate()
            json.dump(data, f)
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    return result


def throttle_remaining(key):
    """Seconds the key stays locked, or 0 if allowed."""
    key = (key or "").lower()
    now = _now()

    def m(data):
        e = data.get(key)
        if e and e.get("locked_until", 0) > now:
            return e["locked_until"] - now
        return 0
    return _with_attempts(m)


def throttle_fail(key):
    key = (key or "").lower()
    now = _now()

    def m(data):
        e = data.get(key, {"fails": 0, "locked_until": 0})
        e["fails"] = e.get("fails", 0) + 1
        if e["fails"] >= LOGIN_MAX_ATTEMPTS:
            e["locked_until"] = now + LOGIN_LOCKOUT_MIN * 60
            e["fails"] = 0
        data[key] = e
        # opportunistic cleanup of stale, unlocked entries
        for k in list(data.keys()):
            if data[k].get("locked_until", 0) <= now and data[k].get("fails", 0) == 0:
                del data[k]
        return None
    _with_attempts(m)


def throttle_reset(key):
    key = (key or "").lower()

    def m(data):
        data.pop(key, None)
        return None
    _with_attempts(m)


def lockout_message(seconds):
    minutes = (seconds + 59) // 60
    return f"Too many failed attempts. Please try again in {minutes} minute(s)."


def _qr_data(secret, username):
    """Return a base64 PNG of the TOTP provisioning QR code."""
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="CertUI")
    img = qrcode.make(uri)
    buffer = BytesIO()
    img.save(buffer)
    return base64.b64encode(buffer.getvalue()).decode()


# ───────── AUTH ─────────
@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.args.get("expired"):
        error = "Your session has expired. Please sign in again."

    if request.method == "POST":
        username = request.form.get("username", "")

        remaining = throttle_remaining(username)
        if remaining:
            return render_template("login.html", error=lockout_message(remaining))

        user = auth(username, request.form.get("password", ""))

        if user:
            # Note: do NOT reset the throttle here — it must keep counting across
            # the 2FA step and only reset on a fully successful login.
            session.permanent = True
            session["tmp_user"] = user
            session["last_active"] = int(datetime.datetime.utcnow().timestamp())

            if not user.get("otp_secret"):
                return redirect("/2fa-setup")

            return redirect("/2fa")

        throttle_fail(username)
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/2fa", methods=["GET", "POST"])
def twofa():
    if "tmp_user" not in session:
        return redirect("/")

    user = session["tmp_user"]

    if request.method == "POST":
        remaining = throttle_remaining(user["username"])
        if remaining:
            return render_template("twofa.html", error=lockout_message(remaining))

        code = request.form.get("code", "").strip().replace(" ", "")

        # valid_window=1 tolerates small clock drift (±30s), matching 2FA setup.
        if pyotp.TOTP(user["otp_secret"]).verify(code, valid_window=1) or verify_backup_code(user, code):
            throttle_reset(user["username"])          # full login succeeded
            session.pop("tmp_user")
            session["user"] = user
            return redirect("/dashboard")

        throttle_fail(user["username"])
        return render_template("twofa.html",
            error="Invalid code. Make sure your authenticator's time is in sync, then try again.")

    return render_template("twofa.html", error=None)


@app.route("/2fa-setup", methods=["GET", "POST"])
def twofa_setup():
    if "tmp_user" not in session:
        return redirect("/")

    session_user = session["tmp_user"]

    # Load the real user from file (single source of truth)
    users = load_users()
    real_user = None

    for u in users:
        if u["username"] == session_user["username"]:
            real_user = u
            break

    if not real_user:
        return "user not found", 500

    # Generate the secret only ONCE
    if not real_user.get("otp_secret"):
        real_user["otp_secret"] = pyotp.random_base32()
        save_users(users)

    # Sync the session
    session["tmp_user"] = real_user
    secret = real_user["otp_secret"]

    # POST = verify the code
    if request.method == "POST":
        remaining = throttle_remaining(real_user["username"])
        if remaining:
            return render_template("twofa_setup.html", qr=_qr_data(secret, real_user["username"]),
                                   error=lockout_message(remaining))

        code = request.form.get("code", "").strip().replace(" ", "")

        totp = pyotp.TOTP(secret)

        # Tolerant of clock drift
        if totp.verify(code, valid_window=1):
            throttle_reset(real_user["username"])     # full login succeeded

            # Generate backup codes
            backup_codes = generate_backup_codes()
            real_user["backup_codes"] = hash_backup_codes(backup_codes)
            save_users(users)

            # Show them once
            session["backup_codes"] = backup_codes

            # Complete login
            session.pop("tmp_user")
            session["user"] = real_user

            audit("2fa_setup", real_user["username"])

            return redirect("/backup-codes")

        throttle_fail(real_user["username"])
        return render_template("twofa_setup.html",
                               qr=_qr_data(secret, real_user["username"]),
                               error="Invalid code. Make sure your authenticator's time is in sync, then try again.")

    return render_template("twofa_setup.html",
                           qr=_qr_data(secret, real_user["username"]), error=None)


@app.route("/backup-codes")
def backup_codes():
    codes = session.get("backup_codes")

    if not codes:
        return redirect("/dashboard")

    session.pop("backup_codes")

    return render_template("backup_codes.html", codes=codes)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ───────── CHANGE PASSWORD ─────────
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    user = session.get("user")
    if not user:
        return redirect("/")

    forced = bool(user.get("must_change_password"))

    def render(error=None):
        return render_template("change_password.html", error=error, forced=forced)

    if request.method == "POST":
        old_pw = request.form.get("old", "")
        new_pw = request.form.get("new", "")
        confirm = request.form.get("confirm", "")

        if not bcrypt.checkpw(old_pw.encode(), user["password"].encode()):
            return render("Current password is incorrect.")
        if len(new_pw) < 8:
            return render("New password must be at least 8 characters long.")
        if new_pw != confirm:
            return render("New password and confirmation do not match.")
        if new_pw == old_pw:
            return render("New password must differ from the current one.")

        users = load_users()
        for u in users:
            if u["username"] == user["username"]:
                u["password"] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                u["must_change_password"] = False
                session["user"] = u

        save_users(users)
        audit("password_change", user["username"])

        return redirect("/dashboard")

    return render()


# ───────── UI ─────────
@app.route("/dashboard")
def dashboard():
    if not session.get("user"):
        return redirect("/")
    return render_template("dashboard.html", user=session["user"])


@app.route("/admin/users")
def admin_users_page():
    if not require_role(["admin"]):
        return redirect("/dashboard")
    return render_template("admin_users.html", user=session["user"])


@app.route("/admin/audit")
def admin_audit_page():
    if not require_role(["admin"]):
        return redirect("/dashboard")
    return render_template("audit.html", user=session["user"])


# ───────── Edit YAML ─────────
def load_targets():
    # File schema: { "targets": { "<domain>": [ {type, host, ...}, ... ] } }
    if not os.path.exists(TARGETS_FILE):
        return {}

    with open(TARGETS_FILE) as f:
        data = yaml.safe_load(f) or {}

    return data.get("targets", {}) or {}


def save_targets(mapping):
    with open(TARGETS_FILE, "w") as f:
        yaml.safe_dump({"targets": mapping}, f,
                       default_flow_style=False, sort_keys=False)



# ───────── API ─────────
@app.route("/domains")
def domains():
    return jsonify([
        {
            "domain": d,
            "cert": get_expiry(d),
            "last_renew": get_last_renew(d)
        }
        for d in get_domains()
    ])


# Accept normal domain names only (letters, digits, dots, hyphens).
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                       r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


@app.route("/domains/<domain>", methods=["DELETE"])
def delete_domain(domain):
    if not require_role(["admin", "technician"]):
        return "forbidden", 403

    if not DOMAIN_RE.match(domain):
        return jsonify({"ok": False, "error": "Invalid domain name."}), 400

    # 1. Remove certs + acme-dns registration + acme.sh data inside the resolver.
    output = subprocess.getoutput(
        f"docker exec {DOCKER_CONTAINER} /scripts/delete.sh {domain}")

    # 2. Remove the domain from the distribution config (cert-targets.yml).
    mapping = load_targets()
    removed_from_yaml = domain in mapping
    if removed_from_yaml:
        del mapping[domain]
        save_targets(mapping)

    audit("delete_domain", domain)

    return jsonify({"ok": True, "output": output, "removed_from_yaml": removed_from_yaml})


@app.route("/status")
def status():
    return jsonify({"daemon": daemon_status()})


@app.route("/run", methods=["POST"])
def run():
    if not session.get("user"):
        return "unauthorized", 401

    domain = request.json["domain"]
    action = request.json["action"]
    role = session["user"]["role"]

    if action == "setup" and role != "admin":
        return "forbidden", 403

    if action in ["issue", "renew"] and role not in ["admin", "technician"]:
        return "forbidden", 403

    if action == "deploy" and role not in ["admin", "technician"]:
        return "forbidden", 403

    if action == "setup":
        cmd = f"docker exec {DOCKER_CONTAINER} /scripts/setup.sh {domain}"
    elif action == "issue":
        cmd = f"docker exec {DOCKER_CONTAINER} /scripts/issue.sh {domain}"
    elif action == "deploy":
        cmd = f"docker exec -e CERTDOMAIN={domain} {DOCKER_CONTAINER} /scripts/deploy.sh"
    else:
        cmd = f"docker exec {DOCKER_CONTAINER} acme.sh --home /data/acme --renew -d {domain}"

    audit(action, domain)

    return app.response_class(run_stream(cmd), mimetype="text/plain")


@app.route("/users", methods=["GET"])
def users():
    if not require_role(["admin"]):
        return "forbidden", 403

    return jsonify([
        {"username": u["username"], "role": u["role"]}
        for u in load_users()
    ])


@app.route("/users", methods=["POST"])
def create_user():
    if not require_role(["admin"]):
        return "forbidden", 403

    data = request.json
    users = load_users()

    hashed = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode()

    user = {
        "username": data["username"],
        "password": hashed,
        "role": data["role"],
        "otp_secret": None,
        "backup_codes": []
    }

    users.append(user)
    save_users(users)

    audit("create_user", data["username"])

    return "ok"


@app.route("/users/<username>", methods=["DELETE"])
def delete_user(username):
    if not require_role(["admin"]):
        return "forbidden", 403

    users = [u for u in load_users() if u["username"] != username]
    save_users(users)

    audit("delete_user", username)

    return "ok"


@app.route("/audit")
def get_audit():
    if not require_role(["admin"]):
        return "forbidden", 403

    if not os.path.exists(AUDIT_FILE):
        return jsonify([])

    with open(AUDIT_FILE) as f:
        return jsonify(f.readlines()[-100:])


@app.route("/targets")
def get_targets():
    if not session.get("user"):
        return "unauthorized", 401

    return jsonify(load_targets())


@app.route("/targets", methods=["POST"])
def save_target():
    if not require_role(["admin", "technician"]):
        return "forbidden", 403

    # Expect the full mapping: { "<domain>": [ {type, host, ...}, ... ], ... }
    data = request.json
    if not isinstance(data, dict):
        return "invalid payload: expected an object", 400

    save_targets(data)
    audit("update_targets")

    return "ok"


@app.route("/targets/restart", methods=["POST"])
def restart_resolver():
    if not require_role(["admin", "technician"]):
        return "forbidden", 403

    subprocess.getoutput(f"docker restart {DOCKER_CONTAINER}")
    audit("restart_resolver")

    return "ok"



# ───────── HEALTH ─────────
@app.route("/health")
def health():
    # Unauthenticated liveness probe for Docker/Portainer healthchecks.
    return "ok", 200


@app.route("/favicon.ico")
def favicon():
    # Browsers request /favicon.ico at the root automatically.
    return redirect("/static/favicon.ico")


# ───────── START ─────────
# Run on import as well, so it also executes under gunicorn (production server),
# not only when started via `python app.py`.
ensure_default_admin()

if __name__ == "__main__":
    # Local development server only. In containers gunicorn is used (see Dockerfile).
    # Bind to "::" so it accepts both IPv6 and IPv4 (v4-mapped) on a dual-stack network.
    app.run(host="::", port=5000)
