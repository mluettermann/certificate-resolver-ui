# SPDX-License-Identifier: GPL-3.0-or-later
"""Gunicorn configuration for certificate-resolver-ui.

Logging policy:
  - STDOUT (docker logs) shows STATUS only (startup, workers, errors).
  - Access logs go to a ROTATING file under DATA_DIR (not stdout).
  - Error/status logs also go to a rotating file, plus stdout.
"""
import os

# Log files go to LOG_DIR (a shared external folder), separate from app data.
_logdir = os.environ.get("LOG_DIR", "/logs")
_max_bytes = int(os.environ.get("LOG_MAX_BYTES", str(10 * 1024 * 1024)))  # 10 MB
_backups = int(os.environ.get("LOG_BACKUPS", "5"))

# ── Server ──────────────────────────────────────────────────────
# Bind only "[::]:5000": on Linux (bindv6only=0) this single socket accepts
# both IPv6 and IPv4 (v4-mapped). gthread handles the streaming endpoint.
bind = "[::]:5000"
workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))
worker_class = "gthread"
timeout = 120
preload_app = True

# Enable access logging (the destination is defined in logconfig_dict below).
accesslog = "-"
errorlog = "-"
loglevel = "info"

# ── Logging: rotating files + status on stdout ──────────────────
logconfig_dict = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "generic": {
            "format": "%(asctime)s [%(process)d] [%(levelname)s] %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "access": {"format": "%(message)s"},
    },
    "handlers": {
        "console": {  # status + errors -> docker logs
            "class": "logging.StreamHandler",
            "formatter": "generic",
            "stream": "ext://sys.stdout",
        },
        "error_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "generic",
            "filename": os.path.join(_logdir, "cert-ui-error.log"),
            "maxBytes": _max_bytes,
            "backupCount": _backups,
        },
        "access_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "access",
            "filename": os.path.join(_logdir, "cert-ui-access.log"),
            "maxBytes": _max_bytes,
            "backupCount": _backups,
        },
    },
    "loggers": {
        "gunicorn.error": {  # startup/status/errors -> stdout + file
            "level": "INFO",
            "handlers": ["console", "error_file"],
            "propagate": False,
            "qualname": "gunicorn.error",
        },
        "gunicorn.access": {  # request logs -> file only (keeps stdout clean)
            "level": "INFO",
            "handlers": ["access_file"],
            "propagate": False,
            "qualname": "gunicorn.access",
        },
    },
    "root": {"level": "INFO", "handlers": ["console"]},
}
