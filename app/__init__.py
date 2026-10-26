"""
Application factory.

Project : Multi-Factor Authentication (MFA) System for Securing Web Applications
Owner   : Yahye Ahmed Adan
Course  : Bachelor of Networks and Cyber Security, ISBAT University, Kampala

The factory pattern keeps configuration out of import time, which is what lets
the test suite build an isolated application per test and lets development and
production differ only by configuration.
"""

import logging
import os
import secrets
from logging.handlers import RotatingFileHandler

from flask import Flask, g, jsonify, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

from .extensions import csrf, db, limiter, migrate

__version__ = "1.0.0"


def create_app(config_name: str | None = None) -> Flask:
    from config import get_config

    app = Flask(__name__, instance_relative_config=False)
    cfg = get_config(config_name)
    app.config.from_object(cfg)

    _finalise_secrets(app)
    _configure_logging(app)

    # Honour X-Forwarded-* when running behind nginx/Gunicorn, so that audit
    # log IP addresses and rate limiting see the real client.
    if app.config.get("TRUST_PROXY_HEADERS", os.environ.get("TRUST_PROXY_HEADERS")):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)

    # Replace Flask's signed-cookie session with the database-backed store, so
    # authentication state really is server-side and logout can revoke it.
    from .security.server_session import ServerSessionInterface

    app.session_interface = ServerSessionInterface()

    app.config["RATELIMIT_ENABLED"] = app.config.get("RATELIMIT_ENABLED", True)
    limiter.init_app(app)

    _register_blueprints(app)
    _register_hooks(app)
    _register_error_handlers(app)
    _register_cli(app)

    with app.app_context():
        from . import models  # noqa: F401  (ensure models are imported for migrations)

    return app


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

def _finalise_secrets(app: Flask) -> None:
    """
    Fail loudly in production when a secret is missing; generate an ephemeral
    one in development and testing so the project can be started quickly.

    An ephemeral key means sessions do not survive a restart — acceptable for
    development, never for production, which is why production refuses instead.
    """
    is_prod = app.config.get("ENV_NAME") == "production"

    if not app.config.get("SECRET_KEY"):
        if is_prod:
            raise RuntimeError(
                "SECRET_KEY must be set in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        app.logger.warning(
            "SECRET_KEY was not set; generated a temporary key. "
            "Sessions will not survive a restart. Set SECRET_KEY in .env."
        )

    if not app.config.get("MFA_ENCRYPTION_KEY"):
        if is_prod:
            raise RuntimeError(
                "MFA_ENCRYPTION_KEY must be set in production. Generate one with: "
                "python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\""
            )
        from cryptography.fernet import Fernet

        app.config["MFA_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
        app.logger.warning(
            "MFA_ENCRYPTION_KEY was not set; generated a temporary key. "
            "Existing enrolled TOTP secrets will not decrypt after a restart. "
            "Set MFA_ENCRYPTION_KEY in .env."
        )


def _configure_logging(app: Flask) -> None:
    level = logging.DEBUG if app.config.get("DEBUG") else logging.INFO
    app.logger.setLevel(level)

    if app.config.get("TESTING"):
        return

    log_dir = os.environ.get("LOG_DIR", "logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
        handler = RotatingFileHandler(
            os.path.join(log_dir, "mfa_app.log"), maxBytes=1_048_576, backupCount=5
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        )
        handler.setLevel(level)
        app.logger.addHandler(handler)
        logging.getLogger("mfa.audit").addHandler(handler)
        logging.getLogger("mfa.audit").setLevel(level)
    except OSError:
        app.logger.warning("Could not open log directory %s; file logging disabled", log_dir)


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def _register_blueprints(app: Flask) -> None:
    from .admin.routes import admin_bp
    from .auth.routes import auth_bp
    from .main.routes import main_bp
    from .mfa.routes import mfa_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(mfa_bp, url_prefix="/mfa")
    app.register_blueprint(admin_bp, url_prefix="/admin")


def _register_hooks(app: Flask) -> None:
    from .security.access import load_current_user
    from .security.session import touch_session

    @app.before_request
    def _before():
        # Idle-timeout check first: an expired session must not be treated as
        # authenticated for the remainder of the request.
        if not touch_session():
            load_current_user()
            if request.path.startswith("/static"):
                return None
            from flask import flash

            flash("Your session timed out after a period of inactivity.", "warning")
            return redirect(url_for("auth.login"))
        load_current_user()
        return None

    @app.after_request
    def _security_headers(response):
        """
        Baseline hardening headers.

        The CSP has no 'unsafe-inline' for scripts: all JavaScript is served
        from static files, so inline script injection has nothing to execute.
        """
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self'; "
            "script-src 'self'; "
            "font-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "object-src 'none'",
        )
        if app.config.get("ENV_NAME") == "production":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.context_processor
    def _inject():
        from .forms import EmptyForm

        return {
            "current_user": g.get("user"),
            "app_version": __version__,
            "csrf_form": EmptyForm(),
            "project_title": "Multi-Factor Authentication System",
        }


def _register_error_handlers(app: Flask) -> None:
    def _wants_json() -> bool:
        return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json"

    @app.errorhandler(400)
    def _400(error):
        if _wants_json():
            return jsonify(error="bad_request"), 400
        return render_template("errors/400.html"), 400

    @app.errorhandler(403)
    def _403(error):
        if _wants_json():
            return jsonify(error="forbidden"), 403
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def _404(error):
        if _wants_json():
            return jsonify(error="not_found"), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(429)
    def _429(error):
        """Rate limit reached. The response deliberately says nothing about
        whether the account exists or the password was close."""
        from .security import audit

        audit.record_event(
            audit.LOGIN_RATE_LIMITED,
            category=audit.CATEGORY_AUTH,
            outcome=audit.OUTCOME_BLOCKED,
            detail=f"rate limit on {request.path}",
        )
        if _wants_json():
            return jsonify(error="too_many_requests"), 429
        return render_template("errors/429.html"), 429

    @app.errorhandler(CSRFError)
    def _csrf(error):
        if _wants_json():
            return jsonify(error="csrf_failed"), 400
        return render_template("errors/csrf.html", reason=error.description), 400

    @app.errorhandler(500)
    def _500(error):
        # Roll back so a failed transaction cannot poison the next request.
        db.session.rollback()
        app.logger.exception("Unhandled server error")
        if _wants_json():
            return jsonify(error="server_error"), 500
        return render_template("errors/500.html"), 500


def _register_cli(app: Flask) -> None:
    from .cli import register_cli_commands

    register_cli_commands(app)
