"""Application factory.

``create_app`` is the single place where configuration, blueprints, error
handlers, security headers and CLI commands are wired together, which keeps
tests independent from each other (each test gets a fresh app + database).
"""

from __future__ import annotations

import os
import secrets
from typing import Any

from flask import Flask

from .config import Config

MIN_SECRET_LENGTH = 32


def _resolve_jwt_secret(app: Flask) -> str:
    """Take JWT_SECRET from the environment; refuse weak or missing values."""
    secret = (app.config.get("JWT_SECRET") or "").strip()
    if secret:
        if len(secret) < MIN_SECRET_LENGTH and not app.config.get("TESTING"):
            raise RuntimeError(
                f"JWT_SECRET is too short ({len(secret)} chars). "
                f"Use at least {MIN_SECRET_LENGTH} characters."
            )
        return secret

    if app.config.get("TESTING"):
        return "test-secret-" + "x" * 40

    # No secret configured: generate an ephemeral one instead of shipping a
    # hard-coded default in the repository. Tokens stop working on restart.
    generated = secrets.token_urlsafe(48)
    app.logger.warning(
        "JWT_SECRET is not set - using an ephemeral secret. "
        "Tokens are invalidated on every restart. Set JWT_SECRET in .env"
    )
    return generated


def register_security_headers(app: Flask) -> None:
    @app.after_request
    def _security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
        )
        # API responses carry user data / tokens: never let a proxy or the
        # browser cache them.
        response.headers.setdefault("Cache-Control", "no-store")
        return response


def register_cli(app: Flask) -> None:
    import click

    @app.cli.command("init-db")
    def init_db_command() -> None:
        """Create the SQLite schema and seed demo data."""
        from . import db

        db.init_db(app.config["DB_PATH"])
        demo_user = os.environ.get("DEMO_USER", "alice")
        demo_password = os.environ.get("DEMO_PASSWORD", "Alice-Str0ng-Pass!")
        connection = db.connect(app.config["DB_PATH"])
        try:
            created = db.seed_demo(
                connection, demo_user, demo_password, app.config["BCRYPT_ROUNDS"]
            )
        finally:
            connection.close()
        if created:
            click.echo(f"database ready: {app.config['DB_PATH']}")
            click.echo(f"demo user created: {demo_user} / {demo_password}")
        else:
            click.echo(f"database already initialised: {app.config['DB_PATH']}")


def create_app(overrides: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)

    # Hard limit on request bodies (memory-exhaustion defence).
    if not app.config.get("MAX_CONTENT_LENGTH"):
        app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    app.config["JWT_SECRET"] = _resolve_jwt_secret(app)

    from . import db
    from .security import LoginThrottle

    app.teardown_appcontext(db.close_db)
    app.extensions["login_throttle"] = LoginThrottle(
        max_attempts=app.config["LOGIN_MAX_ATTEMPTS"],
        window_seconds=app.config["LOGIN_WINDOW_SECONDS"],
    )

    from .api import bp as api_bp
    from .auth import bp as auth_bp
    from .errors import register_error_handlers

    register_error_handlers(app)
    register_security_headers(app)
    register_cli(app)

    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)

    return app
