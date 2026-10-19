"""Configuration loaded from environment variables (see .env.example)."""

import os


def _int_env(name: str, default: int) -> int:
    """Read an integer from the environment, falling back to *default*."""
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    # --- storage -------------------------------------------------------
    DB_PATH = os.environ.get("DB_PATH", "data/app.db")

    # --- JWT -----------------------------------------------------------
    JWT_SECRET = os.environ.get("JWT_SECRET")  # required, validated in create_app()
    JWT_ALGORITHM = "HS256"                    # must stay an allow-list of one
    JWT_ISSUER = "hdu-is-work1-secure-api"
    JWT_TTL_MINUTES = _int_env("JWT_TTL_MINUTES", 30)

    # --- password hashing ----------------------------------------------
    BCRYPT_ROUNDS = _int_env("BCRYPT_ROUNDS", 12)

    # --- login throttling ----------------------------------------------
    LOGIN_MAX_ATTEMPTS = _int_env("LOGIN_MAX_ATTEMPTS", 10)
    LOGIN_WINDOW_SECONDS = _int_env("LOGIN_WINDOW_SECONDS", 300)

    # --- behaviour ------------------------------------------------------
    ALLOW_REGISTRATION = _bool_env("ALLOW_REGISTRATION", True)

    # --- input policy ---------------------------------------------------
    MIN_PASSWORD_LENGTH = 10
    MAX_PASSWORD_BYTES = 72   # bcrypt silently ignores anything past 72 bytes
    MAX_USERNAME_LENGTH = 32
    MAX_TITLE_LENGTH = 200
    MAX_BODY_LENGTH = 5000
