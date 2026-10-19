"""POST /auth/register and POST /auth/login."""

from __future__ import annotations

import sqlite3

from flask import Blueprint, current_app, jsonify, request

from . import db, validators
from .errors import ApiError
from .security import (
    AUTH_SCHEME,
    burn_hash_time,
    hash_password,
    issue_token,
    sanitize,
    verify_password,
)

bp = Blueprint("auth", __name__, url_prefix="/auth")


def _throttle_key(username: str) -> str:
    # Keyed on client IP *and* username: one noisy attacker cannot lock a
    # legitimate user out from a different address, and password spraying
    # across many accounts is still slowed down per account.
    return f"{request.remote_addr or 'unknown'}|{username.lower()}"


@bp.post("/register")
def register():
    if not current_app.config["ALLOW_REGISTRATION"]:
        raise ApiError("self-registration is disabled", 403, "registration_disabled")

    body = validators.json_object()
    username = validators.username_field(body)
    password = validators.password_field(
        body, min_length=current_app.config["MIN_PASSWORD_LENGTH"]
    )

    password_hash = hash_password(password, current_app.config["BCRYPT_ROUNDS"])
    try:
        user_id = db.create_user(db.get_db(), username, password_hash)
    except sqlite3.IntegrityError:
        # UNIQUE constraint — do not reveal more than necessary.
        raise ApiError("username is already taken", 409, "username_taken") from None

    current_app.logger.info("new user registered: id=%s username=%r", user_id, username)
    return jsonify({"id": user_id, "username": sanitize(username), "created": True}), 201


@bp.post("/login")
def login():
    body = validators.json_object()
    username = validators.username_field(body)
    password = validators.password_field(body, min_length=1)

    throttle = current_app.extensions["login_throttle"]
    key = _throttle_key(username)
    wait = throttle.retry_after(key)
    if wait > 0:
        raise ApiError(
            f"too many failed login attempts, retry in {wait}s",
            429,
            "too_many_attempts",
            headers={"Retry-After": str(wait)},
        )

    row = db.find_user_by_username(db.get_db(), username)
    if row is None:
        # Same amount of CPU work as a real check -> no user enumeration by
        # response time.
        burn_hash_time()
        throttle.record_failure(key)
        current_app.logger.warning(
            "login failed (unknown user): username=%r ip=%s", username, request.remote_addr
        )
        raise ApiError("invalid username or password", 401, "invalid_credentials")

    if not verify_password(password, row["password_hash"]):
        throttle.record_failure(key)
        current_app.logger.warning(
            "login failed (bad password): username=%r ip=%s", username, request.remote_addr
        )
        # One message for "no such user" and "wrong password" alike.
        raise ApiError("invalid username or password", 401, "invalid_credentials")

    throttle.reset(key)
    token, ttl = issue_token(
        {"id": row["id"], "username": row["username"], "role": row["role"]},
        secret=current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"],
        issuer=current_app.config["JWT_ISSUER"],
        ttl_minutes=current_app.config["JWT_TTL_MINUTES"],
    )
    current_app.logger.info("login ok: username=%r id=%s", row["username"], row["id"])
    return jsonify(
        {
            "access_token": token,
            "token_type": AUTH_SCHEME,
            "expires_in": ttl,
            "user": {
                "id": row["id"],
                "username": sanitize(row["username"]),
                "role": sanitize(row["role"]),
            },
        }
    )
