"""Request validation.

Expensive/unsafe input never reaches the database: every field is type-checked,
length-checked and pattern-checked first. Validation errors are deliberately
specific about *what* is wrong (the client sent it) and never echo it back.
"""

from __future__ import annotations

import re
from typing import Any

from flask import current_app, request

from .errors import ApiError

# 3-32 chars, must start alphanumeric, then letters/digits/_ . -
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")


def json_object() -> dict[str, Any]:
    """Return the request body as a dict, or fail with 400/415."""
    if not request.is_json:
        raise ApiError(
            "Content-Type must be application/json", 415, "unsupported_media_type"
        )
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ApiError("request body must be a JSON object", 400, "invalid_body")
    return body


def username_field(body: dict[str, Any], name: str = "username") -> str:
    value = body.get(name)
    if not isinstance(value, str):
        raise ApiError(f"'{name}' is required and must be a string", 400, "invalid_username")
    value = value.strip()
    if not USERNAME_RE.fullmatch(value):
        raise ApiError(
            "username must be 3-32 characters: letters, digits, '_', '.', '-' "
            "(must start with a letter or digit)",
            400,
            "invalid_username",
        )
    return value


def password_field(body: dict[str, Any], *, min_length: int) -> str:
    value = body.get("password")
    if not isinstance(value, str):
        raise ApiError("'password' is required and must be a string", 400, "invalid_password")
    if len(value) < min_length:
        raise ApiError(
            f"password must be at least {min_length} characters long",
            400,
            "weak_password",
        )
    max_bytes = current_app.config["MAX_PASSWORD_BYTES"]
    if len(value.encode("utf-8")) > max_bytes:
        # bcrypt only looks at the first 72 bytes -> anything longer is a
        # silent truncation (two different passwords would be equivalent).
        raise ApiError(
            f"password must be at most {max_bytes} bytes long", 400, "password_too_long"
        )
    return value


def text_field(
    body: dict[str, Any], name: str, *, max_length: int, required: bool = True
) -> str:
    value = body.get(name)
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ApiError(f"'{name}' is required and must be a string", 400, f"invalid_{name}")
    value = value.strip()
    if required and not value:
        raise ApiError(f"'{name}' must not be empty", 400, f"invalid_{name}")
    if len(value) > max_length:
        raise ApiError(
            f"'{name}' must be at most {max_length} characters", 400, f"invalid_{name}"
        )
    return value


def int_query(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ApiError(f"'{name}' must be an integer", 400, "invalid_query") from None
    if not minimum <= value <= maximum:
        raise ApiError(
            f"'{name}' must be between {minimum} and {maximum}", 400, "invalid_query"
        )
    return value
