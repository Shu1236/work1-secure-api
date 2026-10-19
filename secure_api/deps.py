"""Authentication dependency: the JWT guard used by every protected endpoint."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable

import jwt
from flask import current_app, g, request

from .errors import ApiError
from .security import decode_token


def _extract_bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


def _unauthorized(message: str, code: str) -> ApiError:
    return ApiError(
        message,
        401,
        code,
        headers={"WWW-Authenticate": 'Bearer realm="api", error="invalid_token"'},
    )


def current_claims() -> dict[str, Any]:
    """Validate the request's bearer token and return its verified claims."""
    token = _extract_bearer_token()
    if token is None:
        raise _unauthorized(
            "authentication required: send 'Authorization: Bearer <token>'", "unauthorized"
        )

    config = current_app.config
    try:
        return decode_token(
            token,
            secret=config["JWT_SECRET"],
            algorithm=config["JWT_ALGORITHM"],
            issuer=config["JWT_ISSUER"],
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("token has expired, sign in again", "token_expired") from None
    except jwt.PyJWTError:
        # Bad signature, wrong algorithm (incl. alg=none), wrong issuer,
        # malformed token, missing claims — the client sees one message.
        raise _unauthorized("invalid token", "invalid_token") from None


def jwt_required(view: Callable) -> Callable:
    """Reject the request unless it carries a valid, unexpired JWT."""

    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any):
        claims = current_claims()
        g.jwt_claims = claims
        g.current_user_id = int(claims["sub"])
        g.current_username = claims.get("username")
        return view(*args, **kwargs)

    return wrapper
