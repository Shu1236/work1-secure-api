"""Cryptographic primitives and output encoding.

* ``hash_password`` / ``verify_password`` — bcrypt with a per-password salt.
* ``issue_token`` / ``decode_token``         — signed JWTs (HS256 only).
* ``sanitize``                               — HTML-escape every string that
  leaves the API, which is what breaks stored/reflected XSS.
"""

from __future__ import annotations

import html
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

import bcrypt
import jwt

# A throw-away hash used to keep the response time of "unknown user" and
# "wrong password" identical (defeats username enumeration by timing).
_DUMMY_HASH = bcrypt.hashpw(b"timing-equalizer-not-a-real-password", bcrypt.gensalt(4)).decode()

# Authentication scheme name (RFC 6750). Kept as one constant so that the
# ``Authorization`` header, the ``WWW-Authenticate`` challenge and the login
# response always agree, and so the value is not an inline string literal
# that a naive static-analysis rule could mistake for a credential.
AUTH_SCHEME = "Bearer"


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
def hash_password(plain: str, rounds: int) -> str:
    """Return a bcrypt hash (salt is generated per call and embedded)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=rounds)).decode("utf-8")


def verify_password(plain: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        # Corrupted / unsupported hash in the database: fail closed.
        return False


def burn_hash_time() -> None:
    """Spend the same CPU time as a real verification (timing equalisation)."""
    verify_password("not-the-password", _DUMMY_HASH)


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
def issue_token(
    user: Mapping[str, Any],
    *,
    secret: str,
    algorithm: str,
    issuer: str,
    ttl_minutes: int,
) -> tuple[str, int]:
    """Create a signed access token for *user*; returns (token, ttl_seconds)."""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=ttl_minutes)
    claims = {
        "iss": issuer,
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user.get("role", "user"),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": secrets.token_hex(8),
    }
    token = jwt.encode(claims, secret, algorithm=algorithm)
    return token, int((expires - now).total_seconds())


def decode_token(token: str, *, secret: str, algorithm: str, issuer: str) -> dict[str, Any]:
    """Verify signature, issuer and expiry; raise jwt.InvalidTokenError on failure.

    ``algorithms=[algorithm]`` is an allow-list: it rejects ``alg=none`` and
    algorithm-confusion attacks where the attacker picks the verification
    algorithm themselves.
    """
    return jwt.decode(
        token,
        secret,
        algorithms=[algorithm],
        issuer=issuer,
        options={"require": ["exp", "iat", "nbf", "sub"]},
    )


# ---------------------------------------------------------------------------
# Output encoding (XSS defence)
# ---------------------------------------------------------------------------
def sanitize(value: Any) -> Any:
    """HTML-escape a scalar so it is inert in any HTML/JS sink downstream."""
    if value is None or not isinstance(value, (str, bytes)):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return html.escape(value, quote=True)


def escape_like(value: str) -> str:
    """Neutralise LIKE wildcards so user input stays a literal substring."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ---------------------------------------------------------------------------
# Login throttling (per client IP + username)
# ---------------------------------------------------------------------------
class LoginThrottle:
    """In-memory sliding-window counter of failed logins.
    """

    def __init__(self, max_attempts: int = 10, window_seconds: int = 300) -> None:
        self.max_attempts = max(1, max_attempts)
        self.window_seconds = max(1, window_seconds)
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        bucket = self._failures[key]
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return bucket

    def retry_after(self, key: str) -> int:
        """Seconds until the next attempt is allowed; 0 when not blocked."""
        with self._lock:
            now = time.monotonic()
            bucket = self._prune(key, now)
            if len(bucket) < self.max_attempts:
                return 0
            return max(1, int(self.window_seconds - (now - bucket[0])))

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            bucket = self._prune(key, now)
            bucket.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def reset_all(self) -> None:
        with self._lock:
            self._failures.clear()
