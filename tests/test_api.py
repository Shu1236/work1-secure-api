"""Protected endpoints, JWT enforcement, SQLi/XSS defences, error contract."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from .conftest import PASSWORD, USERNAME


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _b64(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _claims(app, **overrides):
    now = datetime.now(timezone.utc)
    claims = {
        "iss": app.config["JWT_ISSUER"],
        "sub": "1",
        "username": USERNAME,
        "role": "user",
        "nbf": int(now.timestamp()),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": "unit-test",
    }
    claims.update(overrides)
    return claims


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
def test_health_is_public(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Access control on /api/data
# ---------------------------------------------------------------------------
def test_data_without_token_is_rejected(client):
    response = client.get("/api/data")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Bearer")
    assert response.get_json()["error"]["code"] == "unauthorized"


def test_data_with_non_bearer_scheme_is_rejected(client):
    response = client.get("/api/data", headers={"Authorization": "Basic YWxpY2U6cHc="})
    assert response.status_code == 401


def test_data_with_garbage_token_is_rejected(client):
    response = client.get("/api/data", headers={"Authorization": "Bearer not.a.jwt"})
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "invalid_token"


def test_data_with_wrong_secret_is_rejected(app, client):
    forged = jwt.encode(
        _claims(app), "the-wrong-signing-key-but-long-enough-plus", algorithm="HS256"
    )
    response = client.get("/api/data", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "invalid_token"


def test_data_with_expired_token_is_rejected(app, client):
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    expired = jwt.encode(
        _claims(
            app,
            iat=int((past - timedelta(minutes=30)).timestamp()),
            nbf=int((past - timedelta(minutes=30)).timestamp()),
            exp=int(past.timestamp()),
        ),
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )
    response = client.get("/api/data", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "token_expired"


def test_data_with_alg_none_token_is_rejected(app, client):
    """Classic JWT attack: drop the signature and claim alg=none."""
    unsigned = (
        f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(_claims(app))}."
    )
    response = client.get("/api/data", headers={"Authorization": f"Bearer {unsigned}"})
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "invalid_token"


def test_data_with_wrong_issuer_is_rejected(app, client):
    token = jwt.encode(
        _claims(app, iss="somebody-else"), app.config["JWT_SECRET"], algorithm="HS256"
    )
    response = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_data_with_valid_token_returns_items(client, auth_headers):
    created = client.post(
        "/api/posts",
        json={"title": "Hello", "body": "first post"},
        headers=auth_headers,
    )
    assert created.status_code == 201

    response = client.get("/api/data", headers=auth_headers)
    assert response.status_code == 200
    body = response.get_json()
    assert body["count"] == 1
    assert body["total"] == 1
    assert body["items"][0]["title"] == "Hello"
    assert body["items"][0]["author"] == USERNAME


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------
def test_sqli_in_login_does_not_bypass_authentication(client):
    client.post("/auth/register", json={"username": USERNAME, "password": PASSWORD})
    for payload in (
        "alice' OR '1'='1",
        "alice' --",
        "admin' OR 1=1 --",
        "' OR 1=1 LIMIT 1 --",
    ):
        response = client.post(
            "/auth/login", json={"username": payload, "password": "anything-123"}
        )
        assert response.status_code in (400, 401), payload
        assert "access_token" not in response.get_data(as_text=True)


def test_sqli_in_search_is_not_injectable(client, auth_headers):
    """A quote in ?q= must be treated as a literal character, not as SQL."""
    for title in ("alpha", "beta", "gamma"):
        client.post("/api/posts", json={"title": title, "body": title * 2}, headers=auth_headers)

    all_posts = client.get("/api/data", headers=auth_headers).get_json()
    assert all_posts["total"] == 3

    for payload in ("' OR 1=1 --", "%' OR '1'='1", "'; DROP TABLE posts; --", "%"):
        response = client.get("/api/data", query_string={"q": payload}, headers=auth_headers)
        assert response.status_code == 200
        # The wildcard is escaped, so "%" is a literal and finds nothing;
        # the other payloads are literal strings that match no title.
        assert response.get_json()["total"] == 0, payload

    # The table is obviously still there.
    assert client.get("/api/data", headers=auth_headers).get_json()["total"] == 3


def test_search_filters_by_literal_substring(client, auth_headers):
    client.post("/api/posts", json={"title": "secure coding", "body": "x"}, headers=auth_headers)
    client.post("/api/posts", json={"title": "other", "body": "y"}, headers=auth_headers)
    response = client.get("/api/data", query_string={"q": "secur"}, headers=auth_headers)
    assert response.get_json()["total"] == 1


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------
def test_xss_payload_is_escaped_on_output(client, auth_headers):
    payload = '<script>alert("xss")</script>'
    created = client.post(
        "/api/posts", json={"title": payload, "body": payload}, headers=auth_headers
    )
    assert created.status_code == 201

    raw = client.get("/api/data", headers=auth_headers).get_data(as_text=True)
    assert "<script>" not in raw
    assert "&lt;script&gt;" in raw

    item = client.get("/api/data", headers=auth_headers).get_json()["items"][0]
    assert item["title"] == "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"


def test_xss_payload_in_username_is_escaped(client):
    """Usernames are restricted by a pattern, so this one is rejected."""
    response = client.post(
        "/auth/register", json={"username": "<img src=x>", "password": PASSWORD}
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Write endpoint validation
# ---------------------------------------------------------------------------
def test_create_post_requires_authentication(client):
    response = client.post("/api/posts", json={"title": "t", "body": "b"})
    assert response.status_code == 401


def test_create_post_validates_input(client, auth_headers):
    assert client.post("/api/posts", json={"title": "", "body": "b"}, headers=auth_headers).status_code == 400
    assert client.post("/api/posts", json={"body": "b"}, headers=auth_headers).status_code == 400
    long_title = "x" * 201
    response = client.post(
        "/api/posts", json={"title": long_title, "body": "b"}, headers=auth_headers
    )
    assert response.status_code == 400


def test_create_post_rejects_non_json(client, auth_headers):
    response = client.post(
        "/api/posts", data="title=x", content_type="text/plain", headers=auth_headers
    )
    assert response.status_code == 415


# ---------------------------------------------------------------------------
# /api/me
# ---------------------------------------------------------------------------
def test_me_returns_profile_and_claims(client, auth_headers):
    response = client.get("/api/me", headers=auth_headers)
    assert response.status_code == 200
    body = response.get_json()
    assert body["user"]["username"] == USERNAME
    assert body["token"]["sub"] == str(body["user"]["id"])
    assert body["token"]["expires_at"] > 0


def test_me_requires_token(client):
    assert client.get("/api/me").status_code == 401


# ---------------------------------------------------------------------------
# Query-parameter validation and error contract
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"limit": "abc"}])
def test_pagination_parameters_are_validated(client, auth_headers, params):
    assert client.get("/api/data", query_string=params, headers=auth_headers).status_code == 400


def test_unknown_route_returns_json_404(client):
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "not_found"


def test_wrong_method_returns_json_405(client):
    response = client.get("/auth/login")
    assert response.status_code == 405
    assert response.get_json()["error"]["code"] == "method_not_allowed"


def test_oversized_body_is_rejected(client, auth_headers):
    big = {"title": "t", "body": "x" * (70 * 1024)}
    response = client.post("/api/posts", json=big, headers=auth_headers)
    assert response.status_code == 413


def test_security_headers_are_present(client):
    headers = client.get("/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in headers["Content-Security-Policy"]
