"""Authentication: registration, login, password storage, JWT issuance."""

from __future__ import annotations

import sqlite3

from secure_api.db import connect

from .conftest import PASSWORD, USERNAME


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
def test_register_creates_user(client):
    response = client.post("/auth/register", json={"username": "bob", "password": PASSWORD})
    assert response.status_code == 201
    body = response.get_json()
    assert body["username"] == "bob"
    assert body["created"] is True
    assert "password" not in response.get_data(as_text=True)


def test_register_rejects_duplicate_username(client):
    payload = {"username": "bob", "password": PASSWORD}
    assert client.post("/auth/register", json=payload).status_code == 201
    second = client.post("/auth/register", json=payload)
    assert second.status_code == 409
    assert second.get_json()["error"]["code"] == "username_taken"


def test_register_rejects_weak_password(client):
    response = client.post("/auth/register", json={"username": "bob", "password": "short"})
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "weak_password"


def test_register_rejects_bad_username(client):
    response = client.post("/auth/register", json={"username": "a b!", "password": PASSWORD})
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "invalid_username"


def test_register_requires_json(client):
    response = client.post("/auth/register", data="username=bob&password=x", content_type="text/plain")
    assert response.status_code == 415


def test_password_is_stored_as_bcrypt_hash(app, client):
    client.post("/auth/register", json={"username": USERNAME, "password": PASSWORD})
    with connect(app.config["DB_PATH"]) as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (USERNAME,)
        ).fetchone()
    stored = row["password_hash"]
    assert stored != PASSWORD
    assert PASSWORD not in stored
    assert stored.startswith("$2b$")          # bcrypt marker
    assert len(stored) == 60                   # bcrypt digest length


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
def test_login_returns_jwt(client, auth_headers):
    assert auth_headers["Authorization"].startswith("Bearer ")
    token = auth_headers["Authorization"].split(" ", 1)[1]
    assert token.count(".") == 2               # header.payload.signature


def test_login_success_payload(client):
    client.post("/auth/register", json={"username": USERNAME, "password": PASSWORD})
    response = client.post("/auth/login", json={"username": USERNAME, "password": PASSWORD})
    body = response.get_json()
    assert response.status_code == 200
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] > 0
    assert body["user"]["username"] == USERNAME
    assert "password_hash" not in response.get_data(as_text=True)


def test_login_wrong_password_is_401_with_generic_message(client):
    client.post("/auth/register", json={"username": USERNAME, "password": PASSWORD})
    response = client.post("/auth/login", json={"username": USERNAME, "password": "wrong-pass-1"})
    assert response.status_code == 401
    error = response.get_json()["error"]
    assert error["code"] == "invalid_credentials"
    assert error["message"] == "invalid username or password"


def test_login_unknown_user_looks_identical(client):
    """No user enumeration: same status, code and message as a wrong password."""
    client.post("/auth/register", json={"username": USERNAME, "password": PASSWORD})
    wrong_password = client.post(
        "/auth/login", json={"username": USERNAME, "password": "wrong-pass-1"}
    )
    unknown_user = client.post(
        "/auth/login", json={"username": "no-such-user", "password": "wrong-pass-1"}
    )
    assert unknown_user.status_code == wrong_password.status_code == 401
    assert unknown_user.get_json() == wrong_password.get_json()


def test_login_throttled_after_repeated_failures(app_factory):
    limited = app_factory(LOGIN_MAX_ATTEMPTS=3)
    client = limited.test_client()
    client.post("/auth/register", json={"username": USERNAME, "password": PASSWORD})

    statuses = [
        client.post("/auth/login", json={"username": USERNAME, "password": "nope-nope-1"}).status_code
        for _ in range(3)
    ]
    assert statuses == [401, 401, 401]

    blocked = client.post("/auth/login", json={"username": USERNAME, "password": PASSWORD})
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"].isdigit()

    # A different username is not affected by alice's lockout.
    other = client.post("/auth/login", json={"username": "someone-else", "password": "nope-nope-1"})
    assert other.status_code == 401


def test_login_requires_json(client):
    response = client.post("/auth/login", data="{}", content_type="text/plain")
    assert response.status_code == 415


def test_user_table_has_no_plaintext_passwords(app, client):
    client.post("/auth/register", json={"username": USERNAME, "password": PASSWORD})
    with connect(app.config["DB_PATH"]) as conn:
        rows = conn.execute("SELECT * FROM users").fetchall()
    dumped = " ".join(str(value) for row in rows for value in tuple(row))
    assert PASSWORD not in dumped


def test_schema_is_initialised(app):
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert {"users", "posts"} <= tables
