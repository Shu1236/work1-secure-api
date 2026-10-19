"""Shared pytest fixtures: a throw-away app instance + database per test."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_api import create_app  # noqa: E402
from secure_api.db import init_db  # noqa: E402

TEST_SECRET = "unit-test-secret-0123456789-abcdefghijklmnop"
USERNAME = "alice"
PASSWORD = "Alice-Str0ng-Pass!"

DEFAULT_OVERRIDES = {
    "TESTING": True,
    "JWT_SECRET": TEST_SECRET,
    "JWT_TTL_MINUTES": 30,
    "BCRYPT_ROUNDS": 4,          # keep the test suite fast
    "LOGIN_MAX_ATTEMPTS": 100,   # throttling is tested separately
    "LOGIN_WINDOW_SECONDS": 300,
    "ALLOW_REGISTRATION": True,
}


@pytest.fixture()
def app_factory(tmp_path):
    """Build isolated app instances (each with its own SQLite file)."""
    created = []

    def _make(**overrides):
        config = dict(DEFAULT_OVERRIDES)
        config.update(overrides)
        config["DB_PATH"] = str(tmp_path / f"test-{len(created)}.db")
        application = create_app(config)
        init_db(config["DB_PATH"])
        created.append(application)
        return application

    yield _make

    for application in created:
        application.extensions["login_throttle"].reset_all()


@pytest.fixture()
def app(app_factory):
    return app_factory()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_headers(client):
    """A logged-in alice, returning the Authorization header."""
    assert client.post("/auth/register", json={"username": USERNAME, "password": PASSWORD}).status_code == 201
    response = client.post("/auth/login", json={"username": USERNAME, "password": PASSWORD})
    assert response.status_code == 200
    token = response.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
