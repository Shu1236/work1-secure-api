"""SQLite access layer.

Every statement in this module is a static string executed with *bound*
parameters (``:name`` placeholders). No value is ever interpolated into SQL
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_posts_author_id ON posts(author_id);
"""

# Static SQL. The optional search term is a bound parameter used twice; when it
# is NULL the WHERE clause collapses to "true" and no filtering happens.
SELECT_POSTS = """
SELECT p.id, p.title, p.body, p.created_at, u.username AS author
FROM posts AS p
JOIN users AS u ON u.id = p.author_id
WHERE (:q IS NULL OR p.title LIKE :q ESCAPE '\\' OR p.body LIKE :q ESCAPE '\\')
ORDER BY p.id DESC
LIMIT :limit OFFSET :offset
"""

COUNT_POSTS = """
SELECT COUNT(*) AS total
FROM posts
WHERE (:q IS NULL OR title LIKE :q ESCAPE '\\' OR body LIKE :q ESCAPE '\\')
"""

SELECT_USER_BY_USERNAME = """
SELECT id, username, password_hash, role, created_at
FROM users
WHERE username = :username
"""

SELECT_USER_BY_ID = """
SELECT id, username, role, created_at
FROM users
WHERE id = :id
"""

INSERT_USER = """
INSERT INTO users (username, password_hash) VALUES (:username, :password_hash)
"""

INSERT_POST = """
INSERT INTO posts (author_id, title, body)
VALUES (:author_id, :title, :body)
"""

SELECT_POST_BY_ID = """
SELECT p.id, p.title, p.body, p.created_at, u.username AS author
FROM posts AS p
JOIN users AS u ON u.id = p.author_id
WHERE p.id = :id
"""


# ---------------------------------------------------------------------------
# Connection lifecycle
# ---------------------------------------------------------------------------
def connect(db_path: str) -> sqlite3.Connection:
    directory = os.path.dirname(os.path.abspath(db_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def get_db() -> sqlite3.Connection:
    """One connection per request, closed by ``close_db`` on teardown."""
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db(db_path: str) -> None:
    """Create tables (idempotent)."""
    connection = connect(db_path)
    try:
        connection.executescript(SCHEMA)
        connection.commit()
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------
def find_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(SELECT_USER_BY_USERNAME, {"username": username}).fetchone()


def find_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute(SELECT_USER_BY_ID, {"id": user_id}).fetchone()


def create_user(conn: sqlite3.Connection, username: str, password_hash: str) -> int:
    """Insert a user; raises sqlite3.IntegrityError on duplicate username."""
    cursor = conn.execute(INSERT_USER, {"username": username, "password_hash": password_hash})
    conn.commit()
    return int(cursor.lastrowid)


def create_post(conn: sqlite3.Connection, author_id: int, title: str, body: str) -> int:
    cursor = conn.execute(INSERT_POST, {"author_id": author_id, "title": title, "body": body})
    conn.commit()
    return int(cursor.lastrowid)


def get_post(conn: sqlite3.Connection, post_id: int) -> sqlite3.Row | None:
    return conn.execute(SELECT_POST_BY_ID, {"id": post_id}).fetchone()


def list_posts(
    conn: sqlite3.Connection, *, like: str | None, limit: int, offset: int
) -> list[sqlite3.Row]:
    rows = conn.execute(SELECT_POSTS, {"q": like, "limit": limit, "offset": offset}).fetchall()
    return list(rows)


def count_posts(conn: sqlite3.Connection, *, like: str | None) -> int:
    row = conn.execute(COUNT_POSTS, {"q": like}).fetchone()
    return int(row["total"]) if row else 0


# ---------------------------------------------------------------------------
# Demo seed (used by `flask init-db`)
# ---------------------------------------------------------------------------
def seed_demo(conn: sqlite3.Connection, demo_username: str, demo_password: str,
              demo_rounds: int) -> bool:
    """Create the demo user and a few posts; returns False if already seeded."""
    from .security import hash_password

    if find_user_by_username(conn, demo_username) is not None:
        return False

    user_id = create_user(conn, demo_username, hash_password(demo_password, demo_rounds))
    demo_posts: list[tuple[str, str]] = [
        ("Welcome to the secure API", "This post lives in SQLite and is served over JWT-protected endpoints."),
        ("XSS demo payload", '<script>alert("stored-xss")</script>'),
        ("Search me", "Try GET /api/data?q=secure to filter posts."),
    ]
    for title, body in demo_posts:
        create_post(conn, user_id, title, body)
    return True


def as_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}
