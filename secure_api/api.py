"""Public and JWT-protected data endpoints."""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request

from . import db, validators
from .deps import jwt_required
from .errors import ApiError
from .security import escape_like, sanitize

bp = Blueprint("api", __name__)


def _post_payload(row) -> dict:
    """Serialise a post row, HTML-escaping every user-controlled string."""
    return {
        "id": row["id"],
        "title": sanitize(row["title"]),
        "body": sanitize(row["body"]),
        "author": sanitize(row["author"]),
        "created_at": row["created_at"],
    }


@bp.get("/health")
def health():
    return jsonify({"status": "ok", "service": "secure-api", "version": "1.0.0"})


@bp.get("/api/data")
@jwt_required
def list_data():
    """Return the post feed. Requires a valid JWT (see deps.jwt_required)."""
    limit = validators.int_query("limit", default=20, minimum=1, maximum=100)
    offset = validators.int_query("offset", default=0, minimum=0, maximum=1_000_000)

    raw_query = (request.args.get("q") or "").strip()[:100]
    like = f"%{escape_like(raw_query)}%" if raw_query else None

    conn = db.get_db()
    rows = db.list_posts(conn, like=like, limit=limit, offset=offset)
    total = db.count_posts(conn, like=like)

    return jsonify(
        {
            "items": [_post_payload(row) for row in rows],
            "count": len(rows),
            "total": total,
            "limit": limit,
            "offset": offset,
            "query": sanitize(raw_query) if raw_query else None,
        }
    )


@bp.post("/api/posts")
@jwt_required
def create_post():
    """Create a post. The third method of the assignment: an authenticated
    write operation with server-side validation."""
    body = validators.json_object()
    title = validators.text_field(body, "title", max_length=current_app.config["MAX_TITLE_LENGTH"])
    text = validators.text_field(body, "body", max_length=current_app.config["MAX_BODY_LENGTH"])

    conn = db.get_db()
    post_id = db.create_post(conn, g.current_user_id, title, text)
    row = db.get_post(conn, post_id)
    current_app.logger.info("post created: id=%s by user_id=%s", post_id, g.current_user_id)
    return jsonify({"post": _post_payload(row)}), 201


@bp.get("/api/me")
@jwt_required
def me():
    """Return the caller's profile plus the verified claims of their token."""
    conn = db.get_db()
    row = db.find_user_by_id(conn, g.current_user_id)
    if row is None:
        # The token is valid but the account is gone (deleted after issuance).
        raise ApiError("user no longer exists", 401, "invalid_token")

    claims = g.jwt_claims
    return jsonify(
        {
            "user": {
                "id": row["id"],
                "username": sanitize(row["username"]),
                "role": sanitize(row["role"]),
                "created_at": row["created_at"],
            },
            "token": {
                "sub": sanitize(claims.get("sub")),
                "jti": sanitize(claims.get("jti")),
                "issued_at": claims.get("iat"),
                "expires_at": claims.get("exp"),
            },
        }
    )
