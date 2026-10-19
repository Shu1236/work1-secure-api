"""Uniform JSON error handling.

Every failure leaves the API as a JSON document of the shape::

    {"error": {"code": "invalid_token", "message": "invalid token"}}

Internals (tracebacks, SQL text, file paths) are never echoed to the client:
details go to the server log, the response stays generic.
"""

from __future__ import annotations

from typing import Any

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException


class ApiError(Exception):
    """An expected failure that is safe to report to the client."""

    def __init__(
        self,
        message: str,
        status: int = 400,
        code: str = "bad_request",
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.headers = headers or {}

    def to_response(self):
        response = jsonify({"error": {"code": self.code, "message": self.message}})
        response.status_code = self.status
        for name, value in self.headers.items():
            response.headers[name] = value
        return response


def _slug(name: str) -> str:
    return name.strip().lower().replace(" ", "_").replace("-", "_")


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ApiError)
    def _handle_api_error(exc: ApiError):
        return exc.to_response()

    @app.errorhandler(HTTPException)
    def _handle_http_exception(exc: HTTPException):
        # Covers 400 (malformed JSON), 404, 405, 413 (body too large), 415, ...
        payload: dict[str, Any] = {
            "error": {"code": _slug(exc.name or "error"), "message": exc.description}
        }
        response = jsonify(payload)
        response.status_code = exc.code or 500
        if exc.code == 401:
            response.headers.setdefault("WWW-Authenticate", 'Bearer realm="api"')
        return response

    @app.errorhandler(Exception)
    def _handle_unexpected(exc: Exception):
        if app.config.get("TESTING"):
            raise exc  # make real bugs visible in the test run
        app.logger.exception("unhandled error on %s %s", request.method, request.path)
        response = jsonify(
            {"error": {"code": "internal_error", "message": "internal server error"}}
        )
        response.status_code = 500
        return response
