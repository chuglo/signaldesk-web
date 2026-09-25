from __future__ import annotations

from collections.abc import Callable
from functools import wraps
import secrets
from typing import Any, TypeVar, cast

from flask import Response, abort, request, session


_CSRF_BYTES = 32
_CSRF_MAX_CHARACTERS = 128
F = TypeVar("F", bound=Callable[..., Any])


def ensure_csrf_token() -> str:
    value = session.get("csrf_token")
    if not isinstance(value, str) or not value:
        value = secrets.token_urlsafe(_CSRF_BYTES)
        session["csrf_token"] = value
    return value


def rotate_csrf_token() -> str:
    value = secrets.token_urlsafe(_CSRF_BYTES)
    session["csrf_token"] = value
    return value


def valid_csrf_submission() -> bool:
    presented_values = request.form.getlist("csrf_token")
    expected = session.get("csrf_token")
    if len(presented_values) != 1 or not isinstance(expected, str):
        return False
    presented = presented_values[0]
    if (
        not presented
        or len(presented) > _CSRF_MAX_CHARACTERS
        or not presented.isascii()
        or not expected.isascii()
    ):
        return False
    return secrets.compare_digest(presented, expected)


def csrf_protected(view: F) -> F:
    """Reusable synchronizer-token guard for state-changing browser routes."""

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Response | Any:
        if not valid_csrf_submission():
            abort(400)
        return view(*args, **kwargs)

    return cast(F, wrapped)
