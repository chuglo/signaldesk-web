"""SignalDesk web application factory and authentication boundary."""

from __future__ import annotations

from datetime import timedelta
import re
from typing import Protocol
from uuid import UUID

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for

from signaldesk_web.control_client import ControlApiClient, ControlUnavailable, InvalidLogin
from signaldesk_web.csrf import csrf_protected, ensure_csrf_token, rotate_csrf_token, valid_csrf_submission
from signaldesk_web.routes.diagnostics import blueprint as diagnostics_blueprint
from signaldesk_web.routes.exports import blueprint as exports_blueprint
from signaldesk_web.signed_session import CurrentKeySessionInterface
from signaldesk_web.settings import Settings


_LOGIN_FIELDS = {"csrf_token", "email", "password", "organization_id"}
_FORM_MIMETYPES = {"application/x-www-form-urlencoded", "multipart/form-data"}
_EMAIL_LOCAL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+\Z")
_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_GENERIC_LOGIN_ERROR = "Unable to sign in. Check your credentials and try again."


class AuthenticationClient(Protocol):
    def authenticate(
        self, *, email: str, password: str, organization_id: UUID
    ) -> object: ...


def _is_valid_email(value: str) -> bool:
    if not 3 <= len(value) <= 320 or not value.isascii() or value.count("@") != 1:
        return False
    local, domain = value.rsplit("@", 1)
    if (
        not local
        or len(local) > 64
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or _EMAIL_LOCAL.fullmatch(local) is None
        or not domain
        or len(domain) > 255
    ):
        return False
    labels = domain.split(".")
    return all(_DOMAIN_LABEL.fullmatch(label) is not None for label in labels)


def _single_exact_login_form() -> tuple[str, str, UUID] | None:
    if request.mimetype not in _FORM_MIMETYPES:
        return None
    if request.files or set(request.form) != _LOGIN_FIELDS:
        return None
    if any(len(request.form.getlist(field)) != 1 for field in _LOGIN_FIELDS):
        return None
    email = request.form["email"]
    password = request.form["password"]
    organization_text = request.form["organization_id"]
    if not _is_valid_email(email) or not 1 <= len(password) <= 1024:
        return None
    if len(organization_text) > 36:
        return None
    try:
        organization_id = UUID(organization_text)
    except (ValueError, AttributeError):
        return None
    return email, password, organization_id


def create_app(
    settings: Settings | None = None,
    *,
    control_client: AuthenticationClient | None = None,
) -> Flask:
    configured = settings if settings is not None else Settings()
    app = Flask(__name__)
    app.session_interface = CurrentKeySessionInterface()
    app.config.update(
        SECRET_KEY=configured.flask_secret_key.get_secret_value(),
        SECRET_KEY_FALLBACKS=[
            fallback.get_secret_value() for fallback in configured.flask_secret_key_fallbacks
        ],
        SESSION_COOKIE_NAME="signaldesk_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=configured.session_cookie_secure,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_PATH="/",
        SESSION_COOKIE_DOMAIN=None,
        SESSION_PERMANENT=False,
        SESSION_REFRESH_EACH_REQUEST=False,
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=configured.session_lifetime_seconds),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    app.extensions["signaldesk_settings"] = configured
    app.extensions["signaldesk_control_client"] = (
        control_client if control_client is not None else ControlApiClient(configured)
    )
    app.register_blueprint(diagnostics_blueprint)
    app.register_blueprint(exports_blueprint)

    @app.after_request
    def prevent_sensitive_caching(response: Response) -> Response:
        endpoint = request.endpoint or ""
        if endpoint in {"login", "logout", "index"} or endpoint.startswith(
            ("diagnostics.", "exports.")
        ):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def health() -> Response:
        return jsonify(status="ok")

    @app.get("/")
    def index() -> Response | str:
        approved = {"user_id", "organization_id", "role", "csrf_token"}
        if set(session) != approved:
            return redirect(url_for("login"))
        return render_template("index.html", csrf_token=ensure_csrf_token())

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Response | tuple[str, int] | str:
        csrf_token = ensure_csrf_token()
        if request.method == "GET":
            return render_template("login.html", csrf_token=csrf_token, error=None)

        parsed = _single_exact_login_form()
        if parsed is None or not valid_csrf_submission():
            return render_template(
                "login.html", csrf_token=csrf_token, error=_GENERIC_LOGIN_ERROR
            ), 400

        email, password, organization_id = parsed
        client: AuthenticationClient = app.extensions["signaldesk_control_client"]
        try:
            identity = client.authenticate(
                email=email,
                password=password,
                organization_id=organization_id,
            )
        except InvalidLogin:
            return render_template(
                "login.html", csrf_token=csrf_token, error=_GENERIC_LOGIN_ERROR
            ), 401
        except ControlUnavailable:
            return render_template(
                "login.html", csrf_token=csrf_token, error=_GENERIC_LOGIN_ERROR
            ), 503

        session.clear()
        session["user_id"] = str(identity.user_id)
        session["organization_id"] = str(identity.organization_id)
        session["role"] = identity.role
        rotate_csrf_token()
        return redirect(url_for("index"))

    @app.post("/logout")
    @csrf_protected
    def logout() -> Response:
        if (
            request.mimetype not in _FORM_MIMETYPES
            or request.files
            or set(request.form) != {"csrf_token"}
            or len(request.form.getlist("csrf_token")) != 1
        ):
            return app.make_response(("Bad request", 400))
        session.clear()
        return redirect(url_for("login"))

    return app


__all__ = ["Settings", "create_app"]
