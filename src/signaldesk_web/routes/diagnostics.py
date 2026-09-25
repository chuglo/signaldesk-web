"""Browser diagnostic journeys scoped only by the signed session."""

from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID

from flask import Blueprint, Response, current_app, redirect, render_template, request, session, url_for

from signaldesk_web.control_client import ControlUnavailable
from signaldesk_web.csrf import csrf_protected, ensure_csrf_token


blueprint = Blueprint("diagnostics", __name__)
_FORM_MIMETYPES = {"application/x-www-form-urlencoded", "multipart/form-data"}
_GENERIC_ERROR = "Unable to complete the diagnostic request. Please try again."


class DiagnosticClient(Protocol):
    def create_diagnostic(
        self, *, target: str, user_id: UUID, organization_id: UUID
    ) -> Any: ...

    def get_diagnostic(
        self, *, job_id: UUID, user_id: UUID, organization_id: UUID
    ) -> Any: ...


def _identity() -> tuple[UUID, UUID] | None:
    if set(session) != {"user_id", "organization_id", "role", "csrf_token"}:
        return None
    try:
        return UUID(session["user_id"]), UUID(session["organization_id"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def _client() -> DiagnosticClient:
    return current_app.extensions["signaldesk_control_client"]


def _path_only() -> bool:
    content_length = request.content_length
    return (
        not request.query_string
        and request.headers.get("Transfer-Encoding") is None
        and content_length in {None, 0}
    )


@blueprint.route("/diagnostics", methods=["GET", "POST"])
def index() -> Response | tuple[str, int] | str:
    identity = _identity()
    if identity is None:
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template(
            "diagnostics.html", csrf_token=ensure_csrf_token(), error=None
        )
    return _create(identity)


@csrf_protected
def _create(identity: tuple[UUID, UUID]) -> Response | tuple[str, int]:
    if (
        request.mimetype not in _FORM_MIMETYPES
        or request.files
        or set(request.form) != {"csrf_token", "target"}
        or any(len(request.form.getlist(field)) != 1 for field in request.form)
    ):
        return render_template(
            "diagnostics.html", csrf_token=ensure_csrf_token(), error=_GENERIC_ERROR
        ), 400
    target = request.form["target"].strip()
    if not target or len(target) > 2048:
        return render_template(
            "diagnostics.html", csrf_token=ensure_csrf_token(), error=_GENERIC_ERROR
        ), 400
    user_id, organization_id = identity
    try:
        diagnostic = _client().create_diagnostic(
            target=target, user_id=user_id, organization_id=organization_id
        )
    except ControlUnavailable:
        return render_template(
            "diagnostics.html", csrf_token=ensure_csrf_token(), error=_GENERIC_ERROR
        ), 503
    response = redirect(
        url_for("diagnostics.detail", job_id=diagnostic.id), code=303
    )
    response.headers["X-Correlation-ID"] = str(diagnostic.correlation_id)
    return response


@blueprint.get("/diagnostics/<uuid:job_id>")
def detail(job_id: UUID) -> Response | tuple[str, int] | str:
    identity = _identity()
    if identity is None:
        return redirect(url_for("login"))
    if not _path_only():
        return current_app.make_response(("Bad request", 400))
    user_id, organization_id = identity
    try:
        diagnostic = _client().get_diagnostic(
            job_id=job_id, user_id=user_id, organization_id=organization_id
        )
    except ControlUnavailable:
        return render_template("diagnostic_detail.html", diagnostic=None, error=_GENERIC_ERROR), 503
    response = current_app.make_response(
        render_template("diagnostic_detail.html", diagnostic=diagnostic, error=None)
    )
    response.headers["X-Correlation-ID"] = str(diagnostic.correlation_id)
    return response
