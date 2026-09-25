"""Browser export journeys scoped only by the signed session."""

from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID

from flask import Blueprint, Response, current_app, redirect, render_template, request, session, url_for

from signaldesk_web.control_client import ControlUnavailable
from signaldesk_web.csrf import csrf_protected, ensure_csrf_token


blueprint = Blueprint("exports", __name__)
_FORM_MIMETYPES = {"application/x-www-form-urlencoded", "multipart/form-data"}
_GENERIC_ERROR = "Unable to complete the export request. Please try again."


class ExportClient(Protocol):
    def create_export(
        self, *, export_format: str, user_id: UUID, organization_id: UUID
    ) -> Any: ...

    def get_export(
        self, *, job_id: UUID, user_id: UUID, organization_id: UUID
    ) -> Any: ...

    def get_export_download(
        self, *, job_id: UUID, user_id: UUID, organization_id: UUID
    ) -> Any: ...


def _identity() -> tuple[UUID, UUID] | None:
    if set(session) != {"user_id", "organization_id", "role", "csrf_token"}:
        return None
    try:
        return UUID(session["user_id"]), UUID(session["organization_id"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def _client() -> ExportClient:
    return current_app.extensions["signaldesk_control_client"]


def _path_only() -> bool:
    content_length = request.content_length
    return (
        not request.query_string
        and request.headers.get("Transfer-Encoding") is None
        and content_length in {None, 0}
    )


def _valid_export(
    export: Any,
    *,
    job_id: UUID | None,
    user_id: UUID,
    organization_id: UUID,
) -> bool:
    return (
        isinstance(export.id, UUID)
        and (job_id is None or export.id == job_id)
        and export.organization_id == organization_id
        and export.requested_by_user_id == user_id
        and export.format in {"csv", "json"}
        and export.status in {"pending", "claimed", "completed"}
        and isinstance(export.correlation_id, UUID)
    )


def _valid_download(metadata: Any, *, export: Any) -> bool:
    if (
        metadata.export_job_id != export.id
        or metadata.organization_id != export.organization_id
        or metadata.format != export.format
        or metadata.status != export.status
        or metadata.object_key != export.object_key
        or metadata.object_sha256 != export.object_sha256
        or metadata.size_bytes != export.size_bytes
    ):
        return False
    expected_key = f"exports/{export.organization_id}/{export.id}.{metadata.format}"
    if metadata.status == "completed":
        return (
            metadata.object_key == expected_key
            and isinstance(metadata.object_sha256, str)
            and len(metadata.object_sha256) == 64
            and all(character in "0123456789abcdef" for character in metadata.object_sha256)
            and isinstance(metadata.size_bytes, int)
            and not isinstance(metadata.size_bytes, bool)
            and 0 <= metadata.size_bytes <= 1_073_741_824
        )
    return (
        metadata.object_key is None
        and metadata.object_sha256 is None
        and metadata.size_bytes is None
    )


@blueprint.route("/exports", methods=["GET", "POST"])
def index() -> Response | tuple[str, int] | str:
    identity = _identity()
    if identity is None:
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template("exports.html", csrf_token=ensure_csrf_token(), error=None)
    return _create(identity)


@csrf_protected
def _create(identity: tuple[UUID, UUID]) -> Response | tuple[str, int]:
    if (
        request.mimetype not in _FORM_MIMETYPES
        or request.files
        or set(request.form) != {"csrf_token", "format"}
        or any(len(request.form.getlist(field)) != 1 for field in request.form)
        or request.form["format"] not in {"csv", "json"}
    ):
        return render_template(
            "exports.html", csrf_token=ensure_csrf_token(), error=_GENERIC_ERROR
        ), 400
    user_id, organization_id = identity
    try:
        export = _client().create_export(
            export_format=request.form["format"],
            user_id=user_id,
            organization_id=organization_id,
        )
    except ControlUnavailable:
        return render_template(
            "exports.html", csrf_token=ensure_csrf_token(), error=_GENERIC_ERROR
        ), 503
    if not _valid_export(
        export, job_id=None, user_id=user_id, organization_id=organization_id
    ):
        return render_template(
            "exports.html", csrf_token=ensure_csrf_token(), error=_GENERIC_ERROR
        ), 503
    response = redirect(url_for("exports.detail", job_id=export.id), code=303)
    response.headers["X-Correlation-ID"] = str(export.correlation_id)
    return response


@blueprint.get("/exports/<uuid:job_id>")
def detail(job_id: UUID) -> Response | tuple[str, int] | str:
    identity = _identity()
    if identity is None:
        return redirect(url_for("login"))
    if not _path_only():
        return current_app.make_response(("Bad request", 400))
    user_id, organization_id = identity
    try:
        export = _client().get_export(
            job_id=job_id, user_id=user_id, organization_id=organization_id
        )
    except ControlUnavailable:
        return render_template("export_detail.html", export=None, metadata=None, error=_GENERIC_ERROR), 503
    if not _valid_export(
        export, job_id=job_id, user_id=user_id, organization_id=organization_id
    ):
        return render_template("export_detail.html", export=None, metadata=None, error=_GENERIC_ERROR), 503
    response = current_app.make_response(
        render_template("export_detail.html", export=export, metadata=None, error=None)
    )
    response.headers["X-Correlation-ID"] = str(export.correlation_id)
    return response


@blueprint.get("/exports/<uuid:job_id>/download")
def download(job_id: UUID) -> Response | tuple[str, int] | str:
    identity = _identity()
    if identity is None:
        return redirect(url_for("login"))
    if not _path_only():
        return current_app.make_response(("Bad request", 400))
    user_id, organization_id = identity
    try:
        export = _client().get_export(
            job_id=job_id, user_id=user_id, organization_id=organization_id
        )
    except ControlUnavailable:
        return render_template("export_detail.html", export=None, metadata=None, error=_GENERIC_ERROR), 503
    if not _valid_export(
        export, job_id=job_id, user_id=user_id, organization_id=organization_id
    ):
        return render_template("export_detail.html", export=None, metadata=None, error=_GENERIC_ERROR), 503
    try:
        metadata = _client().get_export_download(
            job_id=job_id, user_id=user_id, organization_id=organization_id
        )
    except ControlUnavailable:
        return render_template("export_detail.html", export=None, metadata=None, error=_GENERIC_ERROR), 503
    if not _valid_download(metadata, export=export):
        return render_template("export_detail.html", export=None, metadata=None, error=_GENERIC_ERROR), 503
    return render_template("export_detail.html", export=None, metadata=metadata, error=None)
