from __future__ import annotations

from dataclasses import dataclass, replace
from io import BytesIO
import json
from uuid import UUID

import httpx
import pytest
from werkzeug.datastructures import MultiDict

from signaldesk_web import create_app
from signaldesk_web.control_client import ControlApiClient, ControlUnavailable
from signaldesk_web.settings import Settings


ORG_ID = UUID("11111111-1111-4111-8111-111111111111")
USER_ID = UUID("22222222-2222-4222-8222-222222222222")
JOB_ID = UUID("55555555-5555-4555-8555-555555555555")
CORRELATION_ID = UUID("66666666-6666-4666-8666-666666666666")
OBJECT_KEY = f"exports/{ORG_ID}/{JOB_ID}.csv"


def export_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": str(JOB_ID),
        "organization_id": str(ORG_ID),
        "requested_by_user_id": str(USER_ID),
        "format": "csv",
        "status": "pending",
        "object_key": None,
        "object_sha256": None,
        "size_bytes": None,
        "correlation_id": str(CORRELATION_ID),
        "created_at": "2026-07-23T12:00:00Z",
        "updated_at": "2026-07-23T12:00:00Z",
    }
    payload.update(overrides)
    return payload


def download_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "export_job_id": str(JOB_ID),
        "organization_id": str(ORG_ID),
        "format": "csv",
        "status": "completed",
        "object_key": OBJECT_KEY,
        "object_sha256": "a" * 64,
        "size_bytes": 123,
    }
    payload.update(overrides)
    return payload


def settings() -> Settings:
    return Settings.model_validate(
        {
            "environment": "test",
            "control_api_base_url": "http://control.test",
            "bff_service_credential": "b" * 32,
            "flask_secret_key": "c" * 32,
            "flask_secret_key_fallbacks": ["f" * 32],
        }
    )


@dataclass(frozen=True)
class Export:
    id: UUID = JOB_ID
    organization_id: UUID = ORG_ID
    requested_by_user_id: UUID = USER_ID
    format: str = "csv"
    status: str = "completed"
    object_key: str | None = OBJECT_KEY
    object_sha256: str | None = "a" * 64
    size_bytes: int | None = 123
    correlation_id: UUID = CORRELATION_ID
    created_at: str = "2026-07-23T12:00:00Z"
    updated_at: str = "2026-07-23T12:00:00Z"


@dataclass(frozen=True)
class DownloadMetadata:
    export_job_id: UUID = JOB_ID
    organization_id: UUID = ORG_ID
    format: str = "csv"
    status: str = "completed"
    object_key: str | None = OBJECT_KEY
    object_sha256: str | None = "a" * 64
    size_bytes: int | None = 123


class FakeControl:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def create_export(self, **values: object) -> Export:
        self.calls.append(("create_export", values))
        return Export()

    def get_export(self, **values: object) -> Export:
        self.calls.append(("get_export", values))
        return Export()

    def get_export_download(self, **values: object) -> DownloadMetadata:
        self.calls.append(("get_export_download", values))
        return DownloadMetadata()


def authenticated_client(control: FakeControl):
    client = create_app(settings(), control_client=control).test_client()
    with client.session_transaction() as signed_session:
        signed_session.update(
            user_id=str(USER_ID),
            organization_id=str(ORG_ID),
            role="analyst",
            csrf_token="csrf-token",
        )
    return client


def test_authenticated_user_requests_reads_and_views_export_metadata_through_bff() -> None:
    control = FakeControl()
    client = authenticated_client(control)

    created = client.post(
        "/exports", data={"csrf_token": "csrf-token", "format": "csv"}
    )
    assert created.status_code == 303
    assert created.headers["Location"] == f"/exports/{JOB_ID}"
    assert created.headers["X-Correlation-ID"] == str(CORRELATION_ID)
    assert control.calls == [
        (
            "create_export",
            {"export_format": "csv", "user_id": USER_ID, "organization_id": ORG_ID},
        )
    ]

    detail = client.get(created.headers["Location"])
    assert detail.status_code == 200
    assert detail.headers["X-Correlation-ID"] == str(CORRELATION_ID)
    assert b"completed" in detail.data
    assert f'href="/exports/{JOB_ID}/download"'.encode() in detail.data
    assert b"minio" not in detail.data.lower()
    assert b"http://" not in detail.data.lower()

    metadata = client.get(f"/exports/{JOB_ID}/download")
    assert metadata.status_code == 200
    assert OBJECT_KEY.encode() in metadata.data
    assert b"minio" not in metadata.data.lower()
    assert b"http://" not in metadata.data.lower()
    assert control.calls[-1] == (
        "get_export_download",
        {"job_id": JOB_ID, "user_id": USER_ID, "organization_id": ORG_ID},
    )


def test_control_client_requests_export_with_exact_contract_and_session_identity() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            201,
            json={
                "id": str(JOB_ID),
                "organization_id": str(ORG_ID),
                "requested_by_user_id": str(USER_ID),
                "format": "csv",
                "status": "pending",
                "object_key": None,
                "object_sha256": None,
                "size_bytes": None,
                "correlation_id": str(CORRELATION_ID),
                "created_at": "2026-07-23T12:00:00Z",
                "updated_at": "2026-07-23T12:00:00Z",
            },
        )

    control = ControlApiClient(settings(), transport=httpx.MockTransport(handler))
    export = control.create_export(
        export_format="csv", user_id=USER_ID, organization_id=ORG_ID
    )

    assert export.id == JOB_ID
    assert export.organization_id == ORG_ID
    assert export.requested_by_user_id == USER_ID
    assert export.correlation_id == CORRELATION_ID
    request = seen[0]
    assert request.method == "POST"
    assert request.url == httpx.URL("http://control.test/exports")
    assert request.headers["X-SignalDesk-User-ID"] == str(USER_ID)
    assert request.headers["X-SignalDesk-Organization-ID"] == str(ORG_ID)
    assert json.loads(request.content) == {"format": "csv"}


def test_export_read_and_metadata_routes_accept_path_authority_only() -> None:
    control = FakeControl()
    client = authenticated_client(control)
    for path in (f"/exports/{JOB_ID}", f"/exports/{JOB_ID}/download"):
        assert client.get(f"{path}?organization_id={UUID(int=9)}").status_code == 400
        assert (
            client.get(
                path,
                data=b'{"organization_id":"attacker"}',
                content_type="application/json",
            ).status_code
            == 400
        )
    assert client.get("/exports/not-a-uuid").status_code == 404
    assert client.get(f"/exports/{JOB_ID}%2F..%2F{UUID(int=9)}").status_code == 404
    assert control.calls == []


def test_export_routes_require_authenticated_exact_signed_session_without_open_redirects() -> None:
    control = FakeControl()
    client = create_app(settings(), control_client=control).test_client()
    for method, path in (
        ("get", "/exports"),
        ("post", "/exports"),
        ("get", f"/exports/{JOB_ID}"),
        ("get", f"/exports/{JOB_ID}/download"),
    ):
        response = getattr(client, method)(path)
        assert response.status_code == 302
        assert response.headers["Location"] == "/login"
    assert control.calls == []


def test_export_create_requires_csrf_and_exact_file_free_form_without_body_authority() -> None:
    invalid_requests = (
        lambda client: client.post(
            "/exports",
            json={"csrf_token": "csrf-token", "format": "csv"},
        ),
        lambda client: client.post(
            "/exports",
            data={
                "csrf_token": "csrf-token",
                "format": "csv",
                "organization_id": str(UUID(int=9)),
            },
        ),
        lambda client: client.post(
            "/exports",
            data=MultiDict(
                (
                    ("csrf_token", "csrf-token"),
                    ("format", "csv"),
                    ("format", "json"),
                )
            ),
        ),
        lambda client: client.post(
            "/exports",
            data={
                "csrf_token": "csrf-token",
                "format": "csv",
                "upload": (BytesIO(b"x"), "x.txt"),
            },
        ),
        lambda client: client.post(
            "/exports", data={"csrf_token": "csrf-token", "format": "CSV"}
        ),
        lambda client: client.post(
            "/exports", data={"csrf_token": "wrong", "format": "csv"}
        ),
    )
    for send in invalid_requests:
        control = FakeControl()
        response = send(authenticated_client(control))
        assert response.status_code == 400
        assert control.calls == []


def test_download_denies_same_organization_different_user_before_metadata_disclosure() -> None:
    other_user_id = UUID("77777777-7777-4777-8777-777777777777")

    class OtherUsersExportControl(FakeControl):
        def get_export(self, **values: object) -> Export:
            self.calls.append(("get_export", values))
            return replace(Export(), requested_by_user_id=other_user_id)

        def get_export_download(self, **values: object) -> DownloadMetadata:
            raise AssertionError("metadata was requested before user ownership was established")

    control = OtherUsersExportControl()
    response = authenticated_client(control).get(f"/exports/{JOB_ID}/download")

    assert response.status_code == 503
    assert OBJECT_KEY.encode() not in response.data
    assert b"Unable to complete the export request" in response.data
    assert control.calls == [
        (
            "get_export",
            {"job_id": JOB_ID, "user_id": USER_ID, "organization_id": ORG_ID},
        )
    ]


@pytest.mark.parametrize(
    "metadata",
    (
        replace(
            DownloadMetadata(),
            format="json",
            object_key=f"exports/{ORG_ID}/{JOB_ID}.json",
        ),
        replace(
            DownloadMetadata(),
            status="pending",
            object_key=None,
            object_sha256=None,
            size_bytes=None,
        ),
        replace(DownloadMetadata(), object_sha256="b" * 64),
        replace(DownloadMetadata(), size_bytes=124),
    ),
)
def test_download_requires_exact_full_record_and_metadata_agreement(
    metadata: DownloadMetadata,
) -> None:
    class DisagreeingControl(FakeControl):
        def get_export_download(self, **values: object) -> DownloadMetadata:
            self.calls.append(("get_export_download", values))
            return metadata

    response = authenticated_client(DisagreeingControl()).get(
        f"/exports/{JOB_ID}/download"
    )

    assert response.status_code == 503
    assert metadata.object_sha256.encode() not in response.data if metadata.object_sha256 else True
    assert b"Unable to complete the export request" in response.data


def test_export_errors_and_unconfined_metadata_are_bounded_generic_and_never_linked() -> None:
    class UnavailableControl(FakeControl):
        def create_export(self, **values: object) -> Export:
            raise ControlUnavailable("upstream-export-secret")

    unavailable = authenticated_client(UnavailableControl()).post(
        "/exports", data={"csrf_token": "csrf-token", "format": "csv"}
    )
    assert unavailable.status_code == 503
    assert len(unavailable.data) < 2048
    assert b"upstream-export-secret" not in unavailable.data
    assert b"Unable to complete the export request" in unavailable.data

    class EscapingControl(FakeControl):
        def get_export_download(self, **values: object) -> DownloadMetadata:
            return replace(
                DownloadMetadata(), object_key="https://minio.attacker.test/private.csv"
            )

    escaped = authenticated_client(EscapingControl()).get(
        f"/exports/{JOB_ID}/download"
    )
    assert escaped.status_code == 503
    assert b"minio.attacker" not in escaped.data
    assert b"Unable to complete the export request" in escaped.data


def test_export_client_reads_job_and_download_metadata_from_exact_local_control_routes() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/download"):
            return httpx.Response(200, json=download_payload())
        return httpx.Response(
            200,
            json=export_payload(
                status="completed",
                object_key=OBJECT_KEY,
                object_sha256="a" * 64,
                size_bytes=123,
            ),
        )

    control = ControlApiClient(settings(), transport=httpx.MockTransport(handler))
    export = control.get_export(
        job_id=JOB_ID, user_id=USER_ID, organization_id=ORG_ID
    )
    metadata = control.get_export_download(
        job_id=JOB_ID, user_id=USER_ID, organization_id=ORG_ID
    )
    assert export.object_key == metadata.object_key == OBJECT_KEY
    assert [request.url.path for request in seen] == [
        f"/exports/{JOB_ID}",
        f"/exports/{JOB_ID}/download",
    ]
    assert all(request.content == b"" for request in seen)
    assert all(
        request.headers["X-SignalDesk-Organization-ID"] == str(ORG_ID)
        for request in seen
    )


@pytest.mark.parametrize("route", (f"/exports/{JOB_ID}", f"/exports/{JOB_ID}/download"))
def test_deep_export_json_is_rendered_as_a_generic_503(route: str) -> None:
    deep_json = ("[" * 1100 + "0" + "]" * 1100).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        if route.endswith("/download") and not request.url.path.endswith("/download"):
            return httpx.Response(
                200,
                json=export_payload(
                    status="completed",
                    object_key=OBJECT_KEY,
                    object_sha256="a" * 64,
                    size_bytes=123,
                ),
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=deep_json,
        )

    control = ControlApiClient(settings(), transport=httpx.MockTransport(handler))
    client = create_app(settings(), control_client=control).test_client()
    with client.session_transaction() as signed_session:
        signed_session.update(
            user_id=str(USER_ID),
            organization_id=str(ORG_ID),
            role="analyst",
            csrf_token="csrf-token",
        )

    response = client.get(route)

    assert response.status_code == 503
    assert len(response.data) < 2048
    assert b"Unable to complete the export request" in response.data


def test_export_parsers_reject_json_decoder_overflow(monkeypatch: pytest.MonkeyPatch) -> None:
    def overflow(*args: object, **kwargs: object) -> object:
        raise OverflowError("decoder nesting overflow")

    monkeypatch.setattr(json, "loads", overflow)

    assert (
        ControlApiClient._parse_export(
            "{}",
            expected_job_id=JOB_ID,
            expected_user_id=USER_ID,
            expected_organization_id=ORG_ID,
            expected_format=None,
        )
        is None
    )
    assert (
        ControlApiClient._parse_export_download(
            "{}", expected_job_id=JOB_ID, expected_organization_id=ORG_ID
        )
        is None
    )


def test_export_client_rejects_cross_scope_and_unconfined_artifact_metadata() -> None:
    invalid_exports = (
        export_payload(extra="uncommitted"),
        export_payload(id=str(UUID(int=9))),
        export_payload(organization_id=str(UUID(int=9))),
        export_payload(requested_by_user_id=str(UUID(int=9))),
        export_payload(correlation_id="not-a-uuid"),
        export_payload(format="xml"),
        export_payload(status="unknown"),
        export_payload(object_key=OBJECT_KEY),
        export_payload(created_at="2026-07-23T12:00:00"),
    )
    for payload in invalid_exports:
        control = ControlApiClient(
            settings(),
            transport=httpx.MockTransport(
                lambda request, response_payload=payload: httpx.Response(
                    200, json=response_payload
                )
            ),
        )
        with pytest.raises(ControlUnavailable):
            control.get_export(
                job_id=JOB_ID, user_id=USER_ID, organization_id=ORG_ID
            )

    invalid_downloads = (
        download_payload(extra="uncommitted"),
        download_payload(export_job_id=str(UUID(int=9))),
        download_payload(organization_id=str(UUID(int=9))),
        download_payload(object_key="https://minio.attacker.test/private.csv"),
        download_payload(object_key=f"exports/{ORG_ID}/../private.csv"),
        download_payload(object_sha256="A" * 64),
        download_payload(size_bytes=-1),
        download_payload(size_bytes=True),
        download_payload(status="pending"),
    )
    for payload in invalid_downloads:
        control = ControlApiClient(
            settings(),
            transport=httpx.MockTransport(
                lambda request, response_payload=payload: httpx.Response(
                    200, json=response_payload
                )
            ),
        )
        with pytest.raises(ControlUnavailable):
            control.get_export_download(
                job_id=JOB_ID, user_id=USER_ID, organization_id=ORG_ID
            )


def test_export_timeout_is_rendered_as_generic_bounded_error() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("secret-timeout-detail", request=request)

    control = ControlApiClient(settings(), transport=httpx.MockTransport(timeout))
    client = create_app(settings(), control_client=control).test_client()
    with client.session_transaction() as signed_session:
        signed_session.update(
            user_id=str(USER_ID),
            organization_id=str(ORG_ID),
            role="analyst",
            csrf_token="csrf-token",
        )
    response = client.post(
        "/exports", data={"csrf_token": "csrf-token", "format": "csv"}
    )
    assert response.status_code == 503
    assert len(response.data) < 2048
    assert b"secret-timeout-detail" not in response.data
    assert b"Unable to complete the export request" in response.data
