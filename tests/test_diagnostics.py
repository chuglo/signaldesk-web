from __future__ import annotations

from dataclasses import dataclass
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
JOB_ID = UUID("33333333-3333-4333-8333-333333333333")
CORRELATION_ID = UUID("44444444-4444-4444-8444-444444444444")


def diagnostic_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": str(JOB_ID),
        "organization_id": str(ORG_ID),
        "requested_by_user_id": str(USER_ID),
        "target": "router.example.test",
        "status": "pending",
        "result_json": None,
        "correlation_id": str(CORRELATION_ID),
        "created_at": "2026-07-23T12:00:00Z",
        "updated_at": "2026-07-23T12:00:00Z",
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
class Diagnostic:
    id: UUID = JOB_ID
    organization_id: UUID = ORG_ID
    requested_by_user_id: UUID = USER_ID
    target: str = "router.example.test"
    status: str = "pending"
    result_json: dict[str, object] | None = None
    correlation_id: UUID = CORRELATION_ID
    created_at: str = "2026-07-23T12:00:00Z"
    updated_at: str = "2026-07-23T12:00:00Z"


class FakeControl:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def create_diagnostic(self, **values: object) -> Diagnostic:
        self.calls.append(("create_diagnostic", values))
        return Diagnostic()

    def get_diagnostic(self, **values: object) -> Diagnostic:
        self.calls.append(("get_diagnostic", values))
        return Diagnostic()


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


def test_authenticated_user_creates_and_reads_diagnostic_through_session_scoped_bff() -> None:
    control = FakeControl()
    client = authenticated_client(control)

    created = client.post(
        "/diagnostics",
        data={"csrf_token": "csrf-token", "target": "router.example.test"},
    )
    assert created.status_code == 303
    assert created.headers["Location"] == f"/diagnostics/{JOB_ID}"
    assert created.headers["X-Correlation-ID"] == str(CORRELATION_ID)
    assert control.calls == [
        (
            "create_diagnostic",
            {
                "target": "router.example.test",
                "user_id": USER_ID,
                "organization_id": ORG_ID,
            },
        )
    ]

    detail = client.get(created.headers["Location"])
    assert detail.status_code == 200
    assert detail.headers["X-Correlation-ID"] == str(CORRELATION_ID)
    assert b"router.example.test" in detail.data
    assert str(CORRELATION_ID).encode() in detail.data
    assert control.calls[-1] == (
        "get_diagnostic",
        {"job_id": JOB_ID, "user_id": USER_ID, "organization_id": ORG_ID},
    )


def test_control_client_creates_diagnostic_with_only_signed_identity_headers_and_exact_schema() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            201,
            json={
                "id": str(JOB_ID),
                "organization_id": str(ORG_ID),
                "requested_by_user_id": str(USER_ID),
                "target": "router.example.test",
                "status": "pending",
                "result_json": None,
                "correlation_id": str(CORRELATION_ID),
                "created_at": "2026-07-23T12:00:00Z",
                "updated_at": "2026-07-23T12:00:00Z",
            },
        )

    control = ControlApiClient(settings(), transport=httpx.MockTransport(handler))
    diagnostic = control.create_diagnostic(
        target="router.example.test", user_id=USER_ID, organization_id=ORG_ID
    )

    assert diagnostic.id == JOB_ID
    assert diagnostic.organization_id == ORG_ID
    assert diagnostic.requested_by_user_id == USER_ID
    assert diagnostic.correlation_id == CORRELATION_ID
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "POST"
    assert request.url == httpx.URL("http://control.test/diagnostics")
    assert request.headers["X-SignalDesk-Service-Credential"] == "b" * 32
    assert request.headers["X-SignalDesk-User-ID"] == str(USER_ID)
    assert request.headers["X-SignalDesk-Organization-ID"] == str(ORG_ID)
    assert request.headers["Accept-Encoding"] == "identity"
    assert json.loads(request.content) == {"target": "router.example.test"}


def test_diagnostic_detail_accepts_path_authority_only() -> None:
    control = FakeControl()
    client = authenticated_client(control)

    assert client.get(f"/diagnostics/{JOB_ID}?organization_id={UUID(int=9)}").status_code == 400
    assert (
        client.get(
            f"/diagnostics/{JOB_ID}",
            data=b'{"organization_id":"attacker"}',
            content_type="application/json",
        ).status_code
        == 400
    )
    assert client.get("/diagnostics/not-a-uuid").status_code == 404
    assert client.get(f"/diagnostics/{JOB_ID}%2F..%2F{UUID(int=9)}").status_code == 404
    assert control.calls == []


def test_diagnostic_routes_require_authenticated_exact_signed_session_without_open_redirects() -> None:
    control = FakeControl()
    client = create_app(settings(), control_client=control).test_client()

    for method, path in (
        ("get", "/diagnostics"),
        ("post", "/diagnostics"),
        ("get", f"/diagnostics/{JOB_ID}"),
    ):
        response = getattr(client, method)(path)
        assert response.status_code == 302
        assert response.headers["Location"] == "/login"
    assert control.calls == []


def test_diagnostic_create_requires_csrf_and_exact_file_free_form_without_body_authority() -> None:
    invalid_requests = (
        lambda client: client.post(
            "/diagnostics",
            json={
                "csrf_token": "csrf-token",
                "target": "router.example.test",
                "organization_id": str(UUID(int=9)),
            },
        ),
        lambda client: client.post(
            "/diagnostics",
            data={
                "csrf_token": "csrf-token",
                "target": "router.example.test",
                "organization_id": str(UUID(int=9)),
            },
        ),
        lambda client: client.post(
            "/diagnostics",
            data=MultiDict(
                (
                    ("csrf_token", "csrf-token"),
                    ("target", "router.example.test"),
                    ("target", "other.example.test"),
                )
            ),
        ),
        lambda client: client.post(
            "/diagnostics",
            data={
                "csrf_token": "csrf-token",
                "target": "router.example.test",
                "upload": (BytesIO(b"x"), "x.txt"),
            },
        ),
        lambda client: client.post(
            "/diagnostics",
            data={"csrf_token": "wrong", "target": "router.example.test"},
        ),
    )
    for send in invalid_requests:
        control = FakeControl()
        response = send(authenticated_client(control))
        assert response.status_code == 400
        assert control.calls == []


def test_diagnostic_control_failures_are_bounded_and_generic() -> None:
    class UnavailableControl(FakeControl):
        def create_diagnostic(self, **values: object) -> Diagnostic:
            raise ControlUnavailable("upstream-secret-diagnostic-detail")

    response = authenticated_client(UnavailableControl()).post(
        "/diagnostics",
        data={"csrf_token": "csrf-token", "target": "router.example.test"},
    )
    assert response.status_code == 503
    assert len(response.data) < 2048
    assert b"upstream-secret" not in response.data
    assert b"Unable to complete the diagnostic request" in response.data


def test_diagnostic_client_rejects_untrusted_schema_scope_ids_and_evidence() -> None:
    payloads = (
        diagnostic_payload(extra="uncommitted"),
        diagnostic_payload(id=str(UUID(int=9))),
        diagnostic_payload(id=JOB_ID.hex),
        diagnostic_payload(organization_id=str(UUID(int=9))),
        diagnostic_payload(requested_by_user_id=str(UUID(int=9))),
        diagnostic_payload(correlation_id="not-a-uuid"),
        diagnostic_payload(status="unknown"),
        diagnostic_payload(target=" router.example.test"),
        diagnostic_payload(result_json=["not", "an", "object"]),
        diagnostic_payload(created_at="2026-07-23T12:00:00"),
    )
    for payload in payloads:
        control = ControlApiClient(
            settings(),
            transport=httpx.MockTransport(
                lambda request, response_payload=payload: httpx.Response(
                    200, json=response_payload
                )
            ),
        )
        with pytest.raises(ControlUnavailable, match="service unavailable"):
            control.get_diagnostic(
                job_id=JOB_ID, user_id=USER_ID, organization_id=ORG_ID
            )


def test_diagnostic_client_bounds_transport_encoding_and_error_bodies() -> None:
    class ExplodingBody(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("upstream error body was read")

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("sensitive-timeout-detail", request=request)

    transports = (
        httpx.MockTransport(
            lambda request: httpx.Response(503, stream=ExplodingBody())
        ),
        httpx.MockTransport(timeout),
        httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
                content=b"not-compressed",
            )
        ),
        httpx.MockTransport(
            lambda request: httpx.Response(
                200, headers={"Content-Type": "text/html"}, content=b"<h1>secret</h1>"
            )
        ),
        httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=b"{" + b"x" * 20_000 + b"}",
            )
        ),
    )
    for transport in transports:
        with pytest.raises(ControlUnavailable) as captured:
            ControlApiClient(settings(), transport=transport).get_diagnostic(
                job_id=JOB_ID, user_id=USER_ID, organization_id=ORG_ID
            )
        assert str(captured.value) == "Authentication service unavailable"
        assert "sensitive" not in str(captured.value)


@pytest.mark.parametrize("delta", (-1, 1))
def test_diagnostic_client_rejects_content_length_that_mismatches_raw_bytes(
    delta: int,
) -> None:
    body = json.dumps(diagnostic_payload(), separators=(",", ":")).encode("utf-8")
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body) + delta),
            },
            content=body,
        )
    )

    with pytest.raises(ControlUnavailable, match="Authentication service unavailable"):
        ControlApiClient(settings(), transport=transport).get_diagnostic(
            job_id=JOB_ID, user_id=USER_ID, organization_id=ORG_ID
        )


@pytest.mark.parametrize(
    ("encoding", "content_type"),
    (
        ("utf-16", "application/json"),
        ("utf-8", "application/json; charset=utf-8"),
        ("utf-8", "Application/JSON"),
    ),
)
def test_diagnostic_client_accepts_only_exact_utf8_application_json_representation(
    encoding: str,
    content_type: str,
) -> None:
    body = json.dumps(diagnostic_payload(), separators=(",", ":")).encode(encoding)
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"Content-Type": content_type},
            content=body,
        )
    )

    with pytest.raises(
        ControlUnavailable, match="Authentication service unavailable"
    ) as captured:
        ControlApiClient(settings(), transport=transport).get_diagnostic(
            job_id=JOB_ID, user_id=USER_ID, organization_id=ORG_ID
        )
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_deep_bounded_diagnostic_json_maps_to_generic_503_before_template_rendering() -> None:
    nested_result = '{"nested":' + "[" * 1100 + "null" + "]" * 1100 + "}"
    body = json.dumps(
        diagnostic_payload(result_json="RESULT_PLACEHOLDER"), separators=(",", ":")
    ).replace('"RESULT_PLACEHOLDER"', nested_result).encode("utf-8")
    assert len(body) < 16_384
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=body,
        )
    )
    control = ControlApiClient(settings(), transport=transport)

    response = authenticated_client(control).get(f"/diagnostics/{JOB_ID}")

    assert response.status_code == 503
    assert len(response.data) < 2048
    assert b"Unable to complete the diagnostic request" in response.data


def test_diagnostic_result_rejects_conservatively_excessive_json_depth() -> None:
    nested_result = '{"nested":' + "[" * 33 + "null" + "]" * 33 + "}"
    body = json.dumps(
        diagnostic_payload(result_json="RESULT_PLACEHOLDER"), separators=(",", ":")
    ).replace('"RESULT_PLACEHOLDER"', nested_result).encode("utf-8")
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=body,
        )
    )

    response = authenticated_client(
        ControlApiClient(settings(), transport=transport)
    ).get(f"/diagnostics/{JOB_ID}")

    assert response.status_code == 503
    assert b"Unable to complete the diagnostic request" in response.data


@pytest.mark.parametrize(
    "overrides",
    (
        {"created_at": "2026-07-23 12:00:00Z"},
        {"created_at": "2026-07-23T12:00:00+00:00"},
        {"created_at": "2026-07-23T12:00:00.000000Z"},
        {
            "created_at": "2026-07-23T12:00:01Z",
            "updated_at": "2026-07-23T12:00:00Z",
        },
    ),
)
def test_diagnostic_client_requires_canonical_ordered_utc_timestamps(
    overrides: dict[str, object],
) -> None:
    payload = diagnostic_payload(**overrides)
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json=payload)
    )

    with pytest.raises(ControlUnavailable, match="Authentication service unavailable"):
        ControlApiClient(settings(), transport=transport).get_diagnostic(
            job_id=JOB_ID, user_id=USER_ID, organization_id=ORG_ID
        )


def test_diagnostic_pages_are_never_cached() -> None:
    client = authenticated_client(FakeControl())
    for response in (
        client.get("/diagnostics"),
        client.get(f"/diagnostics/{JOB_ID}"),
    ):
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"


def test_authenticated_home_links_to_local_diagnostic_and_export_journeys() -> None:
    response = authenticated_client(FakeControl()).get("/")
    assert response.status_code == 200
    assert b'href="/diagnostics"' in response.data
    assert b'href="/exports"' in response.data
