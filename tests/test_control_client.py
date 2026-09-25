from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import threading
import time
import traceback
from uuid import UUID

import httpx
import pytest

import signaldesk_web.control_client as control_client_module
from signaldesk_web.control_client import (
    ControlApiClient,
    ControlUnavailable,
    InvalidLogin,
)
from signaldesk_web.settings import Settings


ORG_ID = "11111111-1111-4111-8111-111111111111"
USER_ID = "22222222-2222-4222-8222-222222222222"
BFF = "b" * 32


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "control_api_base_url": "http://control.test",
        "bff_service_credential": BFF,
        "flask_secret_key": "c" * 32,
        "flask_secret_key_fallbacks": ["f" * 32],
        "control_api_max_response_bytes": 256,
    }
    values.update(overrides)
    return Settings.model_validate(values)


def client_for(handler: httpx.MockTransport) -> ControlApiClient:
    return ControlApiClient(settings(), transport=handler)


def test_authenticate_posts_only_committed_fields_and_service_header() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url == httpx.URL("http://control.test/internal/authenticate")
        assert request.headers["X-SignalDesk-Service-Credential"] == BFF
        assert request.headers["Accept-Encoding"] == "identity"
        assert json.loads(request.content) == {
            "email": "person@example.test",
            "password": "not-retained-password",
            "organization_id": ORG_ID,
        }
        return httpx.Response(
            200,
            json={"user_id": USER_ID, "organization_id": ORG_ID, "role": "analyst"},
        )

    result = client_for(httpx.MockTransport(handler)).authenticate(
        email="person@example.test",
        password="not-retained-password",
        organization_id=UUID(ORG_ID),
    )
    assert result.user_id == UUID(USER_ID)
    assert result.organization_id == UUID(ORG_ID)
    assert result.role == "analyst"


def test_authenticate_rejects_response_extras_and_mismatched_organization() -> None:
    for payload in (
        {"user_id": USER_ID, "organization_id": ORG_ID, "role": "analyst", "extra": "no"},
        {
            "user_id": USER_ID,
            "organization_id": "33333333-3333-4333-8333-333333333333",
            "role": "analyst",
        },
    ):
        transport = httpx.MockTransport(lambda request, body=payload: httpx.Response(200, json=body))
        with pytest.raises(ControlUnavailable, match="Authentication service unavailable"):
            client_for(transport).authenticate(
                email="person@example.test", password="password", organization_id=UUID(ORG_ID)
            )


def test_authenticate_maps_denials_to_one_generic_invalid_login() -> None:
    messages = set()
    for status in (400, 401, 403, 404, 422):
        transport = httpx.MockTransport(
            lambda request, code=status: httpx.Response(code, content=b"sensitive upstream detail")
        )
        with pytest.raises(InvalidLogin) as captured:
            client_for(transport).authenticate(
                email="person@example.test", password="password", organization_id=UUID(ORG_ID)
            )
        messages.add(str(captured.value))
    assert messages == {"Invalid email, password, or organization"}


def test_error_responses_are_closed_without_reading_their_body() -> None:
    class ExplodingBody(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("error response body was read")

    transport = httpx.MockTransport(
        lambda request: httpx.Response(401, stream=ExplodingBody())
    )
    with pytest.raises(InvalidLogin):
        client_for(transport).authenticate(
            email="person@example.test", password="password", organization_id=UUID(ORG_ID)
        )


def test_raw_streaming_stops_as_soon_as_the_response_cap_is_crossed() -> None:
    class OversizedBody(httpx.SyncByteStream):
        def __iter__(self):
            yield b"x" * 200
            yield b"y" * 100
            raise AssertionError("client continued after crossing response cap")

    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, stream=OversizedBody())
    )
    with pytest.raises(ControlUnavailable):
        client_for(transport).authenticate(
            email="person@example.test", password="password", organization_id=UUID(ORG_ID)
        )


def test_authenticate_rejects_compression_and_oversized_responses() -> None:
    good = {"user_id": USER_ID, "organization_id": ORG_ID, "role": "analyst"}
    compressed = httpx.MockTransport(
        lambda request: httpx.Response(200, headers={"Content-Encoding": "gzip"}, content=b"not-gzip")
    )
    declared_huge = httpx.MockTransport(
        lambda request: httpx.Response(200, headers={"Content-Length": "257"}, content=b"")
    )
    streamed_huge = httpx.MockTransport(
        lambda request: httpx.Response(200, content=json.dumps(good).encode() + b" " * 256)
    )
    malformed_length = httpx.MockTransport(
        lambda request: httpx.Response(200, headers={"Content-Length": "not-a-length"})
    )
    signed_lengths = tuple(
        httpx.MockTransport(
            lambda request, value=value: httpx.Response(
                200, headers={"Content-Length": value}
            )
        )
        for value in ("+1", "-1")
    )
    for transport in (
        compressed,
        declared_huge,
        streamed_huge,
        malformed_length,
        *signed_lengths,
    ):
        with pytest.raises(ControlUnavailable, match="Authentication service unavailable"):
            client_for(transport).authenticate(
                email="person@example.test", password="password", organization_id=UUID(ORG_ID)
            )


def test_request_json_enforces_one_monotonic_deadline_across_slow_drip_chunks() -> None:
    class SlowDripBody(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(3):
                time.sleep(0.04)
                yield b" "
            raise AssertionError("client read another chunk after the total deadline")

    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=SlowDripBody(),
        )
    )
    control = ControlApiClient(
        settings(control_api_timeout_seconds=0.1), transport=transport
    )

    with pytest.raises(ControlUnavailable, match="Authentication service unavailable"):
        control.get_diagnostic(
            job_id=UUID(int=3),
            user_id=UUID(USER_ID),
            organization_id=UUID(ORG_ID),
        )


def test_real_socket_dns_and_headers_share_one_absolute_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(1.0)
    _, port = listener.getsockname()
    server_errors: list[BaseException] = []

    real_getaddrinfo = socket.getaddrinfo

    def slow_getaddrinfo(*args: object, **kwargs: object):
        time.sleep(0.08)
        return real_getaddrinfo(*args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", slow_getaddrinfo)
    resolver_script = getattr(control_client_module, "_DNS_LOOKUP_SCRIPT", "")
    monkeypatch.setattr(
        control_client_module,
        "_DNS_LOOKUP_SCRIPT",
        "import time; time.sleep(0.08)\n" + resolver_script,
        raising=False,
    )

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1.0)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    part = connection.recv(4096)
                    if not part:
                        return
                    request.extend(part)
                time.sleep(0.25)
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: close\r\n\r\n{}"
                )
        except BaseException as error:
            server_errors.append(error)
        finally:
            listener.close()

    server = threading.Thread(target=serve)
    server.start()
    control = ControlApiClient(
        settings(
            control_api_base_url=f"http://localhost:{port}",
            control_api_timeout_seconds=0.3,
        )
    )

    started = time.monotonic()
    with pytest.raises(ControlUnavailable, match="Authentication service unavailable"):
        control.get_diagnostic(
            job_id=UUID(int=3),
            user_id=UUID(USER_ID),
            organization_id=UUID(ORG_ID),
        )
    elapsed = time.monotonic() - started

    server.join(1.0)
    assert 0.24 <= elapsed < 0.38
    assert not server.is_alive()
    assert server_errors == []


def test_slow_dns_resolver_is_killed_and_reaped_at_deadline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pid_path = tmp_path / "resolver.pid"
    monkeypatch.setattr(
        control_client_module,
        "_DNS_LOOKUP_SCRIPT",
        (
            "import os, time\n"
            f"with open({str(pid_path)!r}, 'w') as stream:\n"
            "    stream.write(str(os.getpid()))\n"
            "time.sleep(10)\n"
        ),
    )
    control = ControlApiClient(
        settings(
            control_api_base_url="http://slow-dns.test:1",
            control_api_timeout_seconds=0.2,
        )
    )

    started = time.monotonic()
    with pytest.raises(ControlUnavailable, match="Authentication service unavailable"):
        control.get_diagnostic(
            job_id=UUID(int=3),
            user_id=UUID(USER_ID),
            organization_id=UUID(ORG_ID),
        )
    elapsed = time.monotonic() - started

    assert 0.16 <= elapsed < 0.3
    resolver_pid = int(pid_path.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(resolver_pid, 0)


def test_real_socket_connect_obeys_absolute_deadline() -> None:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    filler = socket.create_connection((host, port), timeout=0.5)
    control = ControlApiClient(
        settings(
            control_api_base_url=f"http://{host}:{port}",
            control_api_timeout_seconds=0.1,
        )
    )

    try:
        started = time.monotonic()
        with pytest.raises(ControlUnavailable, match="Authentication service unavailable"):
            control.get_diagnostic(
                job_id=UUID(int=3),
                user_id=UUID(USER_ID),
                organization_id=UUID(ORG_ID),
            )
        elapsed = time.monotonic() - started
    finally:
        filler.close()
        listener.close()

    assert 0.08 <= elapsed < 0.16


def test_real_socket_slow_headers_obey_deadline_and_connection_is_closed() -> None:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(1.0)
    host, port = listener.getsockname()
    peer_closed = threading.Event()
    server_errors: list[BaseException] = []

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1.0)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    part = connection.recv(4096)
                    if not part:
                        return
                    request.extend(part)
                time.sleep(0.2)
                peer_closed.set() if connection.recv(1) == b"" else None
        except BaseException as error:
            server_errors.append(error)
        finally:
            listener.close()

    server = threading.Thread(target=serve)
    server.start()
    control = ControlApiClient(
        settings(
            control_api_base_url=f"http://{host}:{port}",
            control_api_timeout_seconds=0.1,
        )
    )

    started = time.monotonic()
    with pytest.raises(ControlUnavailable, match="Authentication service unavailable"):
        control.get_diagnostic(
            job_id=UUID(int=3),
            user_id=UUID(USER_ID),
            organization_id=UUID(ORG_ID),
        )
    elapsed = time.monotonic() - started

    server.join(1.0)
    assert 0.08 <= elapsed < 0.16
    assert peer_closed.is_set()
    assert not server.is_alive()
    assert server_errors == []


def test_real_socket_chunk_drip_obeys_absolute_deadline_and_closes_connection() -> None:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(1.0)
    host, port = listener.getsockname()
    peer_closed = threading.Event()
    server_errors: list[BaseException] = []

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1.0)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    part = connection.recv(4096)
                    if not part:
                        return
                    request.extend(part)
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Encoding: identity\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"Connection: close\r\n\r\n"
                )
                for _ in range(10):
                    time.sleep(0.09)
                    try:
                        connection.sendall(b"1\r\n \r\n")
                    except OSError:
                        peer_closed.set()
                        return
                connection.sendall(b"0\r\n\r\n")
                peer_closed.set() if connection.recv(1) == b"" else None
        except BaseException as error:
            server_errors.append(error)
        finally:
            listener.close()

    server = threading.Thread(target=serve)
    server.start()
    control = ControlApiClient(
        settings(
            control_api_base_url=f"http://{host}:{port}",
            control_api_timeout_seconds=0.1,
        )
    )

    started = time.monotonic()
    with pytest.raises(ControlUnavailable, match="Authentication service unavailable"):
        control.get_diagnostic(
            job_id=UUID(int=3),
            user_id=UUID(USER_ID),
            organization_id=UUID(ORG_ID),
        )
    elapsed = time.monotonic() - started

    server.join(1.0)
    assert elapsed < 0.16
    assert peer_closed.is_set()
    assert not server.is_alive()
    assert server_errors == []


def test_deadline_at_response_eof_has_no_stop_iteration_context() -> None:
    class DeadlineAtEofBody(httpx.SyncByteStream):
        def __iter__(self):
            yield b"{}"
            time.sleep(0.11)

    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=DeadlineAtEofBody(),
        )
    )
    control = ControlApiClient(
        settings(control_api_timeout_seconds=0.1), transport=transport
    )

    with pytest.raises(ControlUnavailable) as captured:
        control.get_diagnostic(
            job_id=UUID(int=3),
            user_id=UUID(USER_ID),
            organization_id=UUID(ORG_ID),
        )

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_failures_are_sanitized_across_exception_graph_and_traceback() -> None:
    sentinel = "password-and-service-secret-sentinel"

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(sentinel, request=request)

    class ExplodingBody(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("invalid declared-length response body was read")

    pathological_length = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"Content-Length": "9" * 5000},
            stream=ExplodingBody(),
        )
    )

    for transport in (httpx.MockTransport(handler), pathological_length):
        with pytest.raises(ControlUnavailable) as captured:
            client_for(transport).authenticate(
                email="person@example.test", password=sentinel, organization_id=UUID(ORG_ID)
            )

        error = captured.value
        rendered = "".join(traceback.format_exception(error))
        assert str(error) == "Authentication service unavailable"
        assert error.__cause__ is None
        assert error.__context__ is None
        assert sentinel not in rendered
        assert "9" * 128 not in rendered


def test_request_json_transport_failures_drop_credentials_and_httpx_exception_graph() -> None:
    sentinel = "request-credential-and-error-sentinel"
    secret_settings = settings(bff_service_credential=sentinel * 3)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-SignalDesk-Service-Credential"] == sentinel * 3
        raise httpx.ConnectError(sentinel, request=request)

    control = ControlApiClient(
        secret_settings, transport=httpx.MockTransport(handler)
    )
    with pytest.raises(ControlUnavailable) as captured:
        control.get_diagnostic(
            job_id=UUID(int=3),
            user_id=UUID(USER_ID),
            organization_id=UUID(ORG_ID),
        )

    error = captured.value
    rendered = "".join(traceback.format_exception(error))
    error_repr = repr(error)
    assert str(error) == "Authentication service unavailable"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert sentinel not in rendered
    assert sentinel not in error_repr
    assert secret_settings.bff_service_credential.get_secret_value() not in rendered
    assert secret_settings.bff_service_credential.get_secret_value() not in error_repr


def test_timeout_is_bounded_and_redirects_are_disabled() -> None:
    control = client_for(httpx.MockTransport(lambda request: httpx.Response(503)))
    assert control.timeout_seconds == 5.0
    assert control.follows_redirects is False
    with pytest.raises(ControlUnavailable):
        control.authenticate(
            email="person@example.test", password="password", organization_id=UUID(ORG_ID)
        )
