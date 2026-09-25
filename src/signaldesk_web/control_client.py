from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import ipaddress
import json
import select
import socket
import ssl
import subprocess
import sys
import time
from typing import Any, Callable, cast, Iterable, Iterator, TypeVar
from uuid import UUID

import httpcore
import httpx

from signaldesk_web.settings import Settings


_SERVICE_CREDENTIAL_HEADER = "X-SignalDesk-Service-Credential"
_INVALID_LOGIN_MESSAGE = "Invalid email, password, or organization"
_UNAVAILABLE_MESSAGE = "Authentication service unavailable"
_EXPECTED_RESPONSE_FIELDS = {"user_id", "organization_id", "role"}
_DIAGNOSTIC_FIELDS = {
    "id",
    "organization_id",
    "requested_by_user_id",
    "target",
    "status",
    "result_json",
    "correlation_id",
    "created_at",
    "updated_at",
}
_DIAGNOSTIC_STATUSES = {"pending", "claimed", "completed"}
_EXPORT_FIELDS = {
    "id",
    "organization_id",
    "requested_by_user_id",
    "format",
    "status",
    "object_key",
    "object_sha256",
    "size_bytes",
    "correlation_id",
    "created_at",
    "updated_at",
}
_EXPORT_DOWNLOAD_FIELDS = {
    "export_job_id",
    "organization_id",
    "format",
    "status",
    "object_key",
    "object_sha256",
    "size_bytes",
}
_EXPORT_FORMATS = {"csv", "json"}
_EXPORT_STATUSES = {"pending", "claimed", "completed"}
_MAX_EXPORT_BYTES = 1_073_741_824
_MAX_JSON_DEPTH = 32
_MAX_DECLARED_LENGTH_DIGITS = 20
_DNS_LOOKUP_SCRIPT = """
import json
import socket
import sys

request = json.load(sys.stdin)
addresses = socket.getaddrinfo(
    request["host"], request["port"], family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
)
json.dump(
    [
        [family, socktype, protocol, canonical_name, list(sockaddr)]
        for family, socktype, protocol, canonical_name, sockaddr in addresses
    ],
    sys.stdout,
)
"""
_T = TypeVar("_T")


@dataclass(frozen=True)
class _Deadline:
    expires_at: float

    def remaining(self) -> float:
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("control request deadline exceeded")
        return remaining


def _stop_resolver(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.kill()
    process.communicate()


def _resolve_addresses(
    host: str, port: int, deadline: _Deadline
) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        process: subprocess.Popen[str] | None = None
        try:
            deadline.remaining()
            process = subprocess.Popen(
                [sys.executable, "-I", "-c", _DNS_LOOKUP_SCRIPT],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="strict",
                env={},
                close_fds=True,
            )
            output, _ = process.communicate(
                json.dumps({"host": host, "port": port}),
                timeout=deadline.remaining(),
            )
            deadline.remaining()
            if process.returncode != 0 or len(output) > 65_536:
                raise ValueError("resolver failed")
            decoded: Any = json.loads(output)
            if not isinstance(decoded, list) or not 1 <= len(decoded) <= 64:
                raise ValueError("invalid resolver response")
            resolved: list[tuple[int, int, int, tuple[Any, ...]]] = []
            for item in decoded:
                if not isinstance(item, list) or len(item) != 5:
                    raise ValueError("invalid resolver item")
                family, socktype, protocol, canonical_name, sockaddr = item
                if (
                    family not in {socket.AF_INET, socket.AF_INET6}
                    or socktype != socket.SOCK_STREAM
                    or not isinstance(protocol, int)
                    or not isinstance(canonical_name, str)
                    or not isinstance(sockaddr, list)
                    or len(sockaddr) not in {2, 4}
                    or not isinstance(sockaddr[0], str)
                    or not isinstance(sockaddr[1], int)
                ):
                    raise ValueError("invalid resolver address")
                resolved.append((family, socktype, protocol, tuple(sockaddr)))
            return resolved
        except (subprocess.TimeoutExpired, TimeoutError):
            if process is not None:
                _stop_resolver(process)
            raise httpcore.ConnectTimeout("control DNS deadline exceeded") from None
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            if process is not None:
                _stop_resolver(process)
            raise httpcore.ConnectError("control DNS failed") from None
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    sockaddr: tuple[Any, ...] = (
        (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)
    )
    return [(family, socket.SOCK_STREAM, 0, sockaddr)]


class _DeadlineSocketStream(httpcore.NetworkStream):
    def __init__(self, stream_socket: socket.socket, deadline: _Deadline) -> None:
        self._socket = stream_socket
        self._deadline = deadline

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del timeout
        try:
            self._socket.settimeout(self._deadline.remaining())
            return self._socket.recv(max_bytes)
        except (TimeoutError, socket.timeout):
            raise httpcore.ReadTimeout("control read deadline exceeded") from None
        except OSError:
            raise httpcore.ReadError("control read failed") from None

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del timeout
        try:
            remaining = memoryview(buffer)
            while remaining:
                self._socket.settimeout(self._deadline.remaining())
                sent = self._socket.send(remaining)
                if sent == 0:
                    raise OSError("socket closed during write")
                remaining = remaining[sent:]
        except (TimeoutError, socket.timeout):
            raise httpcore.WriteTimeout("control write deadline exceeded") from None
        except OSError:
            raise httpcore.WriteError("control write failed") from None

    def close(self) -> None:
        self._socket.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        del timeout
        try:
            return _DeadlineTlsStream(
                self,
                ssl_context=ssl_context,
                server_hostname=server_hostname,
                deadline=self._deadline,
            )
        except httpcore.TimeoutException:
            self.close()
            raise httpcore.ConnectTimeout("control TLS deadline exceeded") from None
        except Exception:
            self.close()
            raise httpcore.ConnectError("control TLS failed") from None

    def get_extra_info(self, info: str) -> Any:
        if info == "client_addr":
            return self._socket.getsockname()
        if info == "server_addr":
            return self._socket.getpeername()
        if info == "socket":
            return self._socket
        if info == "is_readable":
            readable, _, _ = select.select([self._socket], [], [], 0)
            return bool(readable)
        return None


class _DeadlineTlsStream(httpcore.NetworkStream):
    def __init__(
        self,
        raw_stream: _DeadlineSocketStream,
        *,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None,
        deadline: _Deadline,
    ) -> None:
        self._raw_stream = raw_stream
        self._deadline = deadline
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._ssl_object = ssl_context.wrap_bio(
            self._incoming,
            self._outgoing,
            server_side=False,
            server_hostname=server_hostname,
        )
        self._perform(self._ssl_object.do_handshake)

    def _flush(self) -> None:
        encrypted = self._outgoing.read()
        if encrypted:
            self._raw_stream.write(encrypted, timeout=self._deadline.remaining())

    def _receive(self) -> None:
        encrypted = self._raw_stream.read(65_536, timeout=self._deadline.remaining())
        if encrypted:
            self._incoming.write(encrypted)
        else:
            self._incoming.write_eof()

    def _perform(self, operation: Callable[[], _T]) -> _T:
        while True:
            self._deadline.remaining()
            try:
                result = operation()
            except ssl.SSLWantReadError:
                self._flush()
                self._receive()
            except ssl.SSLWantWriteError:
                self._flush()
            else:
                self._flush()
                return result

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del timeout
        try:
            return self._perform(lambda: self._ssl_object.read(max_bytes))
        except httpcore.TimeoutException:
            raise
        except (ssl.SSLError, OSError):
            raise httpcore.ReadError("control TLS read failed") from None

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del timeout
        try:
            remaining = memoryview(buffer)
            while remaining:
                sent = self._perform(lambda: self._ssl_object.write(remaining))
                remaining = remaining[sent:]
        except httpcore.TimeoutException:
            raise
        except (ssl.SSLError, OSError):
            raise httpcore.WriteError("control TLS write failed") from None

    def close(self) -> None:
        self._raw_stream.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        del ssl_context, server_hostname, timeout
        raise httpcore.ConnectError("nested TLS is unsupported")

    def get_extra_info(self, info: str) -> Any:
        if info == "ssl_object":
            return self._ssl_object
        return self._raw_stream.get_extra_info(info)


class _DeadlineNetworkBackend(httpcore.NetworkBackend):
    def __init__(self, deadline: _Deadline) -> None:
        self._deadline = deadline

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[tuple[Any, ...]] | None = None,
    ) -> httpcore.NetworkStream:
        del timeout
        addresses = _resolve_addresses(host, port, self._deadline)
        timed_out = False
        for family, socktype, protocol, sockaddr in addresses:
            stream_socket = socket.socket(family, socktype, protocol)
            try:
                if local_address is not None:
                    bind_address: tuple[Any, ...] = (
                        (local_address, 0, 0, 0)
                        if family == socket.AF_INET6
                        else (local_address, 0)
                    )
                    stream_socket.bind(bind_address)
                for option in socket_options or ():
                    stream_socket.setsockopt(*option)
                stream_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                stream_socket.settimeout(self._deadline.remaining())
                stream_socket.connect(sockaddr)
                self._deadline.remaining()
                return _DeadlineSocketStream(stream_socket, self._deadline)
            except (TimeoutError, socket.timeout):
                timed_out = True
                stream_socket.close()
            except OSError:
                stream_socket.close()
        if timed_out:
            raise httpcore.ConnectTimeout("control connect deadline exceeded") from None
        raise httpcore.ConnectError("control connect failed") from None

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[tuple[Any, ...]] | None = None,
    ) -> httpcore.NetworkStream:
        del path, timeout, socket_options
        raise httpcore.UnsupportedProtocol("UNIX sockets are unsupported")

    def sleep(self, seconds: float) -> None:
        time.sleep(min(seconds, self._deadline.remaining()))
        self._deadline.remaining()


class _DeadlineResponseStream(httpx.SyncByteStream):
    def __init__(self, stream: Iterable[bytes]) -> None:
        self._stream = stream

    def __iter__(self) -> Iterator[bytes]:
        try:
            yield from self._stream
        except Exception:
            raise httpx.TransportError("control response read failed") from None

    def close(self) -> None:
        try:
            close = getattr(self._stream, "close", None)
            if close is not None:
                close()
        except Exception:
            return


class _DeadlineTransport(httpx.BaseTransport):
    def __init__(self, deadline: _Deadline) -> None:
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False),
            max_connections=1,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_DeadlineNetworkBackend(deadline),
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if not isinstance(request.stream, httpx.SyncByteStream):
            raise httpx.TransportError("invalid control request stream")
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        try:
            response = self._pool.handle_request(core_request)
        except Exception:
            raise httpx.TransportError("control request failed", request=request) from None
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_DeadlineResponseStream(cast(Iterable[bytes], response.stream)),
            extensions=response.extensions,
        )

    def close(self) -> None:
        self._pool.close()


def _strict_uuid(value: str) -> UUID:
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError("UUID must use canonical lowercase text")
    return parsed


def _parse_utc_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    canonical = parsed.isoformat().replace("+00:00", "Z")
    if parsed.tzinfo is None or not value.endswith("Z") or canonical != value:
        raise ValueError("timestamp must use canonical UTC JSON text")
    return parsed


def _valid_json_shape(value: Any) -> bool:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > _MAX_JSON_DEPTH:
            return False
        if isinstance(item, dict):
            stack.extend((nested, depth + 1) for nested in item.values())
        elif isinstance(item, list):
            stack.extend((nested, depth + 1) for nested in item)
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            return False
    return True


class InvalidLogin(Exception):
    """A deliberately generic authentication denial."""


class ControlUnavailable(Exception):
    """A sanitized, retryable control-plane failure."""


@dataclass(frozen=True)
class AuthenticatedIdentity:
    user_id: UUID
    organization_id: UUID
    role: str


@dataclass(frozen=True)
class DiagnosticRecord:
    id: UUID
    organization_id: UUID
    requested_by_user_id: UUID
    target: str
    status: str
    result_json: dict[str, Any] | None
    correlation_id: UUID
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class ExportRecord:
    id: UUID
    organization_id: UUID
    requested_by_user_id: UUID
    format: str
    status: str
    object_key: str | None
    object_sha256: str | None
    size_bytes: int | None
    correlation_id: UUID
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class ExportDownloadMetadata:
    export_job_id: UUID
    organization_id: UUID
    format: str
    status: str
    object_key: str | None
    object_sha256: str | None
    size_bytes: int | None


class ControlApiClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = settings.control_api_base_url
        self._credential = settings.bff_service_credential
        self._timeout = settings.control_api_timeout_seconds
        self._max_response_bytes = settings.control_api_max_response_bytes
        self._transport = transport

    @property
    def timeout_seconds(self) -> float:
        return self._timeout

    @property
    def follows_redirects(self) -> bool:
        return False

    def create_diagnostic(
        self, *, target: str, user_id: UUID, organization_id: UUID
    ) -> DiagnosticRecord:
        body = self._request_json(
            "POST",
            "/diagnostics",
            expected_status=201,
            user_id=user_id,
            organization_id=organization_id,
            json_body={"target": target},
        )
        record = self._parse_diagnostic(
            body,
            expected_job_id=None,
            expected_user_id=user_id,
            expected_organization_id=organization_id,
            expected_target=target,
        )
        if record is None:
            raise ControlUnavailable(_UNAVAILABLE_MESSAGE)
        return record

    def get_diagnostic(
        self, *, job_id: UUID, user_id: UUID, organization_id: UUID
    ) -> DiagnosticRecord:
        body = self._request_json(
            "GET",
            f"/diagnostics/{job_id}",
            expected_status=200,
            user_id=user_id,
            organization_id=organization_id,
        )
        record = self._parse_diagnostic(
            body,
            expected_job_id=job_id,
            expected_user_id=user_id,
            expected_organization_id=organization_id,
            expected_target=None,
        )
        if record is None:
            raise ControlUnavailable(_UNAVAILABLE_MESSAGE)
        return record

    def create_export(
        self, *, export_format: str, user_id: UUID, organization_id: UUID
    ) -> ExportRecord:
        body = self._request_json(
            "POST",
            "/exports",
            expected_status=201,
            user_id=user_id,
            organization_id=organization_id,
            json_body={"format": export_format},
        )
        record = self._parse_export(
            body,
            expected_job_id=None,
            expected_user_id=user_id,
            expected_organization_id=organization_id,
            expected_format=export_format,
        )
        if record is None:
            raise ControlUnavailable(_UNAVAILABLE_MESSAGE)
        return record

    def get_export(
        self, *, job_id: UUID, user_id: UUID, organization_id: UUID
    ) -> ExportRecord:
        body = self._request_json(
            "GET",
            f"/exports/{job_id}",
            expected_status=200,
            user_id=user_id,
            organization_id=organization_id,
        )
        record = self._parse_export(
            body,
            expected_job_id=job_id,
            expected_user_id=user_id,
            expected_organization_id=organization_id,
            expected_format=None,
        )
        if record is None:
            raise ControlUnavailable(_UNAVAILABLE_MESSAGE)
        return record

    def get_export_download(
        self, *, job_id: UUID, user_id: UUID, organization_id: UUID
    ) -> ExportDownloadMetadata:
        body = self._request_json(
            "GET",
            f"/exports/{job_id}/download",
            expected_status=200,
            user_id=user_id,
            organization_id=organization_id,
        )
        metadata = self._parse_export_download(
            body, expected_job_id=job_id, expected_organization_id=organization_id
        )
        if metadata is None:
            raise ControlUnavailable(_UNAVAILABLE_MESSAGE)
        return metadata

    def authenticate(
        self,
        *,
        email: str,
        password: str,
        organization_id: UUID,
    ) -> AuthenticatedIdentity:
        outcome = "unavailable"
        body: bytes | None = None
        try:
            with httpx.Client(
                transport=self._transport,
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    "POST",
                    f"{self._base_url}/internal/authenticate",
                    headers={
                        _SERVICE_CREDENTIAL_HEADER: self._credential.get_secret_value(),
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                    },
                    json={
                        "email": email,
                        "password": password,
                        "organization_id": str(organization_id),
                    },
                ) as response:
                    if response.status_code in {400, 401, 403, 404, 422}:
                        outcome = "invalid"
                    elif response.status_code != 200:
                        outcome = "unavailable"
                    elif response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        outcome = "unavailable"
                    elif not self._valid_declared_length(response.headers.get("Content-Length")):
                        outcome = "unavailable"
                    else:
                        chunks = bytearray()
                        source = (response.content,) if response.is_stream_consumed else response.iter_raw()
                        for chunk in source:
                            if len(chunks) + len(chunk) > self._max_response_bytes:
                                outcome = "unavailable"
                                break
                            chunks.extend(chunk)
                        else:
                            body = bytes(chunks)
                            outcome = "parse"
        except httpx.HTTPError:
            outcome = "unavailable"

        if outcome == "invalid":
            raise InvalidLogin(_INVALID_LOGIN_MESSAGE)
        if outcome != "parse" or body is None:
            raise ControlUnavailable(_UNAVAILABLE_MESSAGE)

        identity = self._parse_identity(body, organization_id)
        if identity is None:
            raise ControlUnavailable(_UNAVAILABLE_MESSAGE)
        return identity

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ControlUnavailable(_UNAVAILABLE_MESSAGE)
        return remaining

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        expected_status: int,
        user_id: UUID,
        organization_id: UUID,
        json_body: dict[str, str] | None = None,
    ) -> str:
        body: str | None = None
        deadline = time.monotonic() + self._timeout
        try:
            transport = self._transport or _DeadlineTransport(_Deadline(deadline))
            headers = {
                _SERVICE_CREDENTIAL_HEADER: self._credential.get_secret_value(),
                "X-SignalDesk-User-ID": str(user_id),
                "X-SignalDesk-Organization-ID": str(organization_id),
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            }
            request_kwargs: dict[str, Any] = {"headers": headers}
            if json_body is not None:
                request_kwargs["json"] = json_body
            with httpx.Client(
                transport=transport,
                timeout=httpx.Timeout(self._remaining(deadline)),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    method,
                    f"{self._base_url}{path}",
                    timeout=self._remaining(deadline),
                    **request_kwargs,
                ) as response:
                    self._remaining(deadline)
                    content_type = response.headers.get("Content-Type")
                    declared_length = response.headers.get("Content-Length")
                    if (
                        response.status_code != expected_status
                        or response.headers.get("Content-Encoding", "identity").lower()
                        != "identity"
                        or content_type != "application/json"
                        or not self._valid_declared_length(declared_length)
                    ):
                        raise ControlUnavailable(_UNAVAILABLE_MESSAGE)
                    chunks = bytearray()
                    source = (
                        (response.content,)
                        if response.is_stream_consumed
                        else response.iter_raw()
                    )
                    iterator = iter(source)
                    while True:
                        self._remaining(deadline)
                        exhausted = False
                        chunk = b""
                        try:
                            chunk = next(iterator)
                        except StopIteration:
                            exhausted = True
                        if exhausted:
                            self._remaining(deadline)
                            break
                        self._remaining(deadline)
                        if len(chunks) + len(chunk) > self._max_response_bytes:
                            raise ControlUnavailable(_UNAVAILABLE_MESSAGE)
                        chunks.extend(chunk)
                    if declared_length is not None and int(declared_length) != len(chunks):
                        raise ControlUnavailable(_UNAVAILABLE_MESSAGE)
                    try:
                        body = bytes(chunks).decode("utf-8")
                    except UnicodeDecodeError:
                        body = None
        except ControlUnavailable:
            raise
        except httpx.HTTPError:
            pass
        if body is None:
            raise ControlUnavailable(_UNAVAILABLE_MESSAGE)
        return body

    @staticmethod
    def _parse_diagnostic(
        body: str,
        *,
        expected_job_id: UUID | None,
        expected_user_id: UUID,
        expected_organization_id: UUID,
        expected_target: str | None,
    ) -> DiagnosticRecord | None:
        try:
            payload: Any = json.loads(
                body,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
            if not isinstance(payload, dict) or set(payload) != _DIAGNOSTIC_FIELDS:
                return None
            if not all(
                isinstance(payload[field], str)
                for field in (
                    "id",
                    "organization_id",
                    "requested_by_user_id",
                    "target",
                    "status",
                    "correlation_id",
                    "created_at",
                    "updated_at",
                )
            ):
                return None
            job_id = _strict_uuid(payload["id"])
            organization_id = _strict_uuid(payload["organization_id"])
            requested_by_user_id = _strict_uuid(payload["requested_by_user_id"])
            correlation_id = _strict_uuid(payload["correlation_id"])
            created_at = _parse_utc_timestamp(payload["created_at"])
            updated_at = _parse_utc_timestamp(payload["updated_at"])
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            TypeError,
            AttributeError,
            RecursionError,
            OverflowError,
        ):
            return None
        target = payload["target"]
        status = payload["status"]
        result = payload["result_json"]
        if (
            (expected_job_id is not None and job_id != expected_job_id)
            or organization_id != expected_organization_id
            or requested_by_user_id != expected_user_id
            or (expected_target is not None and target != expected_target)
            or not 1 <= len(target) <= 2048
            or target != target.strip()
            or status not in _DIAGNOSTIC_STATUSES
            or (result is not None and not isinstance(result, dict))
            or (result is not None and not _valid_json_shape(result))
            or created_at.tzinfo is None
            or updated_at.tzinfo is None
            or updated_at < created_at
        ):
            return None
        return DiagnosticRecord(
            id=job_id,
            organization_id=organization_id,
            requested_by_user_id=requested_by_user_id,
            target=target,
            status=status,
            result_json=result,
            correlation_id=correlation_id,
            created_at=created_at,
            updated_at=updated_at,
        )

    @staticmethod
    def _valid_export_artifact(
        *,
        job_id: UUID,
        organization_id: UUID,
        export_format: str,
        status: str,
        object_key: Any,
        object_sha256: Any,
        size_bytes: Any,
    ) -> bool:
        if status != "completed":
            return object_key is None and object_sha256 is None and size_bytes is None
        expected_key = f"exports/{organization_id}/{job_id}.{export_format}"
        return (
            object_key == expected_key
            and isinstance(object_sha256, str)
            and len(object_sha256) == 64
            and all(character in "0123456789abcdef" for character in object_sha256)
            and isinstance(size_bytes, int)
            and not isinstance(size_bytes, bool)
            and 0 <= size_bytes <= _MAX_EXPORT_BYTES
        )

    @classmethod
    def _parse_export(
        cls,
        body: str,
        *,
        expected_job_id: UUID | None,
        expected_user_id: UUID,
        expected_organization_id: UUID,
        expected_format: str | None,
    ) -> ExportRecord | None:
        try:
            payload: Any = json.loads(
                body,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
            if not isinstance(payload, dict) or set(payload) != _EXPORT_FIELDS:
                return None
            if not all(
                isinstance(payload[field], str)
                for field in (
                    "id",
                    "organization_id",
                    "requested_by_user_id",
                    "format",
                    "status",
                    "correlation_id",
                    "created_at",
                    "updated_at",
                )
            ):
                return None
            job_id = _strict_uuid(payload["id"])
            organization_id = _strict_uuid(payload["organization_id"])
            requested_by_user_id = _strict_uuid(payload["requested_by_user_id"])
            correlation_id = _strict_uuid(payload["correlation_id"])
            created_at = _parse_utc_timestamp(payload["created_at"])
            updated_at = _parse_utc_timestamp(payload["updated_at"])
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            TypeError,
            AttributeError,
            RecursionError,
            OverflowError,
        ):
            return None
        export_format = payload["format"]
        status = payload["status"]
        if (
            (expected_job_id is not None and job_id != expected_job_id)
            or organization_id != expected_organization_id
            or requested_by_user_id != expected_user_id
            or (expected_format is not None and export_format != expected_format)
            or export_format not in _EXPORT_FORMATS
            or status not in _EXPORT_STATUSES
            or created_at.tzinfo is None
            or updated_at.tzinfo is None
            or updated_at < created_at
            or not cls._valid_export_artifact(
                job_id=job_id,
                organization_id=organization_id,
                export_format=export_format,
                status=status,
                object_key=payload["object_key"],
                object_sha256=payload["object_sha256"],
                size_bytes=payload["size_bytes"],
            )
        ):
            return None
        return ExportRecord(
            id=job_id,
            organization_id=organization_id,
            requested_by_user_id=requested_by_user_id,
            format=export_format,
            status=status,
            object_key=payload["object_key"],
            object_sha256=payload["object_sha256"],
            size_bytes=payload["size_bytes"],
            correlation_id=correlation_id,
            created_at=created_at,
            updated_at=updated_at,
        )

    @classmethod
    def _parse_export_download(
        cls,
        body: str,
        *,
        expected_job_id: UUID,
        expected_organization_id: UUID,
    ) -> ExportDownloadMetadata | None:
        try:
            payload: Any = json.loads(
                body,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
            if not isinstance(payload, dict) or set(payload) != _EXPORT_DOWNLOAD_FIELDS:
                return None
            if not all(
                isinstance(payload[field], str)
                for field in ("export_job_id", "organization_id", "format", "status")
            ):
                return None
            job_id = _strict_uuid(payload["export_job_id"])
            organization_id = _strict_uuid(payload["organization_id"])
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            TypeError,
            AttributeError,
            RecursionError,
            OverflowError,
        ):
            return None
        export_format = payload["format"]
        status = payload["status"]
        if (
            job_id != expected_job_id
            or organization_id != expected_organization_id
            or export_format not in _EXPORT_FORMATS
            or status not in _EXPORT_STATUSES
            or not cls._valid_export_artifact(
                job_id=job_id,
                organization_id=organization_id,
                export_format=export_format,
                status=status,
                object_key=payload["object_key"],
                object_sha256=payload["object_sha256"],
                size_bytes=payload["size_bytes"],
            )
        ):
            return None
        return ExportDownloadMetadata(
            export_job_id=job_id,
            organization_id=organization_id,
            format=export_format,
            status=status,
            object_key=payload["object_key"],
            object_sha256=payload["object_sha256"],
            size_bytes=payload["size_bytes"],
        )

    def _valid_declared_length(self, value: str | None) -> bool:
        if value is None:
            return True
        if (
            len(value) > _MAX_DECLARED_LENGTH_DIGITS
            or not value.isascii()
            or not value.isdigit()
        ):
            return False
        try:
            return int(value) <= self._max_response_bytes
        except (ValueError, OverflowError):
            return False

    @staticmethod
    def _parse_identity(body: bytes, requested_organization: UUID) -> AuthenticatedIdentity | None:
        try:
            payload: Any = json.loads(body)
            if not isinstance(payload, dict) or set(payload) != _EXPECTED_RESPONSE_FIELDS:
                return None
            if not all(isinstance(payload[field], str) for field in _EXPECTED_RESPONSE_FIELDS):
                return None
            user_id = _strict_uuid(payload["user_id"])
            organization_id = _strict_uuid(payload["organization_id"])
            role = payload["role"]
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            return None
        if organization_id != requested_organization:
            return None
        if not 1 <= len(role) <= 50 or any(ord(character) < 32 for character in role):
            return None
        return AuthenticatedIdentity(
            user_id=user_id,
            organization_id=organization_id,
            role=role,
        )
