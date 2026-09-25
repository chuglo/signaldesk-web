from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import re
from uuid import UUID

from flask import Flask
from werkzeug.datastructures import MultiDict

from signaldesk_web import create_app
from signaldesk_web.control_client import ControlUnavailable, InvalidLogin
from signaldesk_web.settings import Settings


ORG_ID = "11111111-1111-4111-8111-111111111111"
USER_ID = "22222222-2222-4222-8222-222222222222"
CURRENT = "c" * 32
FALLBACK = "f" * 32


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "control_api_base_url": "http://control.test",
        "bff_service_credential": "b" * 32,
        "flask_secret_key": CURRENT,
        "flask_secret_key_fallbacks": [FALLBACK],
    }
    values.update(overrides)
    return Settings.model_validate(values)


@dataclass(frozen=True)
class Identity:
    user_id: UUID = UUID(USER_ID)
    organization_id: UUID = UUID(ORG_ID)
    role: str = "analyst"


class FakeControl:
    def __init__(self, outcome: object = Identity()) -> None:
        self.outcome = outcome
        self.calls: list[dict[str, object]] = []

    def authenticate(self, **values: object) -> Identity:
        self.calls.append(values)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        assert isinstance(self.outcome, Identity)
        return self.outcome


def csrf_from(response_data: bytes) -> str:
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response_data)
    assert match is not None
    return match.group(1).decode()


def login_form(csrf: str, **overrides: str) -> dict[str, str]:
    form = {
        "csrf_token": csrf,
        "email": "person@example.test",
        "password": "user-password",
        "organization_id": ORG_ID,
    }
    form.update(overrides)
    return form


def test_get_login_creates_random_signed_session_csrf_and_escapes_template() -> None:
    app = create_app(settings(), control_client=FakeControl())
    client = app.test_client()

    response = client.get("/login")
    token = csrf_from(response.data)
    assert response.status_code == 200
    assert len(token) >= 32
    with client.session_transaction() as signed_session:
        assert signed_session["csrf_token"] == token
        assert set(signed_session) == {"csrf_token"}


def test_successful_login_calls_control_and_replaces_fixed_session_with_approved_fields() -> None:
    control = FakeControl()
    app = create_app(settings(), control_client=control)
    client = app.test_client()
    token = csrf_from(client.get("/login").data)
    with client.session_transaction() as signed_session:
        signed_session["attacker_fixed"] = "must disappear"

    response = client.post("/login", data=login_form(token))
    assert response.status_code == 302
    assert response.headers["Location"] == "/"
    assert control.calls == [
        {
            "email": "person@example.test",
            "password": "user-password",
            "organization_id": UUID(ORG_ID),
        }
    ]
    with client.session_transaction() as signed_session:
        assert set(signed_session) == {"user_id", "organization_id", "role", "csrf_token"}
        assert signed_session["user_id"] == USER_ID
        assert signed_session["organization_id"] == ORG_ID
        assert signed_session["role"] == "analyst"
        assert signed_session["csrf_token"] != token
        dumped = repr(dict(signed_session))
        assert "user-password" not in dumped
        assert "person@example.test" not in dumped


def test_login_requires_exact_bounded_form_and_never_uses_json_authority() -> None:
    malformed_forms: list[object] = [
        {},
        {"email": "person@example.test", "password": "x", "organization_id": ORG_ID},
        MultiDict(
            [
                ("csrf_token", "token-one"),
                ("csrf_token", "token-two"),
                ("email", "person@example.test"),
                ("password", "x"),
                ("organization_id", ORG_ID),
            ]
        ),
        login_form("wrong", email="not-an-email"),
        login_form("wrong", password="x" * 1025),
        login_form("wrong", organization_id="not-a-uuid"),
        login_form("wrong") | {"unexpected": "field"},
    ]
    for form in malformed_forms:
        control = FakeControl()
        client = create_app(settings(), control_client=control).test_client()
        client.get("/login")
        response = client.post("/login", data=form)
        assert response.status_code == 400
        assert control.calls == []

    control = FakeControl()
    client = create_app(settings(), control_client=control).test_client()
    response = client.post("/login", json=login_form("anything"))
    assert response.status_code == 400
    assert control.calls == []


def test_login_rejects_multipart_file_fields_before_authentication() -> None:
    control = FakeControl()
    client = create_app(settings(), control_client=control).test_client()
    token = csrf_from(client.get("/login").data)
    response = client.post(
        "/login",
        data=login_form(token) | {"upload": (BytesIO(b"data"), "upload.txt")},
    )
    assert response.status_code == 400
    assert control.calls == []


def test_csrf_wrong_missing_and_replay_are_rejected_before_authentication() -> None:
    control = FakeControl()
    client = create_app(settings(), control_client=control).test_client()
    old_token = csrf_from(client.get("/login").data)
    assert client.post("/login", data=login_form("wrong")).status_code == 400
    assert control.calls == []

    assert client.post("/login", data=login_form(old_token)).status_code == 302
    assert len(control.calls) == 1
    assert client.post("/logout", data={"csrf_token": old_token}).status_code == 400
    with client.session_transaction() as signed_session:
        assert signed_session["user_id"] == USER_ID


def test_auth_failures_are_generic_and_bounded() -> None:
    for error, status in (
        (InvalidLogin("upstream detail"), 401),
        (ControlUnavailable("transport secret"), 503),
    ):
        control = FakeControl(error)
        client = create_app(settings(), control_client=control).test_client()
        token = csrf_from(client.get("/login").data)
        response = client.post("/login", data=login_form(token))
        assert response.status_code == status
        assert b"upstream detail" not in response.data
        assert b"transport secret" not in response.data
        assert b"Unable to sign in" in response.data


def test_logout_requires_an_exact_file_free_form_and_only_then_clears_session() -> None:
    client = create_app(settings(), control_client=FakeControl()).test_client()
    token = csrf_from(client.get("/login").data)
    client.post("/login", data=login_form(token))
    assert client.get("/logout").status_code == 405
    with client.session_transaction() as signed_session:
        logout_token = signed_session["csrf_token"]
        authenticated_session = dict(signed_session)

    invalid_requests = (
        lambda: client.post(
            "/logout",
            data={"csrf_token": logout_token, "upload": (BytesIO(b"data"), "upload.txt")},
        ),
        lambda: client.post(
            "/logout", data={"csrf_token": logout_token, "unexpected": "field"}
        ),
        lambda: client.post(
            "/logout",
            data=MultiDict((("csrf_token", logout_token), ("csrf_token", logout_token))),
        ),
        lambda: client.post(
            "/logout",
            data=f"csrf_token={logout_token}",
            content_type="text/plain",
        ),
        lambda: client.post("/logout", json={"csrf_token": logout_token}),
    )
    for send_invalid_request in invalid_requests:
        invalid_response = send_invalid_request()
        assert invalid_response.status_code == 400
        with client.session_transaction() as signed_session:
            assert dict(signed_session) == authenticated_session

    response = client.post("/logout", data={"csrf_token": logout_token})
    assert response.status_code == 302
    assert response.headers["Location"] == "/login"
    with client.session_transaction() as signed_session:
        assert dict(signed_session) == {}


def test_cookie_policy_is_fixed_in_test_and_production() -> None:
    test_app = create_app(settings(), control_client=FakeControl())
    test_cookie = test_app.test_client().get("/login").headers["Set-Cookie"]
    assert "HttpOnly" in test_cookie
    assert "SameSite=Lax" in test_cookie
    assert "Secure" not in test_cookie
    assert "Expires=" not in test_cookie

    production = settings(
        environment="production",
        control_api_base_url="https://control.example",
        session_cookie_secure=True,
    )
    production_cookie = create_app(production, control_client=FakeControl()).test_client().get(
        "/login"
    ).headers["Set-Cookie"]
    assert "Secure" in production_cookie
    assert "HttpOnly" in production_cookie
    assert "SameSite=Lax" in production_cookie


def test_fallback_accepts_old_cookie_but_mutation_signs_with_current_key() -> None:
    old_signer_app = Flask("old")
    old_signer_app.config.update(SECRET_KEY=FALLBACK, SECRET_KEY_FALLBACKS=[])
    old_serializer = old_signer_app.session_interface.get_signing_serializer(old_signer_app)
    assert old_serializer is not None
    old_cookie = old_serializer.dumps({"user_id": USER_ID})

    app = create_app(settings(), control_client=FakeControl())
    client = app.test_client()
    client.set_cookie(app.config["SESSION_COOKIE_NAME"], old_cookie)
    response = client.get("/login")
    assert response.status_code == 200
    new_cookie = client.get_cookie(app.config["SESSION_COOKIE_NAME"])
    assert new_cookie is not None
    current_only_app = Flask("current")
    current_only_app.config.update(SECRET_KEY=CURRENT, SECRET_KEY_FALLBACKS=[])
    current_serializer = current_only_app.session_interface.get_signing_serializer(current_only_app)
    assert current_serializer is not None
    assert current_serializer.loads(new_cookie.value)["user_id"] == USER_ID
    assert old_serializer.loads(old_cookie)["user_id"] == USER_ID
    assert old_serializer.loads_unsafe(new_cookie.value)[0] is False


def test_health_does_not_mutate_session() -> None:
    client = create_app(settings(), control_client=FakeControl()).test_client()
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json == {"status": "ok"}
    assert "Set-Cookie" not in response.headers
