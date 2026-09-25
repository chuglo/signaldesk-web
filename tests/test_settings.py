from __future__ import annotations

import json
import traceback

import pytest
from pydantic import SecretStr, ValidationError

from signaldesk_web.settings import Settings


CURRENT = "c" * 32
FALLBACK = "f" * 32
BFF = "b" * 32


def valid_settings(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "environment": "test",
        "control_api_base_url": "http://control.test",
        "bff_service_credential": BFF,
        "flask_secret_key": CURRENT,
        "flask_secret_key_fallbacks": [FALLBACK],
    }
    values.update(overrides)
    return values


def test_settings_require_strong_secret_values_and_mask_every_raw_representation() -> None:
    settings = Settings.model_validate(valid_settings())
    assert isinstance(settings.bff_service_credential, SecretStr)
    assert isinstance(settings.flask_secret_key, SecretStr)
    assert settings.flask_secret_key_fallbacks
    assert all(isinstance(value, SecretStr) for value in settings.flask_secret_key_fallbacks)
    assert CURRENT not in repr(settings)
    assert BFF not in json.dumps(settings.model_dump(), default=str)
    assert FALLBACK not in settings.model_dump_json()

    for raw in ("sentinel-secret", b"sentinel-secret", bytearray(b"sentinel-secret"), memoryview(b"sentinel-secret")):
        with pytest.raises(ValidationError) as captured:
            Settings.model_validate(valid_settings(bff_service_credential=raw))
        rendered = repr(captured.value.errors(include_input=True)) + captured.value.json(include_input=True)
        assert "sentinel-secret" not in rendered


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("bff_service_credential", "x" * 31),
        ("bff_service_credential", "x" * 32 + " "),
        ("bff_service_credential", "é" * 32),
        ("flask_secret_key", "x" * 31),
        ("flask_secret_key_fallbacks", []),
        ("flask_secret_key_fallbacks", [""]),
    ],
)
def test_settings_reject_weak_or_missing_secrets(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate(valid_settings(**{field: value}))


def test_settings_require_distinct_service_and_signing_secrets() -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate(valid_settings(flask_secret_key=BFF))
    with pytest.raises(ValidationError):
        Settings.model_validate(valid_settings(flask_secret_key_fallbacks=[CURRENT]))
    with pytest.raises(ValidationError):
        Settings.model_validate(valid_settings(flask_secret_key_fallbacks=[FALLBACK, FALLBACK]))


def test_settings_validate_environment_specific_transport_and_cookie_security() -> None:
    local = Settings.model_validate(valid_settings(environment="local", session_cookie_secure=False))
    assert local.session_cookie_secure is False

    with pytest.raises(ValidationError):
        Settings.model_validate(valid_settings(environment="production", session_cookie_secure=False))
    with pytest.raises(ValidationError):
        Settings.model_validate(
            valid_settings(
                environment="production",
                session_cookie_secure=True,
                control_api_base_url="http://control.example",
            )
        )

    production = Settings.model_validate(
        valid_settings(
            environment="production",
            session_cookie_secure=True,
            control_api_base_url="https://control.example",
        )
    )
    assert production.session_cookie_secure is True


@pytest.mark.parametrize(
    "url",
    [
        "ftp://control.example",
        "https://user:pass@control.example",
        "https://control.example/path",
        "https://control.example/?query=yes",
        "https://control.example/#fragment",
        "https://control.example\n.evil.test",
    ],
)
def test_control_api_url_is_an_unambiguous_http_origin(url: str) -> None:
    with pytest.raises(ValidationError) as captured:
        Settings.model_validate(valid_settings(control_api_base_url=url))
    rendered = repr(captured.value.errors(include_input=True)) + captured.value.json(include_input=True)
    if "user:pass" in url:
        assert "user:pass" not in rendered


def test_scalar_fallback_key_is_rejected_without_leaking_it() -> None:
    sentinel = "scalar-fallback-secret-value-123456789"
    with pytest.raises(ValidationError) as captured:
        Settings.model_validate(valid_settings(flask_secret_key_fallbacks=sentinel))
    assert sentinel not in repr(captured.value.errors(include_input=True))


def test_settings_use_a_strict_environment_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIGNALDESK_WEB_ENVIRONMENT", "test")
    monkeypatch.setenv("SIGNALDESK_WEB_CONTROL_API_BASE_URL", "http://control.test")
    monkeypatch.setenv("SIGNALDESK_WEB_BFF_SERVICE_CREDENTIAL", BFF)
    monkeypatch.setenv("SIGNALDESK_WEB_FLASK_SECRET_KEY", CURRENT)
    monkeypatch.setenv("SIGNALDESK_WEB_FLASK_SECRET_KEY_FALLBACKS", json.dumps([FALLBACK]))
    loaded = Settings()
    assert loaded.environment == "test"
    assert loaded.control_api_base_url == "http://control.test"


def test_malformed_fallback_environment_value_is_absent_from_exception_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "malformed-fallback-secret-sentinel"
    monkeypatch.setenv("SIGNALDESK_WEB_ENVIRONMENT", "test")
    monkeypatch.setenv("SIGNALDESK_WEB_CONTROL_API_BASE_URL", "http://control.test")
    monkeypatch.setenv("SIGNALDESK_WEB_BFF_SERVICE_CREDENTIAL", BFF)
    monkeypatch.setenv("SIGNALDESK_WEB_FLASK_SECRET_KEY", CURRENT)
    monkeypatch.setenv("SIGNALDESK_WEB_FLASK_SECRET_KEY_FALLBACKS", sentinel)
    with pytest.raises(Exception) as captured:
        Settings()
    assert sentinel not in "".join(traceback.format_exception(captured.value))
    nested = captured.value.__cause__ or captured.value.__context__
    assert sentinel not in repr(getattr(nested, "doc", None))
