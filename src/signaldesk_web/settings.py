from __future__ import annotations

import json
import secrets
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


_MASKED_INVALID_SECRET = ""
_MASKED_INVALID_CONTROL_ORIGIN = "invalid-control-api-origin"
_SECRET_FIELDS = (
    "bff_service_credential",
    "flask_secret_key",
)


def _secret(value: Any) -> SecretStr:
    """Convert raw secret representations before validation can expose their input."""
    if isinstance(value, SecretStr):
        return value
    if isinstance(value, str):
        return SecretStr(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return SecretStr(bytes(value).decode("ascii"))
        except UnicodeDecodeError:
            return SecretStr(_MASKED_INVALID_SECRET)
    return SecretStr(_MASKED_INVALID_SECRET)


def _validate_secret(value: SecretStr) -> SecretStr:
    raw = value.get_secret_value()
    if len(raw) < 32 or not raw.isascii() or any(character.isspace() for character in raw):
        raise ValueError("secret must be at least 32 ASCII characters without whitespace")
    return value


def _control_origin(value: Any) -> str:
    if not isinstance(value, str):
        return _MASKED_INVALID_CONTROL_ORIGIN
    if any(character.isspace() or ord(character) < 32 for character in value):
        return _MASKED_INVALID_CONTROL_ORIGIN
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return _MASKED_INVALID_CONTROL_ORIGIN
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or (port is not None and not 1 <= port <= 65535)
    ):
        return _MASKED_INVALID_CONTROL_ORIGIN
    return value.rstrip("/")


class Settings(BaseSettings):
    """Fail-closed process configuration loaded only from the web-app prefix."""

    model_config = SettingsConfigDict(
        env_prefix="SIGNALDESK_WEB_",
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    service_name: str = "signaldesk-web"
    environment: Literal["local", "test", "production"]
    control_api_base_url: str
    bff_service_credential: SecretStr
    flask_secret_key: SecretStr
    flask_secret_key_fallbacks: Annotated[tuple[SecretStr, ...], NoDecode]
    session_cookie_secure: bool = False
    session_lifetime_seconds: int = Field(default=28_800, ge=300, le=86_400)
    control_api_timeout_seconds: float = Field(default=5.0, ge=0.1, le=15.0)
    control_api_max_response_bytes: int = Field(default=16_384, ge=256, le=1_048_576)

    @model_validator(mode="before")
    @classmethod
    def mask_secret_inputs(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        masked = dict(value)
        for field_name in _SECRET_FIELDS:
            if field_name in masked:
                masked[field_name] = _secret(masked[field_name])
        if "control_api_base_url" in masked:
            masked["control_api_base_url"] = _control_origin(masked["control_api_base_url"])
        if "flask_secret_key_fallbacks" in masked:
            fallbacks = masked["flask_secret_key_fallbacks"]
            if isinstance(fallbacks, str):
                try:
                    decoded_fallbacks = json.loads(fallbacks)
                except (json.JSONDecodeError, TypeError):
                    decoded_fallbacks = None
                if isinstance(decoded_fallbacks, list):
                    masked["flask_secret_key_fallbacks"] = tuple(
                        _secret(item) for item in decoded_fallbacks
                    )
                else:
                    masked["flask_secret_key_fallbacks"] = (
                        SecretStr(_MASKED_INVALID_SECRET),
                    )
            elif isinstance(fallbacks, (list, tuple)):
                masked["flask_secret_key_fallbacks"] = tuple(_secret(item) for item in fallbacks)
            else:
                masked["flask_secret_key_fallbacks"] = (_secret(fallbacks),)
        return masked

    @field_validator("bff_service_credential", "flask_secret_key")
    @classmethod
    def validate_scalar_secret(cls, value: SecretStr) -> SecretStr:
        return _validate_secret(value)

    @field_validator("flask_secret_key_fallbacks")
    @classmethod
    def validate_fallback_secrets(cls, value: tuple[SecretStr, ...]) -> tuple[SecretStr, ...]:
        if not value:
            raise ValueError("at least one fallback signing key is required")
        for secret in value:
            _validate_secret(secret)
        return value

    @field_validator("control_api_base_url")
    @classmethod
    def validate_control_origin(cls, value: str) -> str:
        if value == _MASKED_INVALID_CONTROL_ORIGIN:
            raise ValueError("control API URL must be an HTTP(S) origin")
        return value

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        configured_secrets = [
            self.bff_service_credential.get_secret_value(),
            self.flask_secret_key.get_secret_value(),
            *(fallback.get_secret_value() for fallback in self.flask_secret_key_fallbacks),
        ]
        for index, configured_secret in enumerate(configured_secrets):
            if any(
                secrets.compare_digest(configured_secret, other)
                for other in configured_secrets[index + 1 :]
            ):
                raise ValueError("service and signing secrets must be distinct")
        if self.environment == "production":
            if not self.session_cookie_secure:
                raise ValueError("production requires secure session cookies")
            if not self.control_api_base_url.startswith("https://"):
                raise ValueError("production requires an HTTPS control API")
        return self
