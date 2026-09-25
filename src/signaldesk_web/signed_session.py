from __future__ import annotations

from flask import Flask
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer


class CurrentKeySessionInterface(SecureCookieSessionInterface):
    """Verify fallbacks but sign writes with the current key under Flask 3.1.0."""

    def get_signing_serializer(self, app: Flask) -> URLSafeTimedSerializer | None:
        if not app.secret_key:
            return None
        keys: list[str | bytes] = list(app.config["SECRET_KEY_FALLBACKS"] or ())
        keys.append(app.secret_key)
        return URLSafeTimedSerializer(
            keys,
            salt=self.salt,
            serializer=self.serializer,
            signer_kwargs={
                "key_derivation": self.key_derivation,
                "digest_method": self.digest_method,
            },
        )
