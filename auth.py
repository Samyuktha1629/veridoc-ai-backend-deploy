"""Password hashing and signed bearer sessions for workspace accounts."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

TOKEN_LIFETIME_SECONDS = 8 * 60 * 60
PASSWORD_HASH_ITERATIONS = 600_000
_DEVELOPMENT_SESSION_SECRET = "veridoc-ai-development-only-session-secret"


def validate_auth_configuration() -> None:
    if os.getenv("APP_ENV", "").lower() != "production":
        return
    if len(_secret()) < 32:
        raise RuntimeError("Production requires a SESSION_SECRET of at least 32 bytes.")
    origins = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "").split(",")
        if origin.strip()
    ]
    if not origins or any(
        origin == "*" or not origin.startswith("https://")
        for origin in origins
    ):
        raise RuntimeError(
            "Production CORS_ORIGINS must list exact HTTPS frontend origins."
        )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return "$".join((
        "pbkdf2_sha256",
        str(PASSWORD_HASH_ITERATIONS),
        _encode(salt),
        _encode(digest),
    ))


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        if not isinstance(password, str) or not isinstance(stored_hash, str):
            return False
        algorithm, iterations, encoded_salt, encoded_digest = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        expected = _decode(encoded_digest)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            _decode(encoded_salt),
            int(iterations),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, AttributeError):
        return False


def issue_token(username: str) -> str:
    expires_at = int(time.time()) + TOKEN_LIFETIME_SECONDS
    payload = _encode(json.dumps(
        {"sub": username, "exp": expires_at},
        separators=(",", ":"),
    ).encode("utf-8"))
    signature = _encode(hmac.new(
        _secret(),
        payload.encode("ascii"),
        hashlib.sha256,
    ).digest())
    return f"{payload}.{signature}"


def verify_token(token: str) -> bool:
    return token_username(token) is not None


def token_username(token: str) -> str | None:
    try:
        if not isinstance(token, str) or "." not in token:
            return None
        payload, supplied_signature = token.split(".", 1)
        expected_signature = _encode(hmac.new(
            _secret(),
            payload.encode("ascii"),
            hashlib.sha256,
        ).digest())
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return None
        claims = json.loads(_decode(payload))
        username = claims.get("sub")
        if (
            not isinstance(username, str)
            or not username
            or not isinstance(claims.get("exp"), int)
            or claims["exp"] <= int(time.time())
        ):
            return None
        return username
    except (ValueError, TypeError, AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _secret() -> bytes:
    secret = os.getenv("SESSION_SECRET")
    if secret:
        return secret.encode("utf-8")
    if os.getenv("APP_ENV", "").lower() == "production":
        return b""
    return _DEVELOPMENT_SESSION_SECRET.encode("utf-8")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
