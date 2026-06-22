from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import urllib.parse
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Literal, Protocol

import requests
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from mopidy_spotify import utils

if TYPE_CHECKING:
    from pathlib import Path

CLIENT_ID = "f88ee52f92724d51b7579a1d1cdb3128"
REDIRECT_URI = "https://mopidy.com/auth/spotify"
SCOPES = "playlist-read-collaborative playlist-read-private"
AUTH_FILE_VERSION = 1


class AuthPayloadBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = AUTH_FILE_VERSION


class PkceAuthorizedAuthPayload(AuthPayloadBase):
    mode: Literal["pkce"] = "pkce"
    state: Literal["authorized"] = "authorized"
    refresh_token: str


class PkceRevokedAuthPayload(AuthPayloadBase):
    mode: Literal["pkce"] = "pkce"
    state: Literal["revoked"] = "revoked"


class BridgeConfiguredAuthPayload(AuthPayloadBase):
    mode: Literal["bridge"] = "bridge"
    state: Literal["configured"] = "configured"


class BridgeClearedAuthPayload(AuthPayloadBase):
    mode: Literal["bridge"] = "bridge"
    state: Literal["cleared"] = "cleared"


class BridgePermanentErrorAuthPayload(AuthPayloadBase):
    mode: Literal["bridge"] = "bridge"
    state: Literal["permanent_error"] = "permanent_error"
    error_code: str
    error_description: str | None = None


type AuthPayload = Annotated[
    PkceAuthorizedAuthPayload
    | PkceRevokedAuthPayload
    | BridgeConfiguredAuthPayload
    | BridgeClearedAuthPayload
    | BridgePermanentErrorAuthPayload,
    Field(discriminator="state"),
]
AUTH_PAYLOAD_ADAPTER = TypeAdapter(AuthPayload)


class InvalidRefreshTokenError(ValueError):
    pass


class RefreshTokenStore(Protocol):
    def load(self) -> AuthPayload | None: ...

    def save(self, token: str) -> None: ...

    def clear(self) -> None: ...


@dataclass(frozen=True)
class FileRefreshTokenStore:
    path: Path

    def load(self) -> AuthPayload | None:
        return load_auth_payload(self.path)

    def save(self, token: str) -> None:
        _write_auth_payload(self.path, PkceAuthorizedAuthPayload(refresh_token=token))

    def mark_revoked(self) -> None:
        _write_auth_payload(self.path, PkceRevokedAuthPayload())

    def mark_bridge_configured(self) -> None:
        _write_auth_payload(self.path, BridgeConfiguredAuthPayload())

    def mark_bridge_permanent_error(
        self,
        error_code: str,
        error_description: str | None = None,
    ) -> None:
        _write_auth_payload(
            self.path,
            BridgePermanentErrorAuthPayload(
                error_code=error_code,
                error_description=error_description,
            ),
        )

    def clear(self) -> None:
        _write_auth_payload(self.path, BridgeClearedAuthPayload())


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def generate_pkce_verifier() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(96)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def generate_authorization_url(challenge: str, state: str) -> str:
    query = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "code_challenge_method": "S256",
            "code_challenge": challenge,
            "state": state,
            "scope": SCOPES,
        }
    )
    return f"https://accounts.spotify.com/authorize?{query}"


def parse_authorization_result(result: str) -> dict[str, str]:
    result = result.strip()
    for parser in (
        _parse_authorization_url,
        _parse_base64_json_payload,
        _parse_base64_query_string,
        _parse_query_string,
    ):
        if parsed_result := parser(result):
            return parsed_result

    return {}


def _parse_authorization_url(result: str) -> dict[str, str]:
    parsed = urllib.parse.urlsplit(result)
    query = parsed.query or parsed.fragment
    if not query:
        return {}

    return dict(urllib.parse.parse_qsl(query, keep_blank_values=True))


def _parse_base64_json_payload(result: str) -> dict[str, str]:
    try:
        padded_result = result + "=" * (-len(result) % 4)
        decoded_result = base64.urlsafe_b64decode(padded_result)
        payload = json.loads(decoded_result)
    except (ValueError, json.JSONDecodeError):
        return {}

    if not isinstance(payload, dict):
        return {}

    return {
        key: value
        for key, value in payload.items()
        if isinstance(key, str) and isinstance(value, str)
    }


def _parse_base64_query_string(result: str) -> dict[str, str]:
    try:
        padded_result = result + "=" * (-len(result) % 4)
        decoded_result = base64.urlsafe_b64decode(padded_result).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return {}

    return dict(urllib.parse.parse_qsl(decoded_result, keep_blank_values=True))


def _parse_query_string(result: str) -> dict[str, str]:
    return dict(urllib.parse.parse_qsl(result, keep_blank_values=True))


def exchange_code_request(code: str, verifier: str) -> requests.Request:
    return requests.Request(
        "POST",
        "https://accounts.spotify.com/api/token",
        data={
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
    )


def refresh_token_request(path: Path) -> requests.Request:
    payload = load_auth_payload(path)
    if payload is None:
        msg = "missing refresh_token"
        raise ValueError(msg)
    if payload.mode != "pkce":
        error = (
            "Spotify auth.json uses unsupported mode for refresh_token: "
            f"{path} ({payload.mode})"
        )
        raise InvalidRefreshTokenError(error)
    if payload.state == "revoked":
        error = f"Spotify auth.json is revoked: {path}"
        raise InvalidRefreshTokenError(error)
    return requests.Request(
        "POST",
        "https://accounts.spotify.com/api/token",
        data={
            "client_id": CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": payload.refresh_token,
        },
    )


def store_refresh_token(path: Path, value: str) -> None:
    FileRefreshTokenStore(path).save(value)


def load_auth_payload(path: Path) -> AuthPayload | None:
    if not path.exists():
        return None

    try:
        return _load_auth_payload(path.read_text(encoding="utf-8"))
    except (ValidationError, ValueError) as exc:
        msg = f"Invalid Spotify auth.json: {path}"
        raise InvalidRefreshTokenError(msg) from exc


def _load_auth_payload(value: str) -> AuthPayload:
    return AUTH_PAYLOAD_ADAPTER.validate_json(value)


def _write_auth_payload(path: Path, payload: AuthPayloadBase) -> None:
    content = payload.model_dump_json().encode("utf-8")
    with utils.replace(path) as file_handle:
        os.fchmod(file_handle.fileno(), 0o600)
        file_handle.write(content)
