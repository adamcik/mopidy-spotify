from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal

import requests
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    TypeAdapter,
    ValidationError,
    field_serializer,
)

from mopidy_spotify._ext import secrets
from mopidy_spotify.pkce import CLIENT_ID

if TYPE_CHECKING:
    from pathlib import Path

AUTH_FILE_VERSION = 1


class AuthPayloadBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = AUTH_FILE_VERSION


class PkceAuthorizedAuthPayload(AuthPayloadBase):
    mode: Literal["pkce"] = "pkce"
    state: Literal["authorized"] = "authorized"
    refresh_token: SecretStr

    @field_serializer("refresh_token", when_used="json")
    def serialize_refresh_token(self, value: SecretStr) -> str:
        # Persist only at the storage sink; repr and diagnostics stay redacted.
        return value.get_secret_value()


class BridgeConfiguredAuthPayload(AuthPayloadBase):
    mode: Literal["bridge"] = "bridge"
    state: Literal["configured"] = "configured"


class ClearedAuthPayload(AuthPayloadBase):
    mode: Literal["pkce", "bridge"]
    state: Literal["cleared"] = "cleared"


class PermanentErrorAuthPayload(AuthPayloadBase):
    mode: Literal["pkce", "bridge"]
    state: Literal["permanent_error"] = "permanent_error"
    error_code: str
    error_description: str | None = None


type AuthPayload = Annotated[
    PkceAuthorizedAuthPayload
    | BridgeConfiguredAuthPayload
    | ClearedAuthPayload
    | PermanentErrorAuthPayload,
    Field(discriminator="state"),
]
AUTH_PAYLOAD_ADAPTER = TypeAdapter(AuthPayload)


class InvalidRefreshTokenError(ValueError):
    pass


class AuthStateStore:
    def __init__(self, secret_store: secrets.SecretStore) -> None:
        self._secret_store = secret_store

    def load(self) -> AuthPayload | None:
        content = self._secret_store.load()
        if content is None:
            return None

        try:
            return AUTH_PAYLOAD_ADAPTER.validate_json(content)
        except (ValidationError, ValueError):
            pass

        msg = "Invalid Spotify authorization state"
        raise InvalidRefreshTokenError(msg)

    def save(self, payload: AuthPayload) -> None:
        self._secret_store.save(payload.model_dump_json())

    def clear(self) -> None:
        self._secret_store.clear()


class FileAuthStateStore(AuthStateStore):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(secrets.FileBackedSecretStore(path))


def refresh_token_request(auth_state_path: Path) -> requests.Request:
    payload = FileAuthStateStore(auth_state_path).load()
    if payload is None:
        msg = "missing refresh_token"
        raise ValueError(msg)
    if payload.state != "authorized" or payload.mode != "pkce":
        error = (
            "Spotify auth.json uses unsupported state for refresh_token: "
            f"{auth_state_path} ({payload.mode}/{payload.state})"
        )
        raise InvalidRefreshTokenError(error)
    return requests.Request(
        "POST",
        "https://accounts.spotify.com/api/token",
        data={
            "client_id": CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": payload.refresh_token.get_secret_value(),
        },
    )
