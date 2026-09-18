"""Versioned Spotify authorization state and its persistence rules."""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Annotated, Literal

from filelock import FileLock
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

if TYPE_CHECKING:
    from collections.abc import Iterator
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

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize auth-state transitions that atomic replacement cannot protect."""
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with FileLock(f"{self.path}.lock"):
                yield
        except OSError as exc:
            msg = f"Could not lock Spotify authorization state at {self.path}"
            raise secrets.SecretStoreError(msg) from exc

    def save(self, payload: AuthPayload) -> None:
        with self._locked():
            super().save(payload)

    def clear(self) -> None:
        with self._locked():
            super().clear()

    def save_if_current(
        self,
        expected: AuthPayload | None,
        payload: AuthPayload,
    ) -> bool:
        """Save ``payload`` only if state still matches the caller's snapshot."""
        with self._locked():
            if super().load() != expected:
                return False
            super().save(payload)
            return True
