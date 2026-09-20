"""Versioned Spotify authorization state and its persistence rules."""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
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

from mopidy_spotify._ext import atomic, secrets

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

logger = logging.getLogger(__name__)

AUTH_FILE_VERSION = 1
KEYRING_SERVICE = "mopidy-spotify"
_UUID7_LOCK = threading.Lock()
_UUID7_LAST_TIMESTAMP = -1
_UUID7_RANDOM = 0


class SecretStorage(StrEnum):
    INLINE = "inline"
    KEYRING = "keyring"


class InlineRefreshTokenDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    storage: Literal["inline"] = "inline"
    value: SecretStr

    @field_serializer("value", when_used="json")
    def serialize_value(self, value: SecretStr) -> str:
        return value.get_secret_value()


class KeyringRefreshTokenDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    storage: Literal["keyring"] = "keyring"
    service: Literal["mopidy-spotify"] = KEYRING_SERVICE
    username: str


type RefreshTokenDescriptor = Annotated[
    InlineRefreshTokenDescriptor | KeyringRefreshTokenDescriptor,
    Field(discriminator="storage"),
]


class AuthPayloadBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = AUTH_FILE_VERSION


class PkceAuthorizedAuthPayload(AuthPayloadBase):
    mode: Literal["pkce"] = "pkce"
    state: Literal["authorized"] = "authorized"
    refresh_token: RefreshTokenDescriptor


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


class PkceAuthorizedAuthState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    refresh_token: SecretStr
    mode: Literal["pkce"] = "pkce"
    state: Literal["authorized"] = "authorized"


@dataclass(frozen=True)
class BridgeConfiguredAuthState:
    mode: Literal["bridge"] = "bridge"
    state: Literal["configured"] = "configured"


@dataclass(frozen=True)
class ClearedAuthState:
    mode: Literal["pkce", "bridge"]
    state: Literal["cleared"] = "cleared"


@dataclass(frozen=True)
class PermanentErrorAuthState:
    mode: Literal["pkce", "bridge"]
    error_code: str
    error_description: str | None = None
    state: Literal["permanent_error"] = "permanent_error"


type AuthState = (
    PkceAuthorizedAuthState
    | BridgeConfiguredAuthState
    | ClearedAuthState
    | PermanentErrorAuthState
)


@dataclass(frozen=True)
class AuthStateSnapshot:
    """Resolved state plus the exact manifest used to obtain it."""

    state: AuthState
    _payload: AuthPayload


class InvalidAuthStateError(ValueError):
    pass


class AuthStateStoreError(Exception):
    pass


def generate_uuid7() -> str:
    """Return an RFC 9562 UUIDv7 on all supported Python versions."""
    global _UUID7_LAST_TIMESTAMP, _UUID7_RANDOM  # noqa: PLW0603

    with _UUID7_LOCK:
        timestamp_ms = int(time.time() * 1000) & ((1 << 48) - 1)
        if timestamp_ms > _UUID7_LAST_TIMESTAMP:
            _UUID7_RANDOM = int.from_bytes(os.urandom(10), "big") & ((1 << 74) - 1)
        else:
            timestamp_ms = _UUID7_LAST_TIMESTAMP
            _UUID7_RANDOM = (_UUID7_RANDOM + 1) & ((1 << 74) - 1)
            if _UUID7_RANDOM == 0:
                timestamp_ms += 1
        _UUID7_LAST_TIMESTAMP = timestamp_ms
        rand_a = _UUID7_RANDOM >> 62
        rand_b = _UUID7_RANDOM & ((1 << 62) - 1)

    value = (timestamp_ms << 80) | (7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return str(uuid.UUID(int=value))


class AuthStateStore:
    """Own the auth manifest and descriptor-backed secret transitions."""

    def __init__(
        self,
        path: Path,
        *,
        keyring_backend: secrets.KeyringBackend | None = None,
        generate_keyring_username: Callable[[], str] = generate_uuid7,
    ) -> None:
        self.path = path
        self._keyring_backend = keyring_backend
        self._generate_keyring_username = generate_keyring_username

    @contextmanager
    def _locked(self) -> Iterator[None]:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with FileLock(f"{self.path}.lock", mode=0o600):
                yield
        except OSError as exc:
            msg = f"Could not lock Spotify authorization state at {self.path}"
            raise AuthStateStoreError(msg) from exc

    def _load_payload(self) -> AuthPayload | None:
        try:
            content = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError) as exc:
            msg = f"Could not load Spotify authorization state at {self.path}"
            raise AuthStateStoreError(msg) from exc

        try:
            return AUTH_PAYLOAD_ADAPTER.validate_json(content)
        except (ValidationError, ValueError):
            pass

        msg = f"Invalid Spotify authorization state at {self.path}"
        raise InvalidAuthStateError(msg)

    def _secret_store(
        self,
        descriptor: RefreshTokenDescriptor,
    ) -> secrets.SecretStore:
        if isinstance(descriptor, InlineRefreshTokenDescriptor):
            return secrets.InlineSecretStore(descriptor.value)
        return secrets.KeyringSecretStore(
            descriptor.service,
            descriptor.username,
            self._keyring_backend,
        )

    def _resolve(self, payload: AuthPayload) -> AuthState:
        if isinstance(payload, PkceAuthorizedAuthPayload):
            return PkceAuthorizedAuthState(
                refresh_token=self._secret_store(payload.refresh_token).load()
            )
        if isinstance(payload, BridgeConfiguredAuthPayload):
            return BridgeConfiguredAuthState()
        if isinstance(payload, ClearedAuthPayload):
            return ClearedAuthState(mode=payload.mode)
        return PermanentErrorAuthState(
            mode=payload.mode,
            error_code=payload.error_code,
            error_description=payload.error_description,
        )

    def load(self) -> AuthStateSnapshot | None:
        payload = self._load_payload()
        if payload is None:
            return None
        return AuthStateSnapshot(self._resolve(payload), payload)

    def _write_payload(self, payload: AuthPayload) -> None:
        try:
            content = payload.model_dump_json().encode()
            atomic.write(self.path, content, mode=0o600)
        except OSError as exc:
            msg = f"Could not save Spotify authorization state at {self.path}"
            raise AuthStateStoreError(msg) from exc

    def _new_keyring_descriptor(
        self,
        value: SecretStr,
    ) -> KeyringRefreshTokenDescriptor:
        descriptor = KeyringRefreshTokenDescriptor(
            username=self._generate_keyring_username()
        )
        self._secret_store(descriptor).save(value)
        return descriptor

    def _clear_descriptor(
        self,
        descriptor: RefreshTokenDescriptor,
        *,
        suppress_errors: bool,
    ) -> None:
        if isinstance(descriptor, InlineRefreshTokenDescriptor):
            return
        try:
            self._secret_store(descriptor).clear()
        except secrets.SecretStoreError:
            if not suppress_errors:
                raise
            logger.warning(
                "Could not remove replaced Spotify keyring entry %s",
                descriptor.username,
                exc_info=True,
            )

    def _replace_payload(
        self,
        payload: AuthPayload,
        *,
        candidate: KeyringRefreshTokenDescriptor | None = None,
        previous: AuthPayload | None = None,
        strict_cleanup: bool = False,
    ) -> None:
        try:
            self._write_payload(payload)
        except Exception:
            if candidate is not None:
                self._clear_descriptor(candidate, suppress_errors=True)
            raise

        next_descriptor = (
            payload.refresh_token
            if isinstance(payload, PkceAuthorizedAuthPayload)
            else None
        )
        if (
            isinstance(previous, PkceAuthorizedAuthPayload)
            and previous.refresh_token != next_descriptor
        ):
            self._clear_descriptor(
                previous.refresh_token,
                suppress_errors=not strict_cleanup,
            )

    def authorize(
        self,
        refresh_token: SecretStr,
        storage: SecretStorage = SecretStorage.INLINE,
    ) -> None:
        with self._locked():
            try:
                previous = self._load_payload()
            except InvalidAuthStateError:
                previous = None

            candidate = None
            if storage is SecretStorage.KEYRING:
                candidate = self._new_keyring_descriptor(refresh_token)
                descriptor: RefreshTokenDescriptor = candidate
            else:
                descriptor = InlineRefreshTokenDescriptor(value=refresh_token)
            self._replace_payload(
                PkceAuthorizedAuthPayload(refresh_token=descriptor),
                candidate=candidate,
                previous=previous,
            )

    def save_if_current(
        self,
        expected: AuthStateSnapshot | None,
        state: AuthState,
    ) -> bool:
        with self._locked():
            current = self._load_payload()
            expected_payload = expected._payload if expected is not None else None
            if current != expected_payload:
                return False

            candidate = None
            if isinstance(state, PkceAuthorizedAuthState):
                if not isinstance(current, PkceAuthorizedAuthPayload):
                    msg = "PKCE authorization has no current storage descriptor"
                    raise AuthStateStoreError(msg)
                if expected is not None and state == expected.state:
                    descriptor = current.refresh_token
                elif isinstance(current.refresh_token, KeyringRefreshTokenDescriptor):
                    candidate = self._new_keyring_descriptor(state.refresh_token)
                    descriptor = candidate
                else:
                    descriptor = InlineRefreshTokenDescriptor(value=state.refresh_token)
                payload: AuthPayload = PkceAuthorizedAuthPayload(
                    refresh_token=descriptor
                )
            elif isinstance(state, BridgeConfiguredAuthState):
                payload = BridgeConfiguredAuthPayload()
            elif isinstance(state, ClearedAuthState):
                payload = ClearedAuthPayload(mode=state.mode)
            else:
                payload = PermanentErrorAuthPayload(
                    mode=state.mode,
                    error_code=state.error_code,
                    error_description=state.error_description,
                )

            self._replace_payload(
                payload,
                candidate=candidate,
                previous=current,
            )
            return True

    def clear(self) -> None:
        with self._locked():
            try:
                previous = self._load_payload()
            except InvalidAuthStateError:
                previous = None
            mode: Literal["pkce", "bridge"] = (
                previous.mode if previous is not None else "bridge"
            )
            self._replace_payload(
                ClearedAuthPayload(mode=mode),
                previous=previous,
                strict_cleanup=True,
            )
