"""Persistence and transitions for Spotify Web authorization state."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from filelock import FileLock
from pydantic import SecretStr, ValidationError
from uuid_extension import uuid7

from mopidy_spotify._ext import atomic, keyring
from mopidy_spotify.oauth import state

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Snapshot:
    """Resolved state plus the exact manifest used to obtain it."""

    state: state.AuthState
    _payload: state.AuthPayload


class InvalidStateError(ValueError):
    pass


class Error(Exception):
    pass


class MissingInlineRefreshTokenError(Error):
    pass


class MissingKeyringRefreshTokenError(Error):
    pass


class Store:
    """Own the auth manifest and descriptor-backed secret transitions."""

    def __init__(
        self,
        path: Path,
        *,
        keyring_store: keyring.Store | None = None,
        generate_keyring_username: Callable[[], object] = uuid7,
    ) -> None:
        self.path = path
        self._keyring = keyring_store or keyring.system(state.KEYRING_SERVICE)
        self._generate_keyring_username = generate_keyring_username

    @contextmanager
    def _locked(self) -> Iterator[None]:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with FileLock(f"{self.path}.lock", mode=0o600):
                yield
        except OSError as exc:
            msg = f"Could not lock Spotify authorization state at {self.path}"
            raise Error(msg) from exc

    def _load_payload(self) -> state.AuthPayload | None:
        try:
            content = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError) as exc:
            msg = f"Could not load Spotify authorization state at {self.path}"
            raise Error(msg) from exc

        try:
            return state.AUTH_PAYLOAD_ADAPTER.validate_json(content)
        except (ValidationError, ValueError):
            pass

        msg = f"Invalid Spotify authorization state at {self.path}"
        raise InvalidStateError(msg)

    def _resolve(self, payload: state.AuthPayload) -> state.AuthState:
        if isinstance(payload, state.PkceAuthorizedAuthPayload):
            descriptor = payload.refresh_token
            if isinstance(descriptor, state.InlineRefreshToken):
                refresh_token = descriptor.value
                if not refresh_token.get_secret_value():
                    msg = "Inline refresh token is missing"
                    raise MissingInlineRefreshTokenError(msg)
            else:
                # The generic keyring facade returns raw strings. Wrap the
                # secret immediately at this extension-owned source boundary.
                value = self._keyring.load(descriptor.username)
                if value is None:
                    msg = f"Keyring refresh token is missing: {descriptor.username}"
                    raise MissingKeyringRefreshTokenError(msg)
                refresh_token = SecretStr(value)
            return state.PkceAuthorizedAuthState(refresh_token=refresh_token)
        if isinstance(payload, state.BridgeConfiguredAuthPayload):
            return state.BridgeConfiguredAuthState()
        if isinstance(payload, state.ClearedAuthPayload):
            return state.ClearedAuthState(mode=payload.mode)
        return state.PermanentErrorAuthState(
            mode=payload.mode,
            error_code=payload.error_code,
            error_description=payload.error_description,
        )

    def load(self) -> Snapshot | None:
        payload = self._load_payload()
        if payload is None:
            return None
        return Snapshot(self._resolve(payload), payload)

    def _write_payload(self, payload: state.AuthPayload) -> None:
        try:
            content = payload.model_dump_json().encode()
            atomic.write(self.path, content, mode=0o600)
        except OSError as exc:
            msg = f"Could not save Spotify authorization state at {self.path}"
            raise Error(msg) from exc

    def _clear_descriptor(
        self,
        descriptor: state.RefreshToken,
        *,
        suppress_errors: bool,
    ) -> None:
        if isinstance(descriptor, state.InlineRefreshToken):
            return
        try:
            self._keyring.clear(descriptor.username)
        except keyring.Error:
            if not suppress_errors:
                raise
            logger.warning(
                "Could not remove replaced Spotify %s refresh token",
                descriptor.storage,
                exc_info=True,
            )

    def _replace_payload(
        self,
        payload: state.AuthPayload,
        *,
        candidate: state.RefreshToken | None = None,
        previous: state.AuthPayload | None = None,
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
            if isinstance(payload, state.PkceAuthorizedAuthPayload)
            else None
        )
        if (
            isinstance(previous, state.PkceAuthorizedAuthPayload)
            and previous.refresh_token != next_descriptor
        ):
            self._clear_descriptor(
                previous.refresh_token,
                suppress_errors=not strict_cleanup,
            )

    def authorize(
        self,
        refresh_token: SecretStr,
        storage: state.SecretStorage = state.SecretStorage.INLINE,
    ) -> None:
        with self._locked():
            try:
                previous = self._load_payload()
            except InvalidStateError:
                previous = None

            if storage is state.SecretStorage.INLINE:
                candidate: state.RefreshToken = state.InlineRefreshToken(
                    value=refresh_token
                )
            else:
                candidate = state.KeyringRefreshToken(
                    username=str(self._generate_keyring_username())
                )
                self._keyring.save(
                    candidate.username,
                    # Unwrap only at the explicit external-storage sink.
                    refresh_token.get_secret_value(),
                )
            self._replace_payload(
                state.PkceAuthorizedAuthPayload(refresh_token=candidate),
                candidate=candidate,
                previous=previous,
            )

    def save_if_current(
        self,
        expected: Snapshot | None,
        next_state: state.AuthState,
    ) -> bool:
        with self._locked():
            current = self._load_payload()
            expected_payload = expected._payload if expected is not None else None
            if current != expected_payload:
                return False

            candidate = None
            if isinstance(next_state, state.PkceAuthorizedAuthState):
                if not isinstance(current, state.PkceAuthorizedAuthPayload):
                    msg = "PKCE authorization has no current storage descriptor"
                    raise Error(msg)
                if expected is not None and next_state == expected.state:
                    descriptor = current.refresh_token
                elif isinstance(current.refresh_token, state.InlineRefreshToken):
                    descriptor = state.InlineRefreshToken(
                        value=next_state.refresh_token
                    )
                else:
                    candidate = state.KeyringRefreshToken(
                        username=str(self._generate_keyring_username())
                    )
                    self._keyring.save(
                        candidate.username,
                        # Unwrap only at the explicit external-storage sink.
                        next_state.refresh_token.get_secret_value(),
                    )
                    descriptor = candidate
                payload: state.AuthPayload = state.PkceAuthorizedAuthPayload(
                    refresh_token=descriptor
                )
            elif isinstance(next_state, state.BridgeConfiguredAuthState):
                payload = state.BridgeConfiguredAuthPayload()
            elif isinstance(next_state, state.ClearedAuthState):
                payload = state.ClearedAuthPayload(mode=next_state.mode)
            else:
                payload = state.PermanentErrorAuthPayload(
                    mode=next_state.mode,
                    error_code=next_state.error_code,
                    error_description=next_state.error_description,
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
            except InvalidStateError:
                previous = None
            mode: Literal["pkce", "bridge"] = (
                previous.mode if previous is not None else "bridge"
            )
            self._replace_payload(
                state.ClearedAuthPayload(mode=mode),
                previous=previous,
                strict_cleanup=True,
            )
