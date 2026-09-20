"""One-secret storage adapters with explicit missing and failure semantics."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Protocol

from pydantic import SecretStr


class SecretStoreError(Exception):
    """Raised when a configured secret backend cannot complete an operation."""


class SecretNotFoundError(SecretStoreError):
    """Raised when the configured address contains no secret."""


class SecretBackendUnavailableError(SecretStoreError):
    """Raised when a selected secret backend is unavailable."""


class SecretStore(Protocol):
    """Store one logical secret whose address is fixed at construction."""

    def load(self) -> SecretStr:
        """Return the secret or raise when it is absent."""
        ...

    def save(self, value: SecretStr) -> None:
        """Replace the stored secret with ``value``."""
        ...

    def clear(self) -> None:
        """Remove the secret, succeeding when it is already absent."""
        ...


class KeyringBackend(Protocol):
    """Subset of the optional keyring module used by the keyring adapter."""

    def get_password(self, service: str, username: str) -> str | None:
        """Return the addressed password, or ``None`` when absent."""
        ...

    def set_password(self, service: str, username: str, password: str) -> None:
        """Replace the addressed password."""
        ...

    def delete_password(self, service: str, username: str) -> None:
        """Delete the addressed password."""
        ...


@dataclass
class InlineSecretStore:
    """Hold one secret inline without introducing another persistence location."""

    value: SecretStr | None = None

    def load(self) -> SecretStr:
        if self.value is None or not self.value.get_secret_value():
            msg = "Inline refresh token is missing"
            raise SecretNotFoundError(msg)
        return self.value

    def save(self, value: SecretStr) -> None:
        self.value = value

    def clear(self) -> None:
        self.value = None


@dataclass(frozen=True)
class KeyringSecretStore:
    """Store one secret under a fixed keyring service and username."""

    service: str
    username: str
    backend: KeyringBackend | None = None

    def _backend(self) -> KeyringBackend:
        """Return the injected or optional system keyring backend."""
        if self.backend is not None:
            return self.backend
        try:
            return importlib.import_module("keyring")  # type: ignore[return-value]
        except ImportError as exc:
            msg = "Keyring backend is unavailable"
            raise SecretBackendUnavailableError(msg) from exc

    def load(self) -> SecretStr:
        try:
            value = self._backend().get_password(self.service, self.username)
        except SecretStoreError:
            raise
        except Exception as exc:
            msg = f"Could not load secret for {self.service}/{self.username}"
            raise SecretStoreError(msg) from exc
        if value is None:
            msg = f"No secret found for {self.service}/{self.username}"
            raise SecretNotFoundError(msg)
        return SecretStr(value)

    def save(self, value: SecretStr) -> None:
        try:
            self._backend().set_password(
                self.service,
                self.username,
                value.get_secret_value(),
            )
        except SecretStoreError:
            raise
        except Exception as exc:
            msg = f"Could not save secret for {self.service}/{self.username}"
            raise SecretStoreError(msg) from exc

    def clear(self) -> None:
        backend = self._backend()
        try:
            if backend.get_password(self.service, self.username) is not None:
                backend.delete_password(self.service, self.username)
        except Exception as exc:
            msg = f"Could not clear secret for {self.service}/{self.username}"
            raise SecretStoreError(msg) from exc
