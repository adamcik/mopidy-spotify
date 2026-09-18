"""One-secret storage adapters with explicit missing and failure semantics."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from mopidy_spotify._ext import atomic

if TYPE_CHECKING:
    from pathlib import Path


class SecretStoreError(Exception):
    """Raised when a configured secret backend cannot complete an operation."""


class SecretStore(Protocol):
    """Store one logical secret whose address is fixed at construction."""

    def load(self) -> str | None:
        """Return the secret, or ``None`` when no secret exists."""
        ...

    def save(self, value: str) -> None:
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


@dataclass(frozen=True)
class FileBackedSecretStore:
    """Store one UTF-8 secret in an atomically replaced file."""

    path: Path
    mode: int = 0o600

    def load(self) -> str | None:
        """Return file content, or ``None`` when the path does not exist."""
        try:
            return self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError) as exc:
            msg = f"Could not load secret from {self.path}"
            raise SecretStoreError(msg) from exc

    def save(self, value: str) -> None:
        """Atomically save UTF-8 content with the configured file mode."""
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            atomic.write(self.path, value.encode("utf-8"), mode=self.mode)
        except OSError as exc:
            msg = f"Could not save secret to {self.path}"
            raise SecretStoreError(msg) from exc

    def clear(self) -> None:
        """Remove the backing file when present."""
        try:
            self.path.unlink(missing_ok=True)
        except OSError as exc:
            msg = f"Could not clear secret from {self.path}"
            raise SecretStoreError(msg) from exc


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
            raise SecretStoreError(msg) from exc

    def load(self) -> str | None:
        """Return the keyring value, or ``None`` when it is absent."""
        try:
            return self._backend().get_password(self.service, self.username)
        except SecretStoreError:
            raise
        except Exception as exc:
            msg = f"Could not load secret for {self.service}/{self.username}"
            raise SecretStoreError(msg) from exc

    def save(self, value: str) -> None:
        """Replace the keyring value."""
        try:
            self._backend().set_password(self.service, self.username, value)
        except SecretStoreError:
            raise
        except Exception as exc:
            msg = f"Could not save secret for {self.service}/{self.username}"
            raise SecretStoreError(msg) from exc

    def clear(self) -> None:
        """Remove the keyring value when present."""
        backend = self._backend()
        try:
            if backend.get_password(self.service, self.username) is not None:
                backend.delete_password(self.service, self.username)
        except Exception as exc:
            msg = f"Could not clear secret for {self.service}/{self.username}"
            raise SecretStoreError(msg) from exc
