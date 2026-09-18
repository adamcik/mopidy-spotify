from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest import mock

import pytest

from mopidy_spotify._ext import secrets

if TYPE_CHECKING:
    from collections.abc import Callable


class MemoryKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[service, username] = password

    def delete_password(self, service: str, username: str) -> None:
        del self.values[service, username]


def file_secret_store(path: Path) -> secrets.SecretStore:
    return secrets.FileBackedSecretStore(path)


def keyring_secret_store(path: Path) -> secrets.SecretStore:
    return secrets.KeyringSecretStore(
        "mopidy-spotify",
        str(path),
        MemoryKeyring(),
    )


@pytest.fixture(
    params=[
        file_secret_store,
        keyring_secret_store,
    ],
    ids=["file", "keyring"],
)
def secret_store(
    request: pytest.FixtureRequest,
    tmp_path: Path,
) -> secrets.SecretStore:
    factory: Callable[[Path], secrets.SecretStore] = request.param
    return factory(tmp_path / "secret.txt")


def test_secret_store_contract(secret_store: secrets.SecretStore):
    assert secret_store.load() is None

    secret_store.save("first-secret")
    assert secret_store.load() == "first-secret"

    secret_store.save("second-secret")
    assert secret_store.load() == "second-secret"

    secret_store.clear()
    assert secret_store.load() is None
    secret_store.clear()


def test_file_secret_store_uses_private_mode(tmp_path: Path):
    store = secrets.FileBackedSecretStore(tmp_path / "private" / "secret.txt")

    store.save("secret")

    assert store.path.stat().st_mode & 0o777 == 0o600
    assert store.path.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("operation", ["load", "save", "clear"])
def test_file_secret_store_wraps_backend_errors(
    tmp_path: Path,
    operation: str,
):
    store = secrets.FileBackedSecretStore(tmp_path / "secret.txt")

    patcher = (
        mock.patch.object(Path, "read_text", side_effect=PermissionError)
        if operation == "load"
        else mock.patch.object(Path, "mkdir", side_effect=PermissionError)
        if operation == "save"
        else mock.patch.object(Path, "unlink", side_effect=PermissionError)
    )
    with patcher, pytest.raises(secrets.SecretStoreError):
        getattr(store, operation)(*("secret",) if operation == "save" else ())


@pytest.mark.parametrize("operation", ["load", "save", "clear"])
def test_keyring_secret_store_wraps_backend_errors(operation: str):
    backend = mock.Mock(spec=secrets.KeyringBackend)
    store = secrets.KeyringSecretStore("service", "username", backend)
    method_name = {
        "load": "get_password",
        "save": "set_password",
        "clear": "get_password",
    }[operation]
    getattr(backend, method_name).side_effect = RuntimeError("backend failed")

    with pytest.raises(secrets.SecretStoreError):
        getattr(store, operation)(*("secret",) if operation == "save" else ())


def test_keyring_secret_store_reports_unavailable_backend():
    store = secrets.KeyringSecretStore("service", "username")

    with (
        mock.patch.object(secrets.importlib, "import_module", side_effect=ImportError),
        pytest.raises(secrets.SecretStoreError, match="unavailable"),
    ):
        store.load()
