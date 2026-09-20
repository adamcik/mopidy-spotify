from unittest import mock

import pytest
from pydantic import SecretStr

from mopidy_spotify._ext import secrets


class MemoryKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[service, username] = password

    def delete_password(self, service: str, username: str) -> None:
        del self.values[service, username]


@pytest.fixture(params=["inline", "keyring"])
def secret_store(request: pytest.FixtureRequest) -> secrets.SecretStore:
    if request.param == "inline":
        return secrets.InlineSecretStore(SecretStr("first-secret"))
    backend = MemoryKeyring()
    backend.set_password("mopidy-spotify", "token-id", "first-secret")
    return secrets.KeyringSecretStore("mopidy-spotify", "token-id", backend)


def test_secret_store_contract(secret_store: secrets.SecretStore):
    assert secret_store.load() == SecretStr("first-secret")

    secret_store.save(SecretStr("second-secret"))
    assert secret_store.load() == SecretStr("second-secret")

    secret_store.clear()
    with pytest.raises(secrets.SecretNotFoundError):
        secret_store.load()
    secret_store.clear()


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
        getattr(store, operation)(
            *(SecretStr("secret"),) if operation == "save" else ()
        )


def test_keyring_secret_store_reports_unavailable_backend():
    store = secrets.KeyringSecretStore("service", "username")

    with (
        mock.patch.object(secrets.importlib, "import_module", side_effect=ImportError),
        pytest.raises(secrets.SecretBackendUnavailableError, match="unavailable"),
    ):
        store.load()
