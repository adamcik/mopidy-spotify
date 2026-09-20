import json
import uuid
from pathlib import Path
from unittest import mock

import pytest
from pydantic import SecretStr

from mopidy_spotify import auth_state
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


def test_auth_state_store_returns_none_for_missing_file(tmp_path: Path):
    assert auth_state.AuthStateStore(tmp_path / "auth.json").load() is None


def test_auth_state_store_round_trips_inline_authorization(tmp_path: Path):
    path = tmp_path / "auth.json"
    store = auth_state.AuthStateStore(path)

    store.authorize(SecretStr("refresh-token"))

    snapshot = store.load()
    assert snapshot is not None
    assert snapshot.state == auth_state.PkceAuthorizedAuthState(
        refresh_token=SecretStr("refresh-token")
    )
    assert json.loads(path.read_text()) == {
        "version": 1,
        "mode": "pkce",
        "state": "authorized",
        "refresh_token": {"storage": "inline", "value": "refresh-token"},
    }


def test_auth_state_store_round_trips_keyring_authorization(tmp_path: Path):
    path = tmp_path / "auth.json"
    keyring = MemoryKeyring()
    store = auth_state.AuthStateStore(
        path,
        keyring_backend=keyring,
        generate_keyring_username=lambda: "token-id",
    )

    store.authorize(SecretStr("refresh-token"), auth_state.SecretStorage.KEYRING)

    snapshot = store.load()
    assert snapshot is not None
    assert snapshot.state == auth_state.PkceAuthorizedAuthState(
        refresh_token=SecretStr("refresh-token")
    )
    assert json.loads(path.read_text()) == {
        "version": 1,
        "mode": "pkce",
        "state": "authorized",
        "refresh_token": {
            "storage": "keyring",
            "service": "mopidy-spotify",
            "username": "token-id",
        },
    }
    assert keyring.values == {("mopidy-spotify", "token-id"): "refresh-token"}


def test_auth_state_store_rejects_greenfield_raw_token_shape(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text(
        '{"version":1,"mode":"pkce","state":"authorized","refresh_token":"old-shape"}'
    )

    with pytest.raises(auth_state.InvalidAuthStateError):
        auth_state.AuthStateStore(path).load()


def test_auth_state_store_does_not_chain_invalid_payload(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text('{"refresh_token":{"storage":"inline","value":"secret"}}')

    with pytest.raises(auth_state.InvalidAuthStateError) as exc_info:
        auth_state.AuthStateStore(path).load()

    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None


def test_missing_keyring_entry_is_distinct_from_invalid_manifest(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "mode": "pkce",
                "state": "authorized",
                "refresh_token": {
                    "storage": "keyring",
                    "service": "mopidy-spotify",
                    "username": "missing",
                },
            }
        )
    )

    with pytest.raises(secrets.SecretNotFoundError):
        auth_state.AuthStateStore(path, keyring_backend=MemoryKeyring()).load()


def test_missing_inline_value_is_distinct_from_invalid_manifest(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "mode": "pkce",
                "state": "authorized",
                "refresh_token": {"storage": "inline", "value": ""},
            }
        )
    )

    with pytest.raises(secrets.SecretNotFoundError, match="Inline"):
        auth_state.AuthStateStore(path).load()


def test_keyring_descriptor_does_not_fall_back_to_inline_storage(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "mode": "pkce",
                "state": "authorized",
                "refresh_token": {
                    "storage": "keyring",
                    "service": "mopidy-spotify",
                    "username": "missing",
                },
            }
        )
    )

    with (
        mock.patch.object(
            secrets.importlib,
            "import_module",
            side_effect=ImportError,
        ),
        pytest.raises(secrets.SecretBackendUnavailableError),
    ):
        auth_state.AuthStateStore(path).load()


def test_rotated_keyring_token_uses_fresh_address_and_clears_old(tmp_path: Path):
    usernames = iter(["first", "second"])
    keyring = MemoryKeyring()
    store = auth_state.AuthStateStore(
        tmp_path / "auth.json",
        keyring_backend=keyring,
        generate_keyring_username=lambda: next(usernames),
    )
    store.authorize(SecretStr("original"), auth_state.SecretStorage.KEYRING)
    snapshot = store.load()
    assert snapshot is not None

    assert store.save_if_current(
        snapshot,
        auth_state.PkceAuthorizedAuthState(refresh_token=SecretStr("rotated")),
    )

    assert keyring.values == {("mopidy-spotify", "second"): "rotated"}


def test_stale_keyring_rotation_does_not_create_candidate(tmp_path: Path):
    usernames = iter(["first", "replacement", "stale-candidate"])
    keyring = MemoryKeyring()
    store = auth_state.AuthStateStore(
        tmp_path / "auth.json",
        keyring_backend=keyring,
        generate_keyring_username=lambda: next(usernames),
    )
    store.authorize(SecretStr("original"), auth_state.SecretStorage.KEYRING)
    stale = store.load()
    assert stale is not None
    store.authorize(SecretStr("replacement"), auth_state.SecretStorage.KEYRING)

    assert not store.save_if_current(
        stale,
        auth_state.PkceAuthorizedAuthState(refresh_token=SecretStr("rotated")),
    )
    assert "stale-candidate" not in {username for _, username in keyring.values}


def test_failed_manifest_update_removes_keyring_candidate(tmp_path: Path):
    usernames = iter(["first", "candidate"])
    keyring = MemoryKeyring()
    store = auth_state.AuthStateStore(
        tmp_path / "auth.json",
        keyring_backend=keyring,
        generate_keyring_username=lambda: next(usernames),
    )
    store.authorize(SecretStr("original"), auth_state.SecretStorage.KEYRING)
    snapshot = store.load()
    assert snapshot is not None

    with (
        mock.patch.object(auth_state.atomic, "write", side_effect=OSError),
        pytest.raises(auth_state.AuthStateStoreError),
    ):
        store.save_if_current(
            snapshot,
            auth_state.PkceAuthorizedAuthState(refresh_token=SecretStr("rotated")),
        )

    assert keyring.values == {("mopidy-spotify", "first"): "original"}


def test_clear_removes_keyring_token_and_persists_cleared_state(tmp_path: Path):
    keyring = MemoryKeyring()
    path = tmp_path / "auth.json"
    store = auth_state.AuthStateStore(
        path,
        keyring_backend=keyring,
        generate_keyring_username=lambda: "token-id",
    )
    store.authorize(SecretStr("refresh-token"), auth_state.SecretStorage.KEYRING)

    store.clear()

    assert keyring.values == {}
    assert json.loads(path.read_text()) == {
        "version": 1,
        "mode": "pkce",
        "state": "cleared",
    }


def test_generate_uuid7_returns_version_seven_uuid():
    generated = uuid.UUID(auth_state.generate_uuid7())

    assert generated.version == 7
    assert generated.variant == uuid.RFC_4122


def test_generate_uuid7_is_monotonic_within_one_millisecond():
    with mock.patch.object(auth_state.time, "time", return_value=1_000.0):
        first = uuid.UUID(auth_state.generate_uuid7())
        second = uuid.UUID(auth_state.generate_uuid7())

    assert first.int < second.int
