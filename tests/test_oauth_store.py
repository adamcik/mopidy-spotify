import json
from pathlib import Path
from unittest import mock

import pytest
from pydantic import SecretStr

from mopidy_spotify._ext import keyring as keyring_ext
from mopidy_spotify.oauth import state
from mopidy_spotify.oauth import store as auth_store


def test_auth_state_store_returns_none_for_missing_file(tmp_path: Path):
    assert auth_store.Store(tmp_path / "auth.json").load() is None


def test_auth_state_store_round_trips_inline_authorization(tmp_path: Path):
    path = tmp_path / "auth.json"
    store = auth_store.Store(path)

    store.authorize(SecretStr("refresh-token"))

    snapshot = store.load()
    assert snapshot is not None
    assert snapshot.state == state.PkceAuthorizedAuthState(
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
    keyring = keyring_ext.memory()
    store = auth_store.Store(
        path,
        keyring_store=keyring,
        generate_keyring_username=lambda: "token-id",
    )

    store.authorize(SecretStr("refresh-token"), state.SecretStorage.KEYRING)

    snapshot = store.load()
    assert snapshot is not None
    assert snapshot.state == state.PkceAuthorizedAuthState(
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
    assert keyring.values == {"token-id": "refresh-token"}


def test_auth_state_store_rejects_greenfield_raw_token_shape(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text(
        '{"version":1,"mode":"pkce","state":"authorized","refresh_token":"old-shape"}'
    )

    with pytest.raises(auth_store.InvalidStateError):
        auth_store.Store(path).load()


def test_auth_state_store_does_not_chain_invalid_payload(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text('{"refresh_token":{"storage":"inline","value":"secret"}}')

    with pytest.raises(auth_store.InvalidStateError) as exc_info:
        auth_store.Store(path).load()

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

    with pytest.raises(auth_store.MissingKeyringRefreshTokenError):
        auth_store.Store(path, keyring_store=keyring_ext.memory()).load()


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

    with pytest.raises(auth_store.MissingInlineRefreshTokenError, match="Inline"):
        auth_store.Store(path).load()


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
            keyring_ext.importlib,
            "import_module",
            side_effect=ImportError,
        ),
        pytest.raises(keyring_ext.UnavailableError),
    ):
        auth_store.Store(path).load()


def test_rotated_keyring_token_uses_fresh_address_and_clears_old(tmp_path: Path):
    usernames = iter(["first", "second"])
    keyring = keyring_ext.memory()
    store = auth_store.Store(
        tmp_path / "auth.json",
        keyring_store=keyring,
        generate_keyring_username=lambda: next(usernames),
    )
    store.authorize(SecretStr("original"), state.SecretStorage.KEYRING)
    snapshot = store.load()
    assert snapshot is not None

    assert store.save_if_current(
        snapshot,
        state.PkceAuthorizedAuthState(refresh_token=SecretStr("rotated")),
    )

    assert keyring.values == {"second": "rotated"}


def test_stale_keyring_rotation_does_not_create_candidate(tmp_path: Path):
    usernames = iter(["first", "replacement", "stale-candidate"])
    keyring = keyring_ext.memory()
    store = auth_store.Store(
        tmp_path / "auth.json",
        keyring_store=keyring,
        generate_keyring_username=lambda: next(usernames),
    )
    store.authorize(SecretStr("original"), state.SecretStorage.KEYRING)
    stale = store.load()
    assert stale is not None
    store.authorize(SecretStr("replacement"), state.SecretStorage.KEYRING)

    assert not store.save_if_current(
        stale,
        state.PkceAuthorizedAuthState(refresh_token=SecretStr("rotated")),
    )
    assert "stale-candidate" not in keyring.values


def test_failed_manifest_update_removes_keyring_candidate(tmp_path: Path):
    usernames = iter(["first", "candidate"])
    keyring = keyring_ext.memory()
    store = auth_store.Store(
        tmp_path / "auth.json",
        keyring_store=keyring,
        generate_keyring_username=lambda: next(usernames),
    )
    store.authorize(SecretStr("original"), state.SecretStorage.KEYRING)
    snapshot = store.load()
    assert snapshot is not None

    with (
        mock.patch.object(auth_store.atomic, "write", side_effect=OSError),
        pytest.raises(auth_store.Error),
    ):
        store.save_if_current(
            snapshot,
            state.PkceAuthorizedAuthState(refresh_token=SecretStr("rotated")),
        )

    assert keyring.values == {"first": "original"}


def test_clear_removes_keyring_token_and_persists_cleared_state(tmp_path: Path):
    keyring = keyring_ext.memory()
    path = tmp_path / "auth.json"
    store = auth_store.Store(
        path,
        keyring_store=keyring,
        generate_keyring_username=lambda: "token-id",
    )
    store.authorize(SecretStr("refresh-token"), state.SecretStorage.KEYRING)

    store.clear()

    assert keyring.values == {}
    assert json.loads(path.read_text()) == {
        "version": 1,
        "mode": "pkce",
        "state": "cleared",
    }
