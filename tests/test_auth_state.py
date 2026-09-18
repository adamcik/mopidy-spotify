from pathlib import Path

import pytest

from mopidy_spotify import auth_state


def test_file_auth_state_store_round_trips_pkce_authorized(tmp_path: Path):
    store = auth_state.FileAuthStateStore(tmp_path / "auth.json")
    token_id = 1
    refresh_token = f"refresh-token-{token_id}"

    store.save(auth_state.PkceAuthorizedAuthPayload(refresh_token=refresh_token))

    assert store.load() == auth_state.PkceAuthorizedAuthPayload(
        refresh_token=refresh_token
    )


def test_pkce_refresh_token_is_redacted_but_serialized_for_storage():
    token = "refresh-token-secret"  # noqa: S105
    payload = auth_state.PkceAuthorizedAuthPayload(refresh_token=token)

    assert token not in repr(payload)
    assert token in payload.model_dump_json()


def test_file_auth_state_store_round_trips_cleared_bridge(tmp_path: Path):
    store = auth_state.FileAuthStateStore(tmp_path / "auth.json")

    store.save(auth_state.ClearedAuthPayload(mode="bridge"))

    assert store.load() == auth_state.ClearedAuthPayload(mode="bridge")


def test_file_auth_state_store_rejects_invalid_json(tmp_path: Path):
    auth_state_path = tmp_path / "auth.json"
    auth_state_path.write_text("not-json", encoding="utf-8")

    with pytest.raises(auth_state.InvalidRefreshTokenError):
        auth_state.FileAuthStateStore(auth_state_path).load()


def test_file_auth_state_store_does_not_chain_invalid_payload(tmp_path: Path):
    auth_state_path = tmp_path / "auth.json"
    auth_state_path.write_text(
        '{"version":1,"mode":"pkce","state":"authorized",'
        '"refresh_token":"must-not-leak","extra":true}',
        encoding="utf-8",
    )

    with pytest.raises(auth_state.InvalidRefreshTokenError) as exc_info:
        auth_state.FileAuthStateStore(auth_state_path).load()

    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None


def test_file_auth_state_store_does_not_overwrite_newer_state(tmp_path: Path):
    store = auth_state.FileAuthStateStore(tmp_path / "auth.json")
    original = auth_state.PkceAuthorizedAuthPayload(
        refresh_token="original"  # noqa: S106
    )
    replacement = auth_state.PkceAuthorizedAuthPayload(
        refresh_token="replacement"  # noqa: S106
    )
    rotated = auth_state.PkceAuthorizedAuthPayload(
        refresh_token="rotated"  # noqa: S106
    )
    store.save(original)
    store.save(replacement)

    assert not store.save_if_current(original, rotated)
    assert store.load() == replacement
