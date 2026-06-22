import base64
import json
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest

from mopidy_spotify import tokens


@dataclass(kw_only=True, frozen=True)
class ParseAuthorizationResultCase:
    value: str
    expected: dict[str, str]


def _encode_base64_json(payload: dict[str, str]) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode("ascii")).decode("ascii")


def _encode_base64_query_string(payload: dict[str, str]) -> str:
    query_string = "&".join(f"{key}={value}" for key, value in payload.items())
    return base64.urlsafe_b64encode(query_string.encode("ascii")).decode("ascii")


@pytest.mark.parametrize(
    "case",
    [
        ParseAuthorizationResultCase(
            value="state=state-123&code=code-123",
            expected={"state": "state-123", "code": "code-123"},
        ),
        ParseAuthorizationResultCase(
            value="#state=state-123&code=code-123",
            expected={"state": "state-123", "code": "code-123"},
        ),
        ParseAuthorizationResultCase(
            value="https://mopidy.com/auth/spotify?state=state-123&code=code-123",
            expected={"state": "state-123", "code": "code-123"},
        ),
        ParseAuthorizationResultCase(
            value=_encode_base64_json({"state": "state-123", "code": "code-123"}),
            expected={"state": "state-123", "code": "code-123"},
        ),
        ParseAuthorizationResultCase(
            value=_encode_base64_query_string(
                {"state": "state-123", "code": "code-123"}
            ),
            expected={"state": "state-123", "code": "code-123"},
        ),
    ],
)
def test_parse_authorization_result_accepts_supported_formats(
    case: ParseAuthorizationResultCase,
):
    assert tokens.parse_authorization_result(case.value) == case.expected


def test_file_refresh_token_store_loads_json_schema(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "mode": "pkce",
                "state": "authorized",
                "refresh_token": "refresh-token-123",
            }
        ),
        encoding="utf-8",
    )

    store = tokens.FileRefreshTokenStore(path)

    payload = store.load()
    expected_payload = tokens.PkceAuthorizedAuthPayload.model_validate_json(
        path.read_text(encoding="utf-8")
    )

    assert payload is not None
    assert payload == expected_payload


def test_file_refresh_token_store_saves_json_schema_with_restrictive_perms(
    tmp_path: Path,
):
    path = tmp_path / "auth.json"

    store = tokens.FileRefreshTokenStore(path)
    store.save("refresh-token-123")

    assert json.loads(path.read_text(encoding="utf-8")) == {
        "version": 1,
        "mode": "pkce",
        "state": "authorized",
        "refresh_token": "refresh-token-123",
    }
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_file_refresh_token_store_marks_auth_json_revoked(tmp_path: Path):
    path = tmp_path / "auth.json"

    store = tokens.FileRefreshTokenStore(path)
    store.mark_revoked()

    assert json.loads(path.read_text(encoding="utf-8")) == {
        "version": 1,
        "mode": "pkce",
        "state": "revoked",
    }


def test_file_refresh_token_store_clear_marks_auth_json_cleared(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text("{}", encoding="utf-8")

    store = tokens.FileRefreshTokenStore(path)
    store.clear()

    assert json.loads(path.read_text(encoding="utf-8")) == {
        "version": 1,
        "mode": "bridge",
        "state": "cleared",
    }


def test_refresh_token_request_reads_auth_json(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "mode": "pkce",
                "state": "authorized",
                "refresh_token": "refresh-token-123",
            }
        ),
        encoding="utf-8",
    )

    request = tokens.refresh_token_request(path)

    assert request.data == {
        "client_id": tokens.CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": "refresh-token-123",
    }


def test_refresh_token_request_rejects_revoked_auth_json(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps({"version": 1, "mode": "pkce", "state": "revoked"}),
        encoding="utf-8",
    )

    with pytest.raises(tokens.InvalidRefreshTokenError, match="revoked"):
        tokens.refresh_token_request(path)


def test_refresh_token_request_rejects_proxy_bridge_auth_json(tmp_path: Path):
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps({"version": 1, "mode": "bridge", "state": "configured"}),
        encoding="utf-8",
    )

    with pytest.raises(tokens.InvalidRefreshTokenError, match="bridge"):
        tokens.refresh_token_request(path)
