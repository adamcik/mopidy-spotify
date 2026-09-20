"""Pure models for versioned Spotify Web authorization state."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    TypeAdapter,
    field_serializer,
)

AUTH_FILE_VERSION = 1
KEYRING_SERVICE = "mopidy-spotify"


class SecretStorage(StrEnum):
    INLINE = "inline"
    KEYRING = "keyring"


class InlineRefreshToken(BaseModel):
    model_config = ConfigDict(extra="forbid")

    storage: Literal["inline"] = "inline"
    value: SecretStr

    @field_serializer("value", when_used="json")
    def serialize_value(self, value: SecretStr) -> str:
        return value.get_secret_value()


class KeyringRefreshToken(BaseModel):
    model_config = ConfigDict(extra="forbid")

    storage: Literal["keyring"] = "keyring"
    service: Literal["mopidy-spotify"] = KEYRING_SERVICE
    username: str


type RefreshToken = Annotated[
    InlineRefreshToken | KeyringRefreshToken,
    Field(discriminator="storage"),
]


class AuthPayloadBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = AUTH_FILE_VERSION


class PkceAuthorizedAuthPayload(AuthPayloadBase):
    mode: Literal["pkce"] = "pkce"
    state: Literal["authorized"] = "authorized"
    refresh_token: RefreshToken


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
