"""Strict local Google contracts; labels are operator attestations, not OIDC proof."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Annotated, Literal, TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    SecretStr,
    TypeAdapter,
    field_serializer,
    field_validator,
    model_validator,
)

GoogleAccountId: TypeAlias = Literal["propel-dms", "addourteam99"]
GoogleProvider: TypeAlias = Literal["gsc", "ga4"]
GoogleAccountState: TypeAlias = Literal[
    "available", "missing", "invalid", "reauthorization_required", "provider_unavailable"
]
GoogleCredentialGeneration: TypeAlias = str
ACCOUNT_IDS: tuple[GoogleAccountId, GoogleAccountId] = ("propel-dms", "addourteam99")
EXPECTED_EMAILS = MappingProxyType(
    {"propel-dms": "propel.dms@gmail.com", "addourteam99": "addourteam99@gmail.com"}
)
GOOGLE_SCOPES = frozenset(
    {
        "https://www.googleapis.com/auth/webmasters.readonly",
        "https://www.googleapis.com/auth/analytics.readonly",
    }
)
TOKEN_URI = "https://oauth2.googleapis.com/token"
BoundedText = Annotated[str, Field(min_length=1, max_length=4096)]


class GoogleAccountError(RuntimeError):
    """Input-free failures only. Never attach provider or validation context."""

    def __init__(
        self,
        code: Literal[
            "credentials_missing",
            "credentials_invalid",
            "credentials_changed",
            "deadline_exceeded",
            "agency_discovery_incomplete",
            "site_denied",
        ],
    ) -> None:
        allowed = {
            "credentials_missing",
            "credentials_invalid",
            "credentials_changed",
            "deadline_exceeded",
            "agency_discovery_incomplete",
            "site_denied",
        }
        self.code = code if code in allowed else "credentials_invalid"
        super().__init__(self.code)


class _StrictModel(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid", hide_input_in_errors=True)


class GoogleOAuthCredential(_StrictModel):
    version: Literal[1]
    account_id: GoogleAccountId
    client_id: BoundedText
    client_secret: SecretStr = Field(repr=False, min_length=1, max_length=16384)
    refresh_token: SecretStr = Field(repr=False, min_length=1, max_length=65536)
    token_uri: Literal["https://oauth2.googleapis.com/token"]
    scopes: frozenset[str]

    @field_validator("version", mode="before")
    @classmethod
    def exact_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("invalid_version")
        return value

    @field_validator("scopes")
    @classmethod
    def exact_scopes(cls, value: frozenset[str]) -> frozenset[str]:
        if value != GOOGLE_SCOPES:
            raise ValueError("invalid_scopes")
        return value


class GooglePropertyMembership(_StrictModel):
    provider: GoogleProvider
    property_id: BoundedText
    account_ids: tuple[GoogleAccountId, ...] = Field(min_length=1, max_length=2)
    gsc_permissions: Mapping[GoogleAccountId, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_membership(self) -> GooglePropertyMembership:
        if self.account_ids != tuple(sorted(set(self.account_ids))):
            raise ValueError("invalid_accounts")
        if self.provider == "ga4" and not re.fullmatch(r"properties/[0-9]+", self.property_id):
            raise ValueError("invalid_property")
        if (
            set(self.gsc_permissions) - set(self.account_ids)
            or (self.provider == "ga4" and self.gsc_permissions)
            or any(not v or len(v) > 128 for v in self.gsc_permissions.values())
        ):
            raise ValueError("invalid_permissions")
        object.__setattr__(self, "gsc_permissions", MappingProxyType(dict(self.gsc_permissions)))
        return self

    @field_serializer("gsc_permissions")
    def serialize_permissions(self, value: Mapping) -> dict:
        return dict(value)


class GoogleDiscoverySnapshot(_StrictModel):
    provider: GoogleProvider
    credential_generation: BoundedText
    collected_at: float = Field(ge=0, allow_inf_nan=False)
    memberships: tuple[GooglePropertyMembership, ...] = Field(max_length=10000)
    per_account_status: Mapping[GoogleAccountId, GoogleAccountState]
    complete: bool

    @model_validator(mode="after")
    def validate_snapshot(self) -> GoogleDiscoverySnapshot:
        if set(self.per_account_status) != set(ACCOUNT_IDS):
            raise ValueError("invalid_status")
        ids = tuple(m.property_id for m in self.memberships)
        if (
            any(m.provider != self.provider for m in self.memberships)
            or ids != tuple(sorted(set(ids)))
            or (self.complete and any(v != "available" for v in self.per_account_status.values()))
        ):
            raise ValueError("invalid_snapshot")
        object.__setattr__(
            self, "per_account_status", MappingProxyType(dict(self.per_account_status))
        )
        return self

    @field_serializer("per_account_status")
    def serialize_status(self, value: Mapping) -> dict:
        return dict(value)


class GoogleRequestDeadline(_StrictModel):
    end: float = Field(ge=0, allow_inf_nan=False)

    def remaining(self) -> float:
        return max(0.0, self.end - time.monotonic())

    def require_remaining(self) -> None:
        if not self.remaining():
            raise GoogleAccountError("deadline_exceeded")


@dataclass(frozen=True, slots=True, repr=False)
class GoogleSdkClients:
    """Private SDK boundary: never put this record into wire/model serialization."""

    account_id: GoogleAccountId
    generation: GoogleCredentialGeneration
    gsc: object = field(repr=False)
    ga4_admin: object = field(repr=False)
    ga4_data: object = field(repr=False)

    def __post_init__(self) -> None:
        if (
            self.account_id not in ACCOUNT_IDS
            or type(self.generation) is not str
            or not 0 < len(self.generation) <= 4096
        ):
            raise GoogleAccountError("credentials_invalid")

    def __repr__(self) -> str:
        return "<GoogleSdkClients private>"

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("private_sdk_clients")


_WIRE = TypeAdapter(JsonValue, config=ConfigDict(strict=True, hide_input_in_errors=True))


def _validate_wire(value: object) -> JsonValue:
    """Bound SDK results before consumers admit them; no unchecked SDK handles."""
    # Bound traversal before recursive validation/serialization, including cycles.
    pending = [(value, 0)]
    nodes = size = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 100000 or depth > 64:
            raise GoogleAccountError("agency_discovery_incomplete")
        if type(item) is dict:
            if any(type(k) is not str for k in item):
                raise GoogleAccountError("agency_discovery_incomplete")
            size += sum(len(k.encode("utf-8")) for k in item)
            pending.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            pending.extend((v, depth + 1) for v in item)
        elif type(item) is str:
            size += len(item.encode("utf-8"))
        elif type(item) is float:
            if not math.isfinite(item):
                raise GoogleAccountError("agency_discovery_incomplete")
        elif type(item) is int:
            if item.bit_length() > 64:
                raise GoogleAccountError("agency_discovery_incomplete")
        elif item is not None and type(item) is not bool:
            raise GoogleAccountError("agency_discovery_incomplete")
        if size > 2097152:
            raise GoogleAccountError("agency_discovery_incomplete")
    return _WIRE.validate_python(value)


def validate_google_wire(value: object) -> JsonValue:
    """Normalize all wire validation errors without confidential input context."""
    result = None
    failed = False
    try:
        result = _validate_wire(value)
    except Exception:
        failed = True
    if failed:
        raise GoogleAccountError("agency_discovery_incomplete") from None
    return result
