"""Validated process configuration. No credentials are opened at this boundary."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class RuntimeConfigurationError(ValueError):
    """Safe startup error; never includes raw configuration values."""


def _authority(value: str) -> str:
    if (
        not value
        or not value.isascii()
        or any(c.isspace() for c in value)
        or any(c in value for c in "/*?#@\\%")
        or value.endswith(":")
    ):
        raise ValueError("invalid authority")
    parsed = urlsplit("//" + value)
    if parsed.path or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("invalid authority")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid port")
    hostname = parsed.hostname
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if len(hostname) > 253 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in hostname.split(".")
        ):
            raise ValueError("invalid hostname") from None
    return value.lower()


def _origin(value: str, *, https_only: bool = False) -> str:
    if any(c.isspace() for c in value) or "?" in value or "#" in value:
        raise ValueError("invalid origin")
    parsed = urlsplit(value)
    if parsed.scheme not in (("https",) if https_only else ("https", "http")):
        raise ValueError("invalid scheme")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("origin must be exact")
    return parsed.scheme + "://" + _authority(parsed.netloc)


class ProductionRuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    transport: Literal["stdio", "streamable-http"] = "stdio"
    profile: Literal["legacy", "production"] = "legacy"
    host: str = "0.0.0.0"
    port: int = Field(default=8000, ge=1, le=65535, strict=True)
    public_base_url: str = "https://google-seo.mcp.propel.marketing"
    accepted_hosts: tuple[str, ...] = ()
    accepted_origins: tuple[str, ...] = ()
    consumer_keys_file: Path | None = Field(default=None, repr=False)
    service_account_file: Path | None = Field(default=None, repr=False)
    google_auth_mode: Literal["legacy", "service-account"] = "legacy"
    require_google_credentials: bool = False
    allow_indexnow: bool = False
    allow_local_files: bool = False
    allow_private_fetch: bool = False
    allow_destructive: bool = False
    debug: bool = False

    @field_validator("host")
    @classmethod
    def validate_bind(cls, value: str) -> str:
        # Bind address only; never accept URLs, userinfo or an embedded port.
        if not value or any(c in value for c in "/@?#\\%"):
            raise ValueError("invalid bind host")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if _authority(value) != value.lower() or ":" in value:
                raise ValueError("invalid bind host") from None
        return value

    @field_validator("public_base_url")
    @classmethod
    def validate_public_url(cls, value: str) -> str:
        return _origin(value, https_only=True)

    @field_validator("accepted_hosts")
    @classmethod
    def validate_hosts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_authority(value) for value in values))

    @field_validator("accepted_origins")
    @classmethod
    def validate_origins(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_origin(value) for value in values))

    @model_validator(mode="after")
    def enforce_profile(self) -> ProductionRuntimeConfig:
        if self.transport == "streamable-http" and self.profile != "production":
            raise ValueError("HTTP requires production profile")
        if self.profile == "production":
            if self.google_auth_mode != "service-account":
                raise ValueError("production requires service-account mode")
            if any(
                (
                    self.allow_indexnow,
                    self.allow_local_files,
                    self.allow_private_fetch,
                    self.allow_destructive,
                    self.debug,
                )
            ):
                raise ValueError("production forbids unsafe gates")
            if self.service_account_file is None or self.consumer_keys_file is None:
                raise ValueError("production requires configured credential paths")
        if not self.accepted_hosts:
            public = urlsplit(self.public_base_url).netloc
            object.__setattr__(
                self,
                "accepted_hosts",
                (public, f"localhost:{self.port}", f"127.0.0.1:{self.port}", f"[::1]:{self.port}"),
            )
        if not self.accepted_origins:
            object.__setattr__(self, "accepted_origins", (self.public_base_url,))
        return self


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RuntimeConfigurationError("invalid runtime configuration")


def _boolean(value: str) -> bool:
    if value.lower() in ("true", "1", "yes", "on", "y", "t"):
        return True
    if value.lower() in ("false", "0", "no", "off", "n", "f"):
        return False
    raise RuntimeConfigurationError("invalid runtime configuration")


def load_runtime_config(
    argv: list[str] | None = None, environ: Mapping[str, str] | None = None
) -> ProductionRuntimeConfig:
    """CLI overrides environment. Unknown options and all failures are sanitized."""
    environment = os.environ if environ is None else environ
    parser = _SafeArgumentParser(add_help=False, allow_abbrev=False)
    for option in ("transport", "host", "port", "profile"):
        parser.add_argument("--" + option)
    try:
        options = vars(parser.parse_args(argv))
        transport = options["transport"] or environment.get("GOOGLE_SEO_TRANSPORT", "stdio")
        profile = options["profile"] or environment.get(
            "GOOGLE_SEO_PROFILE", "production" if transport == "streamable-http" else "legacy"
        )
        fields = {
            "transport": transport,
            "profile": profile,
            "host": options["host"] or environment.get("GOOGLE_SEO_HOST", "0.0.0.0"),
            "port": int(options["port"] or environment.get("GOOGLE_SEO_PORT", "8000")),
            "public_base_url": environment.get(
                "GOOGLE_SEO_PUBLIC_BASE_URL", "https://google-seo.mcp.propel.marketing"
            ),
            "google_auth_mode": environment.get(
                "GOOGLE_SEO_AUTH_MODE", "service-account" if profile == "production" else "legacy"
            ),
            "consumer_keys_file": environment.get("GOOGLE_SEO_CONSUMER_KEYS_FILE")
            or ("/run/secrets/consumer-keys.json" if profile == "production" else None),
            "service_account_file": environment.get("GOOGLE_SEO_SERVICE_ACCOUNT_FILE")
            or (
                "/run/secrets/google-seo-service-account.json" if profile == "production" else None
            ),
        }
        for field, variable in (
            ("accepted_hosts", "GOOGLE_SEO_ACCEPTED_HOSTS"),
            ("accepted_origins", "GOOGLE_SEO_ACCEPTED_ORIGINS"),
        ):
            if variable in environment:
                if any(ord(character) < 32 for character in environment[variable]):
                    raise ValueError("invalid trusted authority")
                fields[field] = tuple(part.strip() for part in environment[variable].split(","))
        for field, variable in (
            ("require_google_credentials", "GOOGLE_SEO_REQUIRE_GOOGLE_CREDENTIALS"),
            ("allow_indexnow", "GOOGLE_SEO_ALLOW_INDEXNOW"),
            ("allow_local_files", "GOOGLE_SEO_ALLOW_LOCAL_FILES"),
            ("allow_private_fetch", "GOOGLE_SEO_ALLOW_PRIVATE_FETCH"),
            ("allow_destructive", "GSC_ALLOW_DESTRUCTIVE"),
            ("debug", "GOOGLE_SEO_DEBUG"),
        ):
            fields[field] = _boolean(environment.get(variable, "false"))
        return ProductionRuntimeConfig.model_validate(fields)
    except (ValueError, TypeError, OverflowError):
        raise RuntimeConfigurationError("invalid runtime configuration") from None
