"""Three-document local custody; explicit loads only, never ADC/browser/network.

All original directory/leaf handles precede any read and survive admission.
Final observations are sequential, NOT an atomic filesystem transaction. Mutation
following an object's last observation, or restored metadata histories, cannot be
excluded. The lock serializes readers, not external writers. Changes require a
new loader (normally service recreation); missing-to-present also invalidates.
"""

from __future__ import annotations

import hmac
import json
import os
import stat
import threading
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import Field, SecretStr, field_validator

from .models import (
    ACCOUNT_IDS,
    GOOGLE_SCOPES,
    GoogleAccountError,
    GoogleCredentialGeneration,
    GoogleOAuthCredential,
    _StrictModel,
)

_DEFAULTS = (
    "/run/secrets/google-seo-oauth-client.json",
    "/run/secrets/google-seo-oauth-propel-dms.json",
    "/run/secrets/google-seo-oauth-addourteam99.json",
)
_CAP = 131072


class _Installed(_StrictModel):
    client_id: str = Field(min_length=1, max_length=4096)
    client_secret: SecretStr = Field(repr=False, min_length=1, max_length=16384)
    project_id: str = Field(min_length=1, max_length=4096)
    auth_uri: Literal[
        "https://accounts.google.com/o/oauth2/auth", "https://accounts.google.com/o/oauth2/v2/auth"
    ]
    token_uri: Literal["https://oauth2.googleapis.com/token"]
    redirect_uris: tuple[Literal["http://localhost", "http://127.0.0.1"], ...] = ()
    auth_provider_x509_cert_url: Literal["https://www.googleapis.com/oauth2/v1/certs"] | None = None

    @field_validator("auth_provider_x509_cert_url", mode="before")
    @classmethod
    def certificate_not_null(cls, value: object) -> object:
        if value is None:
            raise ValueError("invalid_certificate")
        return value

    @field_validator("client_id")
    @classmethod
    def desktop_client(cls, value: str) -> str:
        if not value.endswith(".apps.googleusercontent.com"):
            raise ValueError("invalid_binding")
        return value


class _ClientDocument(_StrictModel):
    installed: _Installed


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("invalid_document")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("invalid_document")


def _protected(info: os.stat_result, directory: bool = False) -> None:
    if info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
        raise ValueError("invalid_file")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("invalid_file")
    elif (
        not stat.S_ISREG(info.st_mode)
        or info.st_mode & 0o117
        or not info.st_mode & 0o440
        or info.st_nlink != 1
        or not 0 < info.st_size <= _CAP
    ):
        raise ValueError("invalid_file")


def _signature(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
    )


def _directory(info: os.stat_result) -> tuple[int, ...]:
    _protected(info, True)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _parent(path: Path, owned: list[int]) -> tuple[int, list[int]]:
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    owned.append(current)
    chain = [current]
    _directory(os.fstat(current))
    for part in path.parts[1:-1]:
        current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
        owned.append(current)
        chain.append(current)
        _directory(os.fstat(current))
    return current, chain


class _Held:
    def __init__(self, path: Path) -> None:
        self.path = path

    def acquire(self, owned: list[int]) -> None:
        parent, self.chain = _parent(self.path, owned)
        self.parents = tuple(_directory(os.fstat(fd)) for fd in self.chain)
        self.fd = os.open(
            self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
        )
        owned.append(self.fd)
        info = os.fstat(self.fd)
        _protected(info)
        self.before = _signature(info)

    def read(self) -> bytes:
        data = bytearray()
        while len(data) <= _CAP:
            chunk = os.read(self.fd, min(8192, _CAP + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if not 0 < len(data) <= _CAP:
            raise ValueError("invalid_file")
        # JSON's byte auto-detection would otherwise accept UTF16/32.
        text = bytes(data).decode("utf-8", errors="strict")
        parsed = json.loads(text, object_pairs_hook=_unique, parse_constant=_constant)
        if not isinstance(parsed, dict):
            raise ValueError("invalid_document")
        if "scopes" in parsed:
            scopes = parsed["scopes"]
            if (
                type(scopes) is not list
                or len(scopes) != 2
                or any(type(v) is not str for v in scopes)
                or frozenset(scopes) != GOOGLE_SCOPES
            ):
                raise ValueError("invalid_scopes")
        return bytes(data)

    def observe(self, owned: list[int]) -> tuple:
        retained = tuple(_directory(os.fstat(fd)) for fd in self.chain)
        parent, chain = _parent(self.path, owned)
        configured = tuple(_directory(os.fstat(fd)) for fd in chain)
        descriptor = os.fstat(self.fd)
        leaf = os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
        _protected(descriptor)
        _protected(leaf)
        if (
            retained != self.parents
            or configured != self.parents
            or _signature(descriptor) != self.before
            or _signature(leaf) != self.before
        ):
            raise ValueError("invalid_file")
        return self.parents, self.before


def _path(value: str | Path) -> Path:
    text = str(value)
    if (
        not text.startswith("/")
        or any(p in ("", ".", "..") for p in text.split("/")[1:])
        or any(
            c.isspace() or ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in text
        )
        or "\\" in text
    ):
        raise GoogleAccountError("credentials_invalid")
    return Path(text)


class GoogleCredentialLoader:
    """Paths are captured without I/O. Approval must be supplied by the caller.

    The operator-approved ID/project are REQUIRED for readiness and checked
    against the protected installed-client document, never inferred from it.
    Paths may be overridden only by explicit composition (e.g. offline fixtures).
    Slots/order/endpoints are fixed. No environment or HOME lookup exists.
    """

    def __init__(
        self,
        *,
        approved_client_id: str | None = None,
        approved_project_id: str | None = None,
        client_file: str | Path = _DEFAULTS[0],
        propel_dms_file: str | Path = _DEFAULTS[1],
        addourteam99_file: str | Path = _DEFAULTS[2],
    ) -> None:
        self._paths = tuple(_path(p) for p in (client_file, propel_dms_file, addourteam99_file))
        if len(set(self._paths)) != 3:
            raise GoogleAccountError("credentials_invalid")
        self._approved_client_id = approved_client_id
        self._approved_project_id = approved_project_id
        self._epoch = str(uuid4())
        self._lock = threading.RLock()
        self._baseline: tuple | None = None
        self._invalidated = False

    def __repr__(self) -> str:
        return "<GoogleCredentialLoader private>"

    def _inspect(self) -> tuple[str, tuple[GoogleOAuthCredential, GoogleOAuthCredential] | None]:
        with self._lock:
            if self._invalidated:
                return "credentials_changed", None
            if not self._approved_client_id or not self._approved_project_id:
                return "credentials_missing", None
            owned: list[int] = []
            result = None
            failure = "credentials_invalid"
            cancelled = None
            primary_control = None
            current = None
            try:
                held = tuple(_Held(path) for path in self._paths)
                for doc in held:
                    doc.acquire(owned)
                raw = tuple(doc.read() for doc in held)
                client = _ClientDocument.model_validate_json(raw[0]).installed
                first = GoogleOAuthCredential.model_validate_json(raw[1])
                second = GoogleOAuthCredential.model_validate_json(raw[2])
                accounts = (first, second)
                if (
                    client.client_id != self._approved_client_id
                    or client.project_id != self._approved_project_id
                    or tuple(c.account_id for c in accounts) != ACCOUNT_IDS
                    or any(
                        c.client_id != client.client_id
                        or not hmac.compare_digest(
                            c.client_secret.get_secret_value().encode(),
                            client.client_secret.get_secret_value().encode(),
                        )
                        for c in accounts
                    )
                    or hmac.compare_digest(
                        first.refresh_token.get_secret_value().encode(),
                        second.refresh_token.get_secret_value().encode(),
                    )
                ):
                    raise ValueError("invalid_binding")
                # Keep original AND reopened chains through complete logical admission.
                current = tuple(doc.observe(owned) for doc in held)
                result = accounts
                failure = "available"
            except FileNotFoundError:
                failure = "credentials_missing"
            except Exception:
                failure = "credentials_invalid"
            except BaseException as control:
                primary_control = control
                raise
            finally:
                close_failed = False
                for fd in reversed(owned):
                    try:
                        os.close(fd)
                    except BaseException as error:
                        close_failed = True
                        if not isinstance(error, Exception) and cancelled is None:
                            cancelled = error
                if close_failed:
                    self._invalidated = True
                    failure, result = "credentials_invalid", None
                if primary_control is None and cancelled is not None:
                    raise cancelled
            # Failed admission has no file-identity observation. Compare complete
            # observations so equivalent failures retain their exact error class.
            marker = (failure, current if failure == "available" else None)
            if self._baseline is None:
                self._baseline = marker
            elif marker != self._baseline and not close_failed:
                self._invalidated = True
                failure, result = "credentials_changed", None
            return failure, result

    def load_accounts(self) -> tuple[GoogleOAuthCredential, GoogleOAuthCredential]:
        state, result = self._inspect()
        if result is None:
            # Raise outside exception handlers: no confidential validation context.
            raise GoogleAccountError(state) from None
        return result

    def generation(self) -> GoogleCredentialGeneration:
        self.load_accounts()
        return self._epoch

    def readiness(self) -> Literal["available", "missing", "invalid"]:
        state, result = self._inspect()
        return (
            "available" if result else ("missing" if state == "credentials_missing" else "invalid")
        )
