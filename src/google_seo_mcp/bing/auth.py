"""Local-only Bing custody. File changes require explicit service recreation.

Composition captures paths without I/O. The first local boundary captures file
fingerprints; subsequent changes fail closed, including changes after absence.
No key is cached here and no network/client construction belongs in this module.
Each inspection retains the original key leaf/chain through parsing and local
admission, then attempts every close before publication. No policy is read.
The final sweep is sequential, not an atomic filesystem transaction:
each object's last observation bounds its guarantee. Changes after that check,
or restored histories leaving no compared metadata difference, are not detected.
The boundary lock serializes inspectors, not filesystem writers.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import uuid4

from .models import BingCredentialDocument

BingCredentialsState = Literal["pending", "invalid", "available"]
_DEFAULT_KEY = "/run/secrets/bing-webmaster.json"


class BingAuthError(RuntimeError):
    """Only static safe codes cross the custody boundary."""

    def __init__(self, code: Literal["credentials_missing", "credentials_invalid", "site_denied"]):
        self.code = code
        super().__init__(code)


class IBingCredentialLoader(Protocol):
    def load(self) -> BingCredentialDocument: ...

    def generation(self) -> str: ...

    def require_generation(self, expected: str) -> None: ...


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("invalid_document")
        result[key] = value
    return result


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def _protected(info: os.stat_result, *, directory: bool = False) -> None:
    if info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
        raise ValueError("invalid_file")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("invalid_file")
    elif (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o117
          or not info.st_mode & 0o440 or info.st_nlink != 1):
        raise ValueError("invalid_file")


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    # Directory entry churn (notably in /tmp) is not a custody change.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _open_parent(path: Path, descriptors: list[int]):
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors.append(parent)
    chain = [parent]
    for component in path.parts[1:-1]:
        parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=parent)
        descriptors.append(parent)
        chain.append(parent)
    _protected(os.fstat(parent), directory=True)
    return parent, chain


class _HeldDocument:
    """Private candidate only; the enclosing inspect owns every descriptor."""

    def __init__(self, path, cap, model):
        self.path, self.cap, self.model = path, cap, model
        self.state = "pending"
        self.fd = None
        self.chain = ()
        self.directory_before = ()
        self.leaf_before = None
        self.document = None

    def acquire(self, descriptors):
        if self.path is None:
            return
        try:
            if not self.path.is_absolute() or ".." in self.path.parts:
                raise ValueError("invalid_path")
            parent, self.chain = _open_parent(self.path, descriptors)
            self.directory_before = tuple(
                _directory_identity(os.fstat(fd)) for fd in self.chain)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=parent)
            descriptors.append(self.fd)
            before = os.fstat(self.fd)
            _protected(before)
            if before.st_size > self.cap:
                raise ValueError("invalid_file")
            self.leaf_before = _fingerprint(before)
            self.state = "available"
        except FileNotFoundError:
            self.state = "invalid" if self.fd is not None else "pending"
        except Exception:
            self.state = "invalid"

    def read_candidate(self):
        if self.state != "available":
            return
        try:
            chunks, length = [], 0
            while length <= self.cap:
                chunk = os.read(self.fd, min(8192, self.cap + 1 - length))
                if not chunk:
                    break
                chunks.append(chunk)
                length += len(chunk)
            if length > self.cap:
                raise ValueError("invalid_file")
            self.document = self.model.model_validate(
                json.loads(b"".join(chunks).decode("utf-8", errors="strict"),
                           object_pairs_hook=_unique_object))
        except Exception:
            self.state = "invalid"
            self.document = None

    def observe(self, descriptors):
        if self.state != "available":
            return
        try:
            retained = tuple(_directory_identity(os.fstat(fd)) for fd in self.chain)
            _protected(os.fstat(self.chain[-1]), directory=True)
            parent, chain = _open_parent(self.path, descriptors)
            configured = tuple(_directory_identity(os.fstat(fd)) for fd in chain)
            descriptor = os.fstat(self.fd)
            name = os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
            # Each source must independently satisfy every protection predicate.
            _protected(descriptor)
            _protected(name)
            if (retained != self.directory_before or configured != self.directory_before
                    or _fingerprint(descriptor) != self.leaf_before
                    or _fingerprint(name) != self.leaf_before):
                raise ValueError("invalid_file")
        except Exception:
            self.state = "invalid"
            self.document = None

    def signature(self):
        return ((self.directory_before, self.leaf_before)
                if self.state == "available" else None)


class _Boundary:
    def __init__(self, config: Any):
        # Defaults are the approved runtime defaults; explicit None stays absent.
        key = getattr(config, "bing_credentials_file", _DEFAULT_KEY)
        self.key = Path(key) if key else None
        # Opaque composition identity, never derived from credential material.
        self.generation = uuid4().hex
        self.lock = threading.RLock()
        self.snapshot = None
        self.invalidated = False
        self.custody_failed = False

    def inspect(self):
        with self.lock:
            if self.custody_failed:
                return "invalid", None
            descriptors = []
            key = _HeldDocument(self.key, 16384, BingCredentialDocument)
            result = ("invalid", None)
            cleanup_failed = False
            cleanup_cancelled = None
            request_control = None
            try:
                key.acquire(descriptors)
                key.read_candidate()
                key.observe(descriptors)
                current = (key.state, key.signature())
                if self.snapshot is None:
                    self.snapshot = current
                elif current != self.snapshot:
                    self.invalidated = True
                if key.state == "invalid":
                    self.invalidated = self.custody_failed = True
                elif key.state == "pending":
                    result = ("pending", None)
                elif not self.invalidated:
                    # Logical admission with original/verification handles held.
                    # Each final observation has its own instant: this is NOT an
                    # atomic transaction or protection after the last check.
                    result = ("available", key.document)
            except BaseException as error:
                # Explicit local unwind state: ambient caller handlers are irrelevant.
                if not isinstance(error, Exception):
                    request_control = error
                raise
            finally:
                for fd in reversed(descriptors):
                    try:
                        os.close(fd)
                    except BaseException as error:
                        cleanup_failed = True
                        if not isinstance(error, Exception) and cleanup_cancelled is None:
                            cleanup_cancelled = error
                if cleanup_failed:
                    self.invalidated = self.custody_failed = True
                if request_control is None and cleanup_cancelled is not None:
                    raise cleanup_cancelled
            if cleanup_failed:
                return "invalid", None
            return result


_configuration_lock = threading.RLock()
_boundary: _Boundary | None = None


def configure_bing_auth(config: Any) -> None:
    """Capture configured paths ONLY. Reconfiguration revokes old loaders."""
    global _boundary
    replacement = _Boundary(config)
    with _configuration_lock:
        if _boundary is not None:
            with _boundary.lock:
                _boundary.invalidated = True
        _boundary = replacement


class BingCredentialLoader:
    """A loader bound to one composition generation; contains no cached key.

    Construct after configure_bing_auth. Call load at EVERY request boundary,
    before constructing or reusing any HTTP client. Never retain returned keys
    in a client independently of this check. Changes require reconfiguration
    (normally service recreation) AND a fresh loader.
    """

    def __init__(self) -> None:
        with _configuration_lock:
            self._boundary = _boundary

    def load(self) -> BingCredentialDocument:
        state, document = self._boundary.inspect() if self._boundary else ("pending", None)
        if state != "available":
            _refuse("credentials_missing" if state == "pending" else "credentials_invalid")
        return document

    def generation(self) -> str:
        """Fresh local custody observation, not provider grants or cached readiness."""
        self.load()
        return self._boundary.generation

    def require_generation(self, expected: str) -> None:
        """Reinspect after blocking transport entry before a future client dispatch.

        Compare to the raw/discovery generation; no atomic filesystem/network
        guarantee is implied. This seam does not implement the client's gate.
        """
        if self.generation() != expected:
            _refuse("credentials_invalid")


def _refuse(code):
    # from None hides context but retains it; clear only this normalized error.
    try:
        raise BingAuthError(code) from None
    except BingAuthError as error:
        error.__context__ = None
        raise


def bing_credentials_state() -> BingCredentialsState:
    """Bounded local shape only; available does NOT certify current grants."""
    with _configuration_lock:
        boundary = _boundary
    return boundary.inspect()[0] if boundary else "pending"
