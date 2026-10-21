"""Exact-property, explicit-identity adapters; no alternate-account retry.

An adapter is scoped to one caller deadline/generation. Every execute (including
callbacks serving cached values) obtains fresh membership. Reuse after failure
is refused; a new explicit routing call must start discovery again.
"""
from __future__ import annotations

import re
import threading

from .clients import _safe_boundary
from .discovery import GSC_READ_PERMISSIONS, valid_gsc_id
from .models import ACCOUNT_IDS, GoogleAccountError, GoogleRequestDeadline
from .protocols import GooglePropertyExecutor, GoogleSdkOperation, T


def _deny():
    return GoogleAccountError("site_denied")


def _property_id(value):
    if type(value) is int:
        if value < 0 or value.bit_length() > 64:
            raise _deny()
        return f"properties/{value}"
    if type(value) is not str or not 0 < len(value) <= 4096:
        raise _deny()
    if re.fullmatch(r"[0-9]+", value):
        return f"properties/{value}"
    if re.fullmatch(r"properties/[0-9]+", value):
        return value
    raise _deny()


def _eligible(snapshot, provider, property_id):
    if not snapshot.complete or snapshot.provider != provider:
        raise GoogleAccountError("agency_discovery_incomplete")
    for member in snapshot.memberships:
        if member.property_id == property_id:
            return tuple(account for account in ACCOUNT_IDS if account in member.account_ids and (
                provider == "ga4" or member.gsc_permissions.get(account) in GSC_READ_PERMISSIONS
            ))
    return ()


class _Executor:
    def __init__(self, router, provider, property_id, account_id, generation, deadline):
        self._router = router
        self._binding = (provider, property_id, account_id, generation, deadline)
        self._failed = False
        self._lock = threading.Lock()

    def __repr__(self):
        return "<GooglePropertyExecutor private>"

    provider = property(lambda self: self._binding[0])
    property_id = property(lambda self: self._binding[1])
    account_id = property(lambda self: self._binding[2])
    credential_generation = property(lambda self: self._binding[3])
    deadline = property(lambda self: self._binding[4])

    @property
    def cache_partition(self):
        """Consumers append operation/parameters; partition alone is not authority."""
        return (self.account_id, self.credential_generation, self.provider, self.property_id)

    @_safe_boundary
    def execute(self, operation: GoogleSdkOperation[T]) -> T:
        self.deadline.require_remaining()
        if not self._lock.acquire(timeout=self.deadline.remaining()):
            raise GoogleAccountError("deadline_exceeded")
        failure, result = None, None
        try:
            if self._failed:
                raise GoogleAccountError("agency_discovery_incomplete")
            self._router._clients.require_generation(self.credential_generation)
            snapshot = self._router._discovery.discover(self.provider, self.deadline)
            if snapshot.credential_generation != self.credential_generation:
                raise GoogleAccountError("credentials_changed")
            if self.account_id not in _eligible(snapshot, self.provider, self.property_id):
                raise _deny()
            self.deadline.require_remaining()
            # No catch-and-switch: exactly this identity executes the callback.
            result = self._router._clients.execute(self.account_id, operation, self.deadline)
            self._router._clients.require_generation(self.credential_generation)
            self.deadline.require_remaining()
        except GoogleAccountError as error:
            self._failed = True
            failure = GoogleAccountError(error.code)
        except Exception:
            self._failed = True
            failure = GoogleAccountError("agency_discovery_incomplete")
        except BaseException:
            self._failed = True
            raise
        finally:
            self._lock.release()
        if failure is not None:
            raise failure from None
        return result


class GooglePropertyRouter:
    def __init__(self, clients, discovery):
        self._clients, self._discovery = clients, discovery

    def _route(self, provider, property_id, deadline):
        if not isinstance(deadline, GoogleRequestDeadline):
            raise GoogleAccountError("deadline_exceeded")
        deadline.require_remaining()
        snapshot = self._discovery.discover(provider, deadline)
        eligible = _eligible(snapshot, provider, property_id)
        generation = snapshot.credential_generation
        self._clients.require_generation(generation)
        deadline.require_remaining()
        if not eligible:
            raise _deny()
        return _Executor(self, provider, property_id, eligible[0], generation, deadline)

    @_safe_boundary
    def for_gsc(self, site_url: str, deadline: GoogleRequestDeadline) -> GooglePropertyExecutor:
        valid = False
        try:
            valid_gsc_id(site_url)
            valid = True
        except Exception:
            pass
        if not valid:
            raise _deny()
        return self._route("gsc", site_url, deadline)

    @_safe_boundary
    def for_ga4(self, property_id: int | str, deadline: GoogleRequestDeadline) -> GooglePropertyExecutor:
        return self._route("ga4", _property_id(property_id), deadline)
