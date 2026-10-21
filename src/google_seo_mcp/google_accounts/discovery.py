"""Request-local complete union, with bounded real SDK pager consumption.

Metadata/provenance are returned alongside (not added to) the immutable snapshot
contract. No discovery result is retained on this object between requests.
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlsplit

from google.analytics.admin_v1beta.types import ListAccountSummariesResponse

from .clients import _safe_boundary
from .models import (
    ACCOUNT_IDS, GoogleAccountError, GoogleDiscoverySnapshot, GoogleProvider, GoogleRequestDeadline,
    GooglePropertyMembership, validate_google_wire,
)

GSC_READ_PERMISSIONS = frozenset({"siteOwner", "siteFullUser", "siteRestrictedUser"})
_PERMISSIONS = GSC_READ_PERMISSIONS | {"siteUnverifiedUser"}
_MAX_PAGES, _MAX_PROPERTIES = 1000, 10000


def _incomplete():
    return GoogleAccountError("agency_discovery_incomplete")


def _text(value, limit=4096, empty=False):
    if type(value) is not str or len(value) > limit or (not value and not empty) or any(
        ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value
    ):
        raise _incomplete()
    return value


def valid_gsc_id(value):
    _text(value)
    if any(c.isspace() for c in value) or "\\" in value:
        raise _incomplete()
    if value.startswith("sc-domain:"):
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value[10:]):
            raise _incomplete()
    else:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise _incomplete()
        parsed.port  # Validate, but never normalize the provider's identifier.
    return value


def _gsc(sdk, deadline, limits=None):
    deadline.require_remaining()
    wire = validate_google_wire(sdk.gsc.sites().list().execute(num_retries=0))
    deadline.require_remaining()
    if type(wire) is not dict or set(wire) - {"siteEntry"}:
        raise _incomplete()
    entries = wire.get("siteEntry", [])
    if type(entries) is not list or len(entries) >= _MAX_PROPERTIES:
        raise _incomplete()
    if limits is not None:
        limits["properties"] += len(entries)
        if limits["properties"] >= _MAX_PROPERTIES:
            raise _incomplete()
    rows = {}
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"siteUrl", "permissionLevel"}:
            raise _incomplete()
        property_id = valid_gsc_id(entry["siteUrl"])
        permission = _text(entry["permissionLevel"], 128)
        if permission not in _PERMISSIONS or (property_id in rows and rows[property_id]["permission_level"] != permission):
            raise _incomplete()
        rows[property_id] = {
            "site_url": property_id, "permission_level": permission,
            "type": "domain" if property_id.startswith("sc-domain:") else "url",
        }
    return list(rows.values())


def _raw_ga4(wire):
    """Validate original JSON before protobuf drops unknown enums/coerces fields."""
    if type(wire) is not dict or set(wire) - {"accountSummaries", "nextPageToken"}:
        raise _incomplete()
    if "nextPageToken" in wire:
        _text(wire["nextPageToken"], 8192, empty=True)
    summaries = wire.get("accountSummaries", [])
    if type(summaries) is not list:
        raise _incomplete()
    for summary in summaries:
        if type(summary) is not dict or set(summary) - {"name", "account", "displayName", "propertySummaries"}:
            raise _incomplete()
        for key in ("name", "account", "displayName"):
            if key in summary:
                _text(summary[key], empty=key != "account")
        properties = summary.get("propertySummaries", [])
        if type(properties) is not list:
            raise _incomplete()
        for prop in properties:
            if type(prop) is not dict or set(prop) - {"property", "displayName", "propertyType", "parent", "canEdit"}:
                raise _incomplete()
            for key in ("property", "displayName", "parent"):
                if key in prop:
                    _text(prop[key], empty=key == "displayName")
            if "canEdit" in prop and type(prop["canEdit"]) is not bool:
                raise _incomplete()
            if "propertyType" in prop and prop["propertyType"] not in {
                "PROPERTY_TYPE_UNSPECIFIED", "PROPERTY_TYPE_ORDINARY",
                "PROPERTY_TYPE_SUBPROPERTY", "PROPERTY_TYPE_ROLLUP",
            }:
                raise _incomplete()


def _ga4(sdk, deadline, limits=None):
    limits = {"pages": 0, "properties": 0} if limits is None else limits
    rows, tokens = [], set()
    deadline.require_remaining()
    if limits["pages"] >= _MAX_PAGES or limits["properties"] >= _MAX_PROPERTIES:
        raise _incomplete()
    pager = sdk.ga4_admin.list_account_summaries(request={"page_size": 200})
    for page in pager.pages:
        deadline.require_remaining()
        limits["pages"] += 1
        # Hitting a ceiling, even on a terminal page, is not exhaustive success.
        if limits["pages"] >= _MAX_PAGES:
            raise _incomplete()
        if not isinstance(page, ListAccountSummariesResponse):
            raise _incomplete()
        wire = validate_google_wire(ListAccountSummariesResponse.to_dict(page, use_integers_for_enums=False))
        if type(wire) is not dict or set(wire) != {"account_summaries", "next_page_token"}:
            raise _incomplete()
        token = _text(wire["next_page_token"], 8192, empty=True)
        if token and token in tokens:
            raise _incomplete()
        tokens.add(token)
        summaries = wire["account_summaries"]
        if type(summaries) is not list:
            raise _incomplete()
        for summary in summaries:
            if type(summary) is not dict or set(summary) != {"name", "account", "display_name", "property_summaries"}:
                raise _incomplete()
            account = _text(summary["account"])
            if not re.fullmatch(r"accounts/[0-9]+", account):
                raise _incomplete()
            _text(summary["name"], empty=True)
            display_name = _text(summary["display_name"], empty=True)
            if type(summary["property_summaries"]) is not list:
                raise _incomplete()
            for prop in summary["property_summaries"]:
                if type(prop) is not dict or set(prop) != {"property", "display_name", "property_type", "parent", "can_edit"} or type(prop["can_edit"]) is not bool:
                    raise _incomplete()
                pid = _text(prop["property"])
                if not re.fullmatch(r"properties/[0-9]+", pid):
                    raise _incomplete()
                parent = _text(prop["parent"])
                if not re.fullmatch(r"(?:accounts|properties)/[0-9]+", parent):
                    raise _incomplete()
                property_type = _text(prop["property_type"], 128)
                if property_type not in {"PROPERTY_TYPE_UNSPECIFIED", "PROPERTY_TYPE_ORDINARY", "PROPERTY_TYPE_SUBPROPERTY", "PROPERTY_TYPE_ROLLUP"}:
                    raise _incomplete()
                rows.append({
                    "account": account, "account_display_name": display_name,
                    "property": pid, "property_display_name": _text(prop["display_name"], empty=True),
                    "property_type": property_type, "parent": parent,
                })
                limits["properties"] += 1
                if limits["properties"] >= _MAX_PROPERTIES:
                    raise _incomplete()
        deadline.require_remaining()
        if not token:
            return rows
    # A pager terminating while still promising a next page is incomplete.
    raise _incomplete()


class GooglePropertyDiscovery:
    def __init__(self, clients):
        self._clients = clients

    @_safe_boundary
    def inventory(self, provider, deadline):
        """Return snapshot, preferred flat rows, and all parent provenance.

        Incomplete attempts return no rows/memberships. Statuses are safe local
        or provider categories, never provider messages. Both slots are attempted.
        """
        if provider not in {"gsc", "ga4"}:
            raise _incomplete()
        try:
            generation = self._clients.generation()
        except Exception:
            generation = "unavailable"
        statuses, observed = {}, {}
        limits = {"pages": 0, "properties": 0}
        for account in ACCOUNT_IDS:
            try:
                rows = self._clients.execute(
                    account, lambda sdk: (_gsc if provider == "gsc" else _ga4)(sdk, deadline, limits), deadline
                )
                statuses[account], observed[account] = "available", rows
            except GoogleAccountError as error:
                statuses[account] = getattr(error, "account_state", "provider_unavailable")
                if statuses[account] not in {"missing", "invalid", "reauthorization_required", "provider_unavailable"}:
                    statuses[account] = "provider_unavailable"
            except Exception:
                statuses[account] = "provider_unavailable"
        complete = all(state == "available" for state in statuses.values())
        try:
            self._clients.require_generation(generation)
            deadline.require_remaining()
        except Exception:
            complete = False
        memberships, preferred, provenance = [], {}, {}
        if complete:
            grouped = {}
            for account in ACCOUNT_IDS:
                # Stable ordering within an identity, independent of page order.
                for row in sorted(observed[account], key=lambda r: tuple(str(r[k]) for k in sorted(r))):
                    pid = row["site_url" if provider == "gsc" else "property"]
                    grouped.setdefault(pid, {})[account] = row.get("permission_level")
                    preferred.setdefault(pid, {k: v for k, v in row.items() if k != "parent"})
                    provenance.setdefault(pid, []).append({"account_id": account, **row})
            if len(grouped) >= _MAX_PROPERTIES:
                complete = False
            else:
                memberships = [GooglePropertyMembership(
                    provider=provider, property_id=pid, account_ids=tuple(sorted(accounts)),
                    gsc_permissions=accounts if provider == "gsc" else {},
                ) for pid, accounts in sorted(grouped.items())]
        snapshot = GoogleDiscoverySnapshot(
            provider=provider, credential_generation=generation, collected_at=time.monotonic(),
            memberships=tuple(memberships) if complete else (), per_account_status=statuses, complete=complete,
        )
        return snapshot, tuple(preferred[pid] for pid in sorted(preferred)) if complete else (), provenance if complete else {}

    @_safe_boundary
    def discover(self, provider: GoogleProvider, deadline: GoogleRequestDeadline) -> GoogleDiscoverySnapshot:
        return self.inventory(provider, deadline)[0]

    @_safe_boundary
    def list_rows(self, provider, deadline):
        snapshot, rows, _ = self.inventory(provider, deadline)
        if not snapshot.complete:
            raise _incomplete()
        return list(rows)
