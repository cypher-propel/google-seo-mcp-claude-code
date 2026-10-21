"""Request-local Bing inventory; no client import, cache, key or new budget."""

import json
from urllib.parse import urlsplit

from pydantic import ValidationError

from .models import (
    BingBudget,
    BingDiscoverySnapshot,
    BingOperation,
    BingRawAttempt,
    BingRawResponse,
    BingSiteRecord,
    BingToolRequest,
    SafeCode,
    validate_public_url,
)
from .wire_models import RawBingSite


class BingDiscoveryError(Exception):
    """Static typed fault shared by discovery and its private raw producer."""

    def __init__(self, code: SafeCode):
        self.code = code
        super().__init__(code)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("invalid_response")
        result[key] = value
    return result


def decode_body(body: bytes):
    """Strict JSON, including ignored fields; never expose decoder diagnostics."""
    invalid = False
    try:
        value = json.loads(body.decode("utf-8", errors="strict"), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        invalid = True
    if invalid:
        raise BingDiscoveryError("invalid_response")
    return value


def response_data(raw: BingRawResponse):
    """Status and provider faults are not empty inventories or inferred grants."""
    if raw.status_code != 200:
        code = ("access_denied" if raw.status_code in (401, 403) else
                "rate_limited" if raw.status_code == 429 else "provider_error")
        raise BingDiscoveryError(code)
    payload = decode_body(raw.body)
    if not isinstance(payload, dict):
        raise BingDiscoveryError("invalid_response")
    if "ErrorCode" in payload or "Message" in payload:
        raise BingDiscoveryError("provider_error")
    data = payload.get("d")
    if isinstance(data, dict) and ("ErrorCode" in data or "Message" in data):
        raise BingDiscoveryError("provider_error")
    return data


class BingSiteDiscovery:
    """One nonrecursive raw attempt, validating ALL rows before any eligibility."""

    def __init__(self, raw_attempt: BingRawAttempt):
        self._raw_attempt = raw_attempt
        self._source_rows = 0

    def discover(self, deadline: BingBudget) -> BingDiscoverySnapshot:
        if deadline.remaining() <= 0:
            raise BingDiscoveryError("timeout")
        raw = self._raw_attempt(BingToolRequest(operation=BingOperation.GET_USER_SITES), deadline)
        data = response_data(raw)
        if not isinstance(data, list):
            raise BingDiscoveryError("invalid_response")
        self._source_rows = len(data)
        sites, conflicts, counts = {}, set(), {}
        invalid = 0
        for item in data:
            try:
                row = RawBingSite.model_validate(item)
                validate_public_url(row.url)
                if urlsplit(row.url).query:
                    raise ValueError("invalid_property")
            except (ValidationError, ValueError):
                invalid += 1
                continue
            counts[row.url] = counts.get(row.url, 0) + 1
            previous = sites.get(row.url)
            if previous is not None and previous.is_verified != row.is_verified:
                conflicts.add(row.url)
            sites[row.url] = row
        invalid += sum(counts[url] for url in conflicts)
        listed = tuple(BingSiteRecord(**sites[url].model_dump())
                       for url in sorted(sites) if url not in conflicts)
        if deadline.remaining() <= 0:
            raise BingDiscoveryError("timeout")
        return BingDiscoverySnapshot(
            credential_generation=raw.credential_generation,
            listed_sites=listed,
            eligible_sites=frozenset(row.url for row in listed if row.is_verified) if not invalid
            else frozenset(),
            invalid_rows=invalid,
            complete=not invalid,
        )
