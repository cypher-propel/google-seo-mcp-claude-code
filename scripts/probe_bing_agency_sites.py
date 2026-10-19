"""Private, one-shot operator inventory probe; not an MCP tool.

Import performs no credential/configuration reads. The operator must qualify
these bytes and the installed Bing modules before admitting credentials. This
helper cannot establish agency ownership or provider inventory completeness.
"""
import base64
import binascii
import contextlib
import io
import warnings
import json
import math
import re
import sys
from types import SimpleNamespace
from typing import Literal, get_args

class _Diagnostics(io.StringIO):
    """Process-local bounded quarantine, never an operator diagnostic stream."""

    def __init__(self):
        super().__init__()
        self.overflow = False

    def write(self, text):
        remaining = 2 * 1024 * 1024 - self.tell()
        if len(text) > remaining:
            self.overflow = True
        super().write(text[:max(0, remaining)])
        return len(text)


def _static_process_exception(_kind, _value, _traceback):
    # Let the uncaught exception terminate the process, but not print foreign
    # exception values or source lines. No catch-and-continue runner exists.
    sys.__stderr__.write("probe_interrupted\n")


_startup_diagnostics = None
if __name__ == "__main__":
    # Quarantine dependency import diagnostics too. This stream remains private
    # until process exit, including any retained daemon's late writes.
    _startup_diagnostics = _Diagnostics()
    sys.stderr = _startup_diagnostics
    sys.excepthook = _static_process_exception
    warnings.simplefilter("error")

from pydantic import Field, JsonValue, field_validator, model_validator

from google_seo_mcp.bing.auth import BingAuthError, BingCredentialLoader, configure_bing_auth
from google_seo_mcp.bing.client import (
    BingReadClient, _CAP, _Stop, _decoded, _quiet, _reject_reflection, _unique,
)
from google_seo_mcp.bing.models import (
    BingModel, BingOperation, BingProviderFault, BingReadResult, BingToolRequest,
    SafeCode, validate_public_url,
)
from google_seo_mcp.bing.wire_models import RawBingSite

_CODES = frozenset(get_args(SafeCode))


class _Site(BingModel):
    site_url: str
    is_verified: bool

    _url = field_validator("site_url")(validate_public_url)


class _Receipt(BingModel):
    version: Literal[1]
    operation: Literal["GetUserSites"]
    status: Literal["success", "failed"]
    error: SafeCode | None
    sites: list[_Site]
    listed_count: int = Field(ge=0)
    verified_count: int = Field(ge=0)
    provider_completeness: Literal["unknown"]
    ownership_attestation: Literal["pending"]

    @field_validator("version", mode="before")
    @classmethod
    def strict_version(cls, value):
        if type(value) is not int or value != 1:
            raise ValueError("invalid_receipt")
        return value

    @model_validator(mode="after")
    def coherent(self):
        if (type(self.version) is not int or self.listed_count != len(self.sites)
                or self.verified_count != sum(site.is_verified for site in self.sites)
                or [s.site_url for s in self.sites] != sorted({s.site_url for s in self.sites})
                or (self.status == "success") != (self.error is None)
                or (self.status == "failed" and self.sites)):
            raise ValueError("invalid_receipt")
        return self


def _receipt(error: str | None = None, sites: list[dict[str, JsonValue]] | None = None
             ) -> dict[str, JsonValue]:
    rows = [] if error is not None else (sites or [])
    return _Receipt.model_validate({
        "version": 1, "operation": "GetUserSites",
        "status": "failed" if error is not None else "success",
        "error": error, "sites": rows, "listed_count": len(rows),
        "verified_count": sum(row["is_verified"] is True for row in rows),
        "provider_completeness": "unknown", "ownership_attestation": "pending",
    }).model_dump(mode="json")


def _fault(code: object) -> dict[str, JsonValue]:
    # Never pass a foreign exception message, repr, or arbitrary code outward.
    return _receipt(code if type(code) is str and code in _CODES else "provider_error")


def _operator_reflection(value: JsonValue, key: str) -> None:
    """Scan ignored fields too; decode reversible wrappers with bounded work.

    Existing percent/HTML/Unicode semantics remain authoritative. Also recognize
    embedded encoded key spellings and encoded enclosing text, recursively.
    Exhaustion refuses rather than returning material we did not fully inspect.
    """
    _reject_reflection(value, key)
    needles = set()
    for text in _decoded(key):
        raw = text.encode("utf-8")
        needles.update((base64.b64encode(raw).decode().rstrip("="),
                        base64.urlsafe_b64encode(raw).decode().rstrip("=")))
        needles.update((raw.hex(), raw.hex().upper()))
    token_pattern = re.compile(r"[A-Za-z0-9+/_-]{4,}={0,2}")
    raw_key = key.encode("utf-8")

    def inspect_origin(origin):
        # Each lexical origin owns its decoding frontier. In particular, the
        # whole JSON document is NOT one shared frontier for unrelated URLs.
        # Admit before enqueueing: duplicates cannot inflate the pending stack.
        pending, admitted = [(origin, 0)], {origin}
        scale = max(64, len(origin))
        retained = len(origin)
        work_left = 128 * scale
        while pending:
            text, depth = pending.pop()
            for decoded in _decoded(text):
                # Byte-proportional budgets also bound replacement-character
                # expansion, not just the number of recursive variants.
                work_left -= len(decoded)
                if work_left < 0:
                    raise _Stop("credential_reflection")
                _reject_reflection(decoded, key)
                if any(needle and needle in decoded for needle in needles):
                    raise _Stop("credential_reflection")
                for match in token_pattern.finditer(decoded):
                    token = match[0]
                    candidates = []
                    # Hex has its own lexical alphabet: URL slashes and base64
                    # framing must not merge it into an undecodable broad token.
                    # Both nibble alignments retain every interior byte sequence;
                    # a trailing framing nibble is not part of that sequence.
                    for hex_match in re.finditer(r"[0-9a-fA-F]{4,}", token):
                        run = hex_match[0]
                        for offset in range(2):
                            part = run[offset:]
                            part = part[:len(part) - len(part) % 2]
                            if part:
                                candidates.append(bytes.fromhex(part))
                    # Retain every quartet alignment for URL/path prefixes.
                    for offset in range(min(4, len(token))):
                        part = token[offset:]
                        try:
                            candidates.append(base64.b64decode(
                                part + "=" * (-len(part) % 4),
                                altchars=b"-_", validate=True))
                        except (ValueError, binascii.Error):
                            pass
                    for raw in candidates:
                        if raw_key in raw:
                            raise _Stop("credential_reflection")
                        nested = raw.decode("utf-8", errors="replace")
                        if nested and nested != decoded and nested not in admitted:
                            if (depth >= 8 or len(admitted) >= 128
                                    or retained + len(nested) > 16 * scale):
                                raise _Stop("credential_reflection")
                            retained += len(nested)
                            admitted.add(nested)
                            pending.append((nested, depth + 1))

    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, float) and not math.isfinite(item):
            raise _Stop("invalid_response")
        if isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            # Whole-value checks precede lexical splitting; no ignored field or
            # raw-body text is discarded before percent/HTML/Unicode inspection.
            for decoded in _decoded(item):
                _reject_reflection(decoded, key)
                if any(needle and needle in decoded for needle in needles):
                    raise _Stop("credential_reflection")
                for match in token_pattern.finditer(decoded):
                    inspect_origin(match[0])


def parse_inventory(body: bytes, key: str) -> dict[str, JsonValue]:
    """Validate the complete raw envelope before projecting safe exact sites."""
    try:
        if type(body) is not bytes or type(key) is not str or not key:
            return _fault("invalid_response")
        if len(body) > _CAP:
            return _fault("response_too_large")
        text = body.decode("utf-8", errors="strict")
        _operator_reflection(text, key)
        payload = json.loads(text, object_pairs_hook=_unique,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _operator_reflection(payload, key)
        if not isinstance(payload, dict):
            return _fault("invalid_response")
        if "ErrorCode" in payload or "Message" in payload:
            return _fault("provider_error")
        rows = payload.get("d")
        if isinstance(rows, dict) and ("ErrorCode" in rows or "Message" in rows):
            return _fault("provider_error")
        if not isinstance(rows, list):
            return _fault("invalid_response")
        sites: dict[str, bool] = {}
        for row in rows:
            # Require the actual wire member names, never populate_by_name aliases.
            if not isinstance(row, dict) or "Url" not in row or "IsVerified" not in row:
                return _fault("invalid_response")
            site = RawBingSite.model_validate(row)
            url = validate_public_url(site.url)
            if url in sites and sites[url] is not site.is_verified:
                return _fault("invalid_response")
            sites[url] = site.is_verified
        result = _receipt(sites=[{"site_url": url, "is_verified": sites[url]}
                                 for url in sorted(sites)])
        _operator_reflection(result, key)
        return result
    except _Stop as exc:
        return _fault(exc.code)
    except Exception:
        return _fault("invalid_response")


class RawInventoryProbe(BingReadClient):
    """Override only parsing; retain read's quiet worker and real watchdog."""

    def _read(self, request, budget):
        try:
            if request.operation != BingOperation.GET_USER_SITES or request.site_url is not None:
                return _fault("invalid_request")
            if self._loader is None:
                self._loader = BingCredentialLoader()
            self._authorize(request)
            if not budget.remaining():
                return _fault("timeout")
            # Deliberately no retry loop, normalization, selectors or business call.
            status, _retry_after, body, key = self._attempt(request, budget)
            _operator_reflection(body.decode("utf-8", errors="strict"), key)
            if status != 200:
                return _fault({401: "access_denied", 403: "access_denied",
                               429: "rate_limited", -1: "transport_error"}.get(
                                   status, "provider_error"))
            result = parse_inventory(body, key)
            if not budget.remaining():
                return _fault("timeout")
            return result
        except BingAuthError as exc:
            return _fault({"credentials_missing": "provider_not_configured",
                           "credentials_invalid": "credentials_invalid",
                           "site_denied": "site_denied"}.get(exc.code, "credentials_invalid"))
        except _Stop as exc:
            return _fault(exc.code)
        except UnicodeError:
            return _fault("invalid_response")
        except Exception:
            return _fault("transport_error")


def run_probe(client: RawInventoryProbe) -> dict[str, JsonValue]:
    """One inherited supervised read; normalize all other results to statics."""
    with _quiet():
        try:
            request = BingToolRequest(operation=BingOperation.GET_USER_SITES)
            result = client.read(BingOperation.GET_USER_SITES, request)
            if type(result) is BingReadResult:
                # Do not dump unchecked models or trust provider diagnostics.
                fault = result.error
                if type(fault) is BingProviderFault:
                    return _fault(fault.code)
                return _fault("invalid_response")
            if type(result) is not dict:
                return _fault("invalid_response")
            return _Receipt.model_validate(result).model_dump(mode="json")
        except Exception:
            return _fault("provider_error")


class _EgressCustody:
    """Observe existing authorized loads, without another credential read.

    This is only the CLI's diagnostic-egress custody. It neither changes the
    inherited loader's admission nor promises post-entry custody revalidation.
    """

    def __init__(self, loader):
        self._loader = loader
        self._keys = []

    def load(self):
        document = self._loader.load()
        key = document.api_key.get_secret_value()
        if type(key) is not str or not key:
            raise _Stop("credentials_invalid")
        if key not in self._keys:
            self._keys.append(key)
        return document

    def __getattr__(self, name):
        return getattr(self._loader, name)


def main(argv: list[str] | None = None) -> int:
    # Standalone-only containment; do not change the library warning policy.
    # Every argument is refused before composition, including --help and paths.
    args = sys.argv[1:] if argv is None else argv
    custody = None
    diagnostics = _Diagnostics()
    try:
        with contextlib.redirect_stderr(diagnostics), warnings.catch_warnings():
            warnings.simplefilter("error")
            if args:
                result = _fault("invalid_request")
            else:
                with _quiet():
                    try:
                        configure_bing_auth(SimpleNamespace(
                            bing_credentials_file="/run/secrets/bing-webmaster.json",
                            bing_sites_file="/run/secrets/bing-sites.json"))
                        custody = _EgressCustody(BingCredentialLoader())
                        result = run_probe(RawInventoryProbe(custody, max_retries=0))
                    except Exception:
                        result = _fault("provider_error")
            captured = diagnostics.getvalue()
            if _startup_diagnostics is not None:
                captured = _startup_diagnostics.getvalue() + captured
            try:
                if captured:
                    if custody is None or not custody._keys:
                        raise _Stop("provider_error")
                    for key in custody._keys:
                        _operator_reflection(captured, key)
                    # Even harmless unexpected stderr is a failed STOP.
                    raise _Stop("provider_error")
                if (diagnostics.overflow or (_startup_diagnostics is not None
                                             and _startup_diagnostics.overflow)):
                    raise _Stop("provider_error")
                if custody is not None:
                    for key in custody._keys:
                        _operator_reflection(result, key)
                        _operator_reflection(json.dumps(result, ensure_ascii=True), key)
            except Exception:
                result = _fault("provider_error")
        sys.stdout.write(json.dumps(result, ensure_ascii=True, allow_nan=False,
                                    separators=(",", ":")) + "\n")
        return 0 if result["status"] == "success" else 1
    finally:
        # No BaseException handler: interruption unwinds and terminates the
        # standalone process. Never catch it and resume a retained worker.
        if custody is not None:
            custody._keys.clear()
        diagnostics.close()


if __name__ == "__main__":
    raise SystemExit(main())
