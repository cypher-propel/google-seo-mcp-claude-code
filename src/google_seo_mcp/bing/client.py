"""Fixed GET boundary; provider-backed request-local admission.

Claimed workers retain their slot until actual exit. Filesystem/cancellation
checks are observations, not atomic filesystem-to-network admission.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import contextvars
import html
import json
import logging
import math
import re
import threading
import time
import warnings
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import unquote, unquote_plus

import httpx
from pydantic import ValidationError

from .auth import BingAuthError, BingCredentialLoader, IBingCredentialLoader
from .discovery import BingDiscoveryError, BingSiteDiscovery, response_data
from .models import (
    BingOperation,
    BingProviderFault,
    BingRawResponse,
    BingReadResult,
    BingToolRequest,
)
from .normalization import normalize_bing_rows
from .wire_models import (
    RawBingCrawlIssue,
    RawBingCrawlStats,
    RawBingFeed,
    RawBingQueryStats,
    RawBingTrafficStats,
    RawBingUrlInfo,
)


def _install_privacy():
    previous = logging.Logger._log
    existing = getattr(previous, "_bing_private_context", None)
    if existing is not None:
        return existing
    private = contextvars.ContextVar("bing_private_io", default=False)

    def private_log(self, *args, **kwargs):
        if not private.get():
            return previous(self, *args, **kwargs)
        return None

    private_log._bing_private_context = private
    logging.Logger._log = private_log
    return private

_PRIVATE = _install_privacy()


def _install_warning_boundary():
    # This delivery hook precedes custom showwarning/captureWarnings/record=True.
    # No warning filter changes. Unrelated contexts delegate the original object.
    previous = warnings._showwarnmsg
    if getattr(previous, "_bing_private_context", None) is _PRIVATE:
        return

    def private_warning(message):
        if _PRIVATE.get():
            message = warnings.WarningMessage(
                RuntimeWarning("bing_dependency_warning"), RuntimeWarning,
                "<bing-private-dependency>", 1)
            # Only this newly constructed static diagnostic reaches delivery.
            # captureWarnings must not lose it to the inherited private logger
            # guard; original provider objects/source/filename never delegate.
            token = _PRIVATE.set(False)
            try:
                return previous(message)
            finally:
                _PRIVATE.reset(token)
        return previous(message)

    private_warning._bing_private_context = _PRIVATE
    warnings._showwarnmsg = private_warning


_install_warning_boundary()


@contextlib.contextmanager
def _quiet():
    token = _PRIVATE.set(True)
    try:
        yield
    finally:
        _PRIVATE.reset(token)


class BingClientError(RuntimeError):
    """Static error for unrepresentable operation/request admission only."""

    def __init__(self):
        super().__init__("invalid_request")
        self.code = "invalid_request"


class IBingReadClient(Protocol):
    def read(self, operation: BingOperation, request: BingToolRequest) -> BingReadResult: ...


def _invalid_request():
    # "from None" hides, but retains, ambient foreign context. Clear only this
    # newly normalized exception; genuine caller/worker controls keep identity.
    try:
        raise BingClientError() from None
    except BingClientError as error:
        error.__context__ = None
        raise


_Stop = BingDiscoveryError


class _Budget:
    def __init__(self, clock):
        self.clock = clock
        self.end = clock() + 60.0
        self.real_end = time.monotonic() + 60.0
        self.cancelled = threading.Event()
        self.lock = threading.Lock()

    def cancel(self):
        with self.lock:
            self.cancelled.set()

    def remaining(self):
        if self.cancelled.is_set():
            return 0.0
        return max(0.0, min(self.end - self.clock(), self.real_end - time.monotonic()))


class _Attempt:
    """Cancellation and transport-dispatch admission share one linearization lock.

    Never hold it across foreign code: timeout cannot kill synchronous I/O.
    Once dispatch is admitted it is in flight and retains the slot until cleanup.
    """

    def __init__(self, budget, allowed):
        self.budget = budget
        self.start = budget.clock()
        self.end = time.monotonic() + allowed
        self.allowed = allowed
        self.closed = False

    def cancel(self):
        with self.budget.lock:
            self.closed = True

    def check(self):
        # Injected clock code must not hold the supervisor's cancellation lock.
        remaining = self.budget.remaining()
        elapsed = self.budget.clock() - self.start
        with self.budget.lock:
            if (self.closed or self.budget.cancelled.is_set() or remaining <= 0
                    or elapsed >= self.allowed or time.monotonic() >= self.end
                    or time.monotonic() >= self.budget.real_end):
                self.closed = True
                raise _Stop("timeout")


class _Admission:
    def __init__(self):
        self.slot = threading.BoundedSemaphore(1)
        self.lock = threading.Lock()
        self.attempts = deque()

    def charge(self):
        # Real process monotonic time: different injected clocks/clients cannot
        # reset the actual process-wide rate budget.
        with self.lock:
            now = time.monotonic()
            while self.attempts and now - self.attempts[0] >= 60:
                self.attempts.popleft()
            if len(self.attempts) >= 12:
                raise _Stop("rate_limited")
            self.attempts.append(now)


_GLOBAL = _Admission()
_TYPES = {
    BingOperation.GET_RANK_AND_TRAFFIC_STATS: RawBingTrafficStats,
    BingOperation.GET_QUERY_STATS: RawBingQueryStats,
    BingOperation.GET_PAGE_STATS: RawBingQueryStats,
    BingOperation.GET_PAGE_QUERY_STATS: RawBingQueryStats,
    BingOperation.GET_QUERY_PAGE_STATS: RawBingQueryStats,
    BingOperation.GET_CRAWL_STATS: RawBingCrawlStats,
    BingOperation.GET_CRAWL_ISSUES: RawBingCrawlIssue,
    BingOperation.GET_URL_INFO: RawBingUrlInfo,
    BingOperation.GET_FEEDS: RawBingFeed,
    BingOperation.GET_FEED_DETAILS: RawBingFeed,
}
_CAP = 2 * 1024 * 1024


def _decoded(value):
    values = {value}
    for _ in range(8):
        newer = set(values)
        for text in values:
            newer.update((unquote(text), unquote_plus(text), html.unescape(text)))
            escaped = re.sub(
                r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|U([0-9a-fA-F]{8}))",
                lambda m: chr(int(m[1] or m[2] or m[3], 16)), text)
            escaped = (escaped.replace(r"\/", "/").replace(r'\"', '"')
                       .replace(r"\'", "'").replace(r"\\", "\\"))
            newer.add(escaped)
            # Fold escaped UTF-16 surrogate pairs into the original astral
            # Unicode scalar; literal escaped emoji keys must not bypass checks.
            with contextlib.suppress(UnicodeError):
                newer.add(escaped.encode("utf-16", "surrogatepass").decode("utf-16"))
        if newer == values:
            break
        # Bounded decoding work even on adversarial mixed encoding.
        if len(newer) > 128:
            raise _Stop("credential_reflection")
        values = newer
    else:
        # Never return still-decodable deeply wrapped material as "safe" data.
        raise _Stop("credential_reflection")
    return values


def _reject_basic(value, key):
    needles = _decoded(key)
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if any(needle and needle in text for text in _decoded(item) for needle in needles):
                raise _Stop("credential_reflection")
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _reject_reflection(value, key):
    """Scan ignored fields too; decode reversible wrappers with bounded work.

    Existing percent/HTML/Unicode semantics remain authoritative. Also recognize
    embedded encoded key spellings and encoded enclosing text, recursively.
    Exhaustion refuses rather than returning material we did not fully inspect.
    """
    _reject_basic(value, key)
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
                _reject_basic(decoded, key)
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
                        with contextlib.suppress(ValueError, binascii.Error):
                            candidates.append(base64.b64decode(
                                part + "=" * (-len(part) % 4),
                                altchars=b"-_", validate=True))
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
                _reject_basic(decoded, key)
                if any(needle and needle in decoded for needle in needles):
                    raise _Stop("credential_reflection")
                for match in token_pattern.finditer(decoded):
                    inspect_origin(match[0])


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("invalid_response")
        result[key] = value
    return result


def _params(request, key):
    params = {"apikey": key}
    if request.site_url is not None:
        params["siteUrl"] = request.site_url
    for field, name in (("page_url", "page"), ("query", "query"),
                        ("url", "url"), ("sitemap_url", "feedUrl")):
        value = getattr(request, field)
        if value is not None:
            params[name] = value
    return params


def _failure_provenance(result):
    """Clear request-derived context on every typed failure, without loading keys.

    Keep the existing schema: discovery uses null, site reads use the empty
    sentinel already used for credential_reflection. Windows are caller input
    too, even when syntactically valid; retain only static caveats/diagnostics.
    Normalization can itself produce a fault, so it shares this renderer.
    """
    if result.error is None:
        return result
    data = result.model_dump()
    data.update(site_url=None if result.operation == BingOperation.GET_USER_SITES else "",
                requested_period=None, observed_period=None)
    return BingReadResult.model_validate(data)


class _GatedTransport(httpx.BaseTransport):
    """Custody after underlying entry, and final dispatch after HTTPX hooks."""

    def __init__(self, transport, attempt, loader, generation):
        self.transport, self.attempt = transport, attempt
        self.loader, self.generation = loader, generation

    def check(self):
        self.attempt.check()
        self.loader.require_generation(self.generation)
        self.attempt.check()

    def __enter__(self):
        self.transport.__enter__()
        self.check()
        return self

    def close(self):
        self.transport.close()

    def __exit__(self, *args):
        return self.transport.__exit__(*args)

    def handle_request(self, request):
        self.check()
        return self.transport.handle_request(request)


class _Ownership:
    """Worker claim and caller revocation share one mutex, not start's return."""

    def __init__(self, release):
        self.lock = threading.Lock()
        self.state = "caller"
        self.release = release

    def claim(self):
        with self.lock:
            if self.state != "caller":
                return False
            self.state = "worker"
            return True

    def revoke(self):
        with self.lock:
            if self.state != "caller":
                return
            self.state = "revoked"
        if self.release is not None:
            self.release()

    def finish(self):
        if self.release is not None:
            self.release()


def _worker(action, budget, timeout, *, release=None, gate=None, name="bing-boundary"):
    owner = None
    try:
        # Include partial startup construction inside cancellation/release scope.
        owner = _Ownership(release)
        outcome, done = [], threading.Event()

        def run():
            if not owner.claim():
                return
            with _quiet():
                try:
                    if budget.remaining() <= 0:
                        raise _Stop("timeout")
                    outcome.append((True, action()))
                except BingAuthError as error:
                    code = ("provider_not_configured" if error.code == "credentials_missing"
                            else "credentials_invalid")
                    outcome.append((False, _Stop(code)))
                except _Stop as error:
                    outcome.append((False, _Stop(error.code)))
                except Exception:
                    outcome.append((False, _Stop("transport_error")))
                except BaseException as control:
                    outcome.append((False, control))
                finally:
                    try:
                        owner.finish()
                    finally:
                        done.set()

        threading.Thread(target=run, name=name, daemon=True).start()
        if not done.wait(timeout=timeout()):
            raise _Stop("timeout")
        success, value = outcome[0]
        if not success:
            raise value
        # A worker's explicit typed fault/control must not be relabelled timeout
        # merely because its unwind correctly cancelled the shared budget.
        if (budget.remaining() <= 0
                and not (isinstance(value, BingReadResult) and value.error is not None)):
            raise _Stop("timeout")
        return value
    except BaseException:
        budget.cancel()
        if gate is not None:
            gate.cancel()
        if owner is not None:
            owner.revoke()
        elif release is not None:
            release()
        raise
    finally:
        if gate is not None:
            gate.cancel()


def _failure(request, code, *, source_rows=0, dropped_rows=0):
    base = normalize_bing_rows(request.operation, [], request)
    status = {"provider_not_configured": "unavailable", "credentials_invalid": "unavailable",
              "site_denied": "denied", "access_denied": "denied",
              "invalid_request": "invalid_request"}.get(code, "provider_error")
    data = base.model_dump()
    data.update(status=status, error=BingProviderFault(code=code),
                source_rows=source_rows, dropped_rows=dropped_rows)
    if dropped_rows:
        data["warnings"].append("invalid_rows_dropped")
    return _failure_provenance(BingReadResult.model_validate(data))


class BingReadClient:
    """One fresh inventory and at most one business attempt, sharing ONE budget."""

    def __init__(self, credential_loader: IBingCredentialLoader | None = None, *,
                 transport: httpx.BaseTransport | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 max_retries: int = 0):
        if type(max_retries) is not int or max_retries != 0:
            _invalid_request()
        self._loader, self._transport, self._clock = credential_loader, transport, clock

    def read(self, operation: BingOperation, request: BingToolRequest) -> BingReadResult:
        with _quiet():
            return self._admit(operation, request)

    def _admit(self, operation, request):
        validated = None
        try:
            op = BingOperation(operation) if type(operation) in (str, BingOperation) else None
            if op is None or type(request) is not BingToolRequest:
                raise ValueError
            validated = BingToolRequest.model_validate(request.model_dump(warnings=False))
            if op != validated.operation:
                return _failure(validated, "invalid_request")
        except Exception:
            pass
        if validated is None:
            _invalid_request()
        budget = None
        with contextlib.suppress(Exception):
            budget = _Budget(self._clock)
        if budget is None:
            _invalid_request()
        try:
            return _worker(lambda: self._read(validated, budget), budget, budget.remaining)
        except _Stop as error:
            return _failure(validated, error.code)
        except Exception:
            return _failure(validated, "transport_error")

    def _read(self, request, budget):
        try:
            if self._loader is None:
                self._loader = BingCredentialLoader()
            key = self._authorize(request)
            discovery = BingSiteDiscovery(self._attempt)
            snapshot = discovery.discover(budget)
            if not snapshot.complete:
                return _failure(request, "invalid_response", source_rows=discovery._source_rows,
                                dropped_rows=snapshot.invalid_rows)
            if request.operation == BingOperation.GET_USER_SITES:
                result = BingReadResult(
                    status="ok" if snapshot.listed_sites else "empty",
                    operation=request.operation, extracted_at=datetime.now(UTC),
                    records=list(snapshot.listed_sites), source_rows=discovery._source_rows,
                    returned_rows=len(snapshot.listed_sites),
                    warnings=["provider_completeness_unknown"])
            else:
                self._loader.require_generation(snapshot.credential_generation)
                if request.site_url not in snapshot.eligible_sites:
                    raise _Stop("site_denied")
                raw = self._attempt(request, budget,
                                    expected_generation=snapshot.credential_generation)
                data = response_data(raw)
                if request.operation == BingOperation.GET_URL_INFO:
                    if not isinstance(data, dict):
                        raise _Stop("invalid_response")
                    data = [data]
                if not isinstance(data, list):
                    raise _Stop("invalid_response")
                rows, invalid = [], 0
                for row in data:
                    try:
                        rows.append(_TYPES[request.operation].model_validate(row))
                    except ValidationError:
                        invalid += 1
                result = normalize_bing_rows(request.operation, rows, request,
                                             invalid_wire_rows=invalid)
            _reject_reflection(result.model_dump(mode="json"), key)
            self._loader.require_generation(snapshot.credential_generation)
            if budget.remaining() <= 0:
                raise _Stop("timeout")
            return _failure_provenance(result)
        except BingAuthError as error:
            code = ("provider_not_configured" if error.code == "credentials_missing"
                    else "credentials_invalid")
            return _failure(request, code)
        except _Stop as error:
            return _failure(request, error.code)
        except Exception:
            return _failure(request, "transport_error")

    def _authorize(self, request):
        key = self._loader.load().api_key.get_secret_value()
        _reject_reflection(request.model_dump(mode="json"), key)
        return key

    def _attempt(self, request, budget, *, expected_generation=None):
        if not budget.remaining() or not _GLOBAL.slot.acquire(timeout=budget.remaining()):
            raise _Stop("timeout")
        release = _GLOBAL.slot.release
        delegated = False
        try:
            key = self._authorize(request)
            generation = self._loader.generation()
            if expected_generation is not None and generation != expected_generation:
                raise _Stop("credentials_invalid")
            allowed = min(15.0, budget.remaining())
            if allowed <= 0:
                raise _Stop("timeout")
            _GLOBAL.charge()
            gate = _Attempt(budget, allowed)
            delegated = True
            return _worker(lambda: self._wire(request, key, generation, gate, allowed),
                           budget, lambda: max(0.0, gate.end - time.monotonic()),
                           release=release, gate=gate, name="bing-read")
        except BaseException:
            budget.cancel()
            raise
        finally:
            if not delegated:
                release()

    def _wire(self, request, key, generation, gate, allowed):
        client = transport = response = None
        opened = False
        primary = cleanup_control = None
        cleanup_failed = False
        try:
            gate.check()
            transport = _GatedTransport(
                self._transport if self._transport is not None else
                httpx.HTTPTransport(trust_env=False), gate, self._loader, generation)
            client = httpx.Client(transport=transport, trust_env=False, follow_redirects=False,
                                  timeout=allowed,
                                  headers={"Content-Type": "application/json; charset=utf-8"})
            client.__enter__()
            opened = True
            transport.check()
            wire_request = client.build_request(
                "GET", "https://ssl.bing.com/webmaster/api.svc/json/" + request.operation.value,
                params=_params(request, key))
            response = client.send(wire_request, stream=True)
            chunks, size = [], 0
            for chunk in response.iter_bytes(chunk_size=8192):
                size += len(chunk)
                if size > _CAP:
                    raise _Stop("response_too_large")
                gate.check()
                chunks.append(chunk)
            body = b"".join(chunks)
            _reject_reflection(dict(response.headers), key)
            _reject_reflection(body.decode("utf-8", errors="replace"), key)
            try:
                parsed = json.loads(
                    body.decode("utf-8", errors="strict"), object_pairs_hook=_unique,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            except (ValueError, UnicodeError, RecursionError):
                if response.status_code == 200:
                    raise _Stop("invalid_response") from None
            else:
                _reject_reflection(parsed, key)
            result = BingRawResponse(status_code=response.status_code,
                                     retry_after=response.headers.get("Retry-After"), body=body,
                                     credential_generation=generation)
            gate.check()
        except httpx.TimeoutException:
            raise _Stop("timeout") from None
        except BaseException as error:
            if not isinstance(error, Exception):
                primary = error
            raise
        finally:
            actions = []
            if response is not None:
                actions.append(response.close)
            if client is not None:
                actions.append((lambda: client.__exit__(None, None, None)) if opened
                               else client.close)
            elif transport is not None:
                actions.append(transport.close)
            for close in actions:
                try:
                    close()
                except BaseException as error:
                    cleanup_failed = True
                    if not isinstance(error, Exception) and cleanup_control is None:
                        cleanup_control = error
            if primary is None and cleanup_control is not None:
                raise cleanup_control
            if primary is None and cleanup_failed:
                raise _Stop("transport_error") from None
        return result
