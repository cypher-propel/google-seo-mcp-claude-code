"""Fixed Bing GET boundary; offline injection never admits endpoints or keys.

read() is synchronous. Each attempt runs in a daemon worker so the caller's
wall-clock deadline also covers a stalled/decompressed stream or client close.
A timed-out worker RETAINS the process-wide slot until it actually exits: an
uncancellable custom transport cannot create concurrency or retry bypasses.
"""

from __future__ import annotations

import contextlib
import contextvars
import html
import json
import logging
import random
import re
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Protocol
from urllib.parse import unquote, unquote_plus

import httpx
from pydantic import ValidationError

from .auth import BingAuthError, BingCredentialLoader, IBingCredentialLoader
from .models import (
    BingOperation,
    BingProviderFault,
    BingReadResult,
    BingToolRequest,
)
from .normalization import normalize_bing_rows
from .wire_models import (
    RawBingCrawlIssue,
    RawBingCrawlStats,
    RawBingFeed,
    RawBingQueryStats,
    RawBingSite,
    RawBingTrafficStats,
    RawBingUrlInfo,
)


# Suppress BEFORE LogRecord construction, not just propagation/formatting. This
# covers arbitrary logger names in injected constructors/transports as well as
# HTTPX/httpcore in legacy and hosted execution. Other threads are unaffected.
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


class _Stop(Exception):
    def __init__(self, code):
        self.code = code


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


class _GatedTransport(httpx.BaseTransport):
    """Final dispatch gate, also AFTER HTTPX request building/auth/event hooks."""

    def __init__(self, transport, attempt):
        self.transport = transport
        self.attempt = attempt

    def __enter__(self):
        self.transport.__enter__()
        return self

    def close(self):
        self.transport.close()

    def __exit__(self, *args):
        return self.transport.__exit__(*args)

    def handle_request(self, request):
        self.attempt.check()
        return self.transport.handle_request(request)


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
    BingOperation.GET_USER_SITES: RawBingSite,
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
_RETRY = frozenset({429, 502, 503, 504})
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


def _reject_reflection(value, key):
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


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
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


def _failure(request, code):
    # Obtain every analytics diagnostic/caveat from the normalizer even on faults.
    base = normalize_bing_rows(request.operation, [], request, approved_sites=frozenset())
    status = {"provider_not_configured": "unavailable", "credentials_invalid": "unavailable",
              "site_denied": "denied", "access_denied": "denied",
              "invalid_request": "invalid_request"}.get(code, "provider_error")
    data = base.model_dump()
    data.update(status=status, error=BingProviderFault(code=code))
    return _failure_provenance(BingReadResult.model_validate(data))


class BingReadClient:
    """Public seams: loader, HTTPX BaseTransport, monotonic clock and sleep.

    Default loader is created lazily on first validated read AFTER composition.
    No independently cached key/client; every attempt rechecks load+site policy.
    sleep is bounded by a real watchdog too; no caller endpoint/path/key seam.
    """

    def __init__(self, credential_loader: IBingCredentialLoader | None = None, *,
                 transport: httpx.BaseTransport | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep,
                 jitter: Callable[[], float] = random.random,
                 max_retries: int = 1):
        # Composition/qualification may only tighten the retry policy; never a
        # caller tool argument or an additional runtime configuration field.
        if type(max_retries) is not int or max_retries not in (0, 1):
            raise BingClientError()
        self._loader = credential_loader
        self._transport = transport
        self._clock = clock
        self._sleep = sleep
        self._jitter = jitter
        self._max_retries = max_retries

    def read(self, operation: BingOperation, request: BingToolRequest) -> BingReadResult:
        with _quiet():
            return self._admit(operation, request)

    def _admit(self, operation, request):
        validated = None
        # Never dump unchecked models: serialization warnings can reflect values.
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
            raise BingClientError() from None
        request = validated
        try:
            budget = _Budget(self._clock)
        except Exception:
            budget = None
        if budget is None:
            raise BingClientError() from None
        done, outcome = threading.Event(), []

        def execute():
            with _quiet():
                try:
                    outcome.append(self._read(request, budget))
                except BaseException:
                    outcome.append(None)
                finally:
                    done.set()

        threading.Thread(target=execute, name="bing-boundary", daemon=True).start()
        # Supervisor bounds custody, decoding and normalization too, not merely
        # socket read inactivity. Cancellation prevents late retries/new attempts.
        try:
            completed = done.wait(timeout=budget.remaining()) and budget.remaining() > 0
        except Exception:
            completed = False
        if not completed:
            budget.cancel()
            return _failure(request, "timeout")
        if outcome[0] is None:
            raise BingClientError() from None
        return outcome[0]

    def _read(self, request, budget):
        try:
            if self._loader is None:
                self._loader = BingCredentialLoader()
            # Missing local config fails BEFORE admission, DNS or HTTP construction.
            self._authorize(request)
            for attempt in range(self._max_retries + 1):
                if not budget.remaining():
                    raise _Stop("timeout")
                status, retry_after, body, key = self._attempt(request, budget)
                _reject_reflection(body.decode("utf-8", errors="replace"), key)
                if status in _RETRY:
                    if attempt == self._max_retries:
                        return _failure(
                            request, "rate_limited" if status == 429 else "provider_error")
                    self._pause(retry_after, budget)
                    continue
                if status == -1:  # only transient connection failures qualify
                    if attempt == self._max_retries:
                        return _failure(request, "transport_error")
                    self._pause(None, budget)
                    continue
                if 300 <= status < 400:
                    raise _Stop("provider_error")
                try:
                    payload = json.loads(
                        body, object_pairs_hook=_unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                except (ValueError, UnicodeError, RecursionError):
                    raise _Stop("invalid_response") from None
                _reject_reflection(payload, key)
                if not isinstance(payload, dict):
                    raise _Stop("invalid_response")
                # ErrorCode values are NOT documented semantics. Do not guess
                # numeric mappings or classify a Message substring as auth proof.
                if "ErrorCode" in payload or "Message" in payload:
                    raise _Stop("access_denied" if status in (401, 403) else "provider_error")
                if status != 200:
                    raise _Stop("access_denied" if status in (401, 403) else "provider_error")
                data = payload.get("d")
                if isinstance(data, dict) and ("ErrorCode" in data or "Message" in data):
                    raise _Stop("provider_error")
                if request.operation == BingOperation.GET_URL_INFO:
                    if not isinstance(data, dict):
                        raise _Stop("invalid_response")
                    data = [data]
                elif not isinstance(data, list):
                    raise _Stop("invalid_response")
                rows, invalid = [], 0
                for row in data:
                    try:
                        rows.append(_TYPES[request.operation].model_validate(row))
                    except ValidationError:
                        invalid += 1
                result = normalize_bing_rows(request.operation, rows, request,
                                             approved_sites=self._loader.allowed_sites,
                                             invalid_wire_rows=invalid)
                _reject_reflection(result.model_dump(mode="json"), key)
                if not budget.remaining():
                    raise _Stop("timeout")
                return _failure_provenance(result)
        except BingAuthError as exc:
            code = exc.code if exc.code in {"credentials_missing", "credentials_invalid",
                                            "site_denied"} else "credentials_invalid"
            return _failure(request, "provider_not_configured" if code == "credentials_missing"
                            else code)
        except _Stop as exc:
            return _failure(request, exc.code)
        except Exception:
            return _failure(request, "transport_error")
        return _failure(request, "provider_error")

    def _authorize(self, request):
        document = self._loader.load()
        if request.site_url is not None:
            self._loader.authorize_site(request.site_url)
        key = document.api_key.get_secret_value()
        _reject_reflection(request.model_dump(mode="json"), key)
        return key

    def _attempt(self, request, budget):
        if not budget.remaining() or not _GLOBAL.slot.acquire(timeout=budget.remaining()):
            raise _Stop("timeout")
        # Ownership transfers to worker only after a successful start.
        transferred = False
        done = threading.Event()
        outcome = []
        gate = None
        try:
            if not budget.remaining():
                raise _Stop("timeout")
            key = self._authorize(request)  # recheck AFTER concurrency wait/retry
            allowed = min(15.0, budget.remaining())
            if allowed <= 0:
                raise _Stop("timeout")
            _GLOBAL.charge()
            gate = _Attempt(budget, allowed)

            def run():
                with _quiet():
                    try:
                        gate.check()
                        transport = _GatedTransport(
                            self._transport if self._transport is not None else
                            httpx.HTTPTransport(trust_env=False), gate)
                        with httpx.Client(transport=transport, trust_env=False,
                                          follow_redirects=False, timeout=allowed,
                                          headers={"Content-Type":
                                                   "application/json; charset=utf-8"}
                                          ) as client:
                            gate.check()
                            with client.stream("GET", "https://ssl.bing.com/webmaster/api.svc/json/"
                                               + request.operation.value,
                                               params=_params(request, key)) as response:
                                chunks, size = [], 0
                                for chunk in response.iter_bytes(chunk_size=8192):
                                    size += len(chunk)
                                    if size > _CAP:
                                        raise _Stop("response_too_large")
                                    gate.check()
                                    chunks.append(chunk)
                                result = (response.status_code,
                                          response.headers.get("Retry-After"),
                                          b"".join(chunks), key)
                        # Closing response/client is part of the attempt, not
                        # success followed by an ignored foreign close failure.
                        outcome.append(result)
                    except (httpx.ConnectError, httpx.ConnectTimeout):
                        outcome.append((-1, None, b"", key))
                    except httpx.TimeoutException:
                        outcome.append(_Stop("timeout"))
                    except _Stop as exc:
                        outcome.append(_Stop(exc.code))
                    except BaseException:
                        outcome.append(_Stop("transport_error"))
                    finally:
                        _GLOBAL.slot.release()
                        done.set()

            worker = threading.Thread(target=run, name="bing-read", daemon=True)
            worker.start()
            transferred = True
            if not done.wait(timeout=max(0.0, gate.end - time.monotonic())):
                raise _Stop("timeout")
            gate.check()
            if isinstance(outcome[0], _Stop):
                raise outcome[0]
            return outcome[0]
        finally:
            if gate is not None:
                gate.cancel()
            if not transferred:
                _GLOBAL.slot.release()

    def _pause(self, retry_after, budget):
        delay = None
        if retry_after is not None:
            with contextlib.suppress(ValueError, TypeError, OverflowError):
                delay = float(retry_after) if retry_after.isdigit() else (
                    parsedate_to_datetime(retry_after) - datetime.now(UTC)).total_seconds()
        if delay is None:
            delay = 0.5 + max(0.0, min(1.0, float(self._jitter())))
        delay = max(0.0, min(5.0, delay))
        if budget.remaining() <= delay:
            raise _Stop("timeout")
        # Also bound a user-supplied sleep seam that stalls unexpectedly.
        done = threading.Event()
        failed = []
        def pause():
            with _quiet():
                try:
                    self._sleep(delay)
                except BaseException:
                    failed.append(True)
                finally:
                    done.set()
        threading.Thread(target=pause, name="bing-backoff", daemon=True).start()
        if not done.wait(timeout=budget.remaining()) or not budget.remaining():
            raise _Stop("timeout")
        if failed:
            raise _Stop("transport_error")
