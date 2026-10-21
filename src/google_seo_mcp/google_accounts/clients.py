"""Explicit, private Google SDK bundles with one execution lock per identity.

Operations are trusted application callbacks, not arbitrary user callables. They
must consume pagers and serialize SDK messages before returning bounded JSON.
No SDK handle may escape. Network admission is checked again at transport entry.
"""
from __future__ import annotations

import base64
import binascii
import html
import json
import logging
import re
import threading
from functools import wraps
from urllib.parse import unquote
from collections.abc import Callable
from urllib.parse import urlsplit

import httplib2
import requests
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from google.analytics.admin_v1beta import AnalyticsAdminServiceClient
from google.analytics.admin_v1beta.services.analytics_admin_service.transports.rest import (
    AnalyticsAdminServiceRestTransport,
)
from google.analytics.data_v1beta import BetaAnalyticsDataClient
from google.analytics.data_v1beta.services.beta_analytics_data.transports.rest import (
    BetaAnalyticsDataRestTransport,
)
from google.auth.exceptions import RefreshError
from google.api_core.exceptions import Unauthenticated
from google.auth.transport.requests import _Response
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import HttpRequest
from googleapiclient.errors import HttpError

from .models import (
    ACCOUNT_IDS, GOOGLE_SCOPES, TOKEN_URI, GoogleAccountError, GoogleRequestDeadline,
    GoogleSdkClients, GoogleAccountId, GoogleCredentialGeneration, validate_google_wire,
)
from .protocols import IGoogleCredentialLoader, GoogleSdkOperation, T


def _failure(code="agency_discovery_incomplete", state="provider_unavailable"):
    error = GoogleAccountError(code)
    error.account_state = state
    return error


def _cleanup(actions, primary=None):
    """Attempt every action; preserve primary or first cleanup control."""
    failure = None
    for action in actions:
        try:
            action()
        except BaseException as error:
            if failure is None or (isinstance(failure, Exception)
                                   and not isinstance(error, Exception)):
                failure = error
    if primary is not None and not isinstance(primary, Exception):
        return
    if failure is not None and not isinstance(failure, Exception):
        raise failure
    if primary is None and failure is not None:
        error = _failure()
        try:
            raise error from None
        except Exception:
            error.__context__ = error.__cause__ = None
            raise


def _safe_boundary(function):
    """Remove raw chains even when invoked inside a caller exception handler."""
    @wraps(function)
    def invoke(*args, **kwargs):
        failure = None
        try:
            return function(*args, **kwargs)
        except GoogleAccountError as error:
            failure = _failure(error.code, getattr(error, "account_state", "provider_unavailable"))
        except Exception:
            failure = _failure()
        try:
            raise failure from None
        except GoogleAccountError:
            failure.__context__ = failure.__cause__ = None
            raise
    return invoke


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _failure()
        result[key] = value
    return result


def _no_constant(value):
    raise _failure()


def _private(value, credentials):
    """Reject credential reflection before SDK parsing or callback egress."""
    if credentials is None:
        return
    if type(value) is not str:
        if type(value) is dict:
            for key, item in value.items():
                _private(key, credentials)
                _private(item, credentials)
        elif type(value) is list:
            for item in value:
                _private(item, credentials)
        return
    text = value
    secrets = (credentials.client_secret, credentials.refresh_token, getattr(credentials, "token", None))
    variants = []
    for secret in secrets:
        if hasattr(secret, "get_secret_value"):
            secret = secret.get_secret_value()
        if secret:
            raw = secret.encode()
            variants.extend((secret, raw.hex(), raw.hex().upper(),
                             base64.b64encode(raw).decode().rstrip('='),
                             base64.urlsafe_b64encode(raw).decode().rstrip('=')))
    def decoded_forms(text):
        for _ in range(8):
            if any(secret in text for secret in variants):
                raise _failure()
            yield text
            decoded = html.unescape(unquote(text))
            decoded = re.sub(
                r"\\u([dD][89aAbB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})",
                lambda m: chr(0x10000 + ((int(m[1], 16) - 0xD800) << 10)
                              + int(m[2], 16) - 0xDC00) if m[1]
                else chr(int(m[3] or m[4], 16)), decoded,
            )
            if decoded == text:
                return
            text = decoded
        raise _failure()

    # A finite frontier belongs to each lexical origin, not to unrelated fields
    # in a large JSON document. Check whole-value legacy forms before splitting.
    if len(text) > 2097152:
        raise _failure()
    token_pattern = re.compile(r"[A-Za-z0-9+/_-]{4,}={0,2}")
    for form in decoded_forms(text):
        for match in token_pattern.finditer(form):
            origin = match[0]
            scale = max(64, len(origin))
            pending, admitted = [(origin, 0)], {origin}
            retained, work = len(origin), 128 * scale
            while pending:
                candidate, depth = pending.pop()
                for decoded in decoded_forms(candidate):
                    work -= len(decoded)
                    if work < 0:
                        raise _failure()
                    for token_match in token_pattern.finditer(decoded):
                        token = token_match[0]
                        candidates = []
                        # Hex runs have their own alphabet and both nibble
                        # alignments; URL/path framing cannot swallow the run.
                        for run_match in re.finditer(r"[0-9a-fA-F]{4,}", token):
                            run = run_match[0]
                            for offset in range(2):
                                part = run[offset:]
                                part = part[:len(part) - len(part) % 2]
                                if part:
                                    candidates.append(bytes.fromhex(part))
                        for offset in range(min(4, len(token))):
                            part = token[offset:]
                            try:
                                candidates.append(base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True))
                            except (ValueError, binascii.Error):
                                pass
                        for raw in candidates:
                            nested = raw.decode('utf-8', errors='replace')
                            if nested and nested != decoded and nested not in admitted:
                                if depth >= 8 or len(admitted) >= 128 or retained + len(nested) > 16 * scale:
                                    raise _failure()
                                admitted.add(nested)
                                retained += len(nested)
                                pending.append((nested, depth + 1))


def _allowed(method: str, url: str) -> bool:
    target = urlsplit(url)
    if target.scheme != "https" or target.username or target.password or target.fragment:
        return False
    host, path = target.netloc, target.path
    if host == "oauth2.googleapis.com":
        return method == "POST" and url == TOKEN_URI
    if host == "www.googleapis.com":
        return (
            method == "GET" and bool(re.fullmatch(r"/webmasters/v3/sites(?:/[^/]+(?:/sitemaps(?:/[^/]+)?)?)?", path))
            or method == "POST" and bool(re.fullmatch(r"/webmasters/v3/sites/[^/]+/searchAnalytics/query", path))
            or method == "POST" and path == "/webmasters/v3/urlInspection/index:inspect"
        )
    if host == "searchconsole.googleapis.com":
        return method == "POST" and path == "/v1/urlInspection/index:inspect"
    if host == "analyticsadmin.googleapis.com":
        return method == "GET" and bool(re.fullmatch(r"/v1beta/(accountSummaries|properties/[0-9]+)", path))
    if host == "analyticsdata.googleapis.com":
        return (
            method == "GET" and bool(re.fullmatch(r"/v1beta/properties/[0-9]+/metadata", path))
            or method == "POST" and bool(re.fullmatch(r"/v1beta/properties/[0-9]+:(runReport|runRealtimeReport)", path))
        )
    return False


class _Adapter(requests.adapters.HTTPAdapter):
    """Per-bundle urllib3 classes: gate again AFTER DNS/TLS connection entry.

    Never patch process-global transports. A caller timeout retains this worker's
    identity lock; cancellation prevents headers/body transmission after a late
    connection succeeds. Already initiated blocking I/O cannot be forcibly killed.
    """
    def __init__(self, gate):
        class Connection(HTTPSConnection):
            def connect(self):
                self.timeout = gate()
                super().connect()
                try:
                    gate()
                except BaseException as error:
                    _cleanup([self.close], error)
                    raise

            def request(self, *args, **kwargs):
                self.timeout = gate()
                return super().request(*args, **kwargs)

            def send(self, data):
                gate()
                return super().send(data)

        class Pool(HTTPSConnectionPool):
            ConnectionCls = Connection

        self._pool_class = Pool
        super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1, pool_block=False)

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"https": self._pool_class}


def _token_response(value):
    """Literal token-endpoint contract; validate before SDK state mutation."""
    import math
    if type(value) is not dict or not set(value) <= {
        'access_token', 'token_type', 'expires_in', 'scope', 'refresh_token'
    }:
        raise _failure()
    expiry = value.get('expires_in')
    # Compare arbitrary-precision ints directly; isfinite(int) can overflow.
    number = (type(expiry) is int and 1 <= expiry <= 86400) or (
        type(expiry) is float and math.isfinite(expiry)
        and expiry.is_integer() and 1 <= expiry <= 86400
    )
    if (type(value.get('access_token')) is not str
            or not 1 <= len(value['access_token']) <= 16384
            or not value['access_token'].isprintable()
            or type(value.get('token_type')) is not str
            or value['token_type'].lower() != 'bearer' or not number):
        raise _failure()
    if 'scope' in value:
        scope = value['scope']
        if (type(scope) is not str or not scope.isprintable()
                or len(scope.split(' ')) != len(GOOGLE_SCOPES)
                or frozenset(scope.split(' ')) != GOOGLE_SCOPES):
            raise _failure()
    if 'refresh_token' in value and (type(value['refresh_token']) is not str
                                    or not 1 <= len(value['refresh_token']) <= 16384
                                    or not value['refresh_token'].isprintable()):
        raise _failure()
    return value


class _Session(requests.Session):
    """No ambient proxies, netrc, redirects, retries or unbounded response bodies."""

    def __init__(self, gate: Callable[[], float], credentials=None, protect=None):
        super().__init__()
        self.trust_env = False
        self._gate, self._credentials = gate, credentials
        self._protect = protect or (lambda value: _private(value, credentials))
        self._refresh_sent = False
        self.adapters.clear()
        self.mount("https://", _Adapter(gate))

    def request(self, method, url, **kwargs):
        kwargs.update(timeout=self._gate(), allow_redirects=False)
        return super().request(method, url, **kwargs)

    def __exit__(self, typ, value, tb):
        _cleanup([self.close], value)
        return False

    def send(self, request, **kwargs):
        timeout = self._gate()
        if not _allowed(request.method, request.url):
            raise _failure()
        if request.url == TOKEN_URI:
            if self._refresh_sent:
                raise _failure()
            self._refresh_sent = True
        elif self._credentials is not None:
            self._credentials.apply(request.headers)
        timeout = self._gate()
        kwargs.update(timeout=timeout, allow_redirects=False, stream=True, proxies={})
        response = super().send(request, **kwargs)
        primary = None
        try:
            self._gate()
            if 300 <= response.status_code < 400:
                raise _failure()
            chunks, size = [], 0
            for chunk in response.iter_content(65536):
                self._gate()
                size += len(chunk)
                if size > 2097152:
                    raise _failure()
                chunks.append(chunk)
            response._content = b"".join(chunks)
            response._content_consumed = True
            text = response.content.decode("utf-8", errors="strict")
            # Reject invalid raw JSON before lossy SDK protobuf deserialization.
            wire = validate_google_wire(json.loads(text, object_pairs_hook=_unique, parse_constant=_no_constant))
            if request.url == TOKEN_URI and response.status_code == 200:
                _token_response(wire)
            if request.url == TOKEN_URI and response.status_code != 200:
                self._protect(text)
                self._protect(wire)
                if response.status_code in {400, 401, 403} and type(wire) is dict and wire.get("error") not in {"temporarily_unavailable", "server_error"}:
                    raise RefreshError("reauthorization_required")
                raise _failure()
            if request.url != TOKEN_URI:
                if response.status_code == 403:
                    # Classify at our private transport boundary, before the SDK
                    # can construct a raw LogRecord from provider error reasons.
                    logging.getLogger(__name__).warning('Google provider 403 denied; private response classified')
                self._protect(text)
                self._protect(wire)
                self._protect(dict(response.headers))
                if response.status_code == 403:
                    # Keep status/single-attempt SDK refusal semantics, but never
                    # hand arbitrary provider reason/message fields to its logger.
                    response._content = b'{"error":{"code":403,"message":"provider denied","errors":[{"reason":"forbidden"}]}}'
                if urlsplit(request.url).path == "/v1beta/accountSummaries" and response.status_code == 200:
                    from .discovery import _raw_ga4
                    _raw_ga4(wire)
            self._gate()
            return response
        except BaseException as error:
            primary = error
            raise
        finally:
            _cleanup([response.close], primary)


class _Http:
    """google-api-python-client HTTP protocol over the same guarded session."""

    def __init__(self, session):
        self._session = session

    def request(self, uri, method="GET", body=None, headers=None, **kwargs):
        response = self._session.request(method, uri, data=body, headers=headers)
        headers = dict(response.headers)
        headers["status"] = str(response.status_code)
        return httplib2.Response(headers), response.content


class _ReadRequest(HttpRequest):
    def execute(self, http=None, num_retries=0):
        return super().execute(http=http, num_retries=0)


class _Gsc:
    def __init__(self, webmasters, inspection):
        self._webmasters, self._inspection = webmasters, inspection

    def sites(self):
        return self._webmasters.sites()

    def searchanalytics(self):
        return self._webmasters.searchanalytics()

    def sitemaps(self):
        return self._webmasters.sitemaps()

    def urlInspection(self):
        return self._inspection.urlInspection()


class _Ga4:
    """Restrict SDK methods and explicitly disable GAPIC retry defaults."""

    def __init__(self, client, gate, methods):
        self._client, self._gate, self._methods = client, gate, methods

    def __getattr__(self, name):
        if name not in self._methods:
            raise _failure()
        method = getattr(self._client, name)

        def invoke(*args, **kwargs):
            kwargs.update(retry=None, timeout=self._gate())
            result = method(*args, **kwargs)
            self._gate()
            return result
        return invoke


class _Bundle:
    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        # Allocated before any fallible constructor. The worker retains this
        # outer handle even if __init__ never returns.
        instance._sessions = []
        instance.retired = False
        return instance

    def own(self, session):
        self._sessions.append(session)
        return session

    def close(self, sessions=None):
        control, failed = None, False
        for session in tuple(self._sessions if sessions is None else sessions):
            # Claim the attempt before calling foreign code; never double-close
            # on unwinding, and attempt every resource even after control faults.
            self._sessions.remove(session)
            try:
                session.close()
            except Exception:
                failed = True
            except BaseException as error:
                if control is None:
                    control = error
        if control is not None:
            raise control
        if failed:
            raise _failure()

    def __init__(self, credential, generation, owner):
        self.account_id, self.generation, self.owner = credential.account_id, generation, owner
        self.deadline = None
        self.thread = None
        self.cancel = None
        self.credentials = Credentials(
            token=None, refresh_token=credential.refresh_token.get_secret_value(),
            client_id=credential.client_id,
            client_secret=credential.client_secret.get_secret_value(), token_uri=TOKEN_URI,
            scopes=sorted(GOOGLE_SCOPES), enable_reauth_refresh=False,
        )
        self.session = self.own(_Session(self.gate, self.credentials, owner.protect))
        http = _Http(self.session)
        webmasters = build("webmasters", "v3", http=http, cache_discovery=False, static_discovery=True, requestBuilder=_ReadRequest)
        inspection = build("searchconsole", "v1", http=http, cache_discovery=False, static_discovery=True, requestBuilder=_ReadRequest)
        admin_transport = AnalyticsAdminServiceRestTransport(
            credentials=self.credentials, host="analyticsadmin.googleapis.com", scopes=sorted(GOOGLE_SCOPES)
        )
        admin_session = self.own(admin_transport._session)
        data_transport = BetaAnalyticsDataRestTransport(
            credentials=self.credentials, host="analyticsdata.googleapis.com", scopes=sorted(GOOGLE_SCOPES)
        )
        data_session = self.own(data_transport._session)
        # Explicit credentials preclude ADC. Retire BOTH unused SDK sessions
        # even if the first close raises; the primary stays owned by this bundle.
        self.close((admin_session, data_session))
        admin_transport._session = data_transport._session = self.session
        # REST RPC keys capture the session; rebuild their wrappers after the
        # private transport replacement (otherwise the SDK lookup raises KeyError).
        from google.api_core.gapic_v1.client_info import ClientInfo
        admin_transport._prep_wrapped_messages(ClientInfo())
        data_transport._prep_wrapped_messages(ClientInfo())
        self.sdk = GoogleSdkClients(
            account_id=self.account_id, generation=generation,
            gsc=_Gsc(webmasters, inspection),
            ga4_admin=_Ga4(AnalyticsAdminServiceClient(transport=admin_transport), self.gate,
                           {"list_account_summaries", "get_property"}),
            ga4_data=_Ga4(BetaAnalyticsDataClient(transport=data_transport), self.gate,
                          {"run_report", "run_realtime_report", "get_metadata"}),
        )

    def gate(self):
        if self.thread != threading.get_ident() or self.deadline is None:
            raise _failure()
        if self.cancel is not None and self.cancel.is_set():
            raise _failure("deadline_exceeded")
        self.owner.require_generation(self.generation)
        self.deadline.require_remaining()
        return min(15.0, self.deadline.remaining())

    def refresh(self):
        self.gate()
        if not self.credentials.valid:
            # A one-send session also prevents google-auth's token-endpoint
            # retry loop from issuing another credential-bearing request.
            with _Session(self.gate, protect=self.owner.protect) as session:
                # Stock google-auth Request debug-logs credential-bearing bodies.
                def token_request(url, method="GET", body=None, headers=None, **kwargs):
                    return _Response(session.request(method, url, data=body, headers=headers))
                self.credentials.refresh(token_request)
            self.gate()
            if self.credentials.granted_scopes is not None and frozenset(self.credentials.granted_scopes) != GOOGLE_SCOPES:
                raise _failure("credentials_invalid", "invalid")


class GoogleAccountClients:
    """Fixed generation, explicit account selection; no ambient identity state.

    Public operations return validated JSON only. SDK objects remain private.
    A credential epoch change poisons this registry; replacement is explicit.
    """

    def __init__(self, loader: IGoogleCredentialLoader):
        self._loader = loader
        self._locks = {account: threading.Lock() for account in ACCOUNT_IDS}
        self._state_lock = threading.RLock()
        self._bundles = {}
        self._generation = None
        self._invalid = False

    def __repr__(self):
        return "<GoogleAccountClients private>"

    def scan_credentials(self):
        """Load the current pair and snapshot retained tokens for egress scanning.

        Loading failure remains a failure; no cached substitute is admitted.
        Returned objects are private, request-local scanner inputs only.
        """
        credentials = tuple(self._loader.load_accounts())
        with self._state_lock:
            return credentials + tuple(bundle.credentials for bundle in self._bundles.values())

    def protect(self, value):
        for credential in self._loader.load_accounts():
            _private(value, credential)
        with self._state_lock:
            credentials = tuple(bundle.credentials for bundle in self._bundles.values())
        for credential in credentials:
            _private(value, credential)

    @_safe_boundary
    def generation(self) -> GoogleCredentialGeneration:
        failure = None
        current = None
        primary_control = None
        try:
            current = self._loader.generation()
        except GoogleAccountError as error:
            failure = error.code
        except Exception:
            failure = "credentials_invalid"
        except BaseException as control:
            primary_control = control
            failure = "credentials_invalid"
        idle = []
        with self._state_lock:
            if failure or self._invalid or (self._generation is not None and current != self._generation):
                # Poison ALL admissions before releasing any ownership. The
                # account slot, not thread liveness, defines safe idle retirement.
                self._invalid = True
                failure = failure or "credentials_changed"
                for account, bundle in tuple(self._bundles.items()):
                    bundle.retired = True
                    if bundle.cancel is not None:
                        bundle.cancel.set()
                    lock = self._locks[account]
                    if lock.acquire(blocking=False):
                        self._bundles.pop(account)
                        idle.append((bundle, lock))
                    # Active bundles stay discoverable by their owning worker,
                    # including the gap between slot acquisition and bundle use.
            else:
                self._generation = current
        cleanup_control = None
        for bundle, lock in idle:
            try:
                bundle.close()
            except Exception:
                failure = failure or "credentials_invalid"
            except BaseException as control:
                if cleanup_control is None:
                    cleanup_control = control
            finally:
                try:
                    lock.release()
                except Exception:
                    failure = failure or "credentials_invalid"
                except BaseException as control:
                    if cleanup_control is None:
                        cleanup_control = control
        if primary_control is not None:
            raise primary_control
        if cleanup_control is not None:
            raise cleanup_control
        if failure:
            raise _failure(failure, "missing" if failure == "credentials_missing" else "invalid")
        return current

    @_safe_boundary
    def require_generation(self, expected: GoogleCredentialGeneration) -> None:
        if self.generation() != expected:
            raise _failure("credentials_changed", "invalid")

    @_safe_boundary
    def execute(self, account_id: GoogleAccountId, operation: GoogleSdkOperation[T], deadline: GoogleRequestDeadline) -> T:
        if account_id not in ACCOUNT_IDS or not isinstance(deadline, GoogleRequestDeadline):
            raise _failure("credentials_invalid", "invalid")
        deadline.require_remaining()
        if deadline.remaining() > 60.0:
            raise _failure("deadline_exceeded")
        generation = self.generation()
        lock = self._locks[account_id]
        # Allocate transfer/cancellation infrastructure before acquiring a slot;
        # its own constructor faults therefore cannot orphan account ownership.
        transfer = threading.Lock()
        state = ['caller']
        cancel, outcome = threading.Event(), []
        if not lock.acquire(timeout=deadline.remaining()):
            raise _failure("deadline_exceeded")
        # Explicit transfer: a late worker must claim under this mutex before
        # doing anything. Revocation before claim makes even a delayed native
        # launch inert. After claim ONLY the worker can release the account slot.
        def run():
            with transfer:
                if state[0] != 'caller':
                    return
                state[0] = 'worker'
            try:
                if cancel.is_set():
                    raise _failure('deadline_exceeded')
                outcome.append((True, self._execute_locked(account_id, operation, deadline, generation, cancel)))
            except BaseException as error:
                outcome.append((False, error))
            finally:
                try:
                    self._release_slot(account_id)
                except BaseException as error:
                    primary = outcome[0][1] if outcome and not outcome[0][0] else None
                    if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):
                        outcome[:] = [(False, _failure() if isinstance(error, Exception) else error)]
        try:
            worker = threading.Thread(target=run, name="google-account-operation", daemon=True)
            worker.start()
            worker.join(deadline.remaining())
            if worker.is_alive():
                raise _failure("deadline_exceeded")
            succeeded, value = outcome[0]
            if not succeeded and isinstance(value, BaseException) and not isinstance(value, Exception):
                raise value
            if cancel.is_set() or not deadline.remaining():
                raise _failure("deadline_exceeded")
            if not succeeded:
                raise value
            return value
        except BaseException as primary:
            cancel.set()
            local = False
            with transfer:
                if state[0] == 'caller':
                    state[0] = 'revoked'
                    local = True
            if local:
                try:
                    self._release_slot(account_id)
                except BaseException as error:
                    if isinstance(primary, Exception) and not isinstance(error, Exception):
                        raise
            raise

    def _release_slot(self, account_id):
        # Serialize idle handoff with invalidation for BOTH releasers: a
        # constructor/preclaim failure can coincide with an epoch change too.
        with self._state_lock:
            primary = None
            try:
                bundle = self._bundles.get(account_id)
                if bundle is not None and bundle.retired:
                    self._bundles.pop(account_id)
                    bundle.close()
            except BaseException as error:
                primary = error
                raise
            finally:
                _cleanup([self._locks[account_id].release], primary)

    def _execute_locked(self, account_id, operation, deadline, generation, cancel):
        # Ownership transfers to this worker; timeout never releases its slot.
        lock = self._locks[account_id]
        bundle = None
        completed = False
        primary_control = None
        result, failure = None, None
        try:
            deadline.require_remaining()
            self.require_generation(generation)
            with self._state_lock:
                bundle = self._bundles.get(account_id)
            if bundle is None:
                accounts = self._loader.load_accounts()
                if tuple(c.account_id for c in accounts) != ACCOUNT_IDS:
                    raise _failure("credentials_invalid", "invalid")
                bundle = _Bundle.__new__(_Bundle)
                _Bundle.__init__(bundle, accounts[ACCOUNT_IDS.index(account_id)], generation, self)
                self.require_generation(generation)
                deadline.require_remaining()
                with self._state_lock:
                    if self._invalid:
                        raise _failure("credentials_changed", "invalid")
                    self._bundles[account_id] = bundle
            bundle.deadline, bundle.thread = deadline, threading.get_ident()
            bundle.cancel = cancel
            bundle.refresh()
            bundle.gate()
            result = validate_google_wire(operation(bundle.sdk))
            self.protect(result)
            bundle.gate()
            completed = True
        except GoogleAccountError as error:
            failure = _failure(error.code, getattr(error, "account_state", "provider_unavailable"))
        except RefreshError:
            failure = _failure(state="reauthorization_required")
        except Unauthenticated:
            failure = _failure(state="reauthorization_required")
        except HttpError as error:
            failure = _failure(state="reauthorization_required" if error.resp.status == 401 else "provider_unavailable")
        except Exception:
            failure = _failure()
        except BaseException as control:
            primary_control = control
            raise
        finally:
            if bundle is not None:
                bundle.deadline = bundle.thread = None
                bundle.cancel = None
            cleanup_control = None
            if not completed or (bundle is not None and bundle.retired):
                with self._state_lock:
                    self._bundles.pop(account_id, None)
                if bundle is not None:
                    try:
                        bundle.close()
                    except Exception:
                        failure = failure or _failure()
                    except BaseException as control:
                        cleanup_control = control
            if primary_control is None and cleanup_control is not None:
                raise cleanup_control
        if failure is not None:
            raise failure from None
        return result
