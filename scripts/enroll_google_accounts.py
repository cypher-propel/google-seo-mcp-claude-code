#!/usr/bin/env python3
"""Operator-only Desktop OAuth enrollment; never an MCP/server endpoint.

UNACCEPTED BUILDER CANDIDATE. Windows is fail-closed pending a reviewed native
ACL/reparse-point custody implementation. No platform emulation establishes
Windows qualification. Consent additionally requires human app/custody approval.
Only the operator may read/import the explicitly retained restricted files.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import json
import logging
import math
import os
from pathlib import Path
import secrets
import socket
import stat
import sys
import threading
import time
from urllib.parse import parse_qsl, urlsplit
import warnings

SCOPES = ('https://www.googleapis.com/auth/webmasters.readonly',
          'https://www.googleapis.com/auth/analytics.readonly')
TOKEN_URI = 'https://oauth2.googleapis.com/token'
AUTH_URIS = frozenset(('https://accounts.google.com/o/oauth2/auth',
                       'https://accounts.google.com/o/oauth2/v2/auth'))
LABELS = {'propel-dms': 'propel.dms@gmail.com', 'addourteam99': 'addourteam99@gmail.com'}
LIMIT = 131072
TOKEN_EXCHANGE_TIMEOUT = 60.0
_PRIVATE_LOCK = threading.RLock()


class Refused(Exception):
    """Static public refusal; never carries provider data."""
    def __init__(self):
        super().__init__('ENROLLMENT_REFUSED')


def require(value):
    if not value:
        raise Refused()


def _cleanup(actions, primary=None, refusal=Refused):
    """Attempt all actions; primary control, then first cleanup control wins."""
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
        if refusal is None:
            raise failure
        error = refusal()
        try:
            raise error from None
        except Exception:
            error.__context__ = error.__cause__ = None
            raise


def text(value, maximum=4096):
    return type(value) is str and 0 < len(value) <= maximum and all(ord(c) >= 32 and ord(c) != 127 for c in value)


def unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out)
        out[key] = value
    return out


def json_document(raw):
    require(type(raw) is bytes and 0 < len(raw) <= LIMIT)
    def constant(_):
        raise Refused()
    result = None
    failed = False
    try:
        result = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=unique,
                            parse_constant=constant)
    except Exception:
        failed = True
    if failed:
        raise Refused()
    require(type(result) is dict)
    return result


def validate_client(raw, approved_client, approved_project):
    require(text(approved_client, 512) and approved_client.endswith('.apps.googleusercontent.com'))
    require(text(approved_project, 256))
    document = json_document(raw)
    require(set(document) == {'installed'} and type(document['installed']) is dict)
    client = document['installed']
    required = {'client_id', 'client_secret', 'project_id', 'auth_uri', 'token_uri'}
    require(required <= set(client) <= required | {'redirect_uris', 'auth_provider_x509_cert_url'})
    require(all(text(client[k]) for k in required))
    require(client['client_id'] == approved_client and client['project_id'] == approved_project)
    require(client['token_uri'] == TOKEN_URI and client['auth_uri'] in AUTH_URIS)
    if 'auth_provider_x509_cert_url' in client:
        require(client['auth_provider_x509_cert_url'] == 'https://www.googleapis.com/oauth2/v1/certs')
    if 'redirect_uris' in client:
        uris = client['redirect_uris']
        require(type(uris) is list and 0 < len(uris) <= 16)
        require(all(type(u) is str and u in ('http://localhost', 'http://127.0.0.1') for u in uris))
        require(len(set(uris)) == len(uris))
    return {'installed': dict(client)}


def validate_token(token):
    require(type(token) is dict)
    scope = token.get('scope')
    require(type(scope) in (str, list))
    if type(scope) is str:
        require(text(scope, 1024))
        grants = scope.split(' ')
    else:
        require(len(scope) == 2 and all(text(item, 256) for item in scope))
        grants = scope
    require(len(grants) == 2 and len(set(grants)) == 2 and set(grants) == set(SCOPES))
    require(text(token.get('refresh_token'), 16384))
    return token['refresh_token']


def attest(slot, reader=input):
    require(slot in LABELS)
    answer = reader('After checking the account chooser and consent screen, type: I checked '
                    + LABELS[slot] + ' for ' + slot + '\n')
    require(answer == 'I checked ' + LABELS[slot] + ' for ' + slot)


def distinct(first, second):
    require(text(first, 16384) and text(second, 16384))
    require(not hmac.compare_digest(first.encode(), second.encode()))


_enrollment_diagnostic_lock = __import__('threading').RLock()
# The first guard exit that finds a tracked exchange worker alive sets the
# shared once-deferred latch. Thereafter every guard retains its restorers and
# resources until process exit, even after that worker finishes. If no exit
# finds a live worker, the latch stays unset and restoration is unchanged.
_enrollment_exchange_workers = set()
_enrollment_deferred_guards = []
_enrollment_guard_deferred = False


def _enrollment_worker_alive():
    return any(worker.is_alive() for worker in _enrollment_exchange_workers)


def _enrollment_defer_guard_restoration():
    global _enrollment_guard_deferred
    if not _enrollment_guard_deferred and _enrollment_worker_alive():
        _enrollment_guard_deferred = True
    return _enrollment_guard_deferred


@contextlib.contextmanager
def _enrollment_private_redirects(stdout, stderr):
    guards = []
    primary = None
    try:
        for guard in (contextlib.redirect_stdout(stdout),
                      contextlib.redirect_stderr(stderr)):
            guard.__enter__()
            guards.append(guard)
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        if _enrollment_defer_guard_restoration():
            _enrollment_deferred_guards.append(guards)
        else:
            _cleanup([lambda guard=guard: guard.__exit__(None, None, None)
                      for guard in reversed(guards)], primary)


@contextlib.contextmanager
def private_output():
    # The helper is an operator process: diagnostics are globally private while
    # dependency code or an opener can observe enrollment material. In particular
    # do not forward original LogRecord objects or WarningMessage metadata.
    import contextlib as _ctx
    import logging as _log
    import warnings as _warn
    import os as _os
    import threading as _thread
    global _enrollment_diagnostic_lock
    try:
        lock = _enrollment_diagnostic_lock
    except NameError:
        lock = _enrollment_diagnostic_lock = _thread.RLock()
    lock.acquire()
    restorers = []
    primary = None
    try:
        factory = _log.getLogRecordFactory()
        make_record = _log.Logger.makeRecord
        handle = _log.Logger.handle
        warn = _warn.warn
        warn_explicit = _warn.warn_explicit
        showwarning = _warn.showwarning
        def safe_factory(*args, **kwargs):
            return _log.LogRecord('enrollment', _log.WARNING,
                                  '<enrollment>', 1,
                                  'Enrollment diagnostic suppressed.', (), None)
        def safe_record(*args, **kwargs):
            return safe_factory()
        def private_handle(*args, **kwargs):
            return None
        def private_warning(*args, **kwargs):
            return warn_explicit('Enrollment diagnostic suppressed.',
                                 RuntimeWarning, '<enrollment>', 1)
        def private_showwarning(*args, **kwargs):
            return None
        _log.setLogRecordFactory(safe_factory)
        restorers.append(lambda: _log.setLogRecordFactory(factory))
        _log.Logger.makeRecord = safe_record
        restorers.append(lambda: setattr(_log.Logger, 'makeRecord', make_record))
        _log.Logger.handle = private_handle
        restorers.append(lambda: setattr(_log.Logger, 'handle', handle))
        _warn.warn = private_warning
        restorers.append(lambda: setattr(_warn, 'warn', warn))
        _warn.warn_explicit = private_warning
        restorers.append(lambda: setattr(_warn, 'warn_explicit', warn_explicit))
        _warn.showwarning = private_showwarning
        restorers.append(lambda: setattr(_warn, 'showwarning', showwarning))
        # OS-level stdout/stderr redirection also covers browser child processes
        # that inherit standard descriptors. Saved originals are non-inheritable.
        null_fd = _os.open(_os.devnull, _os.O_RDWR)
        restorers.append(lambda fd=null_fd: _os.close(fd))
        for fd in (1, 2):
            inheritable = _os.get_inheritable(fd)
            saved = _os.dup(fd)
            restorers.append(lambda saved=saved: _os.close(saved))
            _os.set_inheritable(saved, False)
            restorers.append(lambda fd=fd, saved=saved, inheritable=inheritable: _os.dup2(saved, fd, inheritable=inheritable))
            _os.dup2(null_fd, fd, inheritable=False)
        sink = open(_os.devnull, 'w', encoding='utf-8')
        restorers.append(sink.close)
        with _enrollment_private_redirects(sink, sink):
            yield
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_control = None
        cleanup_failure = False
        deferred = _enrollment_defer_guard_restoration()
        if deferred:
            _enrollment_deferred_guards.append(restorers)
        for restore in reversed(() if deferred else restorers):
            try:
                restore()
            except Exception:
                cleanup_failure = True
            except BaseException as control:
                if cleanup_control is None:
                    cleanup_control = control
        try:
            lock.release()
        except Exception:
            cleanup_failure = True
        except BaseException as control:
            if cleanup_control is None:
                cleanup_control = control
        if primary is None or isinstance(primary, Exception):
            if cleanup_control is not None:
                raise cleanup_control
            if primary is None and cleanup_failure:
                error = RuntimeError('ENROLLMENT_DIAGNOSTIC_CLEANUP_REFUSED')
                error.__context__ = None
                raise error from None



def _bounded_number(value, maximum, integral=False):
    # Never convert arbitrary-precision ints to float, even for finiteness.
    if type(value) is int:
        return 0 < value <= maximum
    return (type(value) is float and math.isfinite(value)
            and (not integral or value.is_integer()) and 0 < value <= maximum)


def _validate_token_response_shape(value):
    """Literal seq259 token endpoint contract, before OAuthlib coercion."""
    require(type(value) is dict and set(value) <= {
        'access_token', 'token_type', 'expires_in', 'scope', 'refresh_token'
    })
    require(type(value.get('access_token')) is str
            and 1 <= len(value['access_token']) <= 16384
            and value['access_token'].isprintable())
    require(type(value.get('token_type')) is str and value['token_type'].lower() == 'bearer')
    require(_bounded_number(value.get('expires_in'), 86400, integral=True))
    if 'scope' in value:
        scope = value['scope']
        require(type(scope) is str and scope.isprintable()
                and len(scope.split(' ')) == len(SCOPES)
                and set(scope.split(' ')) == set(SCOPES))
    if 'refresh_token' in value:
        require(type(value['refresh_token']) is str
                and 1 <= len(value['refresh_token']) <= 16384
                and value['refresh_token'].isprintable())
    return value


def make_flow(config, redirect_uri, state):
    require(type(config) is dict and set(config) == {'installed'})
    require(text(state, 512))
    callback = urlsplit(redirect_uri)
    require(callback.scheme == 'http' and callback.hostname == '127.0.0.1'
            and callback.path == '/callback' and not callback.query and not callback.fragment
            and not callback.username and callback.port is not None)
    # Do not call run_local_server: its wsgiref logging and URL print behavior
    # are not suitable for private transaction material.
    from google_auth_oauthlib.flow import Flow
    from requests.adapters import HTTPAdapter
    flow = Flow.from_client_config(config, scopes=list(SCOPES), state=state,
                                  code_verifier=secrets.token_urlsafe(64),
                                  autogenerate_code_verifier=False)
    session = flow.oauth2session
    try:
        session.trust_env = False
        session.proxies.clear()
        session.auth = None
        session.mount('https://', HTTPAdapter(max_retries=0))
        send = session.send
        def pinned_send(request, **kwargs):
            end = time.monotonic() + TOKEN_EXCHANGE_TIMEOUT
            require(request.url == TOKEN_URI and request.method == 'POST')
            require(not kwargs.get('proxies'))
            remaining = end - time.monotonic()
            require(remaining > 0)
            kwargs.update(timeout=min(15, remaining), allow_redirects=False, stream=True, proxies={})
            cancelled = threading.Event()
            outcome = []
            transfer = threading.Lock()
            def gate():
                require(not cancelled.is_set() and time.monotonic() < end)
            def exchange_worker():
                response = None
                result = None
                failure = None
                try:
                    gate()
                    response = send(request, **kwargs)
                    gate()
                    require(response.status_code == 200)
                    body = bytearray()
                    for chunk in response.iter_content(1):
                        gate()
                        body.extend(chunk)
                        require(len(body) <= LIMIT)
                    gate()
                    wire = _validate_token_response_shape(json_document(bytes(body)))
                    # Enrollment needs explicit scope + offline refresh evidence;
                    # runtime refresh separately permits omitted/unchanged scope.
                    require(type(wire.get('scope')) is str)
                    validate_token(wire)
                    gate()
                    response._content = bytes(body)
                    response._content_consumed = True
                    result = response
                except BaseException as error:
                    failure = error
                finally:
                    if response is not None:
                        try:
                            response.close()
                        except BaseException as error:
                            if (failure is None or (isinstance(failure, Exception)
                                                    and not isinstance(error, Exception))):
                                failure = error
                with transfer:
                    if not cancelled.is_set():
                        outcome.append((failure is None, result if failure is None else failure))
            try:
                worker = threading.Thread(target=exchange_worker, daemon=True,
                                          name='enrollment-token-exchange')
                _enrollment_exchange_workers.add(worker)
                worker.start()
                worker.join(max(0, end - time.monotonic()))
                with transfer:
                    if (len(outcome) == 1 and not outcome[0][0]
                            and not isinstance(outcome[0][1], Exception)):
                        raise outcome[0][1]
                gate()
                require(not worker.is_alive())
                with transfer:
                    require(len(outcome) == 1)
                    ok, value = outcome.pop()
                if not ok:
                    raise value
                return value
            except BaseException:
                # Revocation and publication share a mutex: late results cannot be
                # published/admitted, including a worker that returns after join.
                with transfer:
                    cancelled.set()
                    outcome.clear()
                try:
                    session.close()
                except BaseException:
                    pass
                raise
        session.send = pinned_send
        flow.redirect_uri = redirect_uri
        # pinned_send now validates original bytes inside the hard wall-bound worker,
        # before OAuthlib can parse text or mutate session.token. No second unbounded
        # compliance-hook validation is necessary.
        return flow
    except BaseException as primary:
        # Ownership transfers only on successful return; no worker exists yet.
        _cleanup((session.close,), primary)
        raise


def authorization(flow, state, slot):
    require(slot in LABELS)
    return flow.authorization_url(state=state, access_type='offline',
                                  prompt='consent select_account',
                                  include_granted_scopes='false', login_hint=LABELS[slot])


def exchange(flow, code):
    require(text(code, 4096))
    result = flow.fetch_token(code=code, timeout=15, allow_redirects=False)
    return validate_token(dict(result))


class Callback:
    """Synchronous single-use callback. No owned background worker exists."""
    def __init__(self, lifetime=180):
        require(_bounded_number(lifetime, 300))
        self.lifetime = float(lifetime)
        self.sock = None
        self.used = False

    def __enter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.bind(('127.0.0.1', 0))
            self.sock.listen(1)
            self.port = self.sock.getsockname()[1]
            self.end = time.monotonic() + self.lifetime
            self.uri = 'http://127.0.0.1:' + str(self.port) + '/callback'
            return self
        except BaseException as error:
            _cleanup([self.sock.close], error)
            raise

    def __exit__(self, *args):
        if self.sock is not None:
            _cleanup([self.sock.close], args[1] if len(args) > 1 else None, refusal=None)

    def remaining(self):
        remaining = self.end - time.monotonic()
        require(remaining > 0)
        return remaining

    def wait(self, state):
        require(not self.used and text(state, 512))
        self.used = True
        connection = None
        failed = False
        primary = None
        code = None
        try:
            self.sock.settimeout(self.remaining())
            connection, address = self.sock.accept()
            require(address[0] == '127.0.0.1')
            data = bytearray()
            while b'\r\n\r\n' not in data:
                connection.settimeout(min(1, self.remaining()))
                part = connection.recv(1024)
                require(bool(part))
                data.extend(part)
                require(len(data) <= 8192)
            head, body = bytes(data).split(b'\r\n\r\n', 1)
            require(not body)
            lines = head.decode('ascii', 'strict').split('\r\n')
            method, target, protocol = lines[0].split(' ')
            require(method == 'GET' and protocol == 'HTTP/1.1')
            headers = {}
            require(len(lines) <= 32)
            for line in lines[1:]:
                key, value = line.split(':', 1)
                require(key == key.strip() and key and key.lower() not in headers)
                headers[key.lower()] = value.strip()
            require(headers.get('host') == '127.0.0.1:' + str(self.port))
            require('transfer-encoding' not in headers and 'content-length' not in headers)
            require(target.startswith('/callback?') and len(target) <= 6144)
            parsed = urlsplit(target)
            require(parsed.path == '/callback' and not parsed.scheme and not parsed.netloc and not parsed.fragment)
            pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True,
                              encoding='utf-8', errors='strict', max_num_fields=8)
            query = unique(pairs)
            require({'code', 'state'} <= set(query) <= {'code', 'state', 'scope', 'authuser', 'prompt'})
            require(text(query['state'], 512) and hmac.compare_digest(query['state'].encode(), state.encode()))
            require(text(query['code'], 4096))
            if 'scope' in query:
                validate_token({'scope': query['scope'], 'refresh_token': 'synthetic-validation-only'})
            self.remaining()
            code = query['code']
            connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 25\r\nConnection: close\r\nCache-Control: no-store\r\n\r\nReturn to operator helper.')
        except Exception as error:
            primary = error
            failed = True
        except BaseException as error:
            primary = error
            raise
        finally:
            actions = []
            if failed and connection is not None:
                actions.append(lambda: connection.sendall(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'))
            if connection is not None:
                actions.append(connection.close)
            actions.append(self.sock.close)
            _cleanup(actions, primary)
        if failed:
            raise Refused()
        return code


# Payload inserted into the single owned helper; never imported as dependency.
# Payload inserted into the single owned helper; never imported as dependency.
def _windows_cleanup(actions, primary=None):
    """Attempt every close; request control, then first cleanup control wins."""
    failure = None
    for action in actions:
        try:
            action()
        except BaseException as error:
            if failure is None or (isinstance(failure, Exception) and (not isinstance(error, Exception))):
                failure = error
    if failure is None or (primary is not None and (not isinstance(primary, Exception))):
        return
    if not isinstance(failure, Exception):
        raise failure
    if primary is None:
        raise OSError('WINDOWS_CUSTODY_REFUSED') from None

class _WindowsAPI:
    """Lazy fixed-width Win32 ABI. Inject only DLL calls in synthetic tests.

    No POSIX custody substitute is used on Windows. ACL and identity failures
    are refusals, including unsupported filesystems and unprovable ownership.
    """
    def __init__(self, kernel=None, advapi=None):
        import ctypes as c
        self.c = c
        if kernel is None or advapi is None:
            kernel = c.WinDLL('kernel32', use_last_error=True)
            advapi = c.WinDLL('advapi32', use_last_error=True)
        self.k, self.a = (kernel, advapi)
        U, H, P = (c.c_uint32, c.c_void_p, c.c_void_p)
    
        class FT(c.Structure):
            _fields_ = [('low', U), ('high', U)]
    
        class Info(c.Structure):
            _fields_ = [('dwFileAttributes', U), ('creation', FT), ('access', FT), ('write', FT), ('dwVolumeSerialNumber', U), ('nFileSizeHigh', U), ('nFileSizeLow', U), ('nNumberOfLinks', U), ('nFileIndexHigh', U), ('nFileIndexLow', U)]
    
        class SA(c.Structure):
            _fields_ = [('nLength', U), ('lpSecurityDescriptor', P), ('bInheritHandle', c.c_int32)]
        self.BY_HANDLE_FILE_INFORMATION, self.SA = (Info, SA)
        signatures = [(kernel, 'GetCurrentProcess', H, []), (kernel, 'CloseHandle', c.c_int32, [H]), (kernel, 'LocalFree', H, [P]), (kernel, 'CreateFileW', H, [c.c_wchar_p, U, U, P, U, U, H]), (kernel, 'GetFileInformationByHandle', c.c_int32, [H, P]), (kernel, 'ReadFile', c.c_int32, [H, P, U, P, P]), (kernel, 'WriteFile', c.c_int32, [H, P, U, P, P]), (kernel, 'FlushFileBuffers', c.c_int32, [H]), (kernel, 'SetFileInformationByHandle', c.c_int32, [H, c.c_int32, P, U]), (advapi, 'OpenProcessToken', c.c_int32, [H, U, P]), (advapi, 'GetTokenInformation', c.c_int32, [H, c.c_int32, P, U, P]), (advapi, 'IsValidSid', c.c_int32, [P]), (advapi, 'GetLengthSid', U, [P]), (advapi, 'EqualSid', c.c_int32, [P, P]), (advapi, 'GetSecurityInfo', U, [H, c.c_int32, U, P, P, P, P, P]), (advapi, 'GetSecurityDescriptorControl', c.c_int32, [P, P, P]), (advapi, 'GetAclInformation', c.c_int32, [P, P, U, c.c_int32]), (advapi, 'GetAce', c.c_int32, [P, U, P]), (advapi, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', c.c_int32, [c.c_wchar_p, U, P, P])]
        for dll, name, result, args in signatures:
            fn = getattr(dll, name)
            fn.restype, fn.argtypes = (result, args)
        token = H()
        self.require(self.a.OpenProcessToken(self.k.GetCurrentProcess(), 8, c.byref(token)))
        _primary = None
        try:
            needed = U()
            self.a.GetTokenInformation(token.value, 1, None, 0, c.byref(needed))
            self.require(0 < needed.value <= 65536)
            buf = c.create_string_buffer(needed.value)
            self.require(self.a.GetTokenInformation(token.value, 1, buf, len(buf), c.byref(needed)))
            sid = c.cast(buf, c.POINTER(P))[0]
            self.require(sid and self.a.IsValidSid(sid))
            length = self.a.GetLengthSid(sid)
            self.require(8 <= length <= 68)
            self.sid = c.create_string_buffer(c.string_at(sid, length))
        except BaseException as _error:
            _primary = _error
            raise
        finally:
            _windows_cleanup([lambda: self.close(token.value)], _primary)

    @staticmethod
    def require(ok):
        if not ok:
            raise OSError('WINDOWS_CUSTODY_REFUSED') from None

    def close(self, handle):
        self.require(self.k.CloseHandle(handle))

    def open(self, path, directory=False, create=False, observe=False):
        c = self.c
        descriptor, handle, primary = (c.c_void_p(), None, None)
        sa = None
        try:
            if create:
                raw = self.sid.raw
                self.require(raw[0] == 1 and 8 + 4 * raw[1] <= len(raw))
                authority = int.from_bytes(raw[2:8], 'big')
                sid = 'S-1-' + str(authority) + ''.join(('-' + str(int.from_bytes(raw[8 + i * 4:12 + i * 4], 'little')) for i in range(raw[1])))
                self.require(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW('O:' + sid + 'D:P(A;;FA;;;' + sid + ')', 1, c.byref(descriptor), None))
                sa = self.SA(c.sizeof(self.SA), descriptor.value, 0)
            access = 0 if observe else 3221422080 if create else 131200 if directory else 2147614720
            share = 7 if observe else 0 if create else 1
            handle = self.k.CreateFileW(str(path), access, share, c.byref(sa) if sa is not None else None, 1 if create else 3, 35651584, None)
            self.require(handle not in (None, 0, c.c_void_p(-1).value))
        except BaseException as error:
            primary = error
            raise
        finally:
            if descriptor.value:
                try:
                    self._free(descriptor.value)
                except BaseException as free_error:
    
                    def failed_free():
                        raise free_error
                    actions = [failed_free]
                    if handle not in (None, 0, c.c_void_p(-1).value):
                        if create:
                            actions.append(lambda: self.delete(handle))
                        actions.append(lambda: self.close(handle))
                    _windows_cleanup(actions, primary)
        return handle

    def security(self, handle):
        c = self.c
        owner, dacl, sd = (c.c_void_p(), c.c_void_p(), c.c_void_p())
        self.require(self.a.GetSecurityInfo(handle, 1, 5, c.byref(owner), None, c.byref(dacl), None, c.byref(sd)) == 0)
        _primary = None
        try:
            self.require(owner.value and self.a.IsValidSid(owner.value) and self.a.EqualSid(owner.value, self.sid))
            control, revision = (c.c_uint16(), c.c_uint32())
            self.require(sd.value and self.a.GetSecurityDescriptorControl(sd.value, c.byref(control), c.byref(revision)))
            self.require(control.value & 4096 and control.value & 4 and dacl.value)
            info = (c.c_uint32 * 3)()
            self.require(self.a.GetAclInformation(dacl.value, info, c.sizeof(info), 2))
            self.require(0 < info[0] <= 1024 and info[1] >= 8)
            for i in range(info[0]):
                ace = c.c_void_p()
                self.require(self.a.GetAce(dacl.value, i, c.byref(ace)) and ace.value)
                header = c.string_at(ace.value, 8)
                size = int.from_bytes(header[2:4], 'little')
                self.require(header[0] == 0 and header[1] == 0 and (16 <= size <= info[1]))
                sid = ace.value + 8
                self.require(self.a.IsValidSid(sid))
                length = self.a.GetLengthSid(sid)
                self.require(8 <= length <= 68 and size == 8 + length)
                self.require(self.a.EqualSid(sid, self.sid))
        except BaseException as _error:
            _primary = _error
            raise
        finally:
            _windows_cleanup([lambda: self._free(sd.value)] if sd.value else [], _primary)

    def info(self, handle, directory=False, secure=True):
        c = self.c
        x = self.BY_HANDLE_FILE_INFORMATION()
        self.require(self.k.GetFileInformationByHandle(handle, c.byref(x)))
        self.require(not (x.dwFileAttributes & 0x400))
        self.require(bool(x.dwFileAttributes & 0x10) == directory)
        if not directory:
            self.require(x.nNumberOfLinks == 1)
        self.require(bool(x.nFileIndexHigh or x.nFileIndexLow))
        if secure:
            self.security(handle)
        return (x.dwVolumeSerialNumber, x.nFileIndexHigh, x.nFileIndexLow,
                x.nNumberOfLinks, x.nFileSizeHigh, x.nFileSizeLow,
                x.write.high, x.write.low, x.dwFileAttributes)

    def observe(self, path, handle, directory=False, secure=True):
        before = self.info(handle, directory, secure)
        named = self.open(path, directory, observe=True)
        _primary = None
        try:
            self.require(self.info(named, directory, False) == before)
        except BaseException as _error:
            _primary = _error
            raise
        finally:
            _windows_cleanup([lambda: self.close(named)], _primary)
        self.require(self.info(handle, directory, secure) == before)
        return before

    def read(self, handle, bound):
        c = self.c
        self.require(type(bound) is int and 0 < bound <= 16777216)
        data = bytearray()
        while len(data) <= bound:
            size = min(65536, bound + 1 - len(data))
            buf, done = c.create_string_buffer(size), c.c_uint32()
            self.require(self.k.ReadFile(handle, buf, size, c.byref(done), None))
            self.require(done.value <= size)
            if not done.value:
                return bytes(data)
            data.extend(buf.raw[:done.value])
        self.require(False)

    def write(self, handle, data):
        c = self.c
        self.require(type(data) is bytes and len(data) <= 16777216)
        offset = 0
        while offset < len(data):
            part = data[offset:offset+65536]
            buf, done = c.create_string_buffer(part), c.c_uint32()
            self.require(self.k.WriteFile(handle, buf, len(part), c.byref(done), None))
            self.require(0 < done.value <= len(part))
            offset += done.value
        self.require(self.k.FlushFileBuffers(handle))

    def delete(self, handle):
        value = self.c.c_int32(1)
        self.require(self.k.SetFileInformationByHandle(handle, 4, self.c.byref(value), self.c.sizeof(value)))

    def _free(self, descriptor):
        self.require(not self.k.LocalFree(descriptor))


def _windows_path(path):
    import ntpath
    from pathlib import PureWindowsPath
    raw = str(path)
    p = PureWindowsPath(raw)
    # Local absolute drive paths only; no UNC/device namespace, ADS, traversal,
    # DOS aliases, or normalization-dependent trailing dots/spaces.
    _WindowsAPI.require(len(p.drive) == 2 and p.drive[1] == ':' and p.root == '\\' and not raw.startswith(('\\\\', '//')))
    _WindowsAPI.require(not any(x in raw for x in ('\x00', '/')))
    for part in raw[3:].split('\\'):
        _windows_leaf(part)
    return p


def _windows_leaf(name):
    import ntpath
    _WindowsAPI.require(type(name) is str and bool(name) and name not in ('.', '..'))
    _WindowsAPI.require(not any(x in name for x in '\\/:\x00<>"|?*') and not name.endswith(('.', ' ')))
    base = name.split('.')[0].upper()
    _WindowsAPI.require(base not in {'CON','PRN','AUX','NUL','CLOCK$'} and not (len(base)==4 and base[:3] in {'COM','LPT'} and base[3] in '0123456789'))
    return name


class _WindowsChain:
    def __init__(self, path, api):
        self.api, self.path, self.entries = api, _windows_path(path), []
    def __enter__(self):
        try:
            parts = list(reversed(self.path.parents)) + [self.path]
            for path in parts:
                handle = self.api.open(path, directory=True)
                # Retain every ancestor without delete/write sharing. The
                # configured custody directory additionally requires its own
                # current-owner protected DACL; ancestors never authorize data.
                self.entries.append((path, handle, path == self.path))
                self.api.observe(path, handle, True, path == self.path)
            self.check()
            return self
        except BaseException:
            self.__exit__(*__import__('sys').exc_info())
            raise
    def check(self):
        for path, handle, secure in self.entries:
            self.api.observe(path, handle, True, secure)
    def __exit__(self, typ, value, tb):
        failure = None
        for path, handle, secure in reversed(self.entries):
            try:
                self.api.close(handle)
            except BaseException as e:
                if failure is None or (isinstance(failure, Exception) and not isinstance(e, Exception)):
                    failure = e
        self.entries.clear()
        if failure is not None and (typ is None or (issubclass(typ, Exception) and not isinstance(failure, Exception))):
            if not isinstance(failure, Exception):
                raise failure
            raise OSError('WINDOWS_CUSTODY_REFUSED') from None
        return False


def _windows_read_bytes(path, api=None, bound=1048576):
    api = api if api is not None else _WindowsAPI()
    p = _windows_path(path)
    with _WindowsChain(p.parent, api) as chain:
        handle, primary = (api.open(p), None)
        try:
            before = api.observe(p, handle)
            data = api.read(handle, bound)
            api.require(api.observe(p, handle) == before)
            chain.check()
            return data
        except BaseException as error:
            primary = error
            raise
        finally:
            _windows_cleanup([lambda: api.close(handle)], primary)


class _WindowsWorkspace:
    def __init__(self, path, api=None):
        self.api = api if api is not None else _WindowsAPI()
        self.path = _windows_path(path)
        self.chain, self.files = _WindowsChain(self.path, self.api), []
    @property
    def name(self):
        return str(self.path)
    def __enter__(self):
        self.chain.__enter__()
        return self
    def check(self):
        self.chain.check()
        for path, handle in self.files:
            self.api.observe(path, handle)
    def create(self, name):
        name = _windows_leaf(name)
        self.check()
        path = self.path / name
        handle = self.api.open(path, create=True)
        self.files.append((path, handle))
        self.api.observe(path, handle)
        self.check()
        return handle
    def write(self, name, content):
        data = content.encode('utf-8') if type(content) is str else content
        handle = self.create(name)
        self.api.write(handle, data)
        self.check()
    def write_chunk(self, handle, data):
        self.api.require(any(h == handle for path, h in self.files))
        self.api.require(type(data) in (bytes, bytearray, memoryview))
        size = data.nbytes if type(data) is memoryview else len(data)
        self.api.require(size <= 16777216)
        self.api.write(handle, bytes(data))
        return size
    def sync(self):
        self.check()
        for path, handle in self.files:
            self.api.require(self.api.k.FlushFileBuffers(handle))
        self.check()
    def __exit__(self, typ, value, tb):
        return self.finish(typ, value, tb, False)
    def finish(self, typ, value, tb, committed):
        failure = None
        def remember(e):
            nonlocal failure
            if failure is None or (isinstance(failure, Exception) and not isinstance(e, Exception)):
                failure = e
        for path, handle in reversed(self.files):
            try:
                self.chain.check()
                self.api.observe(path, handle)
                if not committed:
                    self.api.delete(handle)
            except BaseException as e:
                remember(e)
            finally:
                try:
                    self.api.close(handle)
                except BaseException as e:
                    remember(e)
        self.files.clear()
        try:
            self.chain.__exit__(typ, value, tb)
        except BaseException as e:
            remember(e)
        if failure is not None and (typ is None or (issubclass(typ, Exception) and not isinstance(failure, Exception))):
            if not isinstance(failure, Exception):
                raise failure
            raise OSError('WINDOWS_CUSTODY_REFUSED') from None
        return False



class Directory:
    """Retained no-follow directory chain; POSIX only, no Windows chmod claim."""
    def __init__(self, path, private=True):
        self.fds = []
        self.links = []
        self.private = private
        self.path = Path(path)

    def __enter__(self):
        require(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'))
        require(self.path.is_absolute() and '..' not in self.path.parts)
        try:
            fd = _bounded_posix_open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.fds.append(fd)
            for part in self.path.parts[1:]:
                parent = fd
                fd = _bounded_posix_open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                self.fds.append(fd)
                self.links.append((parent, part, fd))
            self.check()
            return self
        except Exception as error:
            self.__exit__(type(error), error, error.__traceback__)
        except BaseException as error:
            self.__exit__(type(error), error, error.__traceback__)
            raise
        else:
            return self
        raise Refused()

    def check(self):
        for index, fd in enumerate(self.fds):
            st = os.fstat(fd)
            require(stat.S_ISDIR(st.st_mode) and st.st_uid in (0, os.geteuid())
                    and stat.S_IMODE(st.st_mode) & 0o022 == 0)
            if index == len(self.fds) - 1 and self.private:
                require(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700)
        for parent, name, fd in self.links:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(fd)
            require((named.st_dev, named.st_ino) == (held.st_dev, held.st_ino)
                    and stat.S_ISDIR(named.st_mode))

    def __exit__(self, *args):
        fds = tuple(reversed(self.fds))
        self.fds.clear()
        _cleanup([lambda fd=fd: _bounded_posix_close(fd) for fd in fds],
                 args[1] if len(args) > 1 else None)

    @property
    def fd(self):
        return self.fds[-1]


def read_client(path):
    if os.name == 'nt':
        return _windows_read_bytes(path, bound=LIMIT)
    path = Path(path)
    require(path.is_absolute() and path.name not in ('', '.', '..'))
    with Directory(path.parent, private=False) as directory:
        fd = _bounded_posix_open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory.fd)
        primary = None
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                    and 0 < before.st_size <= LIMIT)
            body = bytearray()
            while True:
                chunk = os.read(fd, min(8192, LIMIT + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                require(len(body) <= LIMIT)
            directory.check()
            after = os.fstat(fd)
            named = os.stat(path.name, dir_fd=directory.fd, follow_symlinks=False)
            fields = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink,
                                 st.st_size, st.st_mtime_ns, st.st_ctime_ns)
            require(fields(before) == fields(after) == fields(named))
            return bytes(body)
        except BaseException as error:
            primary = error
            raise
        finally:
            _cleanup([lambda: _bounded_posix_close(fd)], primary)


class Custody:
    """Explicit operator-owned directory; two fixed exclusive files, no overwrite.

    Failure removes only our still-identical inode names. Directory custody loss
    may prevent safe unlink; in that event no success is reported. Retained file
    descriptors and directory links are rechecked before commit. This does not
    promise an atomic filesystem transaction against a hostile same-UID actor.
    """
    def __init__(self, path):
        if os.name == 'nt':
            self._win = _WindowsWorkspace(path)
            self.directory = self._win.path
            self.files = []
            self.committed = False
            return
        self.directory = Directory(Path(path))
        self.files = []
        self.committed = False

    @staticmethod
    def filename(slot):
        require(slot in LABELS)
        return 'google-seo-oauth-' + slot + '.json'

    def __enter__(self):
        if os.name == 'nt':
            self._win.__enter__()
            return self
        self.directory.__enter__()
        try:
            for slot in LABELS:
                name = self.filename(slot)
                try:
                    os.stat(name, dir_fd=self.directory.fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise Refused()
            return self
        except BaseException as error:
            self.directory.__exit__(type(error), error, error.__traceback__)
            raise

    def check(self):
        if os.name == 'nt':
            return self._win.check()
        self.directory.check()
        for name, fd in self.files:
            held = os.fstat(fd)
            named = os.stat(name, dir_fd=self.directory.fd, follow_symlinks=False)
            require(stat.S_ISREG(held.st_mode) and held.st_uid == os.geteuid()
                    and stat.S_IMODE(held.st_mode) == 0o600 and held.st_nlink == 1
                    and (held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_nlink)
                    == (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_nlink))

    def write(self, slot, document):
        if os.name == 'nt':
            require(not self.committed)
            self.check()
            name = self.filename(slot)
            require(name not in [item[0] for item in self.files])
            data = json.dumps(document, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode()
            require(len(data) <= LIMIT)
            fd = self._win.create(name)
            self.files.append((name, fd))
            self.check()
            view = memoryview(data)
            while view:
                n = self._win.write_chunk(fd, view)
                require(n > 0)
                view = view[n:]
            self._win.sync()
            self.check()
            return
        require(not self.committed)
        self.check()
        name = self.filename(slot)
        require(name not in [item[0] for item in self.files])
        data = json.dumps(document, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode()
        require(len(data) <= LIMIT)
        fd = _bounded_posix_open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.directory.fd)
        self.files.append((name, fd))
        self.check()
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            require(n > 0)
            view = view[n:]
        os.fsync(fd)
        self.check()

    def commit(self):
        if os.name == 'nt':
            require(len(self.files) == 2)
            self.check()
            self._win.sync()
            self.check()
            self.committed = True
            return
        require(len(self.files) == 2)
        self.check()
        os.fsync(self.directory.fd)
        self.check()
        self.committed = True

    def __exit__(self, exc_type=None, exc=None, tb=None):
        if os.name == 'nt':
            return self._win.finish(exc_type, exc, tb, self.committed)
        cleanup_failed = False
        control = None
        try:
            if exc_type is not None or not self.committed:
                for name, fd in self.files:
                    try:
                        named = os.stat(name, dir_fd=self.directory.fd, follow_symlinks=False)
                        held = os.fstat(fd)
                        require((named.st_dev, named.st_ino) == (held.st_dev, held.st_ino))
                        os.unlink(name, dir_fd=self.directory.fd)
                    except Exception:
                        cleanup_failed = True
                    except BaseException as error:
                        if control is None:
                            control = error
        finally:
            for _, fd in self.files:
                try:
                    _bounded_posix_close(fd)
                except Exception:
                    cleanup_failed = True
                except BaseException as error:
                    if control is None:
                        control = error
            self.files.clear()
            try:
                self.directory.__exit__(exc_type, exc, tb)
            except Exception:
                cleanup_failed = True
            except BaseException as error:
                if control is None:
                    control = error
        if exc is None or isinstance(exc, Exception):
            if control is not None:
                raise control
            if exc is None:
                require(not cleanup_failed)


def credential(config, slot, refresh):
    client = config['installed']
    # Exact runtime schema; human attestation is not an invented credential field.
    return dict(version=1, account_id=slot, client_id=client['client_id'],
                client_secret=client['client_secret'], refresh_token=refresh,
                token_uri=TOKEN_URI, scopes=list(SCOPES))


def run(args):
    require(args.custody_ack == 'restricted-file' and args.app_preflight_confirmed)
    # Fail before opening real client files or creating a browser/session on NT.
    require(os.name in ('posix', 'nt'))
    require(text(args.approved_client_id, 512) and args.approved_client_id.endswith('.apps.googleusercontent.com'))
    require(text(args.approved_project_id, 256))
    config = validate_client(read_client(args.client_file), args.approved_client_id, args.approved_project_id)
    refreshes = []
    with Custody(args.output_directory) as custody:
        for slot in LABELS:
            flow = None
            primary = None
            try:
                with private_output():
                    with _binding3_browser_private_descriptors():
                        with Callback(args.timeout) as callback:
                            state = secrets.token_urlsafe(48)
                            flow = make_flow(config, callback.uri, state)
                            url, returned_state = authorization(flow, state, slot)
                            require(hmac.compare_digest(returned_state, state))
                            # Capture inherited process FDs before controller creation.
                            import webbrowser
                            require(webbrowser.get().open(url, new=1, autoraise=True))
                            code = callback.wait(state)
                            refresh = exchange(flow, code)
                attest(slot)
                if refreshes:
                    distinct(refreshes[0], refresh)
                refreshes.append(refresh)
            except BaseException as error:
                primary = error
                raise
            finally:
                if flow is not None:
                    def close_flow():
                        admitted = False
                        try:
                            with private_output():
                                admitted = True
                                flow.oauth2session.close()
                        except BaseException as guard_error:
                            if admitted:
                                raise
                            close = flow.oauth2session.close
                            if _enrollment_worker_alive():
                                # Seq324: never retire unguarded beside a live
                                # exchange; retain this bound close to exit.
                                _enrollment_deferred_guards.append([close])
                            else:
                                # Seq324 named fallback: Session.close emits no
                                # token diagnostics; drained channels make owned
                                # retirement preferable to an unretired session.
                                _cleanup([close], guard_error)
                            raise
                    _cleanup([close_flow], primary)
        for slot, refresh in zip(LABELS, refreshes):
            custody.write(slot, credential(config, slot, refresh))
        custody.commit()
    print('ENROLLMENT_FILES_RETAINED: propel-dms addourteam99')
    print('Operator: import both restricted files through the separately approved dashboard; then delete both files. Cleanup ownership: operator.')


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused()


def main(argv=None):
    parser = Parser(description='Human-gated Desktop enrollment. No credential print mode. Windows custody unavailable.')
    parser.add_argument('--client-file', required=True)
    parser.add_argument('--approved-client-id', required=True)
    parser.add_argument('--approved-project-id', required=True)
    parser.add_argument('--output-directory', required=True)
    parser.add_argument('--custody-ack', required=True, choices=('restricted-file',))
    parser.add_argument('--app-preflight-confirmed', action='store_true', required=True)
    parser.add_argument('--timeout', type=int, default=180)
    try:
        args = parser.parse_args(argv)
        require(1 <= args.timeout <= 300)
    except SystemExit as error:
        return 0 if error.code == 0 else 2
    except Exception:
        print('ENROLLMENT_ARGUMENTS_REFUSED', file=sys.stderr)
        return 2
    try:
        run(args)
        return 0
    except BaseException:
        # Never render str/repr/traceback, provider response, URL or chained errors.
        print('ENROLLMENT_NOT_COMPLETED', file=sys.stderr)
        return 1



# POSIX descriptor ownership is request-local. No ambient exception state is used.
import contextvars as _custody_contextvars
_bounded_posix_context = _custody_contextvars.ContextVar("enrollment_posix_custody", default=None)

class _BoundedPosixOperation:
    def __init__(self):
        self.pending = set()
        self.cleanup = []
        self.created = []
        self.retry_identity = {}

    def close(self, fd):
        identity = None
        try:
            before = os.fstat(fd)
            identity = (before.st_dev, before.st_ino)
        except BaseException as error:
            self.cleanup.append(error)
        try:
            os.close(fd)
        except BaseException as error:
            self.cleanup.append(error)
            try:
                after = os.fstat(fd)
            except OSError:
                self.pending.discard(fd)
                self.retry_identity.pop(fd, None)
            except BaseException as inspection_error:
                self.cleanup.append(inspection_error)
                self.pending.discard(fd)
                self.retry_identity.pop(fd, None)
            else:
                if identity is not None and (after.st_dev, after.st_ino) == identity:
                    self.pending.add(fd)
                    self.retry_identity[fd] = identity
                else:
                    self.pending.discard(fd)
                    self.retry_identity.pop(fd, None)
        else:
            self.pending.discard(fd)
            self.retry_identity.pop(fd, None)

    def finish(self, failed=False):
        if failed:
            for name, parent_fd, identity in reversed(self.created):
                try:
                    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == identity:
                        os.unlink(name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                except BaseException as error:
                    self.cleanup.append(error)
        for fd in tuple(self.pending):
            expected = self.retry_identity.get(fd)
            if expected is not None:
                try:
                    current = os.fstat(fd)
                except BaseException as error:
                    self.cleanup.append(error)
                    self.pending.discard(fd)
                    continue
                if (current.st_dev, current.st_ino) != expected:
                    self.pending.discard(fd)
                    continue
            self.close(fd)

def _bounded_posix_open(*args, **kwargs):
    fd = os.open(*args, **kwargs)
    operation = _bounded_posix_context.get()
    if operation is not None:
        operation.pending.add(fd)
        flags = args[1] if len(args) > 1 else kwargs.get("flags", 0)
        if flags & os.O_CREAT and flags & os.O_EXCL:
            parent_fd = kwargs.get("dir_fd")
            if parent_fd is not None:
                current = os.fstat(fd)
                operation.created.append((args[0], parent_fd, (current.st_dev, current.st_ino)))
    return fd

def _bounded_posix_close(fd):
    operation = _bounded_posix_context.get()
    if operation is None:
        return os.close(fd)
    operation.close(fd)

def _bounded_posix_static_failure():
    error = None
    try:
        require(False)
    except Exception as caught:
        error = caught
    if error is None:
        raise AssertionError()
    error.__cause__ = None
    error.__context__ = None
    return error

def _bounded_posix_raise_safe(error):
    try:
        raise error from None
    except Exception:
        error.__context__ = None
        error.__cause__ = None
        raise

def _bounded_posix_invoke(function, args, kwargs, retain=False, request=None):
    if os.name == "nt":
        return function(*args, **kwargs)
    operation = _BoundedPosixOperation()
    token = _bounded_posix_context.set(operation)
    primary = None
    result = None
    try:
        try:
            result = function(*args, **kwargs)
        except BaseException as error:
            primary = error
        if not retain or primary is not None:
            operation.finish(failed=primary is not None)
    finally:
        _bounded_posix_context.reset(token)
    if request is not None and not isinstance(request, Exception):
        return False
    if primary is not None and not isinstance(primary, Exception):
        raise primary
    for error in operation.cleanup:
        if not isinstance(error, Exception):
            raise error
    if request is not None:
        return False
    if primary is not None or operation.cleanup:
        _bounded_posix_raise_safe(_bounded_posix_static_failure())
    return result

_BOUNDED_READ_ORIGINAL = read_client

def read_client(path):
    return _bounded_posix_invoke(_BOUNDED_READ_ORIGINAL, (path,), {})

def _bounded_posix_method(function, retain=False, exit_method=False):
    def bounded(self, *args, **kwargs):
        request = (args[1] if len(args) >= 2 else kwargs.get('exc')) if exit_method else None
        return _bounded_posix_invoke(function, (self, *args), kwargs, retain=retain, request=request)
    return bounded

for _bounded_method_name in ("__init__", "__enter__", "write", "check", "commit", "__exit__"):
    setattr(Custody, _bounded_method_name, _bounded_posix_method(
        getattr(Custody, _bounded_method_name),
        retain=_bounded_method_name in ("__init__", "__enter__", "write", "check", "commit"),
        exit_method=_bounded_method_name == "__exit__",
    ))

@contextlib.contextmanager
def _binding3_browser_private_descriptors(_browser=True):

    import subprocess as _subprocess
    import contextlib as _contextlib
    import io as _io
    _saved = []
    _null = None
    _primary = None
    _cleanup = None
    _popen = _subprocess.Popen
    def _safe_popen(*args, **kwargs):
        kwargs['close_fds'] = True
        kwargs['pass_fds'] = ()
        kwargs['stdin'] = _subprocess.DEVNULL
        kwargs['stdout'] = _subprocess.DEVNULL
        kwargs['stderr'] = _subprocess.DEVNULL
        try:
            return _popen(*args, **kwargs)
        except Exception:
            error = RuntimeError('BROWSER_FAILED')
            try:
                raise error from None
            except RuntimeError:
                error.__context__ = None
                raise
    with _enrollment_private_redirects(_io.StringIO(), _io.StringIO()):
        try:
            _null = os.open(os.devnull, os.O_WRONLY)
            for _fd in (1, 2):
                _inheritable = os.get_inheritable(_fd)
                _backup = os.dup(_fd)
                _saved.append((_fd, _backup, _inheritable))
                os.set_inheritable(_backup, False)
                os.dup2(_null, _fd)
            _subprocess.Popen = _safe_popen
            yield
        except BaseException as _error:
            _primary = _error
            raise
        finally:
            _deferred = _enrollment_defer_guard_restoration()
            if _deferred:
                _enrollment_deferred_guards.append((_saved, _null, _popen))
            else:
                _subprocess.Popen = _popen
            for _fd, _backup, _inheritable in reversed(() if _deferred else _saved):
                try:
                    os.dup2(_backup, _fd, inheritable=_inheritable)
                except BaseException as _error:
                    if _cleanup is None or (isinstance(_cleanup, Exception) and not isinstance(_error, Exception)): _cleanup = _error
                try:
                    os.close(_backup)
                except BaseException as _error:
                    if _cleanup is None or (isinstance(_cleanup, Exception) and not isinstance(_error, Exception)): _cleanup = _error
            if _null is not None and not _deferred:
                try:
                    os.close(_null)
                except BaseException as _error:
                    if _cleanup is None or (isinstance(_cleanup, Exception) and not isinstance(_error, Exception)): _cleanup = _error
            if (_primary is None or isinstance(_primary, Exception)) and _cleanup is not None:
                if not isinstance(_cleanup, Exception):
                    raise _cleanup
            if _primary is None and _cleanup is not None:
                error = RuntimeError('BROWSER_FAILED')
                try:
                    raise error from None
                except RuntimeError:
                    error.__context__ = None
                    raise

if __name__ == '__main__':
    raise SystemExit(main())
