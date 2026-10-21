"""Seq256 regression-first synthetic wire controls; no provider or custody I/O.

No test credential or response is a real provider observation. Token expiry and
access bounds are intentionally not invented here: admission matches explicit
malformed cases from the Coordinator disposition.
"""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from google.oauth2.credentials import Credentials

from google_seo_mcp.google_accounts import clients
from google_seo_mcp.google_accounts.models import GOOGLE_SCOPES, TOKEN_URI, GoogleAccountError


@pytest.fixture
def helper():
    path = Path(__file__).resolve().parents[1] / 'scripts/enroll_google_accounts.py'
    spec = importlib.util.spec_from_file_location('_stage_b_token_helper', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def token():
    return {'access_token': 'synthetic-access-stage-b', 'token_type': 'Bearer', 'expires_in': 3600}


def credential():
    return Credentials(None, refresh_token='synthetic-refresh-stage-b',
                       client_id='synthetic-stage-b.apps.googleusercontent.com',
                       client_secret='synthetic-client-stage-b', token_uri=TOKEN_URI,
                       scopes=sorted(GOOGLE_SCOPES))


def wire(monkeypatch, document):
    sends = []
    def send(self, request, **kwargs):
        assert request.method == 'POST' and request.url == TOKEN_URI
        assert kwargs['allow_redirects'] is False and kwargs['proxies'] == {}
        sends.append(True)
        response = requests.Response()
        response.status_code = 200
        response.url = TOKEN_URI
        response._content = json.dumps(document).encode()
        response._content_consumed = True
        return response
    monkeypatch.setattr(requests.Session, 'send', send)
    return sends


def refresh(monkeypatch, document):
    sends = wire(monkeypatch, document)
    c = credential()
    bundle = clients._Bundle.__new__(clients._Bundle)
    bundle.credentials = c
    bundle.owner = SimpleNamespace(protect=lambda value: None)
    bundle.gate = lambda: 15.0
    return bundle, c, sends


@pytest.mark.parametrize('shape', ['missing-access', 'typed-access', 'oversized-access',
                                 'wrong-type', 'extra-key', 'nonfinite-expiry'])
def test_b02_malformed_success_refuses_before_sdk_state_change(monkeypatch, shape):
    document = token()
    if shape == 'missing-access':
        document.pop('access_token')
    elif shape == 'typed-access':
        document['access_token'] = 7
    elif shape == 'oversized-access':
        document['access_token'] = 'x' * 65537
    elif shape == 'wrong-type':
        document['token_type'] = 'Basic'
    elif shape == 'extra-key':
        document['unexpected'] = True
    else:
        document['expires_in'] = float('inf')
    bundle, c, sends = refresh(monkeypatch, document)
    before = (c.token, c.expiry, c.refresh_token, c.granted_scopes)
    with pytest.raises(GoogleAccountError):
        bundle.refresh()
    assert (c.token, c.expiry, c.refresh_token, c.granted_scopes) == before
    assert sends == [True]


@pytest.mark.parametrize('scope', ['absent', 'equal', 'expanded'])
def test_b01_optional_scope_contract(monkeypatch, scope):
    document = token()
    if scope != 'absent':
        document['scope'] = ' '.join(sorted(GOOGLE_SCOPES)) + (' extra-scope' if scope == 'expanded' else '')
    bundle, c, sends = refresh(monkeypatch, document)
    if scope == 'expanded':
        with pytest.raises(GoogleAccountError):
            bundle.refresh()
    else:
        bundle.refresh()
        assert c.token == document['access_token']
    assert sends == [True]


def test_b03_rotation_is_memory_only(monkeypatch):
    document = token()
    document['refresh_token'] = 'synthetic-rotation-stage-b'
    bundle, c, sends = refresh(monkeypatch, document)
    writes = []
    def refuse_write(*args, **kwargs):
        writes.append(True)
        raise AssertionError('persistence_forbidden')
    import builtins
    import os
    # Runtime refresh has no vault writer; trap filesystem persistence too.
    original_open = builtins.open
    def guarded_open(file, mode='r', *args, **kwargs):
        if any(flag in mode for flag in 'wax+'):
            return refuse_write()
        return original_open(file, mode, *args, **kwargs)
    monkeypatch.setattr(builtins, 'open', guarded_open)
    monkeypatch.setattr(os, 'write', refuse_write)
    bundle.refresh()
    assert c.refresh_token == document['refresh_token']
    assert not writes and sends == [True]


@pytest.mark.parametrize('document', [{}, {'access_token': 'synthetic-access', 'token_type': 'Bearer',
                                        'expires_in': 3600, 'expires_at': False}])
def test_b06_shape_refusal_uses_refused(helper, document):
    with pytest.raises(helper.Refused):
        helper._validate_token_response_shape(document)


def test_b05_slow_drip_total_deadline_refuses(helper, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(helper.time, 'monotonic', lambda: clock[0])
    document = dict(token(), scope=' '.join(helper.SCOPES), refresh_token='synthetic-refresh-stage-b')
    body = json.dumps(document).encode()
    closed = []
    class Response:
        status_code = 200
        def iter_content(self, chunk_size):
            # Respect the transport's requested chunk size.
            for offset in range(0, len(body), chunk_size):
                clock[0] += 30.0
                yield body[offset:offset + chunk_size]
        def close(self):
            closed.append(True)
    def send(self, request, **kwargs):
        assert kwargs['timeout'] <= 15
        assert kwargs['stream'] is True and kwargs['allow_redirects'] is False
        return Response()
    monkeypatch.setattr(requests.Session, 'send', send)
    config = {'installed': {'client_id': 'synthetic-stage-b.apps.googleusercontent.com',
                          'client_secret': 'synthetic-client-stage-b',
                          'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                          'token_uri': TOKEN_URI}}
    flow = helper.make_flow(config, 'http://127.0.0.1:50000/callback', 'synthetic-state-stage-b')
    prepared = requests.Request('POST', TOKEN_URI).prepare()
    with pytest.raises(helper.Refused):
        flow.oauth2session.send(prepared)
    assert closed == [True]


# Literal seq259 token endpoint contract, applied before SDK normalization.
BAD_SHAPES = [
    ('access_token', ''), ('access_token', 'x' * 16385),
    ('token_type', None), ('expires_in', True), ('expires_in', 0),
    ('expires_in', -1), ('expires_in', 1.5), ('expires_in', 86401),
    ('expires_in', 1e100), ('expires_in', 10**400),
    ('expires_at', 10**400), ('id_token', 'synthetic'),
    ('refresh_token', ''), ('refresh_token', 5),
    ('refresh_token', 'x' * 16385), ('scope', []), ('scope', 'extra'),
]


@pytest.mark.parametrize('key,value', BAD_SHAPES, ids=[str(i) for i in range(len(BAD_SHAPES))])
@pytest.mark.parametrize('boundary', ['helper', 'runtime'])
def test_seq259_literal_refusal(helper, monkeypatch, key, value, boundary):
    document = dict(token(), **{key: value})
    if boundary == 'helper':
        with pytest.raises(helper.Refused):
            helper._validate_token_response_shape(document)
    else:
        bundle, c, sends = refresh(monkeypatch, document)
        before = (c.token, c.expiry, c.refresh_token, c.granted_scopes)
        with pytest.raises(GoogleAccountError):
            bundle.refresh()
        assert (c.token, c.expiry, c.refresh_token, c.granted_scopes) == before
        assert sends == [True]


@pytest.mark.parametrize('expiry', [1, 86400, 1.0, 86400.0])
@pytest.mark.parametrize('boundary', ['helper', 'runtime'])
def test_seq259_positive_boundaries(helper, monkeypatch, expiry, boundary):
    document = dict(token(), expires_in=expiry, access_token='x' * 16384,
                    refresh_token='r' * 16384, token_type='bEaReR',
                    scope=' '.join(sorted(GOOGLE_SCOPES)))
    if boundary == 'helper':
        assert helper._validate_token_response_shape(document) is document
    else:
        bundle, c, sends = refresh(monkeypatch, document)
        bundle.refresh()
        assert c.token == document['access_token'] and sends == [True]


def test_seq259_callback_magnitude_refuses(helper):
    with pytest.raises(helper.Refused):
        helper.Callback(10**400)


def flow_config():
    return {'installed': {'client_id': 'synthetic-stage-b.apps.googleusercontent.com',
                          'client_secret': 'synthetic-client-stage-b',
                          'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                          'token_uri': TOKEN_URI}}


@pytest.mark.parametrize('phase', ['headers', 'body', 'validation', 'within'])
def test_seq259_hard_completion_and_late_discard(helper, monkeypatch, phase):
    # Scale only the budget, not the mechanism: real blocked worker, real join.
    import threading
    import time
    release, entered, finished = threading.Event(), threading.Event(), threading.Event()
    monkeypatch.setattr(helper, 'TOKEN_EXCHANGE_TIMEOUT', 0.05)
    body = json.dumps(dict(token(), scope=' '.join(helper.SCOPES),
                           refresh_token='synthetic-refresh-stage-b')).encode()
    closed, sizes, session_closes = [], [], []
    class Response(requests.Response):
        def __init__(self):
            super().__init__()
            self.status_code, self.url = 200, TOKEN_URI
        def iter_content(self, chunk_size):
            sizes.append(chunk_size)
            if phase == 'body':
                entered.set()
                release.wait(2)
            for offset in range(0, len(body), chunk_size):
                yield body[offset:offset + chunk_size]
        def close(self):
            closed.append(True)
    def send(self, request, **kwargs):
        assert kwargs['timeout'] <= 15 and kwargs['stream'] is True
        assert kwargs['allow_redirects'] is False
        if phase == 'headers':
            entered.set()
            release.wait(2)
        return Response()
    original_validate = helper._validate_token_response_shape
    def validate(value):
        if phase == 'validation':
            entered.set()
            release.wait(2)
        return original_validate(value)
    monkeypatch.setattr(requests.Session, 'send', send)
    monkeypatch.setattr(helper, '_validate_token_response_shape', validate)
    flow = helper.make_flow(flow_config(), 'http://127.0.0.1:50000/callback', 'synthetic-state-stage-b')
    session = flow.oauth2session
    monkeypatch.setattr(session, 'close', lambda: session_closes.append(True))
    before = dict(session.token)
    start = time.monotonic()
    try:
        if phase == 'within':
            response = session.send(requests.Request('POST', TOKEN_URI).prepare())
            assert response.content == body and sizes and max(sizes) <= len(body)
        else:
            with pytest.raises(helper.Refused):
                session.send(requests.Request('POST', TOKEN_URI).prepare())
            elapsed = time.monotonic() - start
            assert entered.is_set() and elapsed < 0.5
            assert session_closes == [True]
            assert session.token == before
    finally:
        release.set()
        # Release/observe the late worker before fixture monkeypatch teardown.
        until = time.monotonic() + 1
        while not closed and time.monotonic() < until:
            time.sleep(0.002)
    assert closed == [True]
    assert session.token == before
