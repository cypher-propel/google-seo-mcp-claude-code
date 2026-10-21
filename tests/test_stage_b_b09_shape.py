"""Seq284 B09 regression-first: printable strings refused at the shape layer.

All credentials/response values are generated in memory, never real provider data.
"""
import importlib.util
import json
from pathlib import Path
import secrets
import socket
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
import requests
from google.oauth2.credentials import Credentials

from google_seo_mcp.google_accounts import clients
from google_seo_mcp.google_accounts.models import GOOGLE_SCOPES, TOKEN_URI, GoogleAccountError


@pytest.fixture
def helper():
    path = Path(__file__).resolve().parents[1] / 'scripts/enroll_google_accounts.py'
    spec = importlib.util.spec_from_file_location('_stage_b_b09_helper', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    attempts = []
    def deny(*args, **kwargs):
        attempts.append(True)
        raise AssertionError('external_attempt_refused')
    monkeypatch.setattr(socket, 'getaddrinfo', deny)
    monkeypatch.setattr(socket.socket, 'connect', deny)
    monkeypatch.setattr(socket.socket, 'connect_ex', deny)
    yield attempts
    assert attempts == []


def document():
    return dict(access_token=secrets.token_urlsafe(32), refresh_token=secrets.token_urlsafe(32),
                token_type='Bearer', expires_in=3600, scope=' '.join(sorted(GOOGLE_SCOPES)))


CONTROLS = tuple(range(32)) + (127,)


@pytest.mark.parametrize('boundary', ['helper', 'runtime'])
@pytest.mark.parametrize('field', ['access_token', 'refresh_token'])
@pytest.mark.parametrize('control', CONTROLS, ids=[str(n) for n in CONTROLS])
def test_b09_direct_shape(helper, boundary, field, control):
    value = document()
    value[field] = secrets.token_urlsafe(12) + chr(control) + secrets.token_urlsafe(12)
    validator = helper._validate_token_response_shape if boundary == 'helper' else clients._token_response
    error = helper.Refused if boundary == 'helper' else GoogleAccountError
    with pytest.raises(error):
        validator(value)


def execute_flow(helper, monkeypatch, value, boundary, expect_refusal):
    sends, closes, shape, downstream = [], [], [], []
    wire = json.dumps(value).encode()
    code, state, client_secret, refresh = [secrets.token_urlsafe(32) for _ in range(4)]
    client_id = 'synthetic-b09.apps.googleusercontent.com'
    class Response(requests.Response):
        def __init__(self, request):
            super().__init__()
            self.status_code, self.url, self.request = 200, TOKEN_URI, request
        def iter_content(self, chunk_size):
            for i in range(0, len(wire), chunk_size):
                yield wire[i:i + chunk_size]
        def close(self):
            closes.append(True)
    def send(self, request, **kwargs):
        assert request.method == 'POST' and request.url == TOKEN_URI
        assert kwargs['allow_redirects'] is False and kwargs['proxies'] == {} and kwargs['stream'] is True
        raw = request.body
        fields = parse_qs(raw.decode('ascii') if type(raw) is bytes else raw)
        if boundary == 'helper':
            assert fields['code'] == [code] and 'code_verifier' in fields
        else:
            assert fields['grant_type'] == ['refresh_token'] and fields['refresh_token'] == [refresh]
        sends.append(True)
        return Response(request)
    monkeypatch.setattr(requests.Session, 'send', send)
    target, name = (helper, '_validate_token_response_shape') if boundary == 'helper' else (clients, '_token_response')
    original = getattr(target, name)
    def validate(value):
        shape.append('entered')
        try:
            result = original(value)
        except (helper.Refused, GoogleAccountError):
            shape.append('refused')
            raise
        shape.append('admitted')
        return result
    monkeypatch.setattr(target, name, validate)
    if boundary == 'helper':
        original_token = helper.validate_token
        def token(value):
            downstream.append(True)
            return original_token(value)
        monkeypatch.setattr(helper, 'validate_token', token)
        config = {'installed': dict(client_id=client_id, client_secret=client_secret,
                    auth_uri='https://accounts.google.com/o/oauth2/auth', token_uri=TOKEN_URI)}
        flow = helper.make_flow(config, 'http://127.0.0.1:50000/callback', state)
        try:
            url, returned_state = helper.authorization(flow, state, 'propel-dms')
            assert returned_state == state and url.startswith('https://accounts.google.com/')
            before = dict(flow.oauth2session.token)
            if expect_refusal:
                with pytest.raises(helper.Refused):
                    helper.exchange(flow, code)
                assert flow.oauth2session.token == before
                assert downstream == []
            else:
                assert helper.exchange(flow, code) == value['refresh_token']
                assert flow.oauth2session.token['access_token'] == value['access_token']
                assert flow.credentials.refresh_token == value['refresh_token']
                assert set(flow.credentials.scopes) == set(GOOGLE_SCOPES)
                assert downstream == [True, True]
        finally:
            flow.oauth2session.close()
    else:
        c = Credentials(None, refresh_token=refresh, client_id=client_id,
                        client_secret=client_secret, token_uri=TOKEN_URI, scopes=sorted(GOOGLE_SCOPES))
        bundle = clients._Bundle.__new__(clients._Bundle)
        bundle.credentials = c
        bundle.owner = SimpleNamespace(protect=lambda value: None)
        bundle.gate = lambda: 15.0
        before = (c.token, c.expiry, c.refresh_token, c.granted_scopes)
        if expect_refusal:
            with pytest.raises(GoogleAccountError):
                bundle.refresh()
            assert (c.token, c.expiry, c.refresh_token, c.granted_scopes) == before
        else:
            bundle.refresh()
            assert c.token == value['access_token'] and c.refresh_token == value['refresh_token']
    assert sends == [True] and closes == [True]
    assert shape == ['entered', 'refused' if expect_refusal else 'admitted']


@pytest.mark.parametrize('boundary', ['helper', 'runtime'])
@pytest.mark.parametrize('field', ['access_token', 'refresh_token'])
@pytest.mark.parametrize('control', CONTROLS, ids=[str(n) for n in CONTROLS])
def test_b09_real_exchange_shape_refusal(helper, monkeypatch, boundary, field, control):
    value = document()
    value[field] = secrets.token_urlsafe(12) + chr(control) + secrets.token_urlsafe(12)
    execute_flow(helper, monkeypatch, value, boundary, True)


@pytest.mark.parametrize('boundary', ['helper', 'runtime'])
def test_b09_whole_flow_printable_positive(helper, monkeypatch, boundary):
    execute_flow(helper, monkeypatch, document(), boundary, False)
