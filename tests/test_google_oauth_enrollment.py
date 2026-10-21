"""Offline enrollment admission regressions using only synthetic client material.

No case establishes real consent, current grants, or machine-verified email.
"""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import pytest
from google_auth_oauthlib.flow import Flow
CLIENT_ID = '123456789012-syntheticdesktop.apps.googleusercontent.com'
PROJECT_ID = 'synthetic-agency'
SYNTHETIC_SECRET = 'synthetic-client-private-471'

@pytest.fixture(scope='module')
def enrollment_helper():
    path = Path(__file__).resolve().parents[1] / 'scripts/enroll_google_accounts.py'
    spec = importlib.util.spec_from_file_location('_permanent_enrollment_helper', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(spec.name, None)

@pytest.fixture
def protected_case():
    parent = Path('/home/propel/work')
    observed = parent.stat()
    assert observed.st_uid == os.geteuid()
    assert stat.S_IMODE(observed.st_mode) == 448
    with tempfile.TemporaryDirectory(prefix='google-enrollment-permanent-', dir=parent) as directory:
        root = Path(directory)
        (root / 'ORIGIN.md').write_text('owner: Cypher google-enrollment-tests\npurpose: synthetic permanent enrollment fixture\nsource: approved agency-property-union-build; helper qualified digest 59233b3ce580125e519adcf682e0ac38320108c1f5ab3ec47747940eeeb1328a\nexpiry: assignment close-out +14 days\nmemory_bank: thread_90cb25ccf4934169\ncontains_secrets: no\ndisposal: delete after case\n')
        yield root

def client_document():
    return {'installed': {'client_id': CLIENT_ID, 'client_secret': SYNTHETIC_SECRET, 'project_id': PROJECT_ID, 'auth_uri': 'https://accounts.google.com/o/oauth2/auth', 'token_uri': 'https://oauth2.googleapis.com/token', 'redirect_uris': ['http://localhost']}}

def invoke(helper, root, body):
    path = root / 'client.json'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(body)
    output = root / 'output'
    output.mkdir(mode=448)
    return helper.main(['--client-file', str(path), '--output-directory', str(output), '--approved-client-id', CLIENT_ID, '--approved-project-id', PROJECT_ID, '--custody-ack', 'restricted-file', '--app-preflight-confirmed', '--timeout', '1'])

@pytest.fixture
def flow_boundary(monkeypatch):
    observed = []

    def refused(cls, *args, **kwargs):
        observed.append(True)
        raise RuntimeError('synthetic-constructor-refusal')
    monkeypatch.setattr(Flow, 'from_client_config', classmethod(refused))
    return observed

def test_valid_synthetic_desktop_client_reaches_real_flow_constructor(enrollment_helper, protected_case, flow_boundary, capsys, caplog):
    invoke(enrollment_helper, protected_case, json.dumps(client_document()).encode())
    assert flow_boundary == [True]
    captured = capsys.readouterr()
    assert SYNTHETIC_SECRET not in captured.out + captured.err + caplog.text
    assert 'synthetic-constructor-refusal' not in captured.out + captured.err + caplog.text
    assert list((protected_case / 'output').iterdir()) == []

@pytest.mark.parametrize('mutation', ['web', 'wrong-client', 'wrong-project', 'arbitrary-auth', 'arbitrary-token', 'extra-root', 'extra-client-field', 'empty-secret', 'nonlocal-redirect', 'duplicate-key', 'invalid-utf8', 'oversize', 'invalid-json'])
def test_client_refusal_precedes_flow_and_keeps_output_private(mutation, enrollment_helper, protected_case, flow_boundary, capsys, caplog):
    document = client_document()
    installed = document['installed']
    if mutation == 'web':
        document = {'web': installed}
    elif mutation == 'wrong-client':
        installed['client_id'] = '999999999999-other.apps.googleusercontent.com'
    elif mutation == 'wrong-project':
        installed['project_id'] = 'other-project'
    elif mutation == 'arbitrary-auth':
        installed['auth_uri'] = 'https://synthetic.invalid/authorize'
    elif mutation == 'arbitrary-token':
        installed['token_uri'] = 'https://synthetic.invalid/token'
    elif mutation == 'extra-root':
        document['extra'] = True
    elif mutation == 'extra-client-field':
        installed['extra'] = True
    elif mutation == 'empty-secret':
        installed['client_secret'] = ''
    elif mutation == 'nonlocal-redirect':
        installed['redirect_uris'] = ['https://synthetic.invalid/callback']
    body = json.dumps(document).encode()
    if mutation == 'duplicate-key':
        body = body.replace(b'"installed":', b'"installed": {}, "installed":', 1)
    elif mutation == 'invalid-utf8':
        body = b'\xff'
    elif mutation == 'oversize':
        body = b' ' * 131073
    elif mutation == 'invalid-json':
        body = b'{'
    invoke(enrollment_helper, protected_case, body)
    assert flow_boundary == []
    captured = capsys.readouterr()
    assert SYNTHETIC_SECRET not in captured.out + captured.err + caplog.text
    assert 'synthetic.invalid' not in captured.out + captured.err + caplog.text
    assert list((protected_case / 'output').iterdir()) == []

def _real_flow(helper, root, monkeypatch):
    import inspect
    captured = []

    def constructor(cls, *args, **kwargs):
        frame = inspect.currentframe().f_back
        try:
            captured.append(tuple((frame.f_locals[key] for key in ('config', 'redirect_uri', 'state'))))
        finally:
            del frame
        raise RuntimeError('synthetic-constructor-boundary')
    with monkeypatch.context() as patcher:
        patcher.setattr(Flow, 'from_client_config', classmethod(constructor))
        invoke(helper, root, json.dumps(client_document()).encode())
    assert len(captured) == 1
    return helper.make_flow(*captured[0])

def _authorization(helper, flow):
    return helper.authorization(flow, flow.oauth2session._state, 'propel-dms')[0]

def test_real_flow_pkce_state_fixed_loopback_exact_scopes_and_offline_request(enrollment_helper, protected_case, monkeypatch, capsys, caplog):
    import base64
    import hashlib
    from urllib.parse import urlsplit, parse_qs
    flow = _real_flow(enrollment_helper, protected_case, monkeypatch)
    capsys.readouterr()
    url = _authorization(enrollment_helper, flow)
    parsed = urlsplit(url)
    query = parse_qs(parsed.query)
    assert parsed.scheme == 'https'
    assert parsed.netloc == 'accounts.google.com'
    assert parsed.path in ['/o/oauth2/auth', '/o/oauth2/v2/auth']
    assert query['client_id'] == [CLIENT_ID]
    assert query['state'] == [flow.oauth2session._state]
    assert query['redirect_uri'] == [flow.redirect_uri]
    callback = urlsplit(flow.redirect_uri)
    assert callback.scheme == 'http' and callback.hostname == '127.0.0.1'
    assert 0 < callback.port <= 65535
    assert callback.path == '/callback'
    assert set(query['scope'][0].split()) == {'https://www.googleapis.com/auth/webmasters.readonly', 'https://www.googleapis.com/auth/analytics.readonly'}
    assert len(query['scope'][0].split()) == 2
    assert query['access_type'] == ['offline']
    assert query['prompt'] == ['consent select_account']
    assert query['include_granted_scopes'] == ['false']
    assert query['code_challenge_method'] == ['S256']
    verifier = flow.code_verifier
    assert 43 <= len(verifier) <= 128
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    assert query['code_challenge'] == [challenge]
    captured = capsys.readouterr()
    assert captured.out == captured.err == ''
    assert verifier not in caplog.text
    assert flow.oauth2session._state not in caplog.text
    assert parsed.query not in caplog.text
    flow.oauth2session.close()

@pytest.mark.parametrize('mutation', ['valid', 'no-refresh', 'missing-scope', 'extra-scope', 'wrong-type', 'bad-expiry'])
def test_raw_token_response_is_qualified_before_sdk_normalization(mutation, enrollment_helper, protected_case, monkeypatch, capsys, caplog):
    import io
    import requests
    from urllib.parse import parse_qs
    flow = _real_flow(enrollment_helper, protected_case, monkeypatch)
    capsys.readouterr()
    _authorization(enrollment_helper, flow)
    observed = []
    scopes = ['https://www.googleapis.com/auth/webmasters.readonly', 'https://www.googleapis.com/auth/analytics.readonly']
    payload = dict(access_token='synthetic-access-418', refresh_token='synthetic-refresh-419', token_type='Bearer', expires_in=3600, scope=' '.join(scopes))
    if mutation == 'no-refresh':
        payload.pop('refresh_token')
    elif mutation == 'missing-scope':
        payload['scope'] = scopes[0]
    elif mutation == 'extra-scope':
        payload['scope'] += ' openid'
    elif mutation == 'wrong-type':
        payload['token_type'] = 'MAC'
    elif mutation == 'bad-expiry':
        payload['expires_in'] = '3600'

    def send(adapter, request, **kwargs):
        body = parse_qs(request.body.decode() if isinstance(request.body, bytes) else request.body)
        observed.append(dict(endpoint=request.url, method=request.method, code=body.get('code') == ['synthetic-code-420'], verifier=body.get('code_verifier') == [flow.code_verifier]))
        response = requests.Response()
        response.status_code = 200
        response.url = request.url
        response.request = request
        response.headers['Content-Type'] = 'application/json'
        response._content = json.dumps(payload).encode()
        response._content_consumed = True
        response.raw = io.BytesIO(response._content)
        return response
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    try:
        from urllib.parse import urlencode
        authorization_code = 'synthetic-code-420'
        if mutation == 'valid':
            enrollment_helper.exchange(flow, authorization_code)
            assert flow.credentials.refresh_token == 'synthetic-refresh-419'
        else:
            with pytest.raises(Exception):
                enrollment_helper.exchange(flow, authorization_code)
        assert observed == [dict(endpoint='https://oauth2.googleapis.com/token', method='POST', code=True, verifier=True)]
        captured = capsys.readouterr()
        for value in ['synthetic-access-418', 'synthetic-refresh-419', 'synthetic-code-420', SYNTHETIC_SECRET]:
            assert value not in captured.out + captured.err + caplog.text
    finally:
        flow.oauth2session.close()

@pytest.mark.parametrize('fault_kind', ['ordinary', 'timeout', 'keyboard', 'exit'])
def test_public_enrollment_unwinds_real_loopback_handles_and_empty_artifacts(fault_kind, enrollment_helper, protected_case, monkeypatch, capsys, caplog):
    import socket
    original_socket = socket.socket
    sockets = []
    binds = []

    class TrackingSocket(original_socket):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            sockets.append(self)

        def bind(self, address):
            binds.append(address)
            return super().bind(address)
    marker = 'synthetic-private-cancellation-572'
    error = {'ordinary': RuntimeError, 'timeout': TimeoutError, 'keyboard': KeyboardInterrupt, 'exit': SystemExit}[fault_kind](marker)
    entered = []

    def constructor(cls, *args, **kwargs):
        entered.append(True)
        raise error
    caplog.set_level('DEBUG')
    escaped = None
    with monkeypatch.context() as patcher:
        patcher.setattr(socket, 'socket', TrackingSocket)
        patcher.setattr(Flow, 'from_client_config', classmethod(constructor))
        try:
            result = invoke(enrollment_helper, protected_case, json.dumps(client_document()).encode())
        except BaseException as exc:
            escaped = exc
        else:
            assert result != 0
    assert entered == [True]
    assert binds == [('127.0.0.1', 0)]
    assert sockets and all((sock.fileno() == -1 for sock in sockets))
    assert list((protected_case / 'output').iterdir()) == []
    if escaped is not None:
        assert escaped is error
    captured = capsys.readouterr()
    for value in [marker, SYNTHETIC_SECRET]:
        assert value not in captured.out + captured.err + caplog.text

@pytest.mark.parametrize('scenario', ['success', 'wrong-attestation', 'duplicate-refresh', 'wrong-state', 'timeout', 'cancel'])
def test_operator_flow_real_loopback_synthetic_browser_and_token_adapter(scenario, enrollment_helper, protected_case, monkeypatch, capsys, caplog):
    synthetic_socket_type = __import__('socket').socket
    synthetic_real_accept = synthetic_socket_type.accept
    synthetic_timeout_accepts = []
    synthetic_cancellation_events = []

    def synthetic_accept(self, *args, **kwargs):
        if scenario == 'timeout':
            synthetic_timeout_accepts.append(True)
            raise TimeoutError('synthetic-timeout-fault')
        return synthetic_real_accept(self, *args, **kwargs)

    def synthetic_browser_open(self, url, new=0, autoraise=True):
        browser_adapter_events.append(True)
        if scenario != 'timeout':
            callback(url)
        return True
    synthetic_attestation_calls = []
    original_synthetic_attest = enrollment_helper.attest

    def synthetic_attestation_boundary(label):
        assert type(label) is str
        synthetic_attestation_calls.append(label)

        def operator_input(prompt):
            if scenario == 'cancel':
                synthetic_cancellation_events.append(True)
                raise KeyboardInterrupt('synthetic-cancellation-control')
            return 'wrong-account' if scenario == 'wrong-attestation' else 'I checked ' + {'propel-dms': 'propel.dms@gmail.com', 'addourteam99': 'addourteam99@gmail.com'}[label] + ' for ' + label
        return original_synthetic_attest(label, operator_input)
    browser_adapter_events = []
    import builtins
    import io
    import socket
    import subprocess
    import threading
    import requests
    from urllib.parse import urlsplit, parse_qs, urlencode
    callbacks = []
    threads = []
    token_calls = []
    browser_calls = []
    prompts = []
    original_socket = socket.socket
    sockets = []

    class TrackingSocket(original_socket):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            sockets.append(self)

    def callback(url):
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        redirect = urlsplit(query['redirect_uri'][0])
        assert redirect.hostname == '127.0.0.1'
        assert redirect.scheme == 'http'
        state = query['state'][0]
        if scenario == 'wrong-state':
            state += '-wrong'
        request_path = redirect.path + '?' + urlencode(dict(state=state, code='synthetic-browser-code-613'))

        def send_callback():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.settimeout(2)
                    client.connect(('127.0.0.1', redirect.port))
                    client.sendall(('GET ' + request_path + ' HTTP/1.1\r\nHost: 127.0.0.1:' + str(redirect.port) + '\r\nConnection: close\r\n\r\n').encode())
                    response = client.recv(16384)
                    callbacks.append(response.startswith(b'HTTP/1.'))
            except OSError:
                callbacks.append(False)
        thread = threading.Thread(target=send_callback)
        threads.append(thread)
        thread.start()

    class BrowserInput(io.BytesIO):

        def write(self, value):
            browser_calls.append(True)
            if scenario != 'timeout':
                text = value.decode() if isinstance(value, bytes) else value
                try:
                    data = json.loads(text)
                    url = data if isinstance(data, str) else data.get('url')
                except (ValueError, TypeError):
                    url = text.strip()
                callback(url)
            return super().write(value)

    class Browser:

        def __init__(self, *args, **kwargs):
            self.stdin = BrowserInput()
            self.returncode = None

        def communicate(self, input=None, timeout=None):
            if input is not None:
                self.stdin.write(input)
            self.returncode = 0
            return (b'', b'')

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def terminate(self):
            self.returncode = 0

        def kill(self):
            self.returncode = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stdin.close()
            self.returncode = 0
    from contextlib import contextmanager

    @contextmanager
    def browser_adapter(url):
        browser_calls.append(True)
        if scenario != 'timeout':
            callback(url)
        yield Browser()

    def refuse_spawn(*args, **kwargs):
        raise AssertionError('unexpected_browser_subprocess')

    def send(adapter, request, **kwargs):
        assert request.url == 'https://oauth2.googleapis.com/token'
        assert request.method == 'POST'
        token_calls.append(True)
        number = 1 if scenario == 'duplicate-refresh' else len(token_calls)
        payload = dict(access_token='synthetic-loopback-access-614', refresh_token='synthetic-loopback-refresh-615-' + str(number), token_type='Bearer', expires_in=3600, scope='https://www.googleapis.com/auth/webmasters.readonly https://www.googleapis.com/auth/analytics.readonly')
        response = requests.Response()
        response.status_code = 200
        response.url = request.url
        response.request = request
        response.headers['Content-Type'] = 'application/json'
        response._content = json.dumps(payload).encode()
        response._content_consumed = True
        response.raw = io.BytesIO(response._content)
        return response

    def attest(prompt):
        prompts.append(True)
        if scenario == 'cancel':
            raise KeyboardInterrupt('synthetic-operator-cancel-616')
        if scenario == 'wrong-attestation':
            return 'wrong-account@synthetic.invalid'
        return 'addourteam99@gmail.com' if 'addourteam99' in prompt else 'propel.dms@gmail.com'
    caplog.set_level('DEBUG')
    escaped = None
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(socket, 'socket', TrackingSocket)
            patcher.setattr(synthetic_socket_type, 'accept', synthetic_accept)
            patcher.setattr(__import__('webbrowser'), 'get', lambda: type('SyntheticBrowser', (), {'open': synthetic_browser_open})())
            patcher.setattr(subprocess, 'Popen', refuse_spawn)
            patcher.setattr(requests.adapters.HTTPAdapter, 'send', send)
            patcher.setattr(enrollment_helper, 'attest', synthetic_attestation_boundary)
            try:
                result = invoke(enrollment_helper, protected_case, json.dumps(client_document()).encode())
            except KeyboardInterrupt as exc:
                escaped = exc
                result = 1
    finally:
        for thread in threads:
            thread.join(3)
    assert all((not thread.is_alive() for thread in threads))
    assert sockets and all((sock.fileno() == -1 for sock in sockets))
    assert browser_adapter_events
    if scenario == 'success':
        assert escaped is None and result == 0
        assert len(token_calls) == 2
        assert len(synthetic_attestation_calls) == 2
        assert callbacks == [True, True]
        assert len(list((protected_case / 'output').iterdir())) == 2
    else:
        assert result != 0
        assert list((protected_case / 'output').iterdir()) == []
        if scenario in ['wrong-state', 'timeout']:
            assert token_calls == []
        if scenario == 'duplicate-refresh':
            assert len(token_calls) == 2
        if scenario in ['wrong-attestation', 'cancel']:
            assert len(token_calls) == 1 and synthetic_attestation_calls
    captured = capsys.readouterr()
    for value in ['synthetic-browser-code-613', 'synthetic-loopback-access-614', 'synthetic-loopback-refresh-615', 'synthetic-operator-cancel-616', SYNTHETIC_SECRET, 'wrong-account@synthetic.invalid']:
        assert value not in captured.out + captured.err + caplog.text
    if scenario == 'timeout':
        assert synthetic_timeout_accepts
    if scenario == 'cancel':
        assert synthetic_cancellation_events
