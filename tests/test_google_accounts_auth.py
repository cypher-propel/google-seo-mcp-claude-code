"""Synthetic offline contracts for the actual dual-account custody and SDK boundary.

No real accounts or grants are represented. Secrets are generated in RAM and only
custody test documents are materialized inside a private, short-lived owned root.
"""
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
import google.auth
from google.oauth2 import service_account
from google_seo_mcp.google_accounts.credentials import GoogleCredentialLoader
from google_seo_mcp.google_accounts.clients import GoogleAccountClients
from google_seo_mcp.google_accounts.discovery import GooglePropertyDiscovery
from google_seo_mcp.google_accounts.routing import GooglePropertyRouter
from google_seo_mcp.google_accounts.models import GoogleOAuthCredential, GoogleRequestDeadline

ACCOUNTS = ('propel-dms', 'addourteam99')
SCOPES = frozenset(('https://www.googleapis.com/auth/webmasters.readonly',
                    'https://www.googleapis.com/auth/analytics.readonly'))
CLIENT = 'synthetic-seq208.apps.googleusercontent.com'


def document(account):
    return dict(version=1, account_id=account, client_id=CLIENT,
                client_secret=secrets.token_urlsafe(32), refresh_token=secrets.token_urlsafe(32),
                token_uri='https://oauth2.googleapis.com/token', scopes=sorted(SCOPES))


@pytest.fixture
def custody():
    parent = Path('/home/propel/work')
    for path in (Path('/home'), Path('/home/propel'), parent):
        st = path.lstat()
        assert not path.is_symlink() and not st.st_mode & 0o022
    root = Path(tempfile.mkdtemp(prefix='20261020-google-auth-tests-seq208-', dir=parent))
    os.chmod(root, 0o700)
    (root/'ORIGIN.md').write_text('owner: google-auth-tests\npurpose: synthetic offline custody fixtures\ncreated: 2026-10-20\nsource: approved agency-property-union-build\nexpiry: assignment close-out +14 days\nmemory_bank: thread_90cb25ccf4934169\ncontains_secrets: synthetic only\ndisposal: delete at fixture teardown\n')
    shared_secret = secrets.token_urlsafe(32)
    docs = [document(a) for a in ACCOUNTS]
    for doc in docs:
        doc['client_secret'] = shared_secret
    client_path = root/'client.json'
    client_doc = dict(installed=dict(client_id=CLIENT, client_secret=shared_secret,
                      project_id='synthetic-seq208', auth_uri='https://accounts.google.com/o/oauth2/auth',
                      token_uri='https://oauth2.googleapis.com/token'))
    fd = os.open(client_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(client_doc, f)
    paths = [root/'a.json', root/'b.json']
    def save(index):
        data = json.dumps(docs[index]).encode()
        fd = os.open(paths[index], os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
    for i in range(2):
        save(i)
    loader = GoogleCredentialLoader(propel_dms_file=str(paths[0]), addourteam99_file=str(paths[1]), client_file=str(client_path), approved_client_id=CLIENT, approved_project_id='synthetic-seq208')
    try:
        yield root, docs, paths, save, loader
    finally:
        shutil.rmtree(root)


class LocalWire:
    """Actual requests PreparedRequest/Response boundary, all material in RAM."""
    def __init__(self, docs):
        self.docs = docs
        self.access = {a: secrets.token_urlsafe(32) for a in ACCOUNTS}
        self.calls = []
        self.responses = []
        self.scopes = []
        self.sites = {a: [] for a in ACCOUNTS}
        self.pages = {a: [{}] for a in ACCOUNTS}
        self.fail = set()
        self.guard = threading.Lock()
        self.active = {a: 0 for a in ACCOUNTS}
        self.max_active = {a: 0 for a in ACCOUNTS}
        self.max_total = 0
        self.delay = 0

    def send(self, request, **kwargs):
        path = urlsplit(request.url).path
        response = requests.Response()
        with self.guard:
            self.responses.append(response)
        response.url = request.url
        response.request = request
        response.status_code = 200
        response._content_consumed = True
        response.raw = io.BytesIO()
        response.headers['Content-Type'] = 'application/json'
        if path == '/token':
            body = request.body.decode() if isinstance(request.body, bytes) else request.body
            form = parse_qs(body)
            matches = [a for a, d in zip(ACCOUNTS, self.docs) if form.get('refresh_token') == [d['refresh_token']]]
            assert len(matches) == 1
            a = matches[0]
            assert form.get('client_id') == [CLIENT]
            assert form.get('client_secret') == [self.docs[ACCOUNTS.index(a)]['client_secret']]
            assert form.get('grant_type') == ['refresh_token']
            scope = form.get('scope', [''])[0].split()
            self.scopes.append((a, len(scope) == 2 and frozenset(scope) == SCOPES))
            payload = dict(access_token=self.access[a], token_type='Bearer', expires_in=3600, scope=' '.join(sorted(SCOPES)))
            with self.guard:
                self.calls.append((a, 'refresh'))
            time.sleep(self.delay)
        else:
            auth = request.headers.get('Authorization', '')
            matches = [a for a in ACCOUNTS if auth == 'Bearer '+self.access[a]]
            assert len(matches) == 1
            a = matches[0]
            with self.guard:
                self.calls.append((a, path))
                self.active[a] += 1
                self.max_active[a] = max(self.max_active[a], self.active[a])
                self.max_total = max(self.max_total, sum(self.active.values()))
            try:
                time.sleep(self.delay)
                if (a, path) in self.fail or (a, '*') in self.fail:
                    response.status_code = 403
                    payload = {'error': {'code': 403, 'message': 'synthetic denial', 'status': 'PERMISSION_DENIED'}}
                elif path.endswith('/sites'):
                    payload = {'siteEntry': self.sites[a]}
                elif path.endswith('/accountSummaries'):
                    q = parse_qs(urlsplit(request.url).query)
                    token = q.get('pageToken', [''])[0]
                    index = int(token) if token.isdigit() else 0
                    page = self.pages[a][index]
                    if page is None:
                        response.status_code = 403
                        payload = {'error': {'code': 403, 'message': 'synthetic denial', 'status': 'PERMISSION_DENIED'}}
                    else:
                        payload = page
                elif path.endswith('/metadata'):
                    payload = {'name': path.split('/')[-2]+'/metadata', 'dimensions': [], 'metrics': []}
                else:
                    payload = {'responseAggregationType': 'byProperty', 'rows': []}
            finally:
                with self.guard:
                    self.active[a] -= 1
        response._content = json.dumps(payload).encode()
        return response


@pytest.fixture
def wire(custody, monkeypatch):
    _, docs, _, _, loader = custody
    w = LocalWire(docs)
    # This final adapter is a synthetic local wire, never an internet transport.
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', lambda adapter, request, **kw: w.send(request, **kw))
    def forbidden(*args, **kwargs):
        raise AssertionError('OFFLINE_NETWORK_REFUSED')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    sessions = []
    session_init = requests.sessions.Session.__init__
    def tracked_session(session, *args, **kwargs):
        session_init(session, *args, **kwargs)
        with w.guard:
            sessions.append(session)
    monkeypatch.setattr(requests.sessions.Session, '__init__', tracked_session)
    clients = GoogleAccountClients(loader)
    discovery = GooglePropertyDiscovery(clients)
    router = GooglePropertyRouter(discovery=discovery, clients=clients)
    primary = None
    try:
        yield w, loader, clients, discovery, router
    except BaseException as exc:
        primary = exc
        raise
    finally:
        close_resources([*sessions, *w.responses], primary)


def close_resources(resources, primary=None):
    control = None
    ordinary = False
    seen = set()
    for resource in resources:
        if id(resource) in seen:
            continue
        seen.add(id(resource))
        try:
            resource.close()
        except Exception:
            ordinary = True
        except BaseException as exc:
            if control is None:
                control = exc
    if primary is None:
        if control is not None:
            raise control
        if ordinary:
            raise RuntimeError('SYNTHETIC_FIXTURE_CLEANUP_FAILED') from None


def deadline():
    return GoogleRequestDeadline(end=time.monotonic()+20)


def test_exact_local_readiness(custody):
    *_, loader = custody
    accounts = loader.load_accounts()
    assert tuple(c.account_id for c in accounts) == ACCOUNTS
    assert all(c.scopes == SCOPES for c in accounts)
    assert isinstance(loader.generation(), str)


@pytest.mark.parametrize('field,value', [
    ('scopes', []), ('scopes', [sorted(SCOPES)[0]]),
    ('scopes', sorted(SCOPES)+['openid']), ('client_id', 'wrong.apps.googleusercontent.com'),
    ('account_id', 'unknown'), ('token_uri', 'https://invalid.test/token'), ('version', True),
])
def test_exact_scope_and_binding_refusal(custody, field, value):
    _, docs, _, save, loader = custody
    docs[0][field] = value
    save(0)
    with pytest.raises(RuntimeError):
        loader.load_accounts()


@pytest.mark.parametrize('kind', ['missing', 'duplicate-account', 'duplicate-refresh', 'extra-field', 'duplicate-json-key', 'malformed', 'unsafe-mode', 'symlink'])
def test_missing_duplicate_and_custody_refusal(custody, kind):
    root, docs, paths, save, loader = custody
    if kind == 'missing':
        paths[1].unlink()
    elif kind == 'duplicate-account':
        docs[1]['account_id'] = ACCOUNTS[0]; save(1)
    elif kind == 'duplicate-refresh':
        docs[1]['refresh_token'] = docs[0]['refresh_token']; save(1)
    elif kind == 'extra-field':
        docs[0]['subject'] = 'synthetic'; save(0)
    elif kind == 'duplicate-json-key':
        paths[0].write_bytes(b'{"version":1,"version":1}')
    elif kind == 'malformed':
        paths[0].write_bytes(b'\xff')
    elif kind == 'unsafe-mode':
        paths[0].chmod(0o644)
    else:
        held = root/'held.json'; paths[0].rename(held); paths[0].symlink_to(held)
    with pytest.raises(RuntimeError):
        loader.load_accounts()


@pytest.mark.parametrize('account', ACCOUNTS)
def test_real_sdk_refresh_exact_scope_client_binding(wire, account):
    w, _, clients, _, _ = wire
    assert clients.execute(account, lambda bundle: bundle.account_id, deadline()) == account
    assert w.scopes == [(account, True)]
    assert w.calls == [(account, 'refresh')]


@pytest.mark.parametrize('mutation', ['leaf-mode', 'leaf-symlink', 'parent-mode'])
def test_custody_read_race_refused(custody, monkeypatch, mutation):
    root, _, paths, _, loader = custody
    assert len(loader.load_accounts()) == 2
    original = os.read
    identity = paths[0].stat().st_ino
    triggered = []
    def raced(fd, size):
        data = original(fd, size)
        if data and os.fstat(fd).st_ino == identity and not triggered:
            triggered.append(True)
            if mutation == 'leaf-mode':
                paths[0].chmod(0o644)
            elif mutation == 'leaf-symlink':
                held = root/'held.json'; paths[0].rename(held); paths[0].symlink_to(held)
            else:
                root.chmod(0o770)
        return data
    monkeypatch.setattr(os, 'read', raced)
    try:
        with pytest.raises(RuntimeError):
            loader.load_accounts()
        assert triggered == [True]
    finally:
        root.chmod(0o700)


def test_no_ambient_adc_service_account_or_home(wire, custody, monkeypatch):
    w, loader, clients, _, _ = wire
    import builtins
    import io
    root, docs, _, _, _ = custody
    home = root/'hostile-home'
    for directory in [home, home/'.config', home/'.config/gcloud']:
        directory.mkdir(mode=0o700)
    ambient = root/'ambient-adc.json'
    home_adc = home/'.config/gcloud/application_default_credentials.json'
    payload = {'type':'authorized_user', 'client_id':CLIENT,
               'client_secret':docs[0]['client_secret'], 'refresh_token':docs[0]['refresh_token']}
    for path in [ambient, home_adc]:
        fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(payload, f)
    # Hostile but valid synthetic ADC/HOME documents are not an allowed fallback.
    attempts = []
    def forbidden(*args, **kw):
        attempts.append(True)
        raise AssertionError('AMBIENT_REFUSED')
    monkeypatch.setattr(google.auth, 'default', forbidden)
    monkeypatch.setattr(service_account.Credentials, 'from_service_account_file', forbidden)
    monkeypatch.setattr(service_account.Credentials, 'from_service_account_info', forbidden)
    monkeypatch.setattr(Path, 'home', forbidden)
    for module, name in [(builtins, 'open'), (io, 'open'), (os, 'open')]:
        original = getattr(module, name)
        def guarded(file, *args, _original=original, **kwargs):
            if isinstance(file, (str, os.PathLike)):
                selected = Path(file)
                if selected == ambient or selected == home or home in selected.parents:
                    return forbidden()
            return _original(file, *args, **kwargs)
        monkeypatch.setattr(module, name, guarded)
    monkeypatch.setenv('GOOGLE_APPLICATION_CREDENTIALS', str(ambient))
    monkeypatch.setenv('HOME', str(home))
    assert len(loader.load_accounts()) == 2
    assert clients.execute(ACCOUNTS[0], lambda b: b.account_id, deadline()) == ACCOUNTS[0]
    assert not attempts
    assert w.scopes == [(ACCOUNTS[0], True)]


def test_local_readiness_does_not_attest_current_grants(wire):
    w, loader, _, discovery, _ = wire
    assert len(loader.load_accounts()) == 2
    assert not w.calls
    w.fail.add((ACCOUNTS[1], '*'))
    try:
        snapshot = discovery.discover('gsc', deadline())
    except RuntimeError:
        snapshot = None
    assert snapshot is None or snapshot.complete is False
    assert len(loader.load_accounts()) == 2
