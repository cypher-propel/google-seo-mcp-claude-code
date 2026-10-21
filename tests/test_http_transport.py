"""Real, offline SDK/socket checks of the hosted admission and lifecycle boundary.

GOOGLE_SEO_TEST_PYTHON selects a separately installed production wheel interpreter.
No parent credentials, PYTHONPATH, proxy configuration, or HOME enter children.
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
ROOT = Path(__file__).resolve().parents[1]
OLD35 = frozenset({'cross_gsc_to_ga4_journey', 'cross_landing_page_full_diagnosis', 'cross_multi_property_comparison', 'cross_opportunity_matrix', 'cross_seo_to_revenue_attribution', 'cross_traffic_health_check', 'ga4_anomalies', 'ga4_channel_attribution', 'ga4_cohort_retention', 'ga4_content_decay', 'ga4_conversion_funnel', 'ga4_estimate_query_size', 'ga4_event_volume_comparison', 'ga4_get_property_details', 'ga4_landing_page_health', 'ga4_list_properties', 'ga4_list_schema_categories', 'ga4_query', 'ga4_search_schema', 'ga4_traffic_drops_by_channel', 'gsc_alerts', 'gsc_cannibalization', 'gsc_content_decay', 'gsc_ctr_opportunities', 'gsc_inspect_url', 'gsc_list_sitemaps', 'gsc_list_sites', 'gsc_quick_wins', 'gsc_search_analytics', 'gsc_site_snapshot', 'gsc_traffic_drops', 'serp_aio_monitor', 'serp_check', 'serp_competitor_intersect', 'serp_paa_extractor'})
BING11 = frozenset({'bing_list_sites', 'bing_rank_traffic_stats', 'bing_query_stats', 'bing_page_stats', 'bing_page_query_stats', 'bing_query_page_stats', 'bing_crawl_stats', 'bing_crawl_issues', 'bing_url_info', 'bing_list_sitemaps', 'bing_sitemap_details'})
EXPECTED46 = OLD35 | BING11
PILOT = 'https://kelleyconstructioninc.com/'
BING_PRIVATE = 'SYNTHETIC_BING_KEY_NOT_ENROLLED+/=%'
PRIVATE = 'SYNTHETIC_PRIVATE_ARGUMENT_AND_UPSTREAM_EXCEPTION'
HARNESS = r'''import builtins
from contextlib import asynccontextmanager
import json
from pathlib import Path
import socket
import sys
import time
import google.auth
from google.oauth2 import service_account
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from google_seo_mcp import server
from google_seo_mcp.consumer_auth import load_consumer_key_registry
from google_seo_mcp.http_app import create_http_app
from google_seo_mcp.runtime_config import load_runtime_config
import uvicorn
control = json.loads(sys.argv[1])
root = Path(control['directory'])
import hashlib
import google_seo_mcp
package = Path(google_seo_mcp.__file__).parent
(root / 'provenance.json').write_text(json.dumps({'package': str(package), 'hashes': {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest() for p in package.rglob('*') if p.is_file() and (p.suffix == '.py' or p.name == 'production_tools.json')}}))
original_run = StreamableHTTPSessionManager.run

@asynccontextmanager
async def observed(self):
    async with original_run(self):
        yield
    (root / 'shutdown.json').write_text(json.dumps({'original_manager_exited': True, 'task_group_cleared': self._task_group is None, 'server_instances_empty': not self._server_instances}))
StreamableHTTPSessionManager.run = observed
if control['slow']:

    def slow():
        from google_seo_mcp.consumer_auth import consumer_context
        identity = consumer_context.get().consumer_id
        with (root / 'entered').open('a') as output:
            output.write(identity + '\n')
        time.sleep(2)
        return {'consumer': identity}

    def upstream_error(site_url: str):
        raise RuntimeError('SYNTHETIC_PRIVATE_ARGUMENT_AND_UPSTREAM_EXCEPTION')
    server._LEGACY_TOOL_DEFINITIONS = [(slow if name == 'gsc_list_sites' else upstream_error if name == 'gsc_list_sitemaps' else fn, name) for fn, name in server._LEGACY_TOOL_DEFINITIONS]

def forbidden(*args, **kwargs):
    (root / 'forbidden-attempt').write_text('attempted')
    raise AssertionError('PROVIDER_OR_FILE_ATTEMPT')
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden
socket.getaddrinfo = forbidden
google.auth.default = forbidden
service_account.Credentials.from_service_account_file = forbidden
config = load_runtime_config([])
instance = server.create_server(config)
app = create_http_app(config, load_consumer_key_registry(config.consumer_keys_file), instance)
if control['reflection']:
    import httpx
    from urllib.parse import quote
    from google_seo_mcp.bing.client import BingReadClient
    from google_seo_mcp.bing.tools import configure_bing_tools

    def reflect(request):
        with (root / 'synthetic-upstream').open('a') as output:
            output.write('one fake attempt\n')
        key = request.url.params['apikey']
        mode = control['reflection']
        if mode == 'exception':
            raise RuntimeError(str(request.url))
        value = quote(key, safe='') if mode == 'encoded' else ''.join(('\\u%04x' % ord(c) for c in key)) if mode == 'escaped' else key
        return httpx.Response(200, json={'d': [], 'unknown': {'nested': [{'value': value}]}})
    configure_bing_tools(BingReadClient(transport=httpx.MockTransport(reflect), max_retries=0))
if control['deny_bing_io']:
    from google_seo_mcp.bing import auth as bing_auth, client as bing_client
    bing_auth._read = forbidden
    bing_auth.BingCredentialLoader.load = forbidden
    bing_client.BingReadClient.__init__ = forbidden
original_open, original_path_open = (builtins.open, Path.open)

def guarded_open(file, *args, **kwargs):
    if 'SYNTHETIC_PRIVATE' in str(file):
        return forbidden()
    return original_open(file, *args, **kwargs)

def guarded_path_open(self, *args, **kwargs):
    if 'SYNTHETIC_PRIVATE' in str(self):
        return forbidden()
    return original_path_open(self, *args, **kwargs)
builtins.open, Path.open = (guarded_open, guarded_path_open)
from contextlib import contextmanager
import signal
original_lifespan = app.app.router.lifespan_context
@asynccontextmanager
async def record_startup(application):
    try:
        async with original_lifespan(application):
            yield
    except RuntimeError as error:
        if type(error) is RuntimeError and error.args in (('credentials_missing',), ('credentials_invalid',)):
            (root / 'startup-refusal.json').write_text(json.dumps({'code': error.args[0]}))
        raise
app.app.router.lifespan_context = record_startup
class FixtureServer(uvicorn.Server):
    @contextmanager
    def capture_signals(self):
        prior = {sig: signal.signal(sig, self.handle_exit) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            yield
        finally:
            for sig, handler in prior.items():
                signal.signal(sig, handler)
if control['peer_scope']:
    import asyncio
    import httpx
    async def exercise_peer():
        async with app.app.router.lifespan_context(app.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('203.0.113.42', 49152)), base_url=f'http://127.0.0.1:{config.port}', trust_env=False) as client:
                response = await client.get('/readyz', headers={'X-Forwarded-For': '127.0.0.1', 'Forwarded': 'for=127.0.0.1;host="localhost"'})
                (root / 'peer-response.json').write_text(json.dumps({'status_code': response.status_code, 'body': response.json()}))
    asyncio.run(exercise_peer())
else:
    runner = FixtureServer(uvicorn.Config(app, host=config.host, port=config.port, access_log=False, proxy_headers=False, log_config=None))
    runner.run()
    if not runner.started:
        raise SystemExit(3)
'''

def interpreter():
    selected = os.environ.get('GOOGLE_SEO_TEST_PYTHON', sys.executable)
    assert Path(selected).is_absolute() and Path(selected).is_file()
    return selected

class LiveServer:

    def __init__(self, directory, *, slow=False, entries=None, port=None, google='pending', bing_key='pending', bing_policy='pending', require_google=False, require_bing=False, deny_bing_io=False, reflection=None, peer_scope=False):
        self.directory = directory
        self.directory.mkdir(mode=448)
        home = directory / 'empty-home'
        home.mkdir()
        self.keys = {name: secrets.token_urlsafe(32) for name in ('alpha', 'beta', 'revoked')}
        self.registry = directory / 'consumers.json'
        self.entries = entries or [{'consumer_id': name, 'key_id': name + '-key', 'sha256': hashlib.sha256(key.encode('ascii')).hexdigest(), 'enabled': name != 'revoked'} for name, key in self.keys.items()]
        self.write_registry()
        if port is None:
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
        self.port = port
        self.url = f'http://127.0.0.1:{port}'
        self.environment = {'HOME': str(home), 'TMPDIR': str(home), 'LANG': 'C.UTF-8', 'PATH': f'{Path(interpreter()).parent}:/usr/local/bin:/usr/bin:/bin', 'PYTHONUNBUFFERED': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'GOOGLE_SEO_TRANSPORT': 'streamable-http', 'GOOGLE_SEO_HOST': '0.0.0.0', 'GOOGLE_SEO_PORT': str(port), 'GOOGLE_SEO_CONSUMER_KEYS_FILE': str(self.registry), 'GOOGLE_SEO_OAUTH_PROPEL_DMS_FILE': str(directory / 'intentionally-missing.json'), 'GOOGLE_SEO_REVISION': 'b' * 40, 'GOOGLE_SEO_AUTH_MODE': 'dual-user-oauth', 'GOOGLE_SEO_OAUTH_CLIENT_FILE': str(__import__('pathlib').Path(str(directory / 'intentionally-missing.json')).with_name('google-seo-oauth-client.json')), 'GOOGLE_SEO_OAUTH_ADDOURTEAM99_FILE': str(__import__('pathlib').Path(str(directory / 'intentionally-missing.json')).with_name('google-seo-oauth-addourteam99.json'))}
        self.slow = slow
        self.deny_bing_io = deny_bing_io
        self.reflection = reflection
        self.peer_scope = peer_scope
        self.startup_refusal = require_google and google != 'available'
        self.google_state = 'missing' if google == 'pending' else google
        self.process = None
        self.environment.update({'GOOGLE_SEO_BING_CREDENTIALS_FILE': str(directory / 'synthetic-bing-key.json'), 'GOOGLE_SEO_BING_SITES_FILE': str(directory / 'synthetic-bing-policy.json'), 'GOOGLE_SEO_REQUIRE_BING_CREDENTIALS': str(require_bing).lower(), 'GOOGLE_SEO_REQUIRE_GOOGLE_CREDENTIALS': str(require_google).lower()})
        documents = [(bing_key, 'GOOGLE_SEO_BING_CREDENTIALS_FILE', {'version': 1, 'api_key': BING_PRIVATE}), (bing_policy, 'GOOGLE_SEO_BING_SITES_FILE', {'version': 1, 'sites': [PILOT]})]
        # Both named OAuth slots and their shared, explicitly approved Desktop client.
        client_id = '123456789012-httpfixture.apps.googleusercontent.com'
        project_id = 'synthetic-http-fixture'
        shared_secret = secrets.token_urlsafe(32)
        self.environment.update({'GOOGLE_SEO_APPROVED_CLIENT_ID': client_id,
                                 'GOOGLE_SEO_APPROVED_PROJECT_ID': project_id})
        client_document = {'installed': {'client_id': client_id, 'project_id': project_id,
            'client_secret': shared_secret, 'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
            'token_uri': 'https://oauth2.googleapis.com/token'}}
        documents.append((google, 'GOOGLE_SEO_OAUTH_CLIENT_FILE', client_document))
        for account, variable in [('propel-dms', 'GOOGLE_SEO_OAUTH_PROPEL_DMS_FILE'),
                                  ('addourteam99', 'GOOGLE_SEO_OAUTH_ADDOURTEAM99_FILE')]:
            documents.append((google, variable, {'version': 1, 'account_id': account,
                'client_id': client_id, 'client_secret': shared_secret,
                'refresh_token': secrets.token_urlsafe(32),
                'token_uri': 'https://oauth2.googleapis.com/token',
                'scopes': ['https://www.googleapis.com/auth/webmasters.readonly',
                           'https://www.googleapis.com/auth/analytics.readonly']}))
        for state, variable, document in documents:
            assert state in ('pending', 'invalid', 'available')
            if state != 'pending':
                path = Path(self.environment[variable])
                with open(path, 'x', opener=lambda p, flags: os.open(p, flags, 384)) as output:
                    output.write(json.dumps(document) if state == 'available' else PRIVATE)

    def write_registry(self):
        with open(self.registry, 'w', opener=lambda p, flags: os.open(p, flags, 384)) as output:
            output.write(json.dumps({'version': 1, 'consumers': self.entries}))

    def start(self):
        self.stdout = (self.directory / 'stdout').open('w')
        self.stderr = (self.directory / 'stderr').open('w')
        self.process = _oauth_http_popen([interpreter(), '-c', HARNESS, json.dumps({'directory': str(self.directory), 'slow': self.slow, 'deny_bing_io': self.deny_bing_io, 'reflection': self.reflection, 'peer_scope': self.peer_scope})], env=self.environment, cwd=self.directory, stdout=self.stdout, stderr=self.stderr)
        deadline = time.monotonic() + 25
        if self.startup_refusal or self.peer_scope:
            self.process.wait(timeout=25)
            if self.startup_refusal:
                assert self.process.returncode != 0
                assert json.loads((self.directory / 'startup-refusal.json').read_text()) == {
                    'code': 'credentials_missing' if self.google_state == 'missing' else 'credentials_invalid'}
                with httpx.Client(trust_env=False, timeout=1) as client:
                    with pytest.raises(httpx.TransportError):
                        client.get(self.url + '/healthz')
                assert not (self.directory / 'shutdown.json').exists()
            else:
                assert self.process.returncode == 0
            self.verify_source()
            return self
        with httpx.Client(trust_env=False, timeout=1) as client:
            while time.monotonic() < deadline:
                assert self.process.poll() is None, self.logs()
                try:
                    result = client.get(self.url + '/healthz')
                    if result.status_code == 200:
                        assert result.json() == {'status': 'ok'}
                        self.verify_source()
                        return self
                except httpx.TransportError:
                    pass
                time.sleep(0.025)
        raise AssertionError('test server did not become healthy')

    def verify_source(self):
        package = ROOT / 'src/google_seo_mcp'
        expected = {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest() for p in package.rglob('*') if p.is_file() and (p.suffix == '.py' or p.name == 'production_tools.json')}
        provenance = json.loads((self.directory / 'provenance.json').read_text())
        assert provenance['hashes'] == expected, ('HTTP child is not the current candidate; build/install a fresh wheel and set GOOGLE_SEO_TEST_PYTHON (no PYTHONPATH injection)', provenance['package'])

    def logs(self):
        return (self.directory / 'stderr').read_text()

    def stop(self):
        try:
            _owned_http_process = getattr(self, 'process', None)
            try:
                if self.process is None:
                    return
                started = time.monotonic()
                if self.process.poll() is None:
                    self.process.terminate()
                try:
                    self.process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
                    pytest.fail('SIGTERM did not shut down promptly')
                self.stdout.close()
                self.stderr.close()
                assert time.monotonic() - started < 8
                if self.startup_refusal:
                    assert self.process.returncode != 0
                    assert not (self.directory / 'shutdown.json').exists()
                else:
                    assert self.process.returncode in (0, -signal.SIGTERM)
                    assert json.loads((self.directory / 'shutdown.json').read_text()) == {'original_manager_exited': True, 'task_group_cleared': True, 'server_instances_empty': True}
                assert (self.directory / 'stdout').read_text() == ''
                assert not (self.directory / 'forbidden-attempt').exists()
                assert PRIVATE not in self.logs()
                assert 'SYNTHETIC_BING_KEY' not in self.logs()
                assert all((key not in self.logs() for key in self.keys.values()))
                for line in self.logs().splitlines():
                    row = json.loads(line)
                    assert set(row) <= {'request_id', 'consumer', 'tool', 'outcome', 'duration_ms', 'status'}
                    assert len(row['request_id']) == 32
            finally:
                if _owned_http_process is not None:
                    try:
                        if _owned_http_process.poll() is None:
                            _owned_http_process.kill()
                            _owned_http_process.wait(timeout=10)
                    finally:
                        try:
                            if _owned_http_process.stdout is not None:
                                _owned_http_process.stdout.close()
                        finally:
                            if _owned_http_process.stderr is not None:
                                _owned_http_process.stderr.close()
                    _proof = getattr(_owned_http_process, '_oauth_fixture_proof', None)
                    if _proof is not None:
                        _owned_http_process._oauth_fixture_proof = None
                        _verify, _record = _proof
                        _verify(_record)
        finally:
            try:
                _capture = getattr(self, 'stderr', None)
                if _capture is not None:
                    _capture.close()
            finally:
                _capture = getattr(self, 'stdout', None)
                if _capture is not None:
                    _capture.close()

    def headers(self, name='alpha'):
        return {'Authorization': 'Bearer ' + self.keys[name], 'X-Consumer': PRIVATE}

@pytest.fixture(scope='module')
def _http_fixture_root():
    # Seq376: custody admission precedes leaf semantics. Never chmod an ancestor.
    parent = Path('/home/propel/work')
    for path in (*reversed(parent.parents), parent):
        observed = path.lstat()
        assert path.is_dir() and not path.is_symlink()
        assert observed.st_uid in (0, os.getuid()) and not observed.st_mode & 0o022
    root = Path(tempfile.mkdtemp(prefix='google-seo-http-', dir=parent))
    (root / 'ORIGIN.md').write_text(
        'owner: Cypher\npurpose: seq376 synthetic HTTP custody fixtures\n'
        'source: google-seo-mcp-claude-code/tests/test_http_transport.py\n'
        'expiry: assignment close-out + 14 days\n'
        'memory_bank: thread_90cb25ccf4934169 seq376\n'
        'contains_secrets: synthetic test material only; no enrolled secrets\n'
        'disposal: hold for Coordinator audit\n')
    assert root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o777 == 0o700
    return root


@pytest.fixture
def tmp_path(_http_fixture_root):
    # Module-local routing also covers the direct LiveServer recreation case.
    return Path(tempfile.mkdtemp(prefix='case-', dir=_http_fixture_root))


@pytest.fixture
def launch(tmp_path):
    servers = []

    def factory(**kwargs):
        server = LiveServer(tmp_path / f'server-{len(servers)}', **kwargs)
        servers.append(server)
        return server.start()
    yield factory
    for server in reversed(servers):
        server.stop()

async def sdk_catalog(server, identity='alpha', path='/mcp', calls=()):
    async with httpx.AsyncClient(headers=server.headers(identity), trust_env=False) as http, streamable_http_client(server.url + path, http_client=http) as (read, write, _), ClientSession(read, write) as session:
        initialized = await session.initialize()
        assert initialized.serverInfo.name == 'google-seo-mcp'
        cursor, names, seen = (None, [], set())
        while True:
            page = await session.list_tools(cursor=cursor)
            names.extend((tool.name for tool in page.tools))
            for tool in page.tools:
                if tool.name in BING11:
                    assert tool.annotations.readOnlyHint is True
                    assert tool.annotations.destructiveHint is False
                    assert tool.annotations.openWorldHint is False
                    properties = tool.inputSchema.get('properties', {})
                    assert not set(properties) & {'api_key', 'path', 'endpoint', 'client', 'config'}
                    if tool.name == 'bing_list_sites':
                        assert properties == {}
                    else:
                        assert properties['site_url']['type'] == 'string'
                        assert 'site_url' in tool.inputSchema['required']
                    if 'limit' in properties:
                        assert properties['limit']['type'] == 'integer'
                        assert properties['limit']['default'] == 100
            cursor = page.nextCursor
            if cursor is None:
                break
            assert cursor not in seen
            seen.add(cursor)
        assert len(OLD35) == 35 and len(BING11) == 11 and (not OLD35 & BING11)
        assert len(names) == len(set(names)) == 46
        assert set(names) == EXPECTED46
        results = []
        for name, arguments in calls:
            results.append(await session.call_tool(name, arguments))
        return results

def rpc(tool, arguments=None, request_id=1):
    return {'jsonrpc': '2.0', 'id': request_id, 'method': 'tools/call', 'params': {'name': tool, 'arguments': arguments or {}}}

def rpc_headers(server, name='alpha'):
    return server.headers(name) | {'Accept': 'application/json, text/event-stream', 'Content-Type': 'application/json'}

def test_sdk_exact_catalog_both_paths_two_validated_identities_and_pending_health(launch):
    server = launch()
    with httpx.Client(trust_env=False) as http:
        result = http.get(server.url + '/readyz')
        assert result.status_code == 503
        assert result.json() == {'status': 'credential-pending', 'transport_ready': True, 'google_credentials_state': 'missing', 'google_credentials_required': False, 'bing_credentials_state': 'pending', 'revision': 'b' * 40}
    for identity in ('alpha', 'beta'):
        for path in ('/mcp', '/mcp/'):
            asyncio.run(sdk_catalog(server, identity, path))
    rows = [json.loads(line) for line in server.logs().splitlines()]
    for identity in ('alpha', 'beta'):
        assert any((row['consumer'] == identity and row.get('status') == 200 for row in rows))

def test_every_method_alias_missing_malformed_unknown_revoked_and_duplicate_key_is_401(launch):
    server = launch()
    with httpx.Client(trust_env=False) as http:
        invalid = [[], [('Authorization', 'Bearer')], [('Authorization', 'Basic private')], [('Authorization', 'Bearer unknown-synthetic')], list(server.headers('revoked').items()), [('Authorization', 'Bearer ' + server.keys['alpha'])] * 2]
        for method in ('GET', 'POST', 'DELETE', 'OPTIONS', 'PATCH', 'HEAD'):
            for path in ('/mcp', '/mcp/', '/sse', '/messages', '/unknown-alias'):
                for headers in invalid:
                    response = http.request(method, server.url + path, headers=headers)
                    assert response.status_code == 401, (method, path, response.status_code)
                    assert response.headers['www-authenticate'] == 'Bearer'
                    if method != 'HEAD':
                        assert response.json() == {'error': 'unauthorized'}
        for path in ('/sse', '/messages', '/unknown-alias'):
            assert http.get(server.url + path, headers=server.headers()).status_code == 404
        assert http.post(server.url + '/healthz').status_code == 401
        assert http.get(server.url + '/healthz/').status_code == 401
        for path in ('/mcp', '/mcp/'):
            for method in ('GET', 'DELETE', 'OPTIONS'):
                with http.stream(method, server.url + path, headers=rpc_headers(server)) as result:
                    assert result.status_code in ((200, 405) if method == 'GET' else (405,))
                    if result.status_code == 200:
                        assert result.headers['content-type'].startswith('text/event-stream')

def test_host_origin_duplicates_and_forwarded_host_spoofs_fail_closed(launch):
    server = launch()
    with httpx.Client(trust_env=False) as http:
        cases = [{'Host': 'hostile.invalid'}, {'Origin': 'https://hostile.invalid'}, {'Origin': 'null'}, {'Origin': 'https://google-seo.mcp.propel.marketing.evil'}, {'Host': 'hostile.invalid', 'X-Forwarded-Host': f'127.0.0.1:{server.port}'}]
        for case in cases:
            assert http.post(server.url + '/mcp', headers=server.headers() | case).status_code == 403
        duplicate = list(server.headers().items()) + [('Origin', 'https://google-seo.mcp.propel.marketing'), ('Origin', 'https://google-seo.mcp.propel.marketing')]
        assert http.post(server.url + '/mcp', headers=duplicate).status_code == 403
        assert http.get(server.url + '/healthz', headers={'Host': 'hostile.invalid'}).status_code == 403
        assert http.get(server.url + '/readyz', headers={'X-Forwarded-For': '203.0.113.42'}).status_code == 503
    with socket.create_connection(('127.0.0.1', server.port), timeout=3) as sock:
        request = f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\nHost: 127.0.0.1:{server.port}\r\nAuthorization: Bearer {server.keys['alpha']}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode('ascii'))
        assert sock.recv(4096).split(b' ')[1] in (b'400', b'403')

def test_remote_actual_peer_cannot_spoof_local_readiness(launch):
    # Application-level ASGI peer admission, NOT native-interface/network proof.
    server = launch(peer_scope=True)
    response = json.loads((server.directory / 'peer-response.json').read_text())
    assert response['status_code'] == 403
    assert response['body'] == {'error': 'local_only'}


def test_declared_and_chunked_body_above_four_mib_rejected_before_sdk(launch):
    server = launch()
    with httpx.Client(trust_env=False, timeout=10) as http:
        oversized = b'x' * (4 * 1024 * 1024 + 1)
        for content in (oversized, iter((oversized[:2 * 1024 * 1024], oversized[2 * 1024 * 1024:]))):
            result = http.post(server.url + '/mcp', headers=server.headers(), content=content)
            assert result.status_code == 413
            assert result.json()['error'] in ('invalid_body_size', 'body_too_large')
    with socket.create_connection(('127.0.0.1', server.port), timeout=3) as sock:
        sock.sendall(f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\nAuthorization: Bearer {server.keys['alpha']}\r\nContent-Length: 4194305\r\nConnection: close\r\n\r\n".encode())
        assert sock.recv(4096).split(b' ')[1] == b'413'

def test_sixty_per_minute_rate_isolated_per_consumer(launch):
    server = launch()
    with httpx.Client(trust_env=False) as http:
        responses = [http.get(server.url + '/unknown', headers=server.headers()) for _ in range(61)]
        assert [r.status_code for r in responses[:60]] == [404] * 60
        assert responses[60].status_code == 429
        assert responses[60].json() == {'error': 'rate_limit'}
        assert int(responses[60].headers['retry-after']) > 0
        assert http.get(server.url + '/unknown', headers=server.headers('beta')).status_code == 404
        assert http.get(server.url + '/healthz').status_code == 200

def test_two_sync_calls_offload_worker_keep_health_responsive_and_third_is_429(launch):
    server = launch(slow=True, google='available')

    async def exercise():
        async with httpx.AsyncClient(trust_env=False, timeout=10) as http:

            async def call(identity='alpha'):
                return await http.post(server.url + '/mcp', json=rpc('gsc_list_sites'), headers=rpc_headers(server, identity))
            first, second = (asyncio.create_task(call()), asyncio.create_task(call()))
            try:
                deadline = time.monotonic() + 5
                while True:
                    marker = server.directory / 'entered'
                    if marker.exists() and len(marker.read_text().splitlines()) == 2:
                        break
                    assert time.monotonic() < deadline
                    await asyncio.sleep(0.01)
                started = time.monotonic()
                health = await http.get(server.url + '/healthz')
                assert health.status_code == 200 and time.monotonic() - started < 0.75
                third = await call()
                assert third.status_code == 429 and third.json() == {'error': 'concurrency_limit'}
                assert int(third.headers['retry-after']) >= 1
                beta = asyncio.create_task(call('beta'))
                for result in await asyncio.gather(first, second, beta):
                    assert result.status_code == 200 and (not result.json()['result'].get('isError'))
                assert (server.directory / 'entered').read_text().splitlines() == ['alpha', 'alpha', 'beta']
                result = await call()
                assert result.status_code == 200
            finally:
                await asyncio.gather(first, second, return_exceptions=True)
    asyncio.run(exercise())

def test_google_vendor_missing_and_fenced_direct_calls_never_network_or_open(launch):
    server = launch()
    fenced = ('gsc_submit_sitemap', 'google_indexing_publish', 'google_indexing_delete', 'indexnow_submit', 'indexnow_submit_sitemap', 'indexnow_generate_key', 'logs_parse', 'history_list', 'history_save_snapshot', 'migration_wp_audit_site', 'schema_extract_url', 'aeo_llms_txt_check', 'lighthouse_audit', 'crawl_url', 'get_capabilities', 'reauthenticate', 'reload_credentials', 'gsc_list_sites_alias', '../gsc_list_sites', 'GSC_LIST_SITES')
    results = asyncio.run(sdk_catalog(server, calls=[(name, {'path': '/' + PRIVATE, 'url': 'https://' + PRIVATE + '.invalid'}) for name in fenced] + [('gsc_list_sites', {}), ('serp_check', {'keyword': 'offline'})]))
    for result in results[:-2]:
        assert result.isError and 'tool_not_allowed' in result.model_dump_json()
        assert PRIVATE not in result.model_dump_json()
    assert results[-2].isError and 'agency_discovery_incomplete' in results[-2].model_dump_json()
    # Seq376 / seq270 B08: absent own-provider egress set refuses the result.
    assert results[-1].isError and 'provider_unavailable' in results[-1].model_dump_json()
    assert not (server.directory / 'forbidden-attempt').exists()
    assert not (server.directory / 'forbidden-attempt').exists()
    rows = [json.loads(line) for line in server.logs().splitlines()]
    assert any((row['consumer'] == 'alpha' and row['tool'] == 'denied' for row in rows))

def test_upstream_exception_redacted_and_positive_identity_tool_audit(launch):
    server = launch(slow=True)
    results = asyncio.run(sdk_catalog(server, 'beta', calls=[('gsc_list_sitemaps', {'site_url': PRIVATE})]))
    assert results[0].isError and 'provider_unavailable' in results[0].model_dump_json()
    assert PRIVATE not in results[0].model_dump_json()
    rows = [json.loads(line) for line in server.logs().splitlines()]
    assert any((row['consumer'] == 'beta' and row['tool'] == 'gsc_list_sitemaps' and (row['outcome'] == 'error') for row in rows))

def test_recreate_registry_revocation_new_acceptance_no_stale_identity(tmp_path):
    first = LiveServer(tmp_path / 'first').start()
    try:
        asyncio.run(sdk_catalog(first))
    finally:
        first.stop()
    replacement = LiveServer(tmp_path / 'replacement', port=first.port)
    replacement.keys['old'] = first.keys['alpha']
    replacement.entries.append({'consumer_id': 'alpha', 'key_id': 'retired-key', 'sha256': hashlib.sha256(first.keys['alpha'].encode()).hexdigest(), 'enabled': False})
    replacement.write_registry()
    replacement.start()
    try:
        with httpx.Client(trust_env=False) as http:
            assert http.post(replacement.url + '/mcp', headers={'Authorization': 'Bearer ' + first.keys['alpha']}).status_code == 401
        asyncio.run(sdk_catalog(replacement, 'beta'))
        rows = [json.loads(line) for line in replacement.logs().splitlines()]
        assert any((row['consumer'] is None and row.get('status') == 401 for row in rows))
        assert any((row['consumer'] == 'beta' and row.get('status') == 200 for row in rows))
    finally:
        replacement.stop()

@pytest.mark.parametrize('required', [False, True])
@pytest.mark.parametrize('key_state', ['pending', 'invalid', 'available'])
@pytest.mark.parametrize('policy_state', ['pending', 'invalid', 'available'])
def test_pending_vs_required_readiness_missing_bing_does_not_break_google_readiness(launch, required, key_state, policy_state):
    server = launch(google='available', bing_key=key_state, bing_policy=policy_state, require_google=True, require_bing=required)
    state = key_state  # All retired policy variants must leave key-only readiness unchanged.
    status = 'credential-pending' if required and state == 'pending' else 'credentials-invalid' if required and state == 'invalid' else 'transport-ready'
    with httpx.Client(trust_env=False) as http:
        for _ in range(2):
            response = http.get(server.url + '/readyz')
            assert response.status_code == (503 if required and state != 'available' else 200)
            assert response.headers['cache-control'] == 'no-store'
            assert response.json() == {'status': status, 'transport_ready': True, 'google_credentials_state': 'available', 'google_credentials_required': True, 'bing_credentials_state': state, 'revision': 'b' * 40}
        health = http.get(server.url + '/healthz')
        assert health.status_code == 200 and health.json() == {'status': 'ok'}
    assert not (server.directory / 'forbidden-attempt').exists()

@pytest.mark.parametrize('google', ['pending', 'invalid'])
@pytest.mark.parametrize('required', [False, True])
def test_bing_available_preserves_google_status_and_required_gate(launch, google, required):
    server = launch(google=google, bing_key='available', bing_policy='available', require_google=required, require_bing=True)
    if required:
        # Fail-closed startup/no listener is verified by start(), before manager entry.
        assert json.loads((server.directory / 'startup-refusal.json').read_text()) == {
            'code': 'credentials_missing' if google == 'pending' else 'credentials_invalid'}
        return
    with httpx.Client(trust_env=False) as http:
        response = http.get(server.url + '/readyz')
        assert response.status_code == 503
        assert response.json() == {'status': 'credential-pending' if google == 'pending' else 'credentials-invalid', 'transport_ready': True, 'google_credentials_state': 'missing' if google == 'pending' else 'invalid', 'google_credentials_required': False, 'bing_credentials_state': 'available', 'revision': 'b' * 40}
        assert http.get(server.url + '/healthz').status_code == 200

def bing_calls():
    return [('bing_list_sites', {}), ('bing_rank_traffic_stats', {'site_url': PILOT}), ('bing_query_stats', {'site_url': PILOT}), ('bing_page_stats', {'site_url': PILOT}), ('bing_page_query_stats', {'site_url': PILOT, 'page_url': PILOT + 'page'}), ('bing_query_page_stats', {'site_url': PILOT, 'query': 'synthetic'}), ('bing_crawl_stats', {'site_url': PILOT}), ('bing_crawl_issues', {'site_url': PILOT}), ('bing_url_info', {'site_url': PILOT, 'url': PILOT + 'page'}), ('bing_list_sitemaps', {'site_url': PILOT}), ('bing_sitemap_details', {'site_url': PILOT, 'sitemap_url': PILOT + 'sitemap.xml'})]

def test_pending_bing_calls_no_network_real_sdk_all_eleven(launch):
    server = launch()
    calls = bing_calls()
    assert {name for name, _ in calls} == BING11
    results = asyncio.run(sdk_catalog(server, calls=calls))
    for result in results:
        # Seq376 / seq270 B08 supersedes the pre-egress pending-provider payload.
        assert result.isError and 'provider_unavailable' in result.model_dump_json()
    assert not (server.directory / 'forbidden-attempt').exists()

def test_bing_strict_schema_coercion_and_unknown_args_fail_before_io(launch):
    server = launch(deny_bing_io=True)
    calls = []
    for name, arguments in bing_calls():
        calls.append((name, arguments | {'endpoint': PRIVATE}))
        if name not in ('bing_list_sites', 'bing_url_info'):
            for limit in (True, '1', 1.0):
                calls.append((name, arguments | {'limit': limit}))
    calls.extend([('bing_query_stats', {'site_url': PILOT, 'start_date': '2026-01-01'}), ('bing_query_stats', {'site_url': PILOT, 'start_date': '2026-02-30', 'end_date': '2026-03-01'}), ('bing_query_page_stats', {'site_url': PILOT}), ('bing_query_page_stats', {'site_url': PILOT, 'query': 1}), ('bing_page_query_stats', {'site_url': PILOT, 'page_url': 'https://other.invalid/'}), ('bing_url_info', {'site_url': PILOT, 'url': 'http://127.0.0.1/'}), ('bing_sitemap_details', {'site_url': PILOT, 'sitemap_url': 'domain:example.invalid'})])
    results = asyncio.run(sdk_catalog(server, calls=calls))
    for result in results:
        assert result.isError
        assert any((code in result.model_dump_json() for code in ('invalid_tool_arguments', 'invalid_request')))
        assert PRIVATE not in result.model_dump_json()
    assert not (server.directory / 'forbidden-attempt').exists()

@pytest.mark.parametrize('reflection', ['raw', 'encoded', 'escaped', 'exception'])
def test_bing_failure_redaction_nested_payload(launch, reflection):
    from urllib.parse import quote
    server = launch(bing_key='available', bing_policy='available', reflection=reflection)
    results = asyncio.run(sdk_catalog(server, calls=[('bing_query_stats', {'site_url': PILOT})]))
    result = results[0]
    assert not result.isError
    data = json.loads(result.content[0].text)
    assert data['data']['status'] == 'provider_error'
    assert data['data']['error']['code'] == ('transport_error' if reflection == 'exception' else 'credential_reflection')
    serialized = result.model_dump_json() + server.logs()
    assert BING_PRIVATE not in serialized and quote(BING_PRIVATE, safe='') not in serialized
    assert 'SYNTHETIC_BING_KEY' not in serialized
    assert '\\\\u0053\\\\u0059' not in serialized
    attempts = (server.directory / 'synthetic-upstream').read_text().splitlines()
    assert attempts == ['one fake attempt']
    assert not (server.directory / 'forbidden-attempt').exists()

def test_all_bing_write_names_aliases_and_unknowns_denied_pre_sink(launch):
    server = launch(deny_bing_io=True)
    names = ('bing_submit_url', 'bing_submit_url_batch', 'bing_submit_content', 'bing_submit_sitemap', 'bing_submit_feed', 'bing_remove_feed', 'bing_add_site', 'bing_remove_site', 'bing_verify_site', 'bing_fetch_url', 'bing_save_crawl_settings', 'bing_call_method', 'bing_get_keyword', 'bing_query_traffic_stats', 'bing_list_sites_alias', 'BING_LIST_SITES', '../bing_list_sites', 'GetUserSites', 'SubmitUrl', 'FetchUrl', 'configure_bing_tools')
    results = asyncio.run(sdk_catalog(server, calls=[(name, {'path': PRIVATE}) for name in names]))
    for result in results:
        assert result.isError and 'tool_not_allowed' in result.model_dump_json()
        assert PRIVATE not in result.model_dump_json()
    assert not (server.directory / 'forbidden-attempt').exists()


def _oauth_http_popen(command, *args, **kwargs):
    # Permanent prepare returns env, child prefix, and deferred provenance proof.
    import importlib.util
    from pathlib import Path
    _spec = importlib.util.spec_from_file_location('_oauth_http_startup_fixture', Path(__file__).with_name('test_production_startup.py'))
    _startup_fixture = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_startup_fixture)
    _prepare_oauth_child = _startup_fixture._child_provenance
    _verify_oauth_child = _startup_fixture._assert_child_provenance
    command = list(command)
    index = command.index('-c') + 1
    original_code = command[index]
    env, prefix, proof = _prepare_oauth_child(dict(kwargs['env']), _startup_fixture.sys.executable)
    env['GOOGLE_SEO_HOST'] = '127.0.0.1'
    kwargs['env'] = env
    command[index] = _http_loopback_bootstrap(_startup_fixture.GUARDED_BOOT) + prefix + (original_code or "runpy.run_module('google_seo_mcp', run_name='__main__')")
    process = subprocess.Popen(command, *args, **kwargs)
    # No TemporaryDirectory owner is returned. Preserve evidence; stop owns pipes.
    process._oauth_fixture_proof = (_verify_oauth_child, proof)
    return process


def _http_loopback_bootstrap(strict_bootstrap):
    """Keep provider denials, adapting only sockets for an owned local HTTP server.

    Capture before the stricter startup helper replaces socket methods. Numeric
    loopback only; no wildcard binds, DNS resolution, public connects or listeners.
    The generic startup helper and its users retain their original strict policy.
    """
    before = r"""
import ipaddress as _http_ipaddress
import socket as _http_socket
_http_dns = _http_socket.getaddrinfo
_http_bind = _http_socket.socket.bind
_http_connect = _http_socket.socket.connect
_http_connect_ex = _http_socket.socket.connect_ex
"""
    after = r"""
def _http_local(host):
    try:
        return _http_ipaddress.ip_address(host.decode('ascii') if isinstance(host, bytes) else host).is_loopback
    except (ValueError, UnicodeError, TypeError):
        return False

def _http_dns_only(host, port, *args, **kwargs):
    if host in ('localhost', b'localhost'):
        host = '127.0.0.1'
    if not _http_local(host):
        raise AssertionError('PUBLIC_DNS_REFUSED')
    if len(args) >= 4:
        args = (*args[:3], args[3] | _http_socket.AI_NUMERICHOST, *args[4:])
    else:
        kwargs['flags'] = kwargs.get('flags', 0) | _http_socket.AI_NUMERICHOST
    return _http_dns(host, port, *args, **kwargs)

def _http_check_address(sock, address):
    if sock.family not in (_http_socket.AF_INET, _http_socket.AF_INET6) or not isinstance(address, tuple) or not address or not _http_local(address[0]):
        raise AssertionError('PUBLIC_SOCKET_REFUSED')

def _http_bind_only(sock, address):
    _http_check_address(sock, address)
    return _http_bind(sock, address)

def _http_connect_only(sock, address):
    _http_check_address(sock, address)
    return _http_connect(sock, address)

def _http_connect_ex_only(sock, address):
    _http_check_address(sock, address)
    return _http_connect_ex(sock, address)

_http_socket.getaddrinfo = _http_dns_only
_http_socket.socket.bind = _http_bind_only
_http_socket.socket.connect = _http_connect_only
_http_socket.socket.connect_ex = _http_connect_ex_only
"""
    return before + strict_bootstrap + after
