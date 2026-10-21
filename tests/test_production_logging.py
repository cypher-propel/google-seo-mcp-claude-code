"""Offline hosted Python logging delivery contracts, including real lazy SDK setup.

Each probe runs in a fresh allowlisted empty-HOME process. No enrolled identity or
provider request is needed; GA constructors stop at transport and discovery uses
Google's bundled static documents. Direct native writes are outside this contract.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PRIVATE = "SYNTHETIC_LOGGING_PRIVATE_VALUE"
BOOT = r'''
import asyncio, hashlib, json, logging, socket, sys
from google_seo_mcp import server, auth
from google_seo_mcp.runtime_config import ProductionRuntimeConfig, load_runtime_config
from google_seo_mcp.consumer_auth import (
    AuthenticatedConsumer, ConsumerKeyRegistry, ConsumerKeyEdgeMiddleware,
    consumer_context, request_id_context,
)
attempts = []
def forbidden(*args, **kwargs):
    attempts.append(True)
    raise AssertionError('outbound_forbidden')
socket.getaddrinfo = forbidden
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden
PRIVATE = 'SYNTHETIC_LOGGING_PRIVATE_VALUE'
hosted = ProductionRuntimeConfig(
    transport='streamable-http', profile='production',
    google_auth_mode='dual-user-oauth',
    google_approved_client_id='synthetic.apps.googleusercontent.com',
    google_approved_project_id='synthetic-project',
    google_oauth_client_file='/client.json',
    google_oauth_propel_dms_file='/propel-dms.json',
    google_oauth_addourteam99_file='/addourteam99.json',
    consumer_keys_file='/unused-consumers.json',
)
instance = server.create_server(hosted)
'''


def probe(tmp_path, code, scope=None):
    home = tmp_path / "empty-home"
    home.mkdir(exist_ok=True)
    interpreter = os.environ.get("GOOGLE_SEO_TEST_PYTHON", sys.executable)
    environment = {
        "HOME": str(home), "TMPDIR": str(home), "LANG": "C.UTF-8",
        "PATH": f"{Path(interpreter).parent}:/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
    }
    if "GOOGLE_SEO_TEST_PYTHON" not in os.environ:
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    if scope is not None:
        environment["GOOGLE_SDK_PYTHON_LOGGING_SCOPE"] = scope
    return subprocess.run(
        [interpreter, "-c", BOOT + code], cwd=tmp_path, env=environment,
        text=True, capture_output=True, timeout=30, check=False,
    )


@pytest.mark.parametrize("scope", [None, "google", "google.analytics"])
@pytest.mark.parametrize("client", ["data", "admin", "searchconsole", "webmasters"])
@pytest.mark.parametrize("severity", ["warning", "error", "exception"])
def test_real_offline_constructors_cannot_reopen_logging(tmp_path, scope, client, severity):
    code = r'''
import os, time
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs
import requests
from google.oauth2.credentials import Credentials
from google.api_core import client_logging
from google_seo_mcp.google_accounts import clients, credentials as custody
from google_seo_mcp.google_accounts.models import (
    ACCOUNT_IDS, GOOGLE_SCOPES, TOKEN_URI, GoogleAccountError, GoogleRequestDeadline,
)
# Synthetic documents, not enrolled identities. Redirect only the descriptor
# walk's root to empty HOME; real leaf/owner/mode/read/binding checks still run.
root = Path(os.environ['HOME'])
root.chmod(0o700)
client_id = hosted.google_approved_client_id
client_secret = PRIVATE + '-client'
records = {'client.json': {'installed': {
    'client_id': client_id, 'client_secret': client_secret,
    'project_id': hosted.google_approved_project_id,
    'auth_uri': 'https://accounts.google.com/o/oauth2/v2/auth', 'token_uri': TOKEN_URI,
}}}
for account in ACCOUNT_IDS:
    records[account + '.json'] = {
        'version': 1, 'account_id': account, 'client_id': client_id,
        'client_secret': client_secret, 'refresh_token': PRIVATE + '-' + account,
        'token_uri': TOKEN_URI, 'scopes': sorted(GOOGLE_SCOPES),
    }
for name, record in records.items():
    path = root / name
    path.write_text(json.dumps(record), encoding='utf-8')
    path.chmod(0o600)
original_open = os.open
def fixture_open(path, flags, *args, **kwargs):
    return original_open(str(root) if path == '/' else path, flags, *args, **kwargs)
seen, sends = [], []
def stopped_transport(**kwargs):
    seen.append(kwargs['credentials'].refresh_token)
    raise RuntimeError('offline_transport_stopped')
# Keep real SDK __init__/logging setup. Only the selected GAPIC transport
# factory is stopped, after the registry has built its real REST transports.
factory_name = 'BetaAnalyticsDataClient' if CLIENT == 'data' else 'AnalyticsAdminServiceClient'
factory = getattr(clients, factory_name)
def stopped_client(*, transport):
    return factory(credentials=transport._credentials, transport=stopped_transport)
def wire(adapter, request, **kwargs):
    assert request.method == 'POST' and request.url == TOKEN_URI
    assert kwargs['proxies'] == {} and kwargs['stream'] is True
    assert 0 < kwargs['timeout'] <= 15
    body = parse_qs(request.body.decode() if isinstance(request.body, bytes) else request.body)
    account = next(account for account in ACCOUNT_IDS
                   if body['refresh_token'] == [PRIVATE + '-' + account])
    assert body['client_id'] == [client_id]
    assert body['client_secret'] == [client_secret]
    assert frozenset(body['scope'][0].split()) == GOOGLE_SCOPES
    sends.append(account)
    response = requests.Response()
    response.status_code = 200
    response.url = request.url
    response.headers['Content-Type'] = 'application/json'
    response._content = json.dumps({
        'access_token': PRIVATE + '-access-' + account,
        'token_type': 'Bearer', 'expires_in': 3600,
        'scope': ' '.join(sorted(GOOGLE_SCOPES)),
    }).encode()
    response._content_consumed = True
    return response
registry = auth.get_google_account_registry()
def inspect_sdk(sdk):
    assert sdk.account_id == account
    service = sdk.gsc._inspection if CLIENT == 'searchconsole' else sdk.gsc._webmasters
    assert service._rootDesc['name'] == CLIENT
    credential = service._http._session._credentials
    assert type(credential) is Credentials
    assert credential.client_id == client_id
    assert credential.refresh_token == PRIVATE + '-' + account
    assert frozenset(credential.scopes) == GOOGLE_SCOPES
    return None  # No SDK object escapes the account execution boundary.
with patch.object(custody.os, 'open', fixture_open), patch.object(requests.adapters.HTTPAdapter, 'send', wire):
    try:
        assert tuple(c.account_id for c in registry.loader.load_accounts()) == ACCOUNT_IDS
        for account in ACCOUNT_IDS:
            # Reset only the SDK once flag before each identity's real setup.
            client_logging._LOGGING_INITIALIZED = False
            deadline = GoogleRequestDeadline(end=time.monotonic() + 20)
            if CLIENT in ('data', 'admin'):
                with patch.object(clients, factory_name, stopped_client):
                    try:
                        registry.clients.execute(account, inspect_sdk, deadline)
                    except GoogleAccountError as error:
                        assert error.args == ('agency_discovery_incomplete',)
                    else:
                        raise AssertionError('transport_not_stopped')
                assert seen[-1:] == [PRIVATE + '-' + account]
            else:
                assert registry.clients.execute(account, inspect_sdk, deadline) is None
            assert client_logging._LOGGING_INITIALIZED is True
        assert seen == ([PRIVATE + '-' + account for account in ACCOUNT_IDS]
                        if CLIENT in ('data', 'admin') else [])
        assert sends == ([] if CLIENT in ('data', 'admin') else list(ACCOUNT_IDS))
        # Do not reset logging after real constructor execution.
        logger = logging.getLogger('google.analytics.transport.late')
        try:
            raise RuntimeError(PRIVATE)
        except RuntimeError:
            getattr(logger, SEVERITY)(PRIVATE, extra={'credentialsInfo': PRIVATE, 'metadata': PRIVATE})
        assert attempts == []
    finally:
        # Revocation retires every real bundle/session, including both slots.
        registry.retire()
print('constructor_executed_no_outbound')
'''.replace("CLIENT", repr(client)).replace("SEVERITY", repr(severity))
    result = probe(tmp_path, code, scope)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "constructor_executed_no_outbound\n"
    assert result.stderr == ""


@pytest.mark.parametrize("route", ["root", "existing", "new", "last_resort", "replaced_root"])
def test_late_nonpropagating_handlers_and_fallback_are_guarded(tmp_path, route):
    code = r'''
logger = logging.getLogger('google' if ROUTE == 'existing' else 'late.private.logger')
logger.setLevel(logging.DEBUG)
logger.propagate = False
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(logging.Formatter('%(message)s %(private)s'))
if ROUTE == 'last_resort':
    logger.handlers.clear()
    logging.lastResort = handler
elif ROUTE in ('root', 'replaced_root'):
    logger = logging.getLogger()
    logger.handlers[:] = [handler]
else:
    logger.handlers[:] = [handler]
logger.warning(PRIVATE, extra={'private': PRIVATE})
logger.error(PRIVATE, extra={'private': PRIVATE})
try:
    raise RuntimeError(PRIVATE)
except RuntimeError:
    logger.exception(PRIVATE, extra={'private': PRIVATE})
assert attempts == []
'''.replace("ROUTE", repr(route))
    result = probe(tmp_path, code)
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""


def test_forged_audit_and_hostile_objects_never_reach_formatters(tmp_path):
    result = probe(tmp_path, r'''
calls = []
class Hostile:
    def __str__(self):
        calls.append('str')
        return PRIVATE
    def __repr__(self):
        calls.append('repr')
        return PRIVATE
obj = Hostile()
logger = logging.getLogger('google_seo_mcp.audit')
logger.info(json.dumps({'request_id': 'a'*32, 'consumer': 'alpha', 'tool': 'denied',
    'outcome': 'denied', 'duration_ms': 1}))
logger.info(json.dumps({'outcome': PRIVATE}))
logger.info(obj)
logger.info('%r', obj)
logger.info('safe', extra={'private': obj})
logger.error('safe', exc_info=(RuntimeError, RuntimeError(PRIVATE), None), stack_info=True)
assert calls == []
assert attempts == []
''')
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""


def test_only_bounded_marked_scalar_audit_is_reconstructed(tmp_path):
    # Import inside the probe so pre-fix collection still executes real probes.
    result = probe(tmp_path, r'''
from google_seo_mcp.consumer_auth import emit_hosted_audit
logger = logging.getLogger('google_seo_mcp.audit')
safe = {'request_id': 'a'*32, 'consumer': 'alpha', 'tool': 'denied',
        'outcome': 'denied', 'duration_ms': 1, 'status': 403}
emit_hosted_audit(logger, safe)
class Hostile:
    def __str__(self):
        raise AssertionError('untrusted_str')
    def __repr__(self):
        raise AssertionError('untrusted_repr')
for key, values in {
    'request_id': [PRIVATE, 'a'*33, Hostile()],
    'consumer': [PRIVATE+'\n', 'a'*65, Hostile()],
    'tool': [PRIVATE, Hostile()],
    'outcome': [PRIVATE, Hostile()],
    'duration_ms': [-1, float('nan'), float('inf'), True, Hostile()],
    'status': ['403', True, 99, 600, Hostile()],
}.items():
    for value in values:
        emit_hosted_audit(logger, safe | {key: value})
# Private extras are never copied; no serialization of arbitrary objects.
emit_hosted_audit(logger, safe | {'private': Hostile()})
assert attempts == []
''')
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    rows = [json.loads(line) for line in result.stderr.splitlines()]
    expected = {"request_id": "a"*32, "consumer": "alpha", "tool": "denied",
                "outcome": "denied", "duration_ms": 1, "status": 403}
    assert rows == [expected, expected]
    assert PRIVATE not in result.stderr


def test_real_authenticated_request_and_worker_audit_survive(tmp_path):
    result = probe(tmp_path, r'''
from mcp.server.fastmcp.exceptions import ToolError
from google_seo_mcp.tool_policy import ProductionToolPolicy
manager = server.PolicyToolManager(ProductionToolPolicy())
def controlled_worker():
    logging.getLogger('worker.private').error(PRIVATE)
    return consumer_context.get().consumer_id
manager.add_tool(controlled_worker, name='gsc_list_sites')
registry = ConsumerKeyRegistry.model_validate({'version':1, 'consumers':[
    {'consumer_id':name, 'key_id':name, 'enabled':True,
     'sha256':hashlib.sha256(('fixture-'+name).encode()).hexdigest()}
    for name in ('alpha', 'beta')]})
async def app(scope, receive, send):
    expected = scope['authenticated_consumer'].consumer_id
    assert await manager.call_tool('gsc_list_sites', {}) == expected
    try:
        await manager.call_tool(PRIVATE, {'private':PRIVATE})
    except ToolError as error:
        assert str(error) == 'tool_not_allowed'
    else:
        raise AssertionError('denial_missing')
    await send({'type':'http.response.start', 'status':200})
    await send({'type':'http.response.body', 'body':b''})
middleware = ConsumerKeyEdgeMiddleware(app, registry, hosted)
async def request(name, host=b'google-seo.mcp.propel.marketing'):
    scope = {'type':'http', 'path':'/mcp', 'method':'POST', 'client':('127.0.0.1',1234),
        'headers':[(b'host',host), (b'authorization',('Bearer fixture-'+name).encode())]}
    async def receive(): return {'type':'http.request','body':b''}
    async def send(message): pass
    await middleware(scope, receive, send)
async def exercise():
    await asyncio.gather(request('alpha'), request('beta'))
    await request('alpha', b'hostile.invalid')
    assert consumer_context.get() is None and request_id_context.get() is None
asyncio.run(exercise())
assert attempts == []
''')
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert PRIVATE not in result.stderr
    rows = [json.loads(line) for line in result.stderr.splitlines()]
    assert len(rows) == 7
    grouped = {}
    for row in rows:
        assert set(row) <= {"request_id", "consumer", "tool", "outcome", "duration_ms", "status"}
        assert len(row["request_id"]) == 32 and int(row["request_id"], 16) >= 0
        assert row["duration_ms"] >= 0
        grouped.setdefault(row["request_id"], []).append(row)
    assert len(grouped) == 3
    for group in grouped.values():
        assert len({row["consumer"] for row in group}) == 1
        if len(group) == 1:
            assert group[0]["consumer"] == "alpha"
            assert group[0]["status"] == 403 and group[0]["outcome"] == "denied"
        else:
            assert {row["tool"] for row in group} == {"gsc_list_sites", "denied", None}
            assert {row["outcome"] for row in group} == {"success", "denied"}


def test_explicit_legacy_composition_restores_process_logging(tmp_path):
    result = probe(tmp_path, r'''
# First leave hosted mode, then establish an independent legacy configuration.
server.create_server(load_runtime_config([], {}))
logger = logging.getLogger('restore.existing')
handler = logging.StreamHandler(sys.stderr)
logger.handlers[:] = [handler]
logger.setLevel(logging.WARNING)
logger.propagate = False
root = logging.getLogger()
original = (logging.Logger.callHandlers, logging.lastResort, root.handlers[:], root.level)
first = server.create_server(hosted)
second = server.create_server(hosted)
assert len(first._tool_manager.list_tools()) == len(second._tool_manager.list_tools()) == 46
late = logging.getLogger('restore.created.hosted')
late.handlers[:] = [logging.StreamHandler(sys.stderr)]
late.propagate = False
late.setLevel(logging.DEBUG)
legacy = server.create_server(load_runtime_config([], {}))
assert len(legacy._tool_manager.list_tools()) == 113
assert (logging.Logger.callHandlers, logging.lastResort, root.handlers, root.level) == original
assert logger.handlers == [handler] and logger.level == logging.WARNING and not logger.propagate
assert late.handlers == [] and late.propagate and late.level == logging.NOTSET
logger.warning('legacy_logging_restored')
''')
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == "legacy_logging_restored\n"
