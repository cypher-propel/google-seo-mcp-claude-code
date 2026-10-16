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
from google_seo_mcp.runtime_config import load_runtime_config
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
hosted = load_runtime_config(['--transport', 'streamable-http'], {})
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
from google.auth.credentials import AnonymousCredentials
from google.api_core import client_logging
# Reset only the SDK's once flag: its actual constructor logging setup executes.
client_logging._LOGGING_INITIALIZED = False
auth._build_creds = lambda: AnonymousCredentials()
seen = []
def stopped_transport(**kwargs):
    seen.append(True)
    raise RuntimeError('offline_transport_stopped')
if CLIENT in ('data', 'admin'):
    factory = auth.BetaAnalyticsDataClient if CLIENT == 'data' else auth.AnalyticsAdminServiceClient
    try:
        auth._hosted_client(factory, transport=stopped_transport)
    except RuntimeError as error:
        assert error.args == ('google_client_unavailable',)
    else:
        raise AssertionError('transport_not_stopped')
    assert seen == [True]
    assert client_logging._LOGGING_INITIALIZED is True
else:
    getter = auth.get_searchconsole if CLIENT == 'searchconsole' else auth.get_webmasters
    service = getter()
    assert service._rootDesc['name'] == CLIENT
    assert service._http.credentials.__class__ is AnonymousCredentials
# Do not reset logging after real constructor execution.
logger = logging.getLogger('google.analytics.transport.late')
try:
    raise RuntimeError(PRIVATE)
except RuntimeError:
    getattr(logger, SEVERITY)(PRIVATE, extra={'credentialsInfo': PRIVATE, 'metadata': PRIVATE})
assert attempts == []
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
assert len(first._tool_manager.list_tools()) == len(second._tool_manager.list_tools()) == 35
late = logging.getLogger('restore.created.hosted')
late.handlers[:] = [logging.StreamHandler(sys.stderr)]
late.propagate = False
late.setLevel(logging.DEBUG)
legacy = server.create_server(load_runtime_config([], {}))
assert len(legacy._tool_manager.list_tools()) == 102
assert (logging.Logger.callHandlers, logging.lastResort, root.handlers, root.level) == original
assert logger.handlers == [handler] and logger.level == logging.WARNING and not logger.propagate
assert late.handlers == [] and late.propagate and late.level == logging.NOTSET
logger.warning('legacy_logging_restored')
''')
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == "legacy_logging_restored\n"
