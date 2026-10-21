"""Permanent offline privacy contracts at real legacy/hosted SDK boundaries.

Only upstream HTTP and local synthetic credential fixtures are substituted.
Children have empty HOME, no inherited credentials/proxies and DNS/socket traps.
GOOGLE_SEO_TEST_PYTHON optionally qualifies an installed wheel, without PYTHONPATH;
otherwise each child explicitly imports this checkout, not a stale installed copy.
Native writes or malicious Python outside the owned I/O boundary are not sandboxed.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

BOOT = r'''
import asyncio, hashlib, html, json, logging, socket, sys, threading
from pathlib import Path
from urllib.parse import quote, unquote
network = []
def forbidden(*args, **kwargs):
    network.append(True)
    raise AssertionError('outbound_forbidden')
socket.getaddrinfo = forbidden
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden
import httpx
from mcp import types
from google_seo_mcp import server
from google_seo_mcp.bing import auth, tools
from google_seo_mcp.runtime_config import load_runtime_config
from google_seo_mcp.consumer_auth import ConsumerKeyRegistry, ConsumerKeyEdgeMiddleware
SITE = 'https://kelleyconstructioninc.com/'
KEY = 'synthetic-privacy+/"é-9372'
PRIVATE = 'SYNTHETIC_BING_BODY_PRIVATE'
variants = [KEY, quote(KEY, safe=''), quote(quote(KEY, safe=''), safe=''),
    KEY.replace('"', r'\"'), ''.join(rf'\u{ord(c):04x}' for c in KEY),
    ''.join(rf'\x{ord(c):02x}' for c in KEY), html.escape(KEY),
    KEY.replace('é', '&#233;'), KEY.replace('é', '&eacute;')]
profile = PROFILE
config = load_runtime_config(['--transport', 'streamable-http'] if profile == 'hosted' else [], {})
root = Path.cwd()
root.chmod(0o700)
keyfile = root/'synthetic-key.json'
keyfile.write_text(json.dumps({'version':1, 'api_key':KEY}))
keyfile.chmod(0o600)
config = config.model_copy(update={'bing_credentials_file':keyfile})
instance = server.create_server(config)
# Capture the RAW factory inputs, before hosted callHandlers/filter sanitization.
raw = []
record_violations = []
original_factory = logging.getLogRecordFactory()
def factory(*args, **kwargs):
    raw.append((args, kwargs))
    return original_factory(*args, **kwargs)
logging.setLogRecordFactory(factory)
logging.getLogger().setLevel(logging.WARNING)
# Same handler must never see a private record, including in legacy mode.
private_delivered = []
class Sink(logging.Handler):
    def emit(self, record):
        private_delivered.append(record.__dict__.copy())
sink = Sink()
for name in ('httpx', 'httpcore.connection', 'fixture.private', 'google_seo_mcp.audit'):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(sink)
    logger.propagate = True

def private_log(value):
    before = len(raw)
    for name in ('httpx', 'httpcore.connection', 'fixture.private', 'google_seo_mcp.audit'):
        logger = logging.getLogger(name)
        logger.warning('request %s', value, extra={'nested': {value: [value]}})
        try:
            raise RuntimeError(value)
        except RuntimeError:
            logger.exception('upstream failure %s', value)
    if len(raw) != before:
        record_violations.append(True)

async def sdk(name, arguments):
    handler = instance._mcp_server.request_handlers[types.CallToolRequest]
    result = await handler(types.CallToolRequest(method='tools/call',
        params=types.CallToolRequestParams(name=name, arguments=arguments)))
    return result.model_dump(mode='json')

async def call(name='bing_query_stats', arguments=None):
    arguments = {'site_url':SITE} if arguments is None else arguments
    if profile != 'hosted':
        return await sdk(name, arguments)
    registry = ConsumerKeyRegistry.model_validate({'version':1, 'consumers':[
        {'consumer_id':'privacy-fixture', 'key_id':'fixture', 'enabled':True,
         'sha256':hashlib.sha256(b'synthetic-consumer-fixture').hexdigest()}]})
    output, sent = [], []
    async def app(scope, receive, send):
        output.append(await sdk(name, arguments))
        await send({'type':'http.response.start', 'status':200})
        await send({'type':'http.response.body', 'body':b''})
    middleware = ConsumerKeyEdgeMiddleware(app, registry, config)
    scope = {'type':'http', 'path':'/mcp', 'method':'POST', 'client':('127.0.0.1',1234),
        'headers':[(b'host', b'google-seo.mcp.propel.marketing'),
                   (b'authorization', b'Bearer synthetic-consumer-fixture')]}
    async def receive(): return {'type':'http.request', 'body':b''}
    async def send(message): sent.append(message)
    await middleware(scope, receive, send)
    assert sent[0]['status'] == 200
    return output[0]

def is_discovery(request):
    return request.url.path.endswith('/GetUserSites')

def inventory_response():
    return httpx.Response(200, json={'d':[{'Url':SITE, 'IsVerified':True}]})

def sends_by_stage(seen):
    return {'discovery':sum(is_discovery(request) for request in seen),
            'business':sum(not is_discovery(request) for request in seen)}

def business(result):
    assert result['isError'] is False
    return json.loads(result['content'][0]['text'])

def safe(value):
    text = repr(value)
    assert PRIVATE not in text
    for variant in variants:
        assert variant not in text
    assert 'apikey=' not in text

def finish(count):
    assert not record_violations, 'private logging reached raw LogRecord factory'
    safe(raw)
    safe(private_delivered)
    assert not network
    print(json.dumps({'cases':count, 'profile':profile,
        'server':server.__file__, 'tools':tools.__file__}))
'''


def probe(tmp_path, profile, code):
    home = tmp_path / "empty-home"
    home.mkdir()
    interpreter = os.environ.get("GOOGLE_SEO_TEST_PYTHON", sys.executable)
    environment = {
        "HOME": str(home), "TMPDIR": str(home), "LANG": "C.UTF-8",
        "PATH": f"{Path(interpreter).parent}:/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
    }
    if "GOOGLE_SEO_TEST_PYTHON" not in os.environ:
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    result = subprocess.run(
        [interpreter, "-W", "error", "-c", BOOT.replace("PROFILE", repr(profile)) + code],
        cwd=tmp_path, env=environment, capture_output=True, text=True,
        timeout=40, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["profile"] == profile
    if "GOOGLE_SEO_TEST_PYTHON" not in os.environ:
        assert Path(receipt["server"]).resolve() == (
            Path(__file__).resolve().parents[1] / "src/google_seo_mcp/server.py"
        )
    assert "SYNTHETIC_BING_BODY_PRIVATE" not in result.stderr
    if profile == "hosted":
        rows = [json.loads(line) for line in result.stderr.splitlines()]
        assert rows
        for row in rows:
            assert set(row) <= {
                "request_id", "consumer", "tool", "outcome", "duration_ms", "status",
            }
            assert row["consumer"] == "privacy-fixture"
            assert len(row["request_id"]) == 32
            assert row["duration_ms"] >= 0
    else:
        assert result.stderr == ""
    return receipt


@pytest.mark.parametrize("profile", ["legacy", "hosted"])
@pytest.mark.parametrize("variant_index", range(9))
def test_reflected_key_all_nested_fields_and_dict_keys_actual_sdk(tmp_path, profile, variant_index):
    receipt = probe(tmp_path, profile, r'''
from google_seo_mcp.bing.client import BingReadClient
variant = variants[VARIANT]
locations = ('known', 'unknown', 'key', 'nested_value', 'nested_key', 'fault')
seen = []
for location in locations:
    row = dict(Date='/Date(1704067200000)/', Clicks=1, Impressions=2,
               Query='ordinary', AvgClickPosition=17, AvgImpressionPosition=18)
    if location == 'known': row['Query'] = variant
    if location == 'unknown': row['FutureField'] = variant
    if location == 'key': row[variant] = 'discarded'
    if location == 'nested_value': row['FutureField'] = {'nested':[{'value':variant}]}
    if location == 'nested_key': row['FutureField'] = [{'nested':{variant:'discarded'}}]
    payload = {'d':[row]} if location != 'fault' else {'ErrorCode':2, 'Message':variant}
    def upstream(request):
        seen.append(request)
        private_log(str(request.url))
        if is_discovery(request): return inventory_response()
        return httpx.Response(200, json=payload)
    tools.configure_bing_tools(BingReadClient(
        transport=httpx.MockTransport(upstream), max_retries=0))
    result = asyncio.run(call())
    data = business(result)
    assert data['data']['status'] == 'provider_error'
    assert data['data']['error']['code'] == 'credential_reflection'
    assert not data['data']['records']
    safe(result)
assert sends_by_stage(seen) == {'discovery':len(locations), 'business':len(locations)}
finish(len(locations))
'''.replace("VARIANT", str(variant_index)))
    assert receipt["cases"] == 6


@pytest.mark.parametrize("profile", ["legacy", "hosted"])
@pytest.mark.parametrize("exception", [
    "ConnectError", "ReadTimeout", "ReadError", "RemoteProtocolError",
])
def test_httpx_exception_url_key_never_logs(tmp_path, profile, exception):
    probe(tmp_path, profile, r'''
from google_seo_mcp.bing.client import BingReadClient
seen = []
def upstream(request):
    seen.append(request)
    private_log(str(request.url))
    if is_discovery(request): return inventory_response()
    raise getattr(httpx, EXCEPTION)('private URL '+str(request.url), request=request)
tools.configure_bing_tools(BingReadClient(transport=httpx.MockTransport(upstream), max_retries=0))
result = asyncio.run(call())
data = business(result)
assert data['data']['status'] == 'provider_error'
expected = 'timeout' if EXCEPTION == 'ReadTimeout' else 'transport_error'
assert data['data']['error']['code'] == expected
assert sends_by_stage(seen) == {'discovery':1, 'business':1}
safe(result)
finish(1)
'''.replace("EXCEPTION", repr(exception)))


@pytest.mark.parametrize("profile", ["legacy", "hosted"])
@pytest.mark.parametrize("stage", [
    "constructor", "loader", "entry", "request_hook", "response_hook",
    "stream", "stream_close", "transport_close", "generation", "rate",
])
def test_owned_lifecycle_logs_suppressed_before_raw_record_factory(tmp_path, profile, stage):
    probe(tmp_path, profile, r'''
from google_seo_mcp.bing import client as boundary
BingReadClient = boundary.BingReadClient
stage = STAGE
hits = []
seen = []
entered = []
def hit(point):
    if stage == point:
        hits.append(point)
        private_log(KEY)
        try:
            raise ValueError('foreign cause '+quote(KEY, safe=''))
        except ValueError as cause:
            raise RuntimeError('foreign '+KEY) from cause
class Loader(auth.BingCredentialLoader):
    def load(self):
        hit('loader')
        return super().load()
    def require_generation(self, expected):
        assert entered
        hit('generation')
        return super().require_generation(expected)
class Stream(httpx.SyncByteStream):
    def __iter__(self):
        hit('stream')
        yield json.dumps({'d':[{'Url':SITE, 'IsVerified':True}]}).encode()
    def close(self): hit('stream_close')
class Transport(httpx.MockTransport):
    def __enter__(self):
        entered.append(True)
        hit('entry')
        return super().__enter__()
    def __exit__(self, *args):
        hit('transport_close')
        return super().__exit__(*args)
original = httpx.Client
class Client(original):
    def __init__(self, **kwargs):
        hit('constructor')
        def request_hook(request): hit('request_hook')
        def response_hook(response): hit('response_hook')
        hooks = {'request':[request_hook], 'response':[response_hook]}
        super().__init__(event_hooks=hooks, **kwargs)
httpx.Client = Client
def upstream(request):
    seen.append(request)
    assert is_discovery(request)
    return httpx.Response(200, stream=Stream())
transport = Transport(upstream)
if stage == 'rate':
    original_charge = boundary._GLOBAL.charge
    def charge(): hit('rate')
    boundary._GLOBAL.charge = charge
tools.configure_bing_tools(BingReadClient(Loader(), transport=transport,
    max_retries=0))
result = asyncio.run(call())
assert business(result)['data']['status'] == 'provider_error'
assert business(result)['data']['error']['code'] == 'transport_error'
assert hits == [stage]
assert sends_by_stage(seen) == {
    'discovery':int(stage in ('response_hook', 'stream', 'stream_close', 'transport_close')),
    'business':0}
safe(result)
# The failure's own log calls never even constructed a raw LogRecord.
assert all('fixture.private' != args[0] for args, kwargs in raw)
if stage == 'generation':
    # Independently prove real custody revocation after transport entry, not
    # just containment of a foreign exception at that observation boundary.
    revoked_entries = []
    class RevokingTransport(httpx.MockTransport):
        def __enter__(self):
            result = super().__enter__()
            revoked_entries.append(True)
            auth.configure_bing_auth(config)
            return result
    tools.configure_bing_tools(BingReadClient(auth.BingCredentialLoader(),
        transport=RevokingTransport(upstream), max_retries=0))
    revoked = asyncio.run(call())
    assert revoked_entries == [True]
    assert business(revoked)['data']['error']['code'] == 'credentials_invalid'
    assert sends_by_stage(seen) == {'discovery':0, 'business':0}
    assert hits == [stage]
    safe(revoked)
if stage == 'rate':
    # A full real rolling admission budget also refuses before construction,
    # without retry, sleeping, or spending another transport attempt.
    from unittest.mock import patch
    boundary._GLOBAL.charge = original_charge
    boundary._GLOBAL.attempts.extend([boundary.time.monotonic()] * 12)
    with patch.object(httpx, 'Client', side_effect=AssertionError('rate HTTP')) as client:
        limited = asyncio.run(call())
        client.assert_not_called()
    assert business(limited)['data']['error']['code'] == 'rate_limited'
    assert sends_by_stage(seen) == {'discovery':0, 'business':0}
    assert hits == [stage]
    safe(limited)
finish(1)
'''.replace("STAGE", repr(stage)))


@pytest.mark.parametrize("profile", ["legacy", "hosted"])
def test_sdk_body_validation_no_echo_and_missing_provider_no_client(tmp_path, profile):
    probe(tmp_path, profile, r'''
# No client import/construction is needed by composition or invalid arguments.
assert 'google_seo_mcp.bing.client' not in sys.modules
from unittest.mock import patch
from google_seo_mcp.bing.client import BingReadClient
bad = [
    {'site_url':PRIVATE}, {'site_url':SITE, 'limit':PRIVATE},
    {'site_url':SITE, 'limit':True}, {'site_url':SITE, 'start_date':PRIVATE},
    {'site_url':SITE, 'unexpected':{PRIVATE:[PRIVATE]}},
]
with (
    patch.object(auth.BingCredentialLoader, 'load',
                 side_effect=AssertionError('custody before validation')) as load,
    patch.object(httpx, 'Client',
                 side_effect=AssertionError('client before validation')) as client,
):
    for arguments in bad:
        result = asyncio.run(call(arguments=arguments))
        assert result['isError'] is True
        assert result['content'][0]['text'] in ('invalid_request', 'invalid_tool_arguments')
        safe(result)
    load.assert_not_called()
    client.assert_not_called()
missing = type('Missing', (), {'bing_credentials_file':None, 'bing_sites_file':None})()
auth.configure_bing_auth(missing)
tools.configure_bing_tools(BingReadClient())
with patch.object(httpx, 'Client', side_effect=AssertionError('missing config HTTP')) as client:
    result = asyncio.run(call())
    data = business(result)
    assert data['data']['status'] == 'unavailable'
    assert data['data']['error']['code'] == 'provider_not_configured'
    client.assert_not_called()
safe(result)
finish(len(bad)+1)
''')


@pytest.mark.parametrize("profile", ["legacy", "hosted"])
def test_decoded_and_astral_key_reflection_actual_custody(tmp_path, profile):
    probe(tmp_path, profile, r'''
from google_seo_mcp.bing.client import BingReadClient
cases = [('synthetic%2Bdecoded%2Fkey', 'synthetic+decoded/key'),
         ('synthetic-🔑-key', r'synthetic-\ud83d\udd11-key'),
         ('synthetic-🔑-key', r'synthetic-\U0001f511-key')]
for key, reflected in cases:
    keyfile.write_text(json.dumps({'version':1, 'api_key':key}))
    auth.configure_bing_auth(config)
    seen = []
    def upstream(request):
        seen.append(request)
        assert request.url.params['apikey'] == key
        if is_discovery(request): return inventory_response()
        return httpx.Response(200, json={'d':[{'Unknown':{reflected:['ignored']}}]})
    tools.configure_bing_tools(BingReadClient(
        transport=httpx.MockTransport(upstream), max_retries=0))
    result = asyncio.run(call())
    assert business(result)['data']['error']['code'] == 'credential_reflection'
    serialized = json.dumps(result, ensure_ascii=False)
    assert key not in serialized and reflected not in serialized
    assert sends_by_stage(seen) == {'discovery':1, 'business':1}
finish(len(cases))
''')


@pytest.mark.parametrize("profile", ["legacy", "hosted"])
def test_all_eleven_pending_results_are_explicit_without_http(tmp_path, profile):
    probe(tmp_path, profile, r'''
from unittest.mock import patch
# Independent accepted inventory, not discovered/generated from the registry.
routes = [
    ('bing_list_sites', {}),
    ('bing_rank_traffic_stats', {'site_url':SITE}),
    ('bing_query_stats', {'site_url':SITE}),
    ('bing_page_stats', {'site_url':SITE}),
    ('bing_page_query_stats', {'site_url':SITE, 'page_url':SITE+'page'}),
    ('bing_query_page_stats', {'site_url':SITE, 'query':'ordinary'}),
    ('bing_crawl_stats', {'site_url':SITE}),
    ('bing_crawl_issues', {'site_url':SITE}),
    ('bing_url_info', {'site_url':SITE, 'url':SITE+'page'}),
    ('bing_list_sitemaps', {'site_url':SITE}),
    ('bing_sitemap_details', {'site_url':SITE, 'sitemap_url':SITE+'sitemap.xml'}),
]
missing = type('Missing', (), {'bing_credentials_file':None, 'bing_sites_file':None})()
auth.configure_bing_auth(missing)
with patch.object(httpx, 'Client', side_effect=AssertionError('absent provider HTTP')) as client:
    for name, arguments in routes:
        result = asyncio.run(call(name, arguments))
        data = business(result)
        assert data['data']['status'] == 'unavailable'
        assert data['data']['error']['code'] == 'provider_not_configured'
        assert not data['data']['records']
        assert data['_meta']['source'] == 'bing_webmaster'
        safe(result)
    client.assert_not_called()
finish(len(routes))
''')


@pytest.mark.parametrize("profile", ["legacy", "hosted"])
def test_private_context_does_not_silence_other_threads_or_post_call_logs(tmp_path, profile):
    # Delivery differs intentionally: legacy keeps ordinary logs; hosted retains
    # only marked audits. Both still construct unrelated raw records outside I/O.
    probe(tmp_path, profile, r'''
from concurrent.futures import ThreadPoolExecutor
from google_seo_mcp.bing.client import BingReadClient
entered, release = threading.Event(), threading.Event()
seen = []
def upstream(request):
    seen.append(request)
    private_log(str(request.url))
    if is_discovery(request): return inventory_response()
    entered.set()
    assert release.wait(5)
    return httpx.Response(200, json={'d':[]})
tools.configure_bing_tools(BingReadClient(transport=httpx.MockTransport(upstream), max_retries=0))
logger = logging.getLogger('ordinary.control')
logger.propagate = False
logger.handlers[:] = [sink]
logger.setLevel(logging.WARNING)
with ThreadPoolExecutor(max_workers=1) as pool:
    future = pool.submit(lambda: asyncio.run(call()))
    try:
        assert entered.wait(5)
        logger.warning('ordinary_parallel_control')
    finally:
        release.set()
    assert business(future.result(timeout=5))['data']['status'] == 'empty'
assert sends_by_stage(seen) == {'discovery':1, 'business':1}
logger.error('ordinary_after_control')
controls = [args[4] for args, kwargs in raw if args[0] == 'ordinary.control']
assert controls == ['ordinary_parallel_control', 'ordinary_after_control']
delivered = [r['msg'] for r in private_delivered if r['name'] == 'ordinary.control']
assert delivered == (controls if profile == 'legacy' else [])
finish(1)
''')


@pytest.mark.parametrize("profile", ["legacy", "hosted"])
@pytest.mark.parametrize("encoding", ["raw", "percent", "unicode", "mixed"])
def test_denied_site_input_free_provenance_actual_sdk(tmp_path, profile, encoding):
    probe(tmp_path, profile, r'''
from unittest.mock import patch
from google_seo_mcp.bing import client as boundary
import warnings
warnings.simplefilter('error')
KEY = 'synthetic-denial-9372' if ENCODING in ('raw', 'percent') else 'synthetic-denial-é-9372'
keyfile.write_text(json.dumps({'version':1, 'api_key':KEY}))
auth.configure_bing_auth(config)
encoded = KEY
if ENCODING == 'percent':
    encoded = ''.join('%%%02X' % byte for byte in KEY.encode())
if ENCODING == 'mixed':
    encoded = 'synthetic-' + quote('denial-é', safe='') + '-%39%33%37%32'
site = 'https://bing.com/' + encoded
loader = auth.BingCredentialLoader()
loads, generations = [], []
load, require_generation = loader.load, loader.require_generation
def tracked_load():
    loads.append(True)
    return load()
def tracked_generation(value):
    generations.append(value)
    return require_generation(value)
loader.load, loader.require_generation = tracked_load, tracked_generation
tools.configure_bing_tools(boundary.BingReadClient(loader))
with patch.object(httpx, 'Client', side_effect=AssertionError('denied HTTP')) as http:
    result = asyncio.run(call(arguments={'site_url':site,
        'start_date':'2025-03-04', 'end_date':'2025-03-05'}))
    http.assert_not_called()
payload = business(result)
assert payload['data']['status'] == 'provider_error'
assert payload['data']['error']['code'] == 'credential_reflection'
assert payload['data']['site_url'] == ''
assert payload['_meta']['site_url'] == ''
assert payload['data']['requested_period'] is None
assert payload['_meta']['requested_period'] is None
assert 'period' not in payload['_meta']
assert loads == [True] and generations == []  # Refuse before discovery/admission.
text = json.dumps([result, raw, private_delivered], ensure_ascii=False, default=str)
for marker in (KEY, encoded, site, '2025-03-04', '2025-03-05'):
    assert marker not in text
safe(result)
# The former static-policy denial is now proven against actual inventory:
# neither an unlisted property nor a strictly false row admits business I/O.
for listed in (False, True):
    seen = []
    denied_site = 'https://bing.com/SYNTHETIC_DENIED_PROPERTY/'
    def upstream(request):
        seen.append(request)
        assert is_discovery(request), 'denied property reached business transport'
        rows = [{'Url':SITE, 'IsVerified':True}]
        if listed: rows.append({'Url':denied_site, 'IsVerified':False})
        return httpx.Response(200, json={'d':rows})
    tools.configure_bing_tools(boundary.BingReadClient(
        transport=httpx.MockTransport(upstream), max_retries=0))
    result = asyncio.run(call(arguments={'site_url':denied_site,
        'start_date':'2025-03-04', 'end_date':'2025-03-05'}))
    payload = business(result)
    assert payload['data']['status'] == 'denied'
    assert payload['data']['error']['code'] == 'site_denied'
    for part in (payload['data'], payload['_meta']):
        assert part['site_url'] == ''
        assert part['requested_period'] is None and part['observed_period'] is None
    assert 'period' not in payload['_meta']
    assert payload['data']['records'] == []
    assert sends_by_stage(seen) == {'discovery':1, 'business':0}
    text = json.dumps([result, raw, private_delivered], ensure_ascii=False, default=str)
    for marker in (denied_site, '2025-03-04', '2025-03-05'):
        assert marker not in text
    safe(result)
finish(3)
'''.replace("ENCODING", repr(encoding)))


@pytest.mark.parametrize("profile", ["legacy", "hosted"])
@pytest.mark.parametrize("stage", ["missing", "invalid", "local", "timeout", "busy",
                                   "provider", "schema", "rows", "validation"])
def test_early_and_provider_failures_input_free_actual_sdk(tmp_path, profile, stage):
    probe(tmp_path, profile, r'''
from unittest.mock import patch
from google_seo_mcp.bing import client as boundary
import warnings
warnings.simplefilter('error')
stage = STAGE
# Use raw, noncredential request markers: all failure provenance is input-free,
# not merely key-aware. Selectors and dates must not reappear in data or _meta.
site = SITE if stage in ('busy', 'provider', 'schema', 'rows') else (
    SITE + 'SYNTHETIC_CALLER_SITE/')
query = 'SYNTHETIC_CALLER_QUERY'
arguments = {'site_url':site, 'query':query,
             'start_date':'2025-03-04', 'end_date':'2025-03-05'}
if stage == 'missing':
    auth.configure_bing_auth(type('Missing', (), {
        'bing_credentials_file':None, 'bing_sites_file':None})())
if stage == 'invalid':
    keyfile.write_text('invalid synthetic document')
loader = auth.BingCredentialLoader()
if stage == 'local':
    def load(): raise RuntimeError(query)
    loader.load = load
if stage == 'timeout':
    class Expired(boundary._Budget):
        def remaining(self): return 0
    boundary._Budget = Expired
if stage == 'busy':
    class Busy:
        def acquire(self, timeout): return False
    boundary._GLOBAL.slot = Busy()
seen = []
def upstream(request):
    seen.append(request)
    if is_discovery(request): return inventory_response()
    payload = {'ErrorCode':'synthetic'} if stage == 'provider' else (
        {'d':None} if stage == 'schema' else {'d':[{'Clicks':True}]})
    return httpx.Response(200, json=payload)
tools.configure_bing_tools(boundary.BingReadClient(loader,
    transport=httpx.MockTransport(upstream), max_retries=0))
if stage == 'validation': arguments['limit'] = query
result = asyncio.run(call('bing_query_page_stats', arguments))
if stage == 'validation':
    assert result['isError'] is True
    assert result['content'][0]['text'] in ('invalid_request', 'invalid_tool_arguments')
else:
    payload = business(result)
    expected = {'missing':'provider_not_configured', 'invalid':'credentials_invalid',
                'local':'transport_error', 'timeout':'timeout', 'busy':'timeout',
                'provider':'provider_error', 'schema':'invalid_response', 'rows':'invalid_response'}
    assert payload['data']['error']['code'] == expected[stage]
    for part in (payload['data'], payload['_meta']):
        assert part['site_url'] == ''
        assert part['requested_period'] is None and part['observed_period'] is None
    assert 'period' not in payload['_meta']
    assert payload['data']['records'] == []
    assert payload['data']['provider_cadence'] == 'weekly'
text = json.dumps([result, raw, private_delivered], ensure_ascii=False, default=str)
for marker in (site, query, '2025-03-04', '2025-03-05'):
    assert marker not in text
expected_sends = int(stage in ('provider', 'schema', 'rows'))
assert sends_by_stage(seen) == {'discovery':expected_sends, 'business':expected_sends}
safe(result)
finish(1)
'''.replace("STAGE", repr(stage)))

