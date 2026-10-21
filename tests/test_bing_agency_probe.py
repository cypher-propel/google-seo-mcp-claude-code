"""Independent seq78 scanner regressions; synthetic offline inputs only.

Default: exercise the current helper. To reproduce the pre-fix red, explicitly
set BING_AGENCY_PROBE_HELPER to the frozen helper's absolute file path. This is
only a test harness selector; production has no source/endpoint override.
These tests assert desired behavior, including on the deliberately red original.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
from urllib.parse import quote

import httpx
import pytest

from google_seo_mcp.bing import client as bing_client
from google_seo_mcp.bing.models import BingCredentialDocument

KEY = "SYNTHETIC-review-key.7+Z/19"
CAP = 2 * 1024 * 1024
VALID_CASES = ("exact161", "http257", "mixed513", "long1024", "wide257", "nearcap161")
ENCODINGS = ("raw", "base64", "base64url", "hex", "hexupper", "unicode",
             "longunicode", "percent", "html", "enclosing", "nested", "urlwrapped")


@pytest.fixture(scope="module")
def probe():
    selected = os.environ.get("BING_AGENCY_PROBE_HELPER")
    if selected:
        source = Path(selected)
        assert source.is_absolute(), "explicit helper selector must be absolute"
    else:
        source = Path(__file__).resolve().parents[1] / "scripts/probe_bing_agency_sites.py"
    spec = importlib.util.spec_from_file_location("seq78_independent_probe", source)
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        module._regression_source_path = source
        yield module
    finally:
        if previous is None:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = previous


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    # Counters live outside application handlers: swallowed denial assertions
    # must still fail teardown, rather than masquerade as safe provider errors.
    forbidden = []

    def deny(*args, **kwargs):
        forbidden.append("external-network")
        raise AssertionError("offline boundary entered")

    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket, "gethostbyname", deny)
    monkeypatch.setattr(socket, "gethostbyname_ex", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    # Each synthetic read has an isolated admission state, not a live budget.
    monkeypatch.setattr(bing_client, "_GLOBAL", bing_client._Admission())
    yield
    assert forbidden == [], "forbidden DNS/connect attempted, even if caught"


def valid_input(case):
    counts = dict(exact161=161, http257=257, mixed513=513, long1024=1024,
                  wide257=257, nearcap161=161)
    rows = []
    for i in range(counts[case]):
        url = f"https://site{i:04d}.review-agency.com/"
        if case == "http257":
            url = f"http://branch-{i:05d}.regression-example.com/catalog/item-{i:05d}/"
        elif case == "mixed513":
            scheme = "http" if i % 3 == 0 else "https"
            url = f"{scheme}://dept-{i:05d}.agency-example.net/a_b/c-{i:05d}/?view={i:05d}"
        elif case == "long1024":
            url = f"https://unit-{i:05d}.agency-example.org/" + "section/" * 16 + f"item-{i:05d}/"
        row = {"Url": url, "IsVerified": bool(i % 2)}
        if case == "wide257":
            row["VerificationCode"] = {"ignored": [f"public-note-{i:05d}", " " * 2048]}
        rows.append(row)
    # The exact regression retains the original serialization and row ordering.
    if case != "exact161":
        rows.reverse()
    body = json.dumps({"d": rows}).encode()
    if case == "nearcap161":
        body += b" " * (CAP - 4096 - len(body))
    assert len(body) < CAP
    return rows, body


def receipt(rows=(), error=None):
    projected = [] if error else sorted(
        ({"site_url": r["Url"], "is_verified": r["IsVerified"]} for r in rows),
        key=lambda row: row["site_url"],
    )
    return {"version": 1, "operation": "GetUserSites",
            "status": "failed" if error else "success", "error": error,
            "sites": projected, "listed_count": len(projected),
            "verified_count": sum(r["is_verified"] for r in projected),
            "provider_completeness": "unknown", "ownership_attestation": "pending"}


def observe_input(probe, body, record_property):
    record_property("helper_sha256", hashlib.sha256(probe._regression_source_path.read_bytes()).hexdigest())
    record_property("body_bytes", len(body))
    record_property("body_sha256", hashlib.sha256(body).hexdigest())


def execute(probe, route, body, record_property):
    observe_input(probe, body, record_property)
    if route == "parser":
        return probe.parse_inventory(body, KEY)
    # No overriding read/_admit/_attempt/_authorize and no substitute parser.
    for method in ("read", "_admit", "_attempt", "_authorize"):
        assert getattr(probe.RawInventoryProbe, method) is getattr(bing_client.BingReadClient, method)
    sends = []

    class Loader(P0Loader):
        pass

    def send(request):
        sends.append(request)
        return httpx.Response(200, content=body)

    loader = Loader()
    result = probe.run_probe(probe.RawInventoryProbe(
        loader, transport=httpx.MockTransport(send), max_retries=0))
    record_property("transport_sends", len(sends))
    record_property("synthetic_loader_reads", loader.loads)
    assert loader.generations.count('require_generation') == len(loader.requirements)
    assert len(sends) == 1
    assert loader.authorized_reads == 2
    assert loader.loads == 2 + len(loader.generations)
    assert loader.generations[:2] == ['_read', '_attempt']
    assert loader.forbidden == []
    request = sends[0]
    assert request.method == "GET"
    assert str(request.url.copy_with(query=None)) == "https://ssl.bing.com/webmaster/api.svc/json/GetUserSites"
    assert list(request.url.params.multi_items()) == [("apikey", KEY)]
    return result


@pytest.mark.parametrize("route", ["parser", "inherited_transport"])
@pytest.mark.parametrize("case", VALID_CASES)
def test_complete_valid_inventory(probe, route, case, record_property, capsys):
    rows, body = valid_input(case)
    record_property("fixture_rows", len(rows))
    record_property("fixture_verified", sum(r["IsVerified"] for r in rows))
    if case == "exact161":
        assert len(body) == 11036
        assert len(rows) == 161
        assert sum(r["IsVerified"] for r in rows) == 80
    result = execute(probe, route, body, record_property)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert result == receipt(rows)
    assert KEY not in json.dumps(result)


def encoded_key(kind):
    raw = KEY.encode()
    enclosing = base64.b64encode(("prefix[" + KEY + "]suffix").encode()).decode()
    return {
        "raw": KEY,
        "base64": base64.b64encode(raw).decode(),
        "base64url": base64.urlsafe_b64encode(raw).decode(),
        "hex": raw.hex(), "hexupper": raw.hex().upper(),
        "unicode": "".join(f"\\u{ord(c):04x}" for c in KEY),
        "longunicode": "".join(f"\\U{ord(c):08x}" for c in KEY),
        "percent": quote(KEY, safe=""),
        "html": "".join(f"&#{ord(c)};" for c in KEY),
        "enclosing": enclosing,
        "nested": base64.b64encode(enclosing.encode()).decode(),
        "urlwrapped": "https://ignored-example.com/path/" + enclosing,
    }[kind]


@pytest.mark.parametrize("route", ["parser", "inherited_transport"])
@pytest.mark.parametrize("location", ["row_ignored", "root_ignored"])
@pytest.mark.parametrize("encoding", ENCODINGS)
def test_ignored_reflection_refuses_complete_receipt(
        probe, route, location, encoding, record_property, capsys):
    row = {"Url": "https://safe-example.com/", "IsVerified": False}
    payload = {"d": [row]}
    target = row if location == "row_ignored" else payload
    target["VerificationCode"] = {"nested": [encoded_key(encoding)]}
    body = json.dumps(payload).encode()
    result = execute(probe, route, body, record_property)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert result == receipt(error="credential_reflection")
    assert KEY not in json.dumps(result)


# Full P0 qualification extension. All wire data and custody are synthetic.
# Original 60 case identities/purposes retained; obsolete custody fixtures ported.
import gzip
import logging
import subprocess
import threading
import time
from types import SimpleNamespace
from google_seo_mcp.bing import auth as p0auth
from google_seo_mcp.bing.models import BingOperation, BingToolRequest


class P0Loader:
    def __init__(self):
        self.loads = 0
        self.forbidden = []
        self.authorized_reads = 0
        self.generations = []
        self.requirements = []

    def load(self):
        import inspect
        self.loads += 1
        frame = inspect.currentframe().f_back
        while frame.f_code.co_name == 'load':
            frame = frame.f_back
        if frame.f_code.co_name == '_authorize':
            self.authorized_reads += 1
        del frame
        return BingCredentialDocument(version=1, api_key=KEY)

    def generation(self):
        import inspect
        self.generations.append(inspect.currentframe().f_back.f_code.co_name)
        self.load()
        return 'synthetic-current-generation'

    def require_generation(self, expected):
        import inspect
        self.requirements.append(inspect.currentframe().f_back.f_code.co_name)
        if self.generation() != expected:
            raise p0auth.BingAuthError('credentials_invalid')

    def __getattr__(self, name):
        self.forbidden.append('unsupported-loader-member')
        raise AttributeError(name)


def p0wire(probe, handler, *, loader=None, transport=None, **kwargs):
    sends = []
    loader = loader or P0Loader()
    def send(request):
        sends.append(request)
        return handler(request)
    client = probe.RawInventoryProbe(loader, transport=(transport or httpx.MockTransport(send)),
                                     max_retries=0, **kwargs)
    return client, loader, sends


def p0assertwire(loader, sends, count=1, loads=2):
    assert loader.forbidden == []
    # Old two reads were authorization reads. Current generation/dispatch
    # observations each perform their own real local custody read as well.
    assert loader.authorized_reads == loads
    assert loader.loads == loads + len(loader.generations)
    assert len(loader.generations) == (2 if loads else 0) + len(loader.requirements)
    assert all(name in ('check', '_read') for name in loader.requirements)
    assert len(sends) == count
    for request in sends:
        assert request.method == 'GET'
        assert str(request.url.copy_with(query=None)) == (
            'https://ssl.bing.com/webmaster/api.svc/json/GetUserSites')
        assert list(request.url.params.multi_items()) == [('apikey', KEY)]
        assert request.content == b''
        assert request.headers['Content-Type'] == 'application/json; charset=utf-8'


P0_GOOD = [
    ('empty', [], []),
    ('false_only', [{'Url':'https://unverified.example.com/', 'IsVerified':False}],
     [{'Url':'https://unverified.example.com/', 'IsVerified':False}]),
    ('multi', [{'Url':'https://zeta.example.com/', 'IsVerified':False},
               {'Url':'http://alpha.example.org/path/', 'IsVerified':True},
               {'Url':'https://kelleyconstructioninc.com/', 'IsVerified':True}],
              [{'Url':'https://zeta.example.com/', 'IsVerified':False},
               {'Url':'http://alpha.example.org/path/', 'IsVerified':True},
               {'Url':'https://kelleyconstructioninc.com/', 'IsVerified':True}]),
    ('dedup', [{'Url':'https://duplicate.example.com/', 'IsVerified':False}]*3,
              [{'Url':'https://duplicate.example.com/', 'IsVerified':False}]),
    ('codes', [{'Url':'https://codes.example.com/', 'IsVerified':True,
                'AuthenticationCode':'SYNTHETIC-CODE-DISCARD',
                'DnsVerificationCode': {'nested':['SYNTHETIC-CODE-DISCARD']},
                'FutureField':{'opaque':[17,False,None]}}],
               [{'Url':'https://codes.example.com/', 'IsVerified':True}]),
]


@pytest.mark.parametrize('route', ['parser','inherited_transport'])
@pytest.mark.parametrize('name,rows,expected', P0_GOOD, ids=[r[0] for r in P0_GOOD])
def test_p0_complete_semantics(probe, route, name, rows, expected, record_property):
    actual = execute(probe, route, json.dumps({'d':rows}).encode(), record_property)
    assert actual == receipt(expected)
    assert 'SYNTHETIC-CODE-DISCARD' not in json.dumps(actual)
    assert type(actual['listed_count']) is int and type(actual['verified_count']) is int
    assert all(type(r['is_verified']) is bool for r in actual['sites'])


P0_BAD = [
    ('root_list', b'[]','invalid_response'), ('root_null', b'null','invalid_response'),
    ('root_bool', b'true','invalid_response'), ('missing_d', b'{}','invalid_response'),
    ('null_d', b'{"d":null}','invalid_response'), ('object_d', b'{"d":{}}','invalid_response'),
    ('str_d', b'{"d":""}','invalid_response'), ('number_d', b'{"d":0}','invalid_response'),
    ('bool_d', b'{"d":false}','invalid_response'),
    ('row_null', b'{"d":[null]}','invalid_response'),
    ('row_list', b'{"d":[[]]}','invalid_response'),
    ('row_alias', b'{"d":[{"url":"https://example.com/","is_verified":true}]}','invalid_response'),
    ('missing_url', b'{"d":[{"IsVerified":true}]}','invalid_response'),
    ('missing_flag', b'{"d":[{"Url":"https://example.com/"}]}','invalid_response'),
    ('syntax', b'{','invalid_response'), ('utf8', b'\xff','invalid_response'),
    ('trailing', b'{"d":[]}junk','invalid_response'),
    ('duplicate_root', b'{"d":[],"d":[]}','invalid_response'),
    ('duplicate_row', b'{"d":[{"Url":"https://example.com/","IsVerified":true,"IsVerified":true}]}','invalid_response'),
    ('duplicate_ignored', b'{"d":[],"ignored":{"x":1,"x":2}}','invalid_response'),
    ('nan', b'{"d":[],"ignored":NaN}','invalid_response'),
    ('infinity', b'{"d":[],"ignored":Infinity}','invalid_response'),
    ('negative_inf', b'{"d":[],"ignored":-Infinity}','invalid_response'),
    ('overflow', b'{"d":[],"ignored":1e999}','invalid_response'),
    ('root_error', b'{"d":[],"ErrorCode":0,"Message":"SYNTHETIC-private"}','provider_error'),
    ('nested_error', b'{"d":{"ErrorCode":null,"Message":"SYNTHETIC-private"}}','provider_error'),
    ('message_only', b'{"d":[],"Message":"SYNTHETIC-private"}','provider_error'),
    ('oversize', b' '*(CAP+1),'response_too_large'),
]
for _flag in (None,0,1,'true','false',[],{}):
    P0_BAD.append(('flag_'+repr(_flag),json.dumps({'d':[{'Url':'https://example.com/', 'IsVerified':_flag}]}).encode(),'invalid_response'))
for _url in (None,1,True,'','not-url','http://127.0.0.1/','http://[::1]/',
             'https://user:pass@example.com/','ftp://example.com/','https://localhost/',
             'http://192.168.1.1/','https://example.com/#fragment'):
    P0_BAD.append(('url_'+repr(_url),json.dumps({'d':[{'Url':_url,'IsVerified':True}]}).encode(),'invalid_response'))
for _order in ((True,False),(False,True)):
    P0_BAD.append(('conflict_'+str(_order),json.dumps({'d':[{'Url':'https://example.com/','IsVerified':f} for f in _order]}).encode(),'invalid_response'))
P0_BAD.append(('partial', json.dumps({'d':[{'Url':'https://valid.example.com/','IsVerified':True},{}]}).encode(),'invalid_response'))


@pytest.mark.parametrize('route',['parser','inherited_transport'])
@pytest.mark.parametrize('name,body,code',P0_BAD,ids=[r[0] for r in P0_BAD])
def test_p0_strict_complete_envelope(probe,route,name,body,code,record_property,capsys):
    assert execute(probe,route,body,record_property) == receipt(error=code)
    captured=capsys.readouterr()
    assert captured.out == captured.err == ''


@pytest.mark.parametrize('status',[301,302,303,307,308,400,401,403,404,408,429,500,501,502,503,504])
def test_p0_http_status_single_attempt(probe,status,monkeypatch):
    constructors=[]
    original=httpx.Client
    def factory(**kwargs):
        constructors.append(kwargs)
        return original(**kwargs)
    monkeypatch.setattr(httpx,'Client',factory)
    pauses=[]
    monkeypatch.setattr(bing_client.time,'sleep',lambda s:pauses.append(s))
    client,loader,sends=p0wire(probe,lambda request:httpx.Response(status,
        headers={'Location':'https://redirect-forbidden.example/','Retry-After':'0'},
        json={'Message':'SYNTHETIC-PRIVATE-PROVIDER'}))
    expected={401:'access_denied',403:'access_denied',429:'rate_limited'}.get(status,'provider_error')
    assert probe.run_probe(client) == receipt(error=expected)
    p0assertwire(loader,sends)
    assert pauses == [] and len(constructors)==1
    assert constructors[0]['trust_env'] is False
    assert constructors[0]['follow_redirects'] is False
    assert 0 < constructors[0]['timeout'] <=15


@pytest.mark.parametrize('exception,code',[(httpx.ConnectError,'transport_error'),
    (httpx.ConnectTimeout,'timeout'),(httpx.ReadTimeout,'timeout'),
    (httpx.WriteTimeout,'timeout'),(httpx.PoolTimeout,'timeout'),
    (httpx.ReadError,'transport_error'),(httpx.RemoteProtocolError,'transport_error')],
    ids=['ConnectError-transport_error', 'ConnectTimeout-transport_error',
         'ReadTimeout-timeout', 'WriteTimeout-timeout', 'PoolTimeout-timeout',
         'ReadError-transport_error', 'RemoteProtocolError-transport_error'])
def test_p0_transport_faults_no_retry(probe,exception,code,capsys,monkeypatch):
    def fail(request):
        raise exception('SYNTHETIC-private:'+KEY,request=request)
    pauses=[]
    monkeypatch.setattr(bing_client.time,'sleep',lambda s:pauses.append(s))
    client,loader,sends=p0wire(probe,fail)
    assert probe.run_probe(client)==receipt(error=code)
    p0assertwire(loader,sends)
    assert pauses==[]
    assert capsys.readouterr()==('','')


@pytest.mark.parametrize('compressed',[False,True])
@pytest.mark.parametrize('size',[CAP,CAP+1])
def test_p0_stream_decompressed_cap(probe,compressed,size):
    body=b'{"d":[]}'+b' '*(size-8)
    assert len(body)==size
    data=gzip.compress(body) if compressed else body
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            for i in range(0,len(data),4096):
                yield data[i:i+4096]
    client,loader,sends=p0wire(probe,lambda r:httpx.Response(200,
        headers={'Content-Encoding':'gzip'} if compressed else {},stream=Stream()))
    assert probe.run_probe(client)==receipt(error='response_too_large' if size>CAP else None)
    p0assertwire(loader,sends)


@pytest.mark.parametrize('encoding',ENCODINGS)
@pytest.mark.parametrize('location',['projected_url','ignored_dict_key','malformed_raw'])
@pytest.mark.parametrize('route',['parser','inherited_transport'])
def test_p0_reflection_all_output_boundaries(probe,encoding,location,route,record_property):
    value=encoded_key(encoding)
    if location=='malformed_raw':
        body=('not-json:'+value).encode()
    elif location=='projected_url':
        body=json.dumps({'d':[{'Url':'https://safe.example.com/'+value,'IsVerified':True}]}).encode()
    else:
        body=json.dumps({'d':[], 'ignored':[{value:['discarded']}]}).encode()
    assert execute(probe,route,body,record_property)==receipt(error='credential_reflection')


@pytest.mark.parametrize('stage',['constructor','loader','entry','request_hook','response_hook',
                                  'stream','stream_close','transport_close'])
def test_p0_lifecycle_exceptions_quiet_before_logrecord(probe,stage,monkeypatch,capsys):
    hits,raw,delivered=[],[],[]
    factory=logging.getLogRecordFactory()
    def records(*a,**kw):
        raw.append((a,kw))
        return factory(*a,**kw)
    monkeypatch.setattr(logging,'_logRecordFactory',records)
    class Sink(logging.Handler):
        def emit(self,record):
            delivered.append(record.__dict__.copy())
    sink=Sink()
    logger=logging.getLogger('p0.private.lifecycle')
    monkeypatch.setattr(logger,'handlers',[sink])
    monkeypatch.setattr(logger,'level',logging.DEBUG)
    def hit(point):
        if point==stage:
            hits.append(point)
            for name in ('httpx','httpcore.connection','p0.private.lifecycle','arbitrary.p0'):
                logging.getLogger(name).error('private %s',KEY,extra={'nested':{KEY:[KEY]}})
            raise RuntimeError('SYNTHETIC-private:'+KEY)
    class Loader(P0Loader):
        def load(self):
            hit('loader')
            return super().load()
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            hit('stream')
            yield b'{"d":[]}'
        def close(self):
            hit('stream_close')
    class Transport(httpx.MockTransport):
        def __enter__(self):
            hit('entry')
            return super().__enter__()
        def __exit__(self,*args):
            hit('transport_close')
            return super().__exit__(*args)
    original=httpx.Client
    class Client(original):
        def __init__(self,**kwargs):
            hit('constructor')
            super().__init__(event_hooks={'request':[lambda r:hit('request_hook')],
                                        'response':[lambda r:hit('response_hook')]},**kwargs)
    monkeypatch.setattr(httpx,'Client',Client)
    sends=[]
    def send(r):
        sends.append(r)
        return httpx.Response(200,stream=Stream())
    loader=Loader()
    client=probe.RawInventoryProbe(loader,transport=Transport(send),max_retries=0)
    assert probe.run_probe(client)==receipt(error='transport_error')
    assert hits==[stage] and not raw and not delivered
    assert loader.forbidden==[]
    assert len(sends)==(1 if stage in ('response_hook','stream','stream_close','transport_close') else 0)
    assert capsys.readouterr()==('','')
    logger.error('ordinary-after-private-control')
    assert len(raw)==len(delivered)==1


def test_p0_missing_configuration_no_constructor_or_dns(probe,monkeypatch):
    p0auth.configure_bing_auth(SimpleNamespace(bing_credentials_file=None))
    constructions=[]
    def forbidden(**kwargs):
        constructions.append(True)
        raise AssertionError('client before custody')
    monkeypatch.setattr(httpx,'Client',forbidden)
    try:
        assert probe.run_probe(probe.RawInventoryProbe(max_retries=0))==receipt(error='provider_not_configured')
        assert constructions==[]
    finally:
        p0auth.configure_bing_auth(SimpleNamespace(bing_credentials_file=None))


@pytest.mark.parametrize('field,value',[
    ('version',True),('version',1.0),('version','1'),('operation','GetQueryStats'),
    ('status','partial'),('error','foreign-private'),('listed_count',True),
    ('listed_count',1),('listed_count',-1),('verified_count',1),
    ('verified_count',False),('provider_completeness','complete'),
    ('ownership_attestation','approved'),('extra','private'),
    ('sites',[{'site_url':'https://example.com/','is_verified':'true'}]),
    ('sites',[{'site_url':'https://example.com/','is_verified':True}]),
])
def test_p0_run_probe_revalidates_receipt(field,value,probe):
    # This tests the foreign-result validation seam, not the transport fixture.
    class Foreign:
        def read(self,operation,request):
            assert operation is BingOperation.GET_USER_SITES
            assert request.site_url is None
            return {**receipt(),field:value}
    assert probe.run_probe(Foreign())==receipt(error='provider_error')


def test_p0_global_rate_not_reset_per_probe(probe):
    sends=[]
    def send(request):
        sends.append(request)
        return httpx.Response(200,json={'d':[]})
    for _ in range(12):
        assert probe.run_probe(probe.RawInventoryProbe(P0Loader(),
            transport=httpx.MockTransport(send),max_retries=0))==receipt()
    loader=P0Loader()
    assert probe.run_probe(probe.RawInventoryProbe(loader,transport=httpx.MockTransport(send),
        max_retries=0))==receipt(error='rate_limited')
    assert len(sends)==12 and loader.authorized_reads==2
    assert loader.loads==4 and loader.generations==['_read','_attempt']


# Whole CLI bootstrap: unchanged helper run as __main__, actual Bing/HTTPX code;
# substitute only synthetic local loader and upstream transport dependencies.
P0_CLI_BOOT=r'''
import builtins,hashlib,json,logging,os,runpy,socket,sys
from pathlib import Path
import httpx
from google_seo_mcp.bing import auth,client,models,wire_models
helper=Path(sys.argv[1]); evidence=Path(sys.argv[2]); mode=sys.argv[3]; args=sys.argv[4:]
key='SYNTHETIC-review-key.7+Z/19'
state={'network':[],'credential_files':[],'credential_env':[], 'loads':0,'config':[],
       'sends':[], 'constructors':[], 'private_records':[], 'violations':[]}
def deny(*a,**kw):
    state['network'].append('denied')
    raise AssertionError('offline-network')
for name in ('getaddrinfo','gethostbyname','gethostbyname_ex'):
    setattr(socket,name,deny)
socket.socket.connect=deny; socket.socket.connect_ex=deny
credential_names={'BING_API_KEY','BING_WEBMASTER_API_KEY','BING_CREDENTIALS_FILE','BING_SITES_FILE',
                  'GOOGLE_APPLICATION_CREDENTIALS','GOOGLE_SEO_BING_CREDENTIALS_FILE',
                  'GOOGLE_SEO_BING_SITES_FILE'}
getitem=os._Environ.__getitem__
def envread(self,name):
    if name in credential_names: state['credential_env'].append(name)
    return getitem(self,name)
os._Environ.__getitem__=envread
open0=builtins.open; osopen=os.open
# No /run/secrets read is permitted, even if application catches the denial.
def protected(path):
    try: return os.fspath(path).startswith('/run/secrets/')
    except TypeError: return False
def opened(path,*a,**kw):
    if protected(path):
        state['credential_files'].append(str(path)); raise AssertionError('actual-credential-read')
    return open0(path,*a,**kw)
def osopened(path,*a,**kw):
    if protected(path):
        state['credential_files'].append(str(path)); raise AssertionError('actual-credential-read')
    return osopen(path,*a,**kw)
builtins.open=opened; os.open=osopened
configure=auth.configure_bing_auth
def config(value):
    state['config'].append([value.bing_credentials_file])
    configure(value)
auth.configure_bing_auth=config
class Loader:
    def load(self):
        state['loads']+=1
        if mode=='missing': raise auth.BingAuthError('credentials_missing')
        return models.BingCredentialDocument(version=1,api_key=key)
    def generation(self):
        state['generation_calls']+=1
        self.load()
        return 'synthetic-current-generation'
    def require_generation(self,expected):
        state['generation_checks']+=1
        if self.generation()!=expected: raise auth.BingAuthError('credentials_invalid')
auth.BingCredentialLoader=Loader
state.update(generation_calls=0,generation_checks=0)
records=logging.getLogRecordFactory()
def factory(*a,**kw):
    state['private_records'].append('record'); return records(*a,**kw)
logging.setLogRecordFactory(factory)
original=httpx.Client
class Stream(httpx.SyncByteStream):
    def __iter__(self):
        logging.getLogger('cli.private').error('%s',key)
        if mode=='stream': raise RuntimeError(key)
        yield b'{"d":[{"Url":"https://agency.example.com/","IsVerified":false}]}'
    def close(self):
        if mode=='close': raise RuntimeError(key)
def send(request):
    state['sends'].append({'method':request.method,'url':str(request.url.copy_with(query=None)),
                           'param_names':list(request.url.params),'key_correct':request.url.params['apikey']==key})
    if mode=='reflection': return httpx.Response(200,json={'d':[], 'ignored':key})
    return httpx.Response(200,stream=Stream())
class Client(original):
    def __init__(self,**kw):
        state['constructors'].append({'trust_env':kw['trust_env'],
            'follow_redirects':kw['follow_redirects'],'timeout':kw['timeout']})
        logging.getLogger('cli.constructor').error('%s',key)
        if mode=='constructor': raise RuntimeError(key)
        gate=kw['transport']
        kw['transport']=client._GatedTransport(httpx.MockTransport(send),gate.attempt,
                                             gate.loader,gate.generation)
        super().__init__(**kw)
httpx.Client=Client
state['provenance']={str(Path(m.__file__).resolve()):hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest()
                     for m in (auth,client,models,wire_models)}
state['helper_path']=str(helper.resolve());state['helper_sha256']=hashlib.sha256(helper.read_bytes()).hexdigest()
sys.argv=[str(helper),*args]
try:
    runpy.run_path(str(helper),run_name='__main__')
finally:
    evidence.write_text(json.dumps(state,sort_keys=True))
'''


@pytest.mark.parametrize('args',[[],['--help'],['-h'],['--endpoint','https://forbidden.example/'],
    ['--key','SYNTHETIC-ARG-REFLECTION'],['--sites-file','/tmp/forbidden'],
    ['--'],['--help=SYNTHETIC-ARG-REFLECTION'],['SYNTHETIC-ARG-REFLECTION']])
@pytest.mark.parametrize('mode',['success','missing'])
def test_p0_cli_whole_source_zeroargs_and_early_refusal(probe,tmp_path,args,mode,record_property):
    p0cli(probe,tmp_path,args,mode,record_property)


@pytest.mark.parametrize('mode',['constructor','stream','close','reflection'])
def test_p0_cli_private_failures_single_json(probe,tmp_path,mode,record_property):
    p0cli(probe,tmp_path,[],mode,record_property)


def p0cli(probe,tmp_path,args,mode,record_property):
    evidence=tmp_path/'cli-evidence.json'
    root=Path(__file__).resolve().parents[1]
    env={'HOME':str(tmp_path),'PATH':str(Path(sys.executable).parent)+':/usr/bin:/bin',
         'LANG':'C.UTF-8','PYTHONPATH':str(root/'src'),'PYTHONDONTWRITEBYTECODE':'1',
         'PYTHONWARNINGS':'error','HTTP_PROXY':'http://127.0.0.1:9',
         'HTTPS_PROXY':'http://127.0.0.1:9','ALL_PROXY':'http://127.0.0.1:9',
         'BING_API_KEY':'SYNTHETIC-AMBIENT-MUST-NOT-READ',
         'GOOGLE_APPLICATION_CREDENTIALS':'/run/secrets/MUST-NOT-READ'}
    result=subprocess.run([sys.executable,'-W','error','-c',P0_CLI_BOOT,
        str(probe._regression_source_path),str(evidence),mode,*args],
        cwd=tmp_path,env=env,text=True,capture_output=True,timeout=15,check=False)
    assert result.stderr==''
    assert result.stdout.endswith('\n') and len(result.stdout.splitlines())==1
    code=('invalid_request' if args else {'missing':'provider_not_configured',
        'constructor':'transport_error','stream':'transport_error','close':'transport_error',
        'reflection':'credential_reflection'}.get(mode))
    rows=[{'Url':'https://agency.example.com/','IsVerified':False}]
    assert json.loads(result.stdout)==receipt(rows if code is None else (),error=code)
    assert result.returncode==(0 if code is None else 1)
    state=json.loads(evidence.read_text())
    assert state['network']==state['credential_files']==state['credential_env']==[]
    assert state['violations']==state['private_records']==[]
    assert state['config']==([] if args else [['/run/secrets/bing-webmaster.json']])
    assert state['loads']==(0 if args else 1 if mode=='missing' else 2+state['generation_calls'])
    assert state['generation_calls']==(
        0 if args or mode=='missing' else 2+state['generation_checks'])
    sendcount=0 if args or mode in ('missing','constructor') else 1
    assert len(state['sends'])==sendcount
    assert len(state['constructors'])==(0 if args or mode=='missing' else 1)
    for sent in state['sends']:
        assert sent=={'method':'GET','url':'https://ssl.bing.com/webmaster/api.svc/json/GetUserSites',
                      'param_names':['apikey'],'key_correct':True}
    for constructor in state['constructors']:
        assert constructor['trust_env'] is constructor['follow_redirects'] is False
        assert 0<constructor['timeout']<=15
    assert state['helper_sha256']==hashlib.sha256(probe._regression_source_path.read_bytes()).hexdigest()
    assert state['helper_path']==str(probe._regression_source_path.resolve())
    for path,digest in state['provenance'].items():
        assert Path(path).is_relative_to(root/'src/google_seo_mcp/bing')
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest
    record_property('cli_evidence',json.dumps(state,sort_keys=True))


@pytest.mark.parametrize('stage',['initial_credentials','attempt_credentials','constructor','entry','params','build','slot'])
def test_p0_total_supervisor_cancels_all_late_dispatch(probe,stage,monkeypatch):
    original_budget=bing_client._Budget
    budgets=[]
    class ShortBudget(original_budget):
        def __init__(self,clock):
            super().__init__(clock)
            self.end=clock()+0.12
            self.real_end=time.monotonic()+0.12
            budgets.append(self)
    monkeypatch.setattr(bing_client,'_Budget',ShortBudget)
    entered,release,finished=threading.Event(),threading.Event(),threading.Event()
    hits=[]
    def stall():
        hits.append(stage)
        entered.set()
        release.wait(3)
    class Loader(P0Loader):
        def load(self):
            if (stage=='initial_credentials' and self.loads==0 or
                    stage=='attempt_credentials' and self.authorized_reads==1
                    and __import__('inspect').currentframe().f_back.f_code.co_name=='_authorize'):
                stall()
            try:
                return super().load()
            finally:
                if stage=='initial_credentials': finished.set()
    original_client=httpx.Client
    class Client(original_client):
        def __init__(self,**kwargs):
            if stage=='constructor': stall()
            super().__init__(**kwargs)
        def build_request(self,*args,**kwargs):
            result=super().build_request(*args,**kwargs)
            if stage=='build': stall()
            return result
    monkeypatch.setattr(httpx,'Client',Client)
    class Transport(httpx.MockTransport):
        def __enter__(self):
            if stage=='entry': stall()
            return super().__enter__()
        def close(self):
            try:
                return super().close()
            finally:
                finished.set()
        def __exit__(self,*args):
            try: return super().__exit__(*args)
            finally: finished.set()
    original_params=bing_client._params
    def params(*args):
        if stage=='params': stall()
        return original_params(*args)
    monkeypatch.setattr(bing_client,'_params',params)
    slot=bing_client._GLOBAL.slot
    class Slot:
        def acquire(self,timeout):
            got=slot.acquire(timeout=timeout)
            if got and stage=='slot': stall()
            return got
        def release(self):
            slot.release()
            if stage in ('attempt_credentials','slot'): finished.set()
    monkeypatch.setattr(bing_client._GLOBAL,'slot',Slot())
    sends=[]
    def send(r):
        sends.append(r)
        return httpx.Response(200,json={'d':[]})
    loader=Loader()
    client=probe.RawInventoryProbe(loader,transport=Transport(send),max_retries=0)
    start=time.monotonic()
    try:
        assert probe.run_probe(client)==receipt(error='timeout')
        assert 0.07<=time.monotonic()-start<1
        assert entered.is_set() and hits==[stage] and not sends
        assert budgets[0].cancelled.is_set() and budgets[0].remaining()==0
        if stage!='initial_credentials':
            assert not slot.acquire(blocking=False)
    finally:
        release.set()
        assert finished.wait(2)
        assert slot.acquire(timeout=2)
        slot.release()
        # Join both actual daemon boundaries before fixture restoration.
        for thread in threading.enumerate():
            if thread.name in ('bing-boundary','bing-read'): thread.join(2)
    assert not sends and loader.forbidden==[]


@pytest.mark.parametrize('stage',['entry','stream'])
def test_p0_actual_fifteen_second_attempt_retains_concurrency(probe,stage,monkeypatch):
    entered,release,closed=threading.Event(),threading.Event(),threading.Event()
    sends=[]
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            if stage=='stream':
                entered.set(); release.wait(23)
            yield b'{"d":[]}'
    class Transport(httpx.MockTransport):
        def __enter__(self):
            if stage=='entry':
                entered.set(); release.wait(23)
            return super().__enter__()
        def close(self):
            try:
                return super().close()
            finally:
                closed.set()
        def __exit__(self,*args):
            try: return super().__exit__(*args)
            finally: closed.set()
    def send(r):
        sends.append(r)
        return httpx.Response(200,stream=Stream())
    client=probe.RawInventoryProbe(P0Loader(),transport=Transport(send),max_retries=0)
    start=time.monotonic()
    try:
        assert probe.run_probe(client)==receipt(error='timeout')
        assert 14.5<=time.monotonic()-start<19
        assert entered.is_set()
        assert len(sends)==(1 if stage=='stream' else 0)
        original=bing_client._Budget
        class ShortBudget(original):
            def __init__(self,clock):
                super().__init__(clock)
                self.end=clock()+0.08; self.real_end=time.monotonic()+0.08
        monkeypatch.setattr(bing_client,'_Budget',ShortBudget)
        other,loader,other_sends=p0wire(probe,lambda r:httpx.Response(200,json={'d':[]}))
        assert probe.run_probe(other)==receipt(error='timeout')
        assert other_sends==[] and loader.authorized_reads==1
        assert loader.loads==2 and loader.generations==['_read']
        assert not bing_client._GLOBAL.slot.acquire(blocking=False)
    finally:
        release.set()
        assert closed.wait(2)
        assert bing_client._GLOBAL.slot.acquire(timeout=2)
        bing_client._GLOBAL.slot.release()
        for thread in threading.enumerate():
            if thread.name in ('bing-boundary','bing-read'): thread.join(2)
    assert len(sends)==(1 if stage=='stream' else 0), 'late dispatch after returned timeout'


@pytest.mark.parametrize('operation', [BingOperation.GET_QUERY_STATS, BingOperation.GET_URL_INFO,
                                     BingOperation.GET_FEEDS])
def test_p0_business_operations_refuse_before_custody(probe,operation):
    client,loader,sends=p0wire(probe,lambda r:httpx.Response(200,json={'d':[]}))
    request=BingToolRequest(operation=operation,site_url='https://example.com/',
                            **({'url':'https://example.com/page'} if operation is BingOperation.GET_URL_INFO else {}))
    assert client.read(operation,request)==receipt(error='invalid_request')
    p0assertwire(loader,sends,count=0,loads=0)


@pytest.mark.parametrize('body,key', [(bytearray(b'{"d":[]}'),KEY), ('{"d":[]}',KEY),
                                     (None,KEY),(b'{"d":[]}',None),(b'{"d":[]}',''),
                                     (b'{"d":[]}',17)])
def test_p0_parser_boundary_types(probe,body,key):
    assert probe.parse_inventory(body,key)==receipt(error='invalid_response')


def test_p0_exact_url_identity_and_true_dedup(probe,record_property):
    rows=[{'Url':'http://distinct.example.com/','IsVerified':False},
          {'Url':'https://distinct.example.com/','IsVerified':True},
          {'Url':'https://distinct.example.com/path/','IsVerified':False},
          {'Url':'https://distinct.example.com/','IsVerified':True}]
    assert execute(probe,'inherited_transport',json.dumps({'d':rows}).encode(),record_property)==receipt(rows[:3])


def test_p0_scanner_reaches_raw_parsed_and_projected(probe,monkeypatch):
    observed=[]
    original=probe._operator_reflection
    def scanner(value,key):
        observed.append(value)
        return original(value,key)
    monkeypatch.setattr(probe,'_operator_reflection',scanner)
    payload={'d':[{'Url':'https://safe.example.com/','IsVerified':False,
                   'VerificationCode':{'ignored':['public-only']}}]}
    client,loader,sends=p0wire(probe,lambda r:httpx.Response(200,json=payload))
    expected=receipt(payload['d'])
    assert probe.run_probe(client)==expected
    assert len(observed)==5
    assert observed[0]==[None,'synthetic-current-generation']
    assert isinstance(observed[1],str) and isinstance(observed[2],str)
    assert observed[3]==payload and observed[4]==expected
    p0assertwire(loader,sends)


def test_p0_actual_sixty_second_supervisor_no_late_custody_dispatch(probe):
    entered,release,returned=threading.Event(),threading.Event(),threading.Event()
    class Loader(P0Loader):
        def load(self):
            entered.set()
            release.wait(70)
            try:
                return super().load()
            finally:
                returned.set()
    loader=Loader()
    client,_,sends=p0wire(probe,lambda r:httpx.Response(200,json={'d':[]}),loader=loader)
    start=time.monotonic()
    try:
        assert probe.run_probe(client)==receipt(error='timeout')
        assert entered.is_set() and 59.5<=time.monotonic()-start<65
        assert not sends and loader.loads==0
    finally:
        release.set()
        assert returned.wait(2)
        for thread in threading.enumerate():
            if thread.name in ('bing-boundary','bing-read'): thread.join(2)
    assert not sends and loader.loads==1 and not loader.forbidden


def test_p0_runtime_provenance_and_inherited_methods(probe,record_property):
    root=Path(__file__).resolve().parents[1]
    for module in (bing_client,p0auth):
        source=Path(module.__file__).resolve()
        assert source.is_relative_to(root/'src/google_seo_mcp/bing')
        record_property(source.name+'_path',str(source))
        record_property(source.name+'_sha256',hashlib.sha256(source.read_bytes()).hexdigest())
    assert set(probe.RawInventoryProbe.__dict__)-{'__module__','__doc__'}=={'_read'}
    for name in ('read','_admit','_attempt','_authorize'):
        assert getattr(probe.RawInventoryProbe,name) is getattr(bing_client.BingReadClient,name)
    record_property('helper_sha256',hashlib.sha256(probe._regression_source_path.read_bytes()).hexdigest())


# Seq84 independent regressions. Never put reflective values in pytest assertions,
# properties, IDs or retained streams; every observation below is a safe predicate.
SEQ84_FRAMES = ('url', 'odd_prefix', 'even_prefix', 'odd_tail', 'even_tail', 'both')


def seq84_value(frame):
    nested = base64.b64encode(KEY.encode()).hex()
    prefix, suffix = {
        'url': ('', ''), 'odd_prefix': ('a', ''),
        'even_prefix': ('ab', ''), 'odd_tail': ('', 'f'),
        'even_tail': ('', 'ef'), 'both': ('abc', 'def'),
    }[frame]
    # Deliberately whole public URL: lexical framing, not a bare hex token.
    return 'https://framing.example.com/catalog/' + prefix + nested + suffix + '/item/'


def seq84_body(frame, location):
    value = seq84_value(frame)
    if location == 'raw':
        return ('not-json:' + value).encode()
    row = {'Url': 'https://safe.example.com/', 'IsVerified': False}
    if location == 'projected_url':
        row['Url'] = value
    else:
        row['VerificationCode'] = {'nested': [value]}
    return json.dumps({'d': [row]}).encode()


def seq84_wire(probe, body):
    client, loader, sends = p0wire(probe, lambda r: httpx.Response(200, content=body))
    result = probe.run_probe(client)
    # Only booleans reach assertion rewriting, never the request/key/body.
    safe_wire = (loader.authorized_reads == 2
                 and loader.loads == 2 + len(loader.generations)
                 and loader.generations[:2] == ['_read','_attempt']
                 and not loader.forbidden and len(sends) == 1
                 and sends[0].method == 'GET'
                 and str(sends[0].url.copy_with(query=None)) ==
                 'https://ssl.bing.com/webmaster/api.svc/json/GetUserSites'
                 and list(sends[0].url.params.multi_items()) == [('apikey', KEY)])
    assert safe_wire, 'seq84 fixed synthetic wire contract'
    return result


@pytest.mark.parametrize('frame', SEQ84_FRAMES)
@pytest.mark.parametrize('location', ['raw', 'ignored', 'projected_url'])
@pytest.mark.parametrize('route', ['parser', 'inherited_transport'])
def test_seq84_f1_framed_parser_wire(probe, frame, location, route):
    body = seq84_body(frame, location)
    actual = (probe.parse_inventory(body, KEY) if route == 'parser'
              else seq84_wire(probe, body))
    refused = actual == receipt(error='credential_reflection')
    assert refused, 'F1 framed reflection must refuse complete receipt'


@pytest.mark.parametrize('stage', ['raw', 'parsed_ignored', 'projection'])
@pytest.mark.parametrize('frame', SEQ84_FRAMES)
def test_seq84_f1_each_scanner_boundary(probe, stage, frame):
    # Isolate each real scanner input, so raw refusal cannot conceal a later gap.
    value = seq84_value(frame)
    target = (seq84_body(frame, 'projected_url').decode() if stage == 'raw' else
              {'d': [{'VerificationCode': {'nested': [value]}}]} if stage == 'parsed_ignored'
              else receipt([{'Url': value, 'IsVerified': True}]))
    refused = False
    try:
        probe._operator_reflection(target, KEY)
    except bing_client._Stop as exc:
        refused = exc.code == 'credential_reflection'
    assert refused, 'F1 real scanner must refuse at every boundary'


def seq84_boot():
    # Reuse the established synthetic loader, source execution, traps and real
    # inherited HTTPX path. Only offline dependencies/telemetry are extended.
    boot = P0_CLI_BOOT.replace(
        "import builtins,hashlib,json,logging,os,runpy,socket,sys",
        "import base64,builtins,hashlib,json,logging,os,runpy,signal,socket,sys,threading,time,warnings")
    boot = boot.replace("original=httpx.Client", r'''
state.update(injected=0, diagnostic_scans=0, scanner_key_correct=True,
             stderr_captured=False, entry_ready=False, after_entry=0)
diag = 'SEQ84-DIAGNOSTIC:' + (
    key if mode=='stderr_raw' else
    base64.b64encode(key.encode()).hex() if mode=='stderr_encoded' else 'public-note')
def profile(frame,event,arg):
    if event=='call' and frame.f_code.co_name=='_operator_reflection':
        value=frame.f_locals.get('value')
        # Observe the real scanner, never substitute a scanner result.
        if isinstance(value,str) and diag in value:
            state['diagnostic_scans']+=1
            state['scanner_key_correct'] &= frame.f_locals.get('key')==key
sys.setprofile(profile)
threading.setprofile(profile)
class OperatorAbort(BaseException): pass
def aborted(signum,frame):
    raise OperatorAbort('operator-interrupted')
if mode=='interrupt_other': signal.signal(signal.SIGUSR1,aborted)
class EntryTransport(httpx.MockTransport):
    def __enter__(self):
        if mode.startswith('interrupt_'):
            state['entry_ready']=True
            evidence.with_suffix('.ready').write_text('ready')
            while not evidence.with_suffix('.release').exists(): time.sleep(.01)
            state['after_entry']+=1
        return super().__enter__()
original=httpx.Client''')
    boot = boot.replace("    if mode=='reflection':", r'''
    if mode.startswith('framing:'):
        _,frame,location=mode.split(':')
        nested=base64.b64encode(key.encode()).hex()
        prefix,suffix={'url':('',''),'odd_prefix':('a',''),'even_prefix':('ab',''),
                       'odd_tail':('','f'),'even_tail':('','ef'),'both':('abc','def')}[frame]
        value='https://framing.example.com/catalog/'+prefix+nested+suffix+'/item/'
        if location=='raw': return httpx.Response(200,content=('not-json:'+value).encode())
        row={'Url':'https://safe.example.com/','IsVerified':False}
        if location=='projected_url': row['Url']=value
        else: row['VerificationCode']={'nested':[value]}
        return httpx.Response(200,json={'d':[row]})
    if mode=='warning':
        state['injected']+=1
        warnings.warn(key,RuntimeWarning)
    if mode.startswith('stderr_'):
        state['injected']+=1
        state['stderr_captured']=sys.stderr is not sys.__stderr__
        sys.stderr.write(diag+'\n')
    if mode=='reflection':''')
    boot = boot.replace('httpx.MockTransport(send),gate.attempt',
                        'EntryTransport(send),gate.attempt')
    boot = boot.replace("        if mode=='missing':", """        if mode=='stderr_no_key':
            state['injected']+=1
            state['stderr_captured']=sys.stderr is not sys.__stderr__
            sys.stderr.write(diag+'\\n')
            raise auth.BingAuthError('credentials_missing')
        if mode=='missing':""")
    return boot


def seq84_command(probe, tmp_path, mode, policy):
    root = Path(__file__).resolve().parents[1]
    evidence = tmp_path / 'seq84-cli-evidence.json'
    env = {'HOME': str(tmp_path), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
           'PYTHONPATH': str(root / 'src'), 'PYTHONDONTWRITEBYTECODE': '1'}
    flags = ['-W', 'error'] if policy == 'error' else []
    return ([sys.executable, '-B', *flags, '-c', seq84_boot(),
             str(probe._regression_source_path), str(evidence), mode], env, evidence)


def seq84_cli(probe, tmp_path, mode, policy):
    command, env, evidence = seq84_command(probe, tmp_path, mode, policy)
    child = subprocess.run(command, cwd=tmp_path, env=env, text=True,
                           capture_output=True, timeout=15, check=False)
    state = json.loads(evidence.read_text())
    # Do not persist either stream, even on a failed privacy assertion.
    try:
        output = json.loads(child.stdout)
    except (ValueError, TypeError):
        output = None
    safe = {'exit': child.returncode, 'one_line': len(child.stdout.splitlines()) == 1,
            'stderr_empty': not child.stderr,
            'reflection_refused': output == receipt(error='credential_reflection'),
            'success_complete': output == receipt([{'Url': 'https://agency.example.com/', 'IsVerified': False}]),
            'failed_static': (type(output) is dict and output.get('status') == 'failed'
                              and output == receipt(error=output.get('error')))}
    safe_provenance = (state['helper_sha256'] == hashlib.sha256(
        probe._regression_source_path.read_bytes()).hexdigest()
        and state['network'] == state['credential_files'] == state['credential_env'] == []
        and state['violations'] == [] and len(state['sends']) == (0 if mode == 'stderr_no_key' else 1)
        and all(Path(path).is_relative_to(Path(__file__).resolve().parents[1] / 'src')
                and hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
                for path, digest in state['provenance'].items()))
    assert safe_provenance, 'seq84 actual source/offline/single-send provenance'
    return safe, state


@pytest.mark.parametrize('frame', SEQ84_FRAMES)
@pytest.mark.parametrize('location', ['raw', 'ignored', 'projected_url'])
def test_seq84_f1_actual_cli(probe, tmp_path, frame, location):
    safe, _ = seq84_cli(probe, tmp_path, 'framing:' + frame + ':' + location, 'normal')
    refused = (safe['exit'] == 1 and safe['one_line'] and safe['stderr_empty']
               and safe['reflection_refused'])
    assert refused, 'F1 actual CLI must refuse framed reflection'


@pytest.mark.parametrize('policy', ['normal', 'error'])
@pytest.mark.parametrize('mode', ['warning', 'stderr_public', 'stderr_raw', 'stderr_encoded', 'stderr_no_key'])
def test_seq84_f2_cli_warning_and_captured_stderr(probe, tmp_path, mode, policy):
    safe, state = seq84_cli(probe, tmp_path, mode, policy)
    injected = state['injected'] == 1
    assert injected, 'F2 injection must actually execute'
    if mode == 'stderr_no_key':
        no_diagnostic_fetch = state['loads'] == 1 and not state['sends']
        assert no_diagnostic_fetch, 'F2 missing key provenance forbids diagnostic secret retrieval'
    elif mode.startswith('stderr_'):
        scanned = (state['stderr_captured'] and state['diagnostic_scans'] > 0
                   and state['scanner_key_correct'])
        assert scanned, 'F2 captured stderr must reach real key-aware scanner before discard'
    stopped = (safe['exit'] == 1 and safe['one_line'] and safe['stderr_empty']
               and safe['failed_static'])
    assert stopped, 'F2 warning or unexpected stderr must produce safe failed STOP'


@pytest.mark.parametrize('mode', ['interrupt_sigint', 'interrupt_other'])
def test_seq84_f4_actual_cli_process_termination(probe, tmp_path, mode):
    import signal
    command, env, evidence = seq84_command(probe, tmp_path, mode, 'normal')
    child = subprocess.Popen(command, cwd=tmp_path, env=env, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 8
        while not evidence.with_suffix('.ready').exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        ready = evidence.with_suffix('.ready').exists() and child.poll() is None
        assert ready, 'F4 actual worker must pause at transport entry'
        child.send_signal(signal.SIGINT if mode == 'interrupt_sigint' else signal.SIGUSR1)
        stdout, stderr = child.communicate(timeout=5)
        # No catch-and-continue in the child: runpy finally records only telemetry;
        # the real BaseException must terminate this exact process.
        evidence.with_suffix('.release').write_text('release-after-exit')
        state = json.loads(evidence.read_text())
        terminated = child.returncode != 0 and child.poll() is not None
        no_dispatch = state['sends'] == [] and state['after_entry'] == 0
        no_success = not stdout
        safe_diagnostics = (KEY not in stderr and base64.b64encode(KEY.encode()).hex() not in stderr)
        assert terminated, 'F4 standalone CLI must terminate on caller BaseException'
        assert no_dispatch, 'F4 no dispatch/retry after interrupted process exit'
        assert no_success, 'F4 interruption cannot become successful receipt'
        assert safe_diagnostics, 'F4 traceback must not disclose synthetic key'
        offline_ok = state['network'] == state['credential_files'] == state['credential_env'] == []
        assert offline_ok, 'F4 no external network or protected credential reads'
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        # On an early failed readiness assertion the child may already have
        # exited: close both captured pipes without suppressing ResourceWarning.
        child.stdout.close()
        child.stderr.close()


@pytest.mark.parametrize('policy', ['normal', 'error'])
def test_seq84_f2_cli_clean_positive_control(probe, tmp_path, policy):
    safe, state = seq84_cli(probe, tmp_path, 'success', policy)
    clean = (safe['exit'] == 0 and safe['one_line'] and safe['stderr_empty']
             and safe['success_complete'] and state['injected'] == 0)
    assert clean, 'F2 clean source CLI remains complete success under both policies'


# Typed migration: real producer observations are separate from deliberately
# foreign/unchecked transfer tests. No outward API acquires a provider key.
@pytest.mark.parametrize('location', ['body', 'header', 'ignored_key', 'ignored_value'])
def test_typed_producer_refuses_before_private_handoff(probe, monkeypatch, location):
    produced = []
    original = bing_client.BingRawResponse

    def construct(**values):
        produced.append(True)
        return original(**values)

    monkeypatch.setattr(bing_client, 'BingRawResponse', construct)
    value = seq84_value('both')
    payload = {'d': []}
    headers = {}
    if location == 'ignored_key':
        payload[value] = 'discarded'
    elif location == 'ignored_value':
        payload['VerificationCode'] = {'nested': [value]}
    elif location == 'header':
        headers['X-Synthetic-Private'] = value
    body = value.encode() if location == 'body' else json.dumps(payload).encode()
    client, loader, sends = p0wire(
        probe, lambda r: httpx.Response(200, headers=headers, content=body))
    refused = probe.run_probe(client) == receipt(error='credential_reflection')
    assert refused, 'real producer must reject before constructing raw transfer'
    assert produced == []
    p0assertwire(loader, sends)


def test_typed_real_response_budget_generation_and_projection(probe, monkeypatch):
    attempts, transfers, producer_scans = [], [], []
    original_attempt = bing_client.BingReadClient._attempt
    original_scan = bing_client._reject_reflection
    original_parse = probe.parse_inventory
    parsed = []

    def scan(value, key):
        producer_scans.append(type(value).__name__)
        return original_scan(value, key)

    def attempt(self, request, budget, *, expected_generation=None):
        attempts.append((budget, expected_generation, len(producer_scans)))
        raw = original_attempt(self, request, budget, expected_generation=expected_generation)
        transfers.append((raw, len(producer_scans)))
        return raw

    def parse(body, key):
        parsed.append((body, key))
        return original_parse(body, key)

    monkeypatch.setattr(bing_client, '_reject_reflection', scan)
    monkeypatch.setattr(bing_client.BingReadClient, '_attempt', attempt)
    monkeypatch.setattr(probe, 'parse_inventory', parse)
    row = {'Url': 'https://typed.example.com/', 'IsVerified': False}
    body = json.dumps({'d': [row], 'VerificationCode': {'ignored': ['public']}}).encode()
    client, loader, sends = p0wire(probe, lambda r: httpx.Response(200, content=body))
    assert probe.run_probe(client) == receipt([row])
    assert len(attempts) == len(transfers) == len(parsed) == 1
    raw, scanned = transfers[0]
    assert type(raw) is probe.BingRawResponse
    assert raw.body == body and raw.model_dump() == {}
    assert set(vars(raw)) == {'status_code', 'retry_after', 'body', 'credential_generation'}
    assert scanned >= attempts[0][2] + 4
    assert attempts[0][1] == raw.credential_generation == 'synthetic-current-generation'
    assert attempts[0][0].remaining() > 0
    assert parsed[0] == (body, KEY)
    assert loader.requirements[-1] == '_read'
    p0assertwire(loader, sends)


@pytest.mark.parametrize('field', ['status_code', 'retry_after', 'body',
                                  'credential_generation', 'extra', 'foreign_tuple'])
def test_typed_unchecked_transfer_revalidated(probe, monkeypatch, field):
    values = {'status_code': 200, 'retry_after': None, 'body': b'{"d":[]}',
              'credential_generation': 'synthetic-current-generation'}
    invalid = {'status_code': True, 'retry_after': object(), 'body': bytearray(b'{"d":[]}'),
               'credential_generation': '', 'extra': 'unexpected'}
    if field != 'foreign_tuple':
        values[field] = invalid[field]
    raw = (200, None, b'{"d":[]}', KEY) if field == 'foreign_tuple' else (
        probe.BingRawResponse.model_construct(**values))
    if field == 'extra':
        raw.__dict__['extra'] = 'unexpected'
    observed = []

    def attempt(self, request, budget, *, expected_generation=None):
        observed.append(expected_generation)
        return raw

    monkeypatch.setattr(bing_client.BingReadClient, '_attempt', attempt)
    client, loader, sends = p0wire(probe, lambda r: httpx.Response(200, json={'d': []}))
    assert probe.run_probe(client) == receipt(error='invalid_response')
    assert observed == ['synthetic-current-generation'] and sends == []
    assert loader.authorized_reads == 1


@pytest.mark.parametrize('field', ['body', 'retry_after', 'credential_generation'])
def test_typed_private_attributes_not_assumed_egress_safe(probe, monkeypatch, field):
    values = {'status_code': 200, 'retry_after': None, 'body': b'{"d":[]}',
              'credential_generation': 'synthetic-current-generation'}
    value = seq84_value('odd_prefix')
    values[field] = value.encode() if field == 'body' else value
    # A structurally valid private record still needs actual key-aware scanning.
    raw = probe.BingRawResponse(**values)
    assert raw.model_dump() == {}

    def attempt(self, request, budget, *, expected_generation=None):
        return raw

    monkeypatch.setattr(bing_client.BingReadClient, '_attempt', attempt)
    client, loader, sends = p0wire(probe, lambda r: httpx.Response(200, json={'d': []}))
    refused = probe.run_probe(client) == receipt(error='credential_reflection')
    assert refused, 'excluded transfer fields are private, not certified safe'
    assert sends == [] and loader.authorized_reads == 1


@pytest.mark.parametrize('stage', ['attempt_generation', 'transport_entry', 'stream_close'])
def test_typed_generation_change_never_publishes_inventory(probe, stage):
    class Loader(P0Loader):
        changed = False

        def generation(self):
            generation = super().generation()
            if stage == 'attempt_generation' and self.authorized_reads == 2:
                self.changed = True
            return 'synthetic-replacement-generation' if self.changed else generation

    loader = Loader()

    class Transport(httpx.MockTransport):
        def __enter__(self):
            if stage == 'transport_entry':
                loader.changed = True
            return super().__enter__()

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"d":[]}'

        def close(self):
            if stage == 'stream_close':
                loader.changed = True

    sends = []

    def send(request):
        sends.append(True)
        return httpx.Response(200, stream=Stream())

    client = probe.RawInventoryProbe(loader, transport=Transport(send), max_retries=0)
    assert probe.run_probe(client) == receipt(error='credentials_invalid')
    assert len(sends) == (1 if stage == 'stream_close' else 0)


@pytest.mark.parametrize('mutate', [False, True])
def test_typed_actual_keyonly_custody_no_stale_authority(probe, tmp_path, mutate):
    path = tmp_path / 'synthetic-key.json'
    path.write_text(json.dumps({'version': 1, 'api_key': KEY}))
    path.chmod(0o600)
    p0auth.configure_bing_auth(SimpleNamespace(bing_credentials_file=str(path)))
    loader = p0auth.BingCredentialLoader()
    custody = probe._EgressCustody(loader)

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"d":[{"Url":"https://custody.example.com/","IsVerified":false}]}'

        def close(self):
            if mutate:
                path.chmod(0o644)

    sends = []

    def send(request):
        sends.append(True)
        return httpx.Response(200, stream=Stream())

    client = probe.RawInventoryProbe(custody, transport=httpx.MockTransport(send), max_retries=0)
    try:
        result = probe.run_probe(client)
        expected = (receipt(error='credentials_invalid') if mutate else
                    receipt([{'Url': 'https://custody.example.com/', 'IsVerified': False}]))
        assert result == expected and sends == [True]
        assert custody._keys == [KEY]
        # Explicit reconfiguration revokes this loader, even with the same path.
        p0auth.configure_bing_auth(SimpleNamespace(bing_credentials_file=str(path)))
        assert probe.run_probe(client) == receipt(error='credentials_invalid')
        assert sends == [True]
    finally:
        custody._keys.clear()
        p0auth.configure_bing_auth(SimpleNamespace(bing_credentials_file=None))
