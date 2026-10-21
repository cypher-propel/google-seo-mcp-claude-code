"""Property-bound execution, independent legs and account worker isolation."""
from concurrent.futures import ThreadPoolExecutor
import os
import sys
import subprocess
import json
from pathlib import Path
import pytest
from tests.test_google_accounts_auth import ACCOUNTS, custody, wire, deadline
from tests.test_google_property_union import URL, DOMAIN, site, page

A, B = ACCOUNTS


def populate(w):
    w.sites[A] = [site(URL)]
    w.sites[B] = [site(DOMAIN)]
    w.pages[A] = [page([101])]
    w.pages[B] = [page([202])]


def gsc_operation(url):
    def operation(bundle):
        result = bundle.gsc.searchanalytics().query(siteUrl=url, body={
            'startDate':'2026-01-01', 'endDate':'2026-01-02'}).execute()
        return {'account':bundle.account_id, 'rows':len(result.get('rows', []))}
    return operation


def ga4_operation(resource):
    def operation(bundle):
        bundle.ga4_data.get_metadata(name=resource+'/metadata')
        return {'account':bundle.account_id}
    return operation


def test_independent_gsc_a_ga4_b_real_sdk_legs(wire):
    w, _, _, _, router = wire
    populate(w)
    gsc = router.for_gsc(URL, deadline())
    ga4 = router.for_ga4('properties/202', deadline())
    assert gsc.execute(gsc_operation(URL)) == {'account':A, 'rows':0}
    assert ga4.execute(ga4_operation('properties/202')) == {'account':B}
    assert any(a == A and '/searchAnalytics/query' in p for a,p in w.calls)
    assert any(a == B and '/metadata' in p for a,p in w.calls)


@pytest.mark.parametrize('selector', ['https://SYNTHETIC.example/', 'https://synthetic.example', URL+'other/', 'sc-domain:other.example'])
def test_gsc_exact_identifier_never_broadens_membership(wire, selector):
    w, _, _, _, router = wire
    populate(w)
    with pytest.raises(RuntimeError):
        router.for_gsc(selector, deadline())
    assert not any('/searchAnalytics/query' in p for _,p in w.calls)


def test_unverified_gsc_is_listed_but_not_eligible(wire):
    w, _, _, discovery, router = wire
    w.sites[A] = [site(URL, 'siteUnverifiedUser')]
    snap = discovery.discover('gsc', deadline())
    assert snap.complete and {m.property_id for m in snap.memberships} == {URL}
    with pytest.raises(RuntimeError):
        router.for_gsc(URL, deadline())


def test_mixed_worker_explicit_account_and_identity_lock(wire):
    w, _, _, _, router = wire
    populate(w)
    w.delay = 0.01
    adapters = {A:router.for_gsc(URL, deadline()), B:router.for_gsc(DOMAIN, deadline())}
    def run(index):
        a = ACCOUNTS[index%2]
        url = URL if a == A else DOMAIN
        result = adapters[a].execute(gsc_operation(url))
        return a, result['account']
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(run, range(16)))
    assert all(expected == observed for expected,observed in results)
    assert w.max_active == {A:1, B:1}
    assert w.max_total >= 2
    assert sorted(a for a,p in w.calls if p == 'refresh') == sorted(ACCOUNTS)


def test_generation_change_refuses_prebound_cached_result(wire, custody):
    w, _, _, _, router = wire
    populate(w)
    executor = router.for_gsc(URL, deadline())
    assert executor.execute(lambda b: {'cached':'synthetic'}) == {'cached':'synthetic'}
    _, docs, _, save, _ = custody
    docs[0]['refresh_token'] = docs[0]['refresh_token']+'changed'
    save(0)
    entered = []
    with pytest.raises(RuntimeError):
        executor.execute(lambda b: entered.append(True) or {'cached':'synthetic'})
    assert not entered


def test_fresh_request_revocation_blocks_cached_admission(wire):
    w, _, _, _, router = wire
    populate(w)
    assert router.for_gsc(URL, deadline()).execute(lambda b: {'cached':'synthetic'}) == {'cached':'synthetic'}
    w.sites[A] = []
    with pytest.raises(RuntimeError):
        router.for_gsc(URL, deadline())


def test_upstream_business_denial_has_no_alternate_identity_retry(wire):
    w, _, _, _, router = wire
    w.sites[A] = [site(URL)]; w.sites[B] = [site(URL)]
    executor = router.for_gsc(URL, deadline())
    # Refuse only business requests, after both identities' real discovery.
    before = len(w.calls)
    original = w.send
    def denied(request, **kw):
        if '/searchAnalytics/query' in request.url:
            w.fail.add((A, '*')); w.fail.add((B, '*'))
        return original(request, **kw)
    w.send = denied
    with pytest.raises(RuntimeError):
        executor.execute(gsc_operation(URL))
    business = [(a,p) for a,p in w.calls[before:] if '/searchAnalytics/query' in p]
    assert len(business) == 1 and business[0][0] == A


def test_actual_metadata_cache_fresh_revocation_before_cached_result(custody):
    root = Path(__file__).resolve().parents[1]
    env = {'PATH': os.environ['PATH'], 'PYTHONPATH': str(root/'src')+os.pathsep+str(root),
           'PYTHONDONTWRITEBYTECODE':'1', 'SEQ208_CUSTODY_ROOT':str(custody[0])}
    result = subprocess.run([sys.executable, '-W', 'error', '-c',
        'from tests.test_google_property_routing import _exercise_metadata_cache; _exercise_metadata_cache()'],
        cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False)
    assert result.returncode == 0


def _exercise_metadata_cache():
    import requests
    import socket
    import google_seo_mcp.ga4.schema as schema
    import google_seo_mcp.auth as auth
    from google_seo_mcp.runtime_config import ProductionRuntimeConfig
    from tests.test_google_accounts_auth import LocalWire, CLIENT, close_resources
    root = Path(os.environ['SEQ208_CUSTODY_ROOT'])
    docs = [json.loads((root/name).read_bytes()) for name in ['a.json','b.json']]
    w = LocalWire(docs)
    populate(w)
    def forbidden(*a, **kw):
        raise AssertionError('OFFLINE_NETWORK_REFUSED')
    requests.adapters.HTTPAdapter.send = lambda adapter, request, **kw: w.send(request, **kw)
    socket.getaddrinfo = forbidden
    socket.socket.connect = forbidden
    sessions = []
    session_init = requests.sessions.Session.__init__
    def tracked_session(session, *args, **kwargs):
        session_init(session, *args, **kwargs)
        sessions.append(session)
    requests.sessions.Session.__init__ = tracked_session
    primary = None
    try:
        config = ProductionRuntimeConfig(profile='production', transport='streamable-http',
            public_base_url='https://synthetic.invalid', consumer_keys_file=str(root/'unused-consumers.json'),
            google_auth_mode='dual-user-oauth',
            google_oauth_client_file=str(root/'client.json'), google_oauth_propel_dms_file=str(root/'a.json'),
            google_oauth_addourteam99_file=str(root/'b.json'), google_approved_client_id=CLIENT,
            google_approved_project_id='synthetic-seq208')
        auth.configure_hosted_auth(config)
        first = schema.get_schema('properties/202')
        second = schema.get_schema('properties/202')
        assert first == second
        metadata = [(a,p) for a,p in w.calls if p.endswith('/metadata')]
        assert len(metadata) == 1 and metadata[0][0] == B
        w.pages[B] = [{}]
        with pytest.raises(RuntimeError):
            schema.get_schema('properties/202')
        assert len([(a,p) for a,p in w.calls if p.endswith('/metadata')]) == 1
    except BaseException as exc:
        primary = exc
        raise
    finally:
        close_resources([*sessions, *w.responses], primary)


def test_concurrent_first_refresh_one_per_identity(wire):
    w, _, clients, _, _ = wire
    w.delay = 0.03
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda i: clients.execute(ACCOUNTS[i%2], lambda b:b.account_id, deadline()), range(16)))
    assert results == [ACCOUNTS[i%2] for i in range(16)]
    assert sorted(a for a,p in w.calls if p == 'refresh') == sorted(ACCOUNTS)
    assert sorted(w.scopes) == [(B,True),(A,True)]
