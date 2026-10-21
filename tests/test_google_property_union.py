"""Exact complete union through installed Google SDKs and synthetic local wire."""
import pytest
import json
from tests.test_google_accounts_auth import ACCOUNTS, custody, wire, deadline

A, B = ACCOUNTS
URL = 'https://synthetic.example/'
DOMAIN = 'sc-domain:synthetic.example'


def site(name, permission='siteOwner'):
    return {'siteUrl': name, 'permissionLevel': permission}


def page(ids, token=None, label='Synthetic'):
    data = {'accountSummaries': [{'account': 'accounts/1', 'name': 'accountSummaries/1',
            'displayName': label, 'propertySummaries': [
                {'property': 'properties/'+str(i), 'displayName': label+str(i), 'parent':'accounts/1', 'propertyType':'PROPERTY_TYPE_ORDINARY'} for i in ids]}]}
    if token is not None:
        data['nextPageToken'] = token
    return data


@pytest.mark.parametrize('provider', ['gsc', 'ga4'])
@pytest.mark.parametrize('overlap', [False, True])
def test_complete_disjoint_overlap_union(wire, provider, overlap):
    w, _, _, discovery, _ = wire
    w.sites[A] = [site(URL)]
    w.sites[B] = [site(URL if overlap else DOMAIN)]
    w.pages[A] = [page([101])]
    w.pages[B] = [page([101 if overlap else 202])]
    snapshot = discovery.discover(provider, deadline())
    assert snapshot.complete is True
    assert set(snapshot.per_account_status) == set(ACCOUNTS)
    assert all(s == 'available' for s in snapshot.per_account_status.values())
    assert len(snapshot.memberships) == (1 if overlap else 2)
    if overlap:
        assert snapshot.memberships[0].account_ids == tuple(sorted(ACCOUNTS))
    else:
        expected = {URL, DOMAIN} if provider == 'gsc' else {'properties/101', 'properties/202'}
        assert {m.property_id for m in snapshot.memberships} == expected
        assert {m.account_ids for m in snapshot.memberships} == {(A,), (B,)}


def test_url_domain_and_prefix_are_distinct_exact_properties(wire):
    w, _, _, discovery, _ = wire
    exact = [DOMAIN, URL, URL+'section/']
    w.sites[A] = [site(x) for x in exact]
    snapshot = discovery.discover('gsc', deadline())
    assert snapshot.complete
    assert sorted(m.property_id for m in snapshot.memberships) == sorted(exact)
    assert len(snapshot.memberships) == 3


@pytest.mark.parametrize('provider', ['gsc', 'ga4'])
@pytest.mark.parametrize('failed_account', ACCOUNTS)
@pytest.mark.parametrize('fault', ['denied', 'missing'])
def test_revoked_account_never_returns_subset_success(wire, custody, provider, failed_account, fault):
    w, loader, _, discovery, _ = wire
    assert len(loader.load_accounts()) == 2
    w.sites[A] = [site(URL)]; w.sites[B] = [site(DOMAIN)]
    w.pages[A] = [page([101])]; w.pages[B] = [page([202])]
    if fault == 'denied':
        w.fail.add((failed_account, '*'))
    else:
        custody[2][ACCOUNTS.index(failed_account)].unlink()
    try:
        snapshot = discovery.discover(provider, deadline())
    except RuntimeError:
        snapshot = None
    assert snapshot is None or snapshot.complete is False
    with pytest.raises(RuntimeError):
        discovery.list_rows(provider, deadline())


def test_ga4_exhausts_later_pages(wire):
    w, _, _, discovery, _ = wire
    w.pages[A] = [page([101], '1'), page([102])]
    w.pages[B] = [page([202])]
    snapshot = discovery.discover('ga4', deadline())
    assert snapshot.complete
    assert {m.property_id for m in snapshot.memberships} == {'properties/101','properties/102','properties/202'}
    assert len([x for x in w.calls if x[0] == A and x[1].endswith('/accountSummaries')]) == 2


@pytest.mark.parametrize('fault', ['later-denied', 'repeated-token'])
def test_later_page_fault_or_cycle_is_not_complete(wire, fault):
    w, _, _, discovery, _ = wire
    w.pages[A] = [page([101], '1'), None if fault == 'later-denied' else page([102], '1')]
    w.pages[B] = [page([202])]
    try:
        snapshot = discovery.discover('ga4', deadline())
    except RuntimeError:
        snapshot = None
    assert snapshot is None or snapshot.complete is False
    assert len([(a,p) for a,p in w.calls if a == A and p.endswith('/accountSummaries')]) == 2


def test_duplicate_permission_metadata_deterministic(wire):
    w, _, _, discovery, _ = wire
    w.sites[A] = [site(URL, 'siteOwner')]
    w.sites[B] = [site(URL, 'siteFullUser')]
    first = discovery.discover('gsc', deadline())
    second = discovery.discover('gsc', deadline())
    assert first.complete and second.complete
    assert first.memberships == second.memberships
    membership = first.memberships[0]
    assert membership.account_ids == tuple(sorted(ACCOUNTS))
    assert membership.gsc_permissions == {A:'siteOwner', B:'siteFullUser'}


@pytest.mark.parametrize('ceiling', ['properties', 'pages'])
def test_local_safety_ceiling_never_claims_complete_union(wire, monkeypatch, ceiling):
    import google_seo_mcp.google_accounts.discovery as module
    w, _, _, discovery, _ = wire
    w.pages[A] = [page([101])]
    w.pages[B] = [page([202])]
    assert discovery.discover('ga4', deadline()).complete
    if ceiling == 'properties':
        assert module._MAX_PROPERTIES == 10000
        monkeypatch.setattr(module, '_MAX_PROPERTIES', 2)
        w.pages[A] = [page([101,102,103])]
    else:
        assert module._MAX_PAGES == 1000
        monkeypatch.setattr(module, '_MAX_PAGES', 2)
        w.pages[A] = [page([101],'1'),page([102],'2'),page([103])]
    before = len(w.calls)
    snapshot = discovery.discover('ga4', deadline())
    assert not snapshot.complete
    attempts = [(a,p) for a,p in w.calls[before:] if p.endswith('/accountSummaries')]
    assert 1 <= len(attempts) <= 4


def test_ga4_duplicate_metadata_prefers_stable_identity(wire):
    w, _, _, discovery, _ = wire
    w.pages[A] = [page([101], label='Preferred')]
    w.pages[B] = [page([101], label='Secondary')]
    first = discovery.list_rows('ga4', deadline())
    second = discovery.list_rows('ga4', deadline())
    assert first == second
    assert len(first) == 1
    serialized = json.dumps(first, sort_keys=True)
    assert 'Preferred101' in serialized
    assert 'Secondary101' not in serialized
