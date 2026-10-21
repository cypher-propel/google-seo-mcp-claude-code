"""Coordinator seq270 synthetic egress contract; no custody/provider IO."""
import asyncio
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from google_seo_mcp import auth, server
from google_seo_mcp.google_accounts import clients
from google_seo_mcp.tool_policy import ProductionToolPolicy


@pytest.fixture
def providers(monkeypatch):
    google = SimpleNamespace(client_secret='synthetic-google-client',
        refresh_token='synthetic-quote-"-slash-\\-refresh', token=None)
    bing = SimpleNamespace(api_key='synthetic-bing-key')
    state = {'google': True, 'bing': True}
    def load_google():
        if not state['google']:
            raise RuntimeError('credentials_missing')
        return (google,)
    def load_bing():
        if not state['bing']:
            raise RuntimeError('credentials_missing')
        return bing
    registry = clients.GoogleAccountClients(SimpleNamespace(load_accounts=load_google))
    monkeypatch.setattr(auth, 'is_hosted_production', lambda: True)
    monkeypatch.setattr(auth, 'get_google_account_registry', lambda: SimpleNamespace(clients=registry))
    monkeypatch.setattr(server.bing_auth, 'BingCredentialLoader', lambda: SimpleNamespace(load=load_bing))
    monkeypatch.setenv('DATAFORSEO_LOGIN', 'synthetic-serp-login')
    monkeypatch.setenv('DATAFORSEO_PASSWORD', 'synthetic-serp-password')
    return state, google, bing


def invoke(name, value, seam, converted):
    async def fn() -> dict:
        return {'data': [], '_meta': {'keyword': value}}
    manager = server.PolicyToolManager(ProductionToolPolicy())
    tool = manager.add_tool(fn, name=name)
    return asyncio.run(tool.run({}, convert_result=converted) if seam == 'direct'
                       else manager.call_tool(name, {}, convert_result=converted))


@pytest.mark.parametrize('seam', ['direct', 'manager'])
@pytest.mark.parametrize('converted', [False, True])
def test_quote_backslash_refuses(providers, seam, converted):
    with pytest.raises(ToolError, match='^agency_discovery_incomplete$'):
        invoke('ga4_search_schema', providers[1].refresh_token, seam, converted)


@pytest.mark.parametrize('seam', ['direct', 'manager'])
@pytest.mark.parametrize('converted', [False, True])
@pytest.mark.parametrize('case', ['missing_google_bing_clean', 'missing_google_google_refused',
    'missing_bing_google_clean', 'google_in_bing', 'bing_in_google', 'serp_in_google'])
def test_independent_union(providers, seam, converted, case):
    state, google, bing = providers
    name, value, refused = 'ga4_search_schema', 'sessions', False
    if case.startswith('missing_google'):
        state['google'] = False
        name = 'bing_list_sites' if case == 'missing_google_bing_clean' else name
        refused = case == 'missing_google_google_refused'
    elif case == 'missing_bing_google_clean':
        state['bing'] = False
    elif case == 'google_in_bing':
        name, value, refused = 'bing_list_sites', google.client_secret, True
    elif case == 'bing_in_google':
        value, refused = bing.api_key, True
    elif case == 'serp_in_google':
        value, refused = 'synthetic-serp-password', True
    if refused:
        with pytest.raises(ToolError):
            invoke(name, value, seam, converted)
    else:
        assert invoke(name, value, seam, converted) is not None
