"""Synthetic final hosted boundary regressions for Coordinator seq265/267.

No real custody/provider traffic; the existing production scanner is real.
"""
import asyncio
import base64
import json
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from google_seo_mcp import auth, server
from google_seo_mcp.google_accounts import clients
from google_seo_mcp.google_accounts.models import GoogleAccountError
from google_seo_mcp.tool_policy import ProductionToolPolicy


@pytest.fixture
def scanner(monkeypatch):
    credential = SimpleNamespace(client_secret='synthetic-private-egress-client',
                                 refresh_token='synthetic-private-egress-refresh', token=None)
    registry = clients.GoogleAccountClients(SimpleNamespace(load_accounts=lambda: (credential,)))
    monkeypatch.setattr(auth, 'is_hosted_production', lambda: True)
    monkeypatch.setattr(auth, 'get_google_account_registry', lambda: SimpleNamespace(clients=registry))
    # seq270 own-provider-required: Bing positives need their independent set.
    monkeypatch.setattr(server.bing_auth, 'BingCredentialLoader',
                        lambda: SimpleNamespace(load=lambda: SimpleNamespace(api_key='synthetic-bing-egress-key')))
    return credential, registry


@pytest.mark.parametrize('scope', ['tabs', 'spaces', 'duplicate'])
@pytest.mark.parametrize('boundary', ['helper', 'runtime'])
def test_strict_scope_shape_refuses(scope, boundary):
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / 'scripts/enroll_google_accounts.py'
    spec = importlib.util.spec_from_file_location('_strict_shape_helper', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    names = sorted(clients.GOOGLE_SCOPES)
    scope_value = {'tabs': '\t'.join(names), 'spaces': '  '.join(names),
                   'duplicate': ' '.join(names + names[:1])}[scope]
    value = dict(access_token='synthetic-access', token_type='Bearer', expires_in=3600, scope=scope_value)
    if boundary == 'helper':
        with pytest.raises(helper.Refused):
            helper._validate_token_response_shape(value)
    else:
        with pytest.raises(GoogleAccountError):
            clients._token_response(value)


@pytest.mark.parametrize('converted', [False, True])
@pytest.mark.parametrize('seam', ['direct', 'manager'])
@pytest.mark.parametrize('encoding', ['raw', 'base64', 'hex'])
def test_final_boundary_refuses_private_metadata(scanner, converted, seam, encoding):
    credential, registry = scanner
    marker = credential.refresh_token
    marker = {'raw': marker, 'base64': base64.b64encode(marker.encode()).decode(),
              'hex': marker.encode().hex()}[encoding]
    async def fn() -> dict:
        # Simulate a clean callback result followed by caller metadata assembly.
        data = {'fields': []}
        registry.protect(data)
        return {'data': data, '_meta': {'keyword': marker}}
    manager = server.PolicyToolManager(ProductionToolPolicy())
    tool = manager.add_tool(fn, name='ga4_search_schema')
    with pytest.raises(ToolError, match='^agency_discovery_incomplete$'):
        asyncio.run(tool.run({}, convert_result=converted) if seam == 'direct'
                    else manager.call_tool('ga4_search_schema', {}, convert_result=converted))


@pytest.mark.parametrize('converted', [False, True])
def test_public_reporting_consumer_refuses(scanner, monkeypatch, converted):
    from google_seo_mcp.ga4.tools import reporting
    _, registry = scanner
    def search(pid, keyword, top_n=10):
        data = {'dimensions': [], 'metrics': []}
        registry.protect(data)
        return data
    monkeypatch.setattr(reporting, 'search_schema', search)
    manager = server.PolicyToolManager(ProductionToolPolicy())
    manager.add_tool(reporting.search_ga4_schema, name='ga4_search_schema')
    with pytest.raises(ToolError, match='^agency_discovery_incomplete$'):
        asyncio.run(manager.call_tool('ga4_search_schema',
                    {'property_id': '123', 'keyword': scanner[0].refresh_token}, convert_result=converted))


@pytest.mark.parametrize('converted', [False, True])
def test_clean_success_preserved(scanner, converted):
    async def fn() -> dict:
        return {'data': {'fields': []}, '_meta': {'keyword': 'sessions'}}
    manager = server.PolicyToolManager(ProductionToolPolicy())
    manager.add_tool(fn, name='ga4_search_schema')
    result = asyncio.run(manager.call_tool('ga4_search_schema', {}, convert_result=converted))
    if not converted:
        assert result == {'data': {'fields': []}, '_meta': {'keyword': 'sessions'}}
    else:
        from pydantic_core import to_json
        assert 'sessions' in to_json(result).decode()


def test_legacy_bing_conversion_uses_hosted_boundary(scanner):
    from mcp.server.fastmcp.tools.tool_manager import ToolManager
    def fn() -> dict:
        return {'data': {'site': scanner[0].refresh_token}}
    manager = ToolManager()
    server._register_bing(manager, fn, name='bing_list_sites')
    tool = manager.get_tool('bing_list_sites')
    assert isinstance(tool, server.HostedTool)
    with pytest.raises(ToolError, match='^agency_discovery_incomplete$'):
        asyncio.run(tool.run({}))
