"""Allowed Google helpers fail closed without leaking nested provider errors."""

from __future__ import annotations

import asyncio
import json
import socket
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

import httpx
import pytest
import requests

from google_seo_mcp import auth, server
from google_seo_mcp.bing import auth as bing_auth
from google_seo_mcp.bing import client as bing_client
from google_seo_mcp.bing import tools as bing_tools
from google_seo_mcp.bing.models import BingCredentialDocument
from google_seo_mcp.crossplatform import multi_property
from google_seo_mcp.google_accounts import clients as google_clients
from google_seo_mcp.google_accounts.models import GoogleAccountError
from google_seo_mcp.gsc.tools import sitemaps
from google_seo_mcp.runtime_config import ProductionRuntimeConfig, load_runtime_config
from tests.test_server_registration import ANALYTICS, BING_ROUTES, SITE, bing_arguments, sdk_call


@pytest.fixture(autouse=True)
def isolated_identity(monkeypatch):
    monkeypatch.delenv("GOOGLE_SEO_PROFILE", raising=False)
    monkeypatch.delenv("GSC_ALLOW_DESTRUCTIVE", raising=False)
    auth.configure_hosted_auth(ProductionRuntimeConfig())

    def reject_network(*args, **kwargs):
        pytest.fail("unexpected outbound connection")

    monkeypatch.setattr(socket.socket, "connect", reject_network)
    monkeypatch.setattr(socket.socket, "connect_ex", reject_network)
    monkeypatch.setattr(socket, "getaddrinfo", reject_network)
    yield
    auth.configure_hosted_auth(ProductionRuntimeConfig())


@pytest.fixture
def sink_google_custody():
    # Explicit protected synthetic documents for both accepted named slots.
    from tests.test_google_accounts_auth import custody

    fixture = custody.__wrapped__()
    try:
        yield next(fixture)
    finally:
        fixture.close()


@pytest.fixture
def hosted(sink_google_custody):
    from tests.test_google_accounts_auth import CLIENT

    root = sink_google_custody[0]
    config = ProductionRuntimeConfig(
        profile="production",
        transport="streamable-http",
        public_base_url="https://synthetic.invalid",
        google_auth_mode="dual-user-oauth",
        google_oauth_client_file=root / "client.json",
        google_oauth_propel_dms_file=root / "a.json",
        google_oauth_addourteam99_file=root / "b.json",
        google_approved_client_id=CLIENT,
        google_approved_project_id="synthetic-seq208",
        consumer_keys_file=root / "unused-registry.json",
    )
    auth.configure_hosted_auth(config)
    return config


@pytest.fixture
def sink_google_wire(hosted, sink_google_custody, monkeypatch):
    """Keep OAuth, discovery, routing and SDKs real; replace only HTTP send."""
    from tests.test_google_accounts_auth import ACCOUNTS, LocalWire, close_resources

    wire = LocalWire(sink_google_custody[1])
    for account in ACCOUNTS:
        wire.sites[account] = [
            {"siteUrl": "https://example.com/", "permissionLevel": "siteOwner"}
        ]
        wire.pages[account] = [{"accountSummaries": [{
            "account": "accounts/1",
            "propertySummaries": [{
                "property": "properties/123", "displayName": "synthetic",
                "parent": "accounts/1", "propertyType": "PROPERTY_TYPE_ORDINARY",
            }],
        }]}]
    sessions = []
    session_init = requests.sessions.Session.__init__

    def tracked_session(session, *args, **kwargs):
        session_init(session, *args, **kwargs)
        sessions.append(session)

    monkeypatch.setattr(requests.sessions.Session, "__init__", tracked_session)
    monkeypatch.setattr(
        requests.adapters.HTTPAdapter, "send",
        lambda adapter, request, **kwargs: wire.send(request, **kwargs),
    )
    registry = auth.get_google_account_registry()
    primary = None
    try:
        yield wire
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            registry.retire()
        finally:
            close_resources([*sessions, *wire.responses], primary)


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (RuntimeError("credentials_missing"), "credentials_missing"),
        (RuntimeError("credentials_invalid"), "credentials_invalid"),
        (GoogleAccountError("agency_discovery_incomplete"), "agency_discovery_incomplete"),
        (RuntimeError("credentials_missing: private-provider-sentinel"), "provider_unavailable"),
        (RuntimeError("private-provider-sentinel /run/secrets/key.json"), "provider_unavailable"),
        (ValueError("private-provider-sentinel"), "provider_unavailable"),
    ],
)
def test_hosted_nested_errors_are_sanitized(hosted, monkeypatch, caplog, exception, expected):
    monkeypatch.setattr(multi_property, "run_report", Mock(side_effect=exception))
    # Mode is captured at configuration, not controlled by a mutable env flag.
    monkeypatch.setenv("GOOGLE_SEO_PROFILE", "legacy")
    result = multi_property.multi_property_comparison([123, "properties/456"])
    assert [row["error"] for row in result["data"]] == [expected, expected]
    assert all(row["total"] is None and row["breakdown"] is None for row in result["data"])
    assert "private-provider-sentinel" not in json.dumps(result)
    assert "private-provider-sentinel" not in caplog.text


def test_hosted_does_not_stringify_unknown_provider_exception(hosted, monkeypatch):
    class UnprintableProviderError(Exception):
        def __str__(self):
            pytest.fail("provider exception stringified")

    monkeypatch.setattr(multi_property, "run_report", Mock(side_effect=UnprintableProviderError()))
    result = multi_property.multi_property_comparison([123])
    assert result["data"][0]["error"] == "provider_unavailable"


def test_missing_hosted_credentials_never_use_legacy_or_client_constructor(hosted, monkeypatch):
    # Absent named documents under the protected synthetic parent, not a retired
    # SA path or an unsafe pytest temporary ancestor that could mask absence.
    auth.configure_hosted_auth(hosted.model_copy(update={
        "google_oauth_propel_dms_file": hosted.google_oauth_propel_dms_file.with_name("absent-a.json"),
        "google_oauth_addourteam99_file": hosted.google_oauth_addourteam99_file.with_name("absent-b.json"),
    }))
    forbidden = Mock(side_effect=AssertionError("unexpected credential/client fallback"))
    for name in (
        "_from_adc",
        "_from_service_account",
        "_from_oauth_flow",
        "_config_dir",
        "BetaAnalyticsDataClient",
    ):
        monkeypatch.setattr(auth, name, forbidden)
    for name in ("Credentials", "build", "BetaAnalyticsDataClient", "AnalyticsAdminServiceClient"):
        monkeypatch.setattr(google_clients, name, forbidden)
    result = multi_property.multi_property_comparison([123, 456])
    assert [row["error"] for row in result["data"]] == ["agency_discovery_incomplete"] * 2
    assert all(row["total"] is None and row["breakdown"] is None for row in result["data"])
    forbidden.assert_not_called()


def test_hosted_real_report_path_redacts_humanized_google_error(
    hosted, sink_google_wire, monkeypatch, caplog
):
    from google.api_core.exceptions import GoogleAPIError
    from google_seo_mcp.ga4 import data

    wire = sink_google_wire
    send = wire.send
    business = Mock(side_effect=GoogleAPIError("private-provider-sentinel"))

    def failing_business(request, **kwargs):
        if urlsplit(request.url).path.endswith(":runReport"):
            return business(request, **kwargs)
        return send(request, **kwargs)

    monkeypatch.setattr(wire, "send", failing_business)
    account_clients = auth.get_google_account_registry().clients
    execute = account_clients.execute
    safe_failures = []

    def observe_account_boundary(*args, **kwargs):
        try:
            return execute(*args, **kwargs)
        except GoogleAccountError as error:
            safe_failures.append((
                error.code, error.__cause__ is None, error.__context__ is None,
            ))
            raise

    monkeypatch.setattr(account_clients, "execute", observe_account_boundary)
    legacy_getter = Mock(side_effect=AssertionError("unbound Google client accessed"))
    monkeypatch.setattr(data, "get_data_client", legacy_getter)
    result = multi_property.multi_property_comparison([123])
    # The account executor now sanitizes SDK errors before the nested helper;
    # legacy _humanize_error is deliberately not part of hosted dispatch.
    assert result["data"][0]["error"] == "agency_discovery_incomplete"
    assert result["data"][0]["total"] is result["data"][0]["breakdown"] is None
    assert "private-provider-sentinel" not in json.dumps(result)
    assert "private-provider-sentinel" not in caplog.text
    business.assert_called_once()
    assert safe_failures == [("agency_discovery_incomplete", True, True)]
    assert urlsplit(business.call_args.args[0].url).path == "/v1beta/properties/123:runReport"
    legacy_getter.assert_not_called()


def test_stdio_keeps_legacy_nested_error_diagnostics(monkeypatch):
    monkeypatch.setattr(
        multi_property, "run_report", Mock(side_effect=RuntimeError("legacy-detail"))
    )
    result = multi_property.multi_property_comparison([123], max_concurrent=6)
    assert result["data"][0]["error"] == "legacy-detail"


@pytest.mark.parametrize("workers", [0, -1, 6, 100000, True, 1.5, "2", None])
def test_hosted_invalid_concurrency_denied_before_pool_or_provider(hosted, monkeypatch, workers):
    pool = Mock(side_effect=AssertionError("pool created before validation"))
    provider = Mock(side_effect=AssertionError("provider called before validation"))
    monkeypatch.setattr(multi_property, "ThreadPoolExecutor", pool)
    monkeypatch.setattr(multi_property, "run_report", provider)
    with pytest.raises(ValueError, match="max_concurrent must be an integer between 1 and 5"):
        multi_property.multi_property_comparison([123], max_concurrent=workers)
    pool.assert_not_called()
    provider.assert_not_called()


@pytest.mark.parametrize("properties", [[], list(range(51))])
def test_hosted_property_count_denied_before_pool_or_provider(hosted, monkeypatch, properties):
    pool = Mock(side_effect=AssertionError("pool created before validation"))
    provider = Mock(side_effect=AssertionError("provider called before validation"))
    monkeypatch.setattr(multi_property, "ThreadPoolExecutor", pool)
    monkeypatch.setattr(multi_property, "run_report", provider)
    with pytest.raises(ValueError):
        multi_property.multi_property_comparison(properties)
    pool.assert_not_called()
    provider.assert_not_called()


@pytest.mark.parametrize("workers", [1, 5])
def test_hosted_bounded_fanout_keeps_successful_results(hosted, monkeypatch, workers):
    seen = []

    def pool_factory(*, max_workers):
        seen.append(max_workers)
        return ThreadPoolExecutor(max_workers=max_workers)

    def report(pid, **kwargs):
        assert auth.hosted_auth_enabled()
        assert kwargs["limit"] == 200
        return {"totals": [{"sessions": 7}], "rows": [{"country": "ES", "sessions": 7}]}

    monkeypatch.setattr(multi_property, "ThreadPoolExecutor", pool_factory)
    monkeypatch.setattr(multi_property, "run_report", report)
    result = multi_property.multi_property_comparison(
        list(range(50)), dimension="country", max_concurrent=workers
    )
    assert seen == [workers]
    assert len(result["data"]) == 50
    assert all(row["error"] is None and row["total"] == 7 for row in result["data"])
    assert result["data"][0]["breakdown"] == [{"country": "ES", "sessions": 7.0}]


def test_hosted_sitemap_write_denied_after_env_mutation_before_client_getter(hosted, monkeypatch):
    getter = Mock(side_effect=AssertionError("Google client accessed before refusal"))
    monkeypatch.setattr(sitemaps, "get_webmasters", getter)
    monkeypatch.setenv("GOOGLE_SEO_PROFILE", "legacy")
    monkeypatch.setenv("GSC_ALLOW_DESTRUCTIVE", "true")
    result = sitemaps.submit_sitemap("https://example.com/", "https://example.com/sitemap.xml")
    assert result["error"] == "destructive_disabled"
    getter.assert_not_called()


def test_production_env_also_fences_direct_sitemap_helper(monkeypatch):
    getter = Mock(side_effect=AssertionError("Google client accessed before refusal"))
    monkeypatch.setattr(sitemaps, "get_webmasters", getter)
    monkeypatch.setenv("GOOGLE_SEO_PROFILE", "production")
    monkeypatch.setenv("GSC_ALLOW_DESTRUCTIVE", "true")
    assert sitemaps.submit_sitemap("x", "y")["error"] == "destructive_disabled"
    getter.assert_not_called()


def test_stdio_sitemap_disabled_result_keeps_legacy_guidance(monkeypatch):
    getter = Mock(side_effect=AssertionError("Google client accessed before refusal"))
    monkeypatch.setattr(sitemaps, "get_webmasters", getter)
    result = sitemaps.submit_sitemap("https://example.com/", "https://example.com/sitemap.xml")
    assert result["error"] == "destructive_disabled"
    assert "GSC_ALLOW_DESTRUCTIVE=true" in result["message"]
    getter.assert_not_called()


def test_stdio_sitemap_optin_preserves_submit_behavior(monkeypatch):
    client = Mock()
    monkeypatch.setattr(sitemaps, "get_webmasters", Mock(return_value=client))
    monkeypatch.setenv("GSC_ALLOW_DESTRUCTIVE", "true")
    result = sitemaps.submit_sitemap("https://example.com/", "https://example.com/sitemap.xml")
    client.sitemaps.return_value.submit.assert_called_once_with(
        siteUrl="https://example.com/", feedpath="https://example.com/sitemap.xml"
    )
    client.sitemaps.return_value.submit.return_value.execute.assert_called_once_with()
    assert result["data"] == {"status": "submitted", "feedpath": "https://example.com/sitemap.xml"}


def test_hosted_read_sitemap_behavior_unchanged(hosted, sink_google_wire, monkeypatch):
    from tests.test_google_accounts_auth import ACCOUNTS

    wire = sink_google_wire
    send = wire.send
    business = []

    def sitemap_response(request, **kwargs):
        response = send(request, **kwargs)
        if urlsplit(request.url).path.endswith("/sitemaps"):
            business.append(request)
            response._content = json.dumps({"sitemap": [{"path": "safe"}]}).encode()
        return response

    monkeypatch.setattr(wire, "send", sitemap_response)
    getter = Mock(side_effect=AssertionError("hosted read used unbound Google getter"))
    monkeypatch.setattr(sitemaps, "get_webmasters", getter)
    result = sitemaps.list_sitemaps("https://example.com/")
    assert len(business) == 1
    request = business[0]
    assert request.method == "GET"
    assert urlsplit(request.url).netloc == "www.googleapis.com"
    assert urlsplit(request.url).path == (
        "/webmasters/v3/sites/https%3A%2F%2Fexample.com%2F/sitemaps"
    )
    assert request.headers["Authorization"] == "Bearer " + wire.access[ACCOUNTS[0]]
    assert all((account, True) in wire.scopes for account in ACCOUNTS)
    getter.assert_not_called()
    assert result["data"] == [{"path": "safe"}]


@pytest.fixture(params=["initial", "legacy", "production"])
def bing_server(request, monkeypatch):
    monkeypatch.setattr(server, "_configure_hosted_logging", lambda: None)
    monkeypatch.setattr(bing_client, "_GLOBAL", bing_client._Admission())
    bing_tools.configure_bing_tools()
    instance = (
        server.mcp
        if request.param == "initial"
        else server.create_server(
            ProductionRuntimeConfig()
            if request.param == "legacy"
            else load_runtime_config(
                [],
                {"GOOGLE_SEO_TRANSPORT": "streamable-http"},
            ),
        )
    )
    yield instance
    bing_tools.configure_bing_tools()
    bing_auth.configure_bing_auth(None)


class SyntheticBingLoader:
    """Synthetic key custody only; actual provider discovery admits sites."""

    def __init__(self):
        self.loads = 0
        self.generations = 0
        self.requirements = []

    def load(self):
        self.loads += 1
        return BingCredentialDocument(version=1, api_key="synthetic-policy-sink-key-8271")

    def generation(self):
        self.generations += 1
        self.load()
        return "synthetic-sink-generation"

    def require_generation(self, expected):
        self.requirements.append(expected)
        assert self.generation() == expected


def synthetic_bing_wire(row):
    # Synthetic empty lists are method-access evidence, not zero business data.
    if row[0] != "bing_url_info":
        return []
    return {
        "AnchorCount": 1,
        "DiscoveryDate": "/Date(1704067200000)/",
        "DocumentSize": 2,
        "HttpStatus": 200,
        "IsPage": True,
        "LastCrawledDate": "/Date(1704067200000)/",
        "TotalChildUrlCount": 0,
        "Url": SITE + "a",
    }


@pytest.mark.parametrize("status", [200, 400, 302])
def test_bing_provider_fault_or_redirect_never_becomes_empty_success(bing_server, status):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            status,
            json={"ErrorCode": "InvalidApiKey", "Message": "SYNTHETIC_PRIVATE_FAULT"},
            headers={"Location": "http://169.254.169.254/metadata"},
        )

    bing_tools.configure_bing_tools(bing_client.BingReadClient(
        SyntheticBingLoader(), transport=httpx.MockTransport(handler), max_retries=0,
    ))
    for row in BING_ROUTES:
        result = sdk_call(bing_server, row[0], bing_arguments(row))
        assert result["isError"] is False  # Transport completion only.
        value = json.loads(result["content"][0]["text"])
        assert value["data"]["status"] == "provider_error"
        assert value["data"]["error"]["code"] == "provider_error"
        assert value["data"]["records"] == []
        assert "SYNTHETIC_PRIVATE" not in json.dumps(result)
    assert len(seen) == 11  # One failed fresh discovery per call; no business/retry/follow.
    assert all(r.url.host == "ssl.bing.com" and r.method == "GET" for r in seen)
    assert all(r.url.path == "/webmaster/api.svc/json/GetUserSites" for r in seen)
    assert all(dict(r.url.params) == {"apikey": "synthetic-policy-sink-key-8271"} for r in seen)


@pytest.mark.parametrize("row", BING_ROUTES, ids=[r[0] for r in BING_ROUTES])
def test_each_bing_backend_reaches_only_exact_fixed_bing_sink(bing_server, monkeypatch, row):
    seen, loader = [], SyntheticBingLoader()

    def handler(request):
        seen.append(request)
        data = (
            [{"Url": SITE, "IsVerified": True}]
            if request.url.path.endswith("/GetUserSites")
            else synthetic_bing_wire(row)
        )
        return httpx.Response(200, json={"d": data})

    bing_tools.configure_bing_tools(
        bing_client.BingReadClient(
            loader,
            transport=httpx.MockTransport(handler),
            max_retries=0,
        )
    )
    deny = Mock(side_effect=AssertionError("Bing reached Google/SERP/file sink"))
    for getter in ("get_webmasters", "get_searchconsole", "get_data_client", "get_admin_client"):
        monkeypatch.setattr(auth, getter, deny)
    monkeypatch.setattr(server.serp_tools, "call_dataforseo", deny)
    payload = bing_arguments(row)
    if row[0] in ANALYTICS:
        payload |= {"start_date": "2024-01-01", "end_date": "2024-01-02", "limit": 1}
    with patch("builtins.open", deny), patch("pathlib.Path.open", deny):
        result = sdk_call(bing_server, row[0], payload)
    deny.assert_not_called()
    assert result["isError"] is False
    value = json.loads(result["content"][0]["text"])
    assert value["data"]["operation"] == row[1]
    assert value["data"]["status"] == (
        "ok" if row[0] in {"bing_list_sites", "bing_url_info"} else "empty"
    )
    assert value["_meta"]["source"] == "bing_webmaster"
    discovery_only = row[0] == "bing_list_sites"
    assert len(seen) == (1 if discovery_only else 2)
    # Keep the original authorization-read bound separate from added generation
    # custody observations; no static authorizer or extra business calls.
    assert loader.loads == (2 if discovery_only else 3) + loader.generations
    assert loader.generations == len(seen) + len(loader.requirements)
    assert loader.requirements and set(loader.requirements) == {"synthetic-sink-generation"}
    discovery = seen[0]
    assert discovery.url.path == "/webmaster/api.svc/json/GetUserSites"
    assert dict(discovery.url.params) == {"apikey": "synthetic-policy-sink-key-8271"}
    assert all(
        (request.method, request.url.scheme, request.url.host, request.url.port)
        == ("GET", "https", "ssl.bing.com", None)
        for request in seen
    )
    assert all(
        request.headers["Content-Type"] == "application/json; charset=utf-8"
        for request in seen
    )
    request = seen[-1]
    assert request.method == "GET"
    assert (request.url.scheme, request.url.host, request.url.port) == (
        "https",
        "ssl.bing.com",
        None,
    )
    assert request.url.path == "/webmaster/api.svc/json/" + row[1]
    assert dict(request.url.params) == {
        "apikey": "synthetic-policy-sink-key-8271",
        **({} if row[0] == "bing_list_sites" else {"siteUrl": SITE}),
        **row[3],
    }
    assert request.headers["Content-Type"] == "application/json; charset=utf-8"
    assert "synthetic-policy-sink-key" not in json.dumps(result)


@pytest.mark.parametrize("profile", ["legacy", "production"])
def test_pending_bing_calls_no_http_and_composition_is_lazy(
    sink_google_custody, monkeypatch, profile
):
    root = sink_google_custody[0]
    monkeypatch.setattr(server, "_configure_hosted_logging", lambda: None)
    config = (
        ProductionRuntimeConfig()
        if profile == "legacy"
        else load_runtime_config(
            [],
            {"GOOGLE_SEO_TRANSPORT": "streamable-http"},
        )
    )
    config = config.model_copy(
        update={
            "bing_credentials_file": root / "absent-synthetic-key.json",
            "require_bing_credentials": False,
        }
    )
    deny = Mock(
        side_effect=AssertionError("pending provider constructed HTTP or composition read custody")
    )
    acquired = []
    acquire = bing_auth._HeldDocument.acquire

    def observe_acquire(held, descriptors):
        # Execute actual key-only acquisition on the absent synthetic path.
        acquire(held, descriptors)
        acquired.append((held.path, held.state, held.fd, held.document))

    bing_tools.configure_bing_tools(object())
    try:
        with (
            patch.object(bing_auth._Boundary, "inspect", deny),
            patch.object(bing_auth._HeldDocument, "acquire", deny),
            patch.object(bing_auth.os, "open", deny),
            patch.object(bing_auth.os, "read", deny),
            patch.object(httpx, "Client", deny),
        ):
            instance = server.create_server(config)
            assert bing_tools._client is None
            asyncio.run(instance.list_tools())
        with (
            patch.object(bing_auth._HeldDocument, "acquire", observe_acquire),
            patch.object(bing_auth.os, "read", deny),
            patch.object(httpx, "Client", deny),
            patch.object(httpx, "HTTPTransport", deny),
        ):
            for row in BING_ROUTES:
                result = sdk_call(instance, row[0], bing_arguments(row))
                assert result["isError"] is False  # SDK completion, NOT business success
                value = json.loads(result["content"][0]["text"])
                assert value["data"]["status"] == "unavailable"
                assert value["data"]["error"]["code"] == "provider_not_configured"
                assert value["data"]["records"] == []
                assert value["_meta"]["source"] == "bing_webmaster"
        assert acquired == [
            (config.bing_credentials_file, "pending", None, None)
            for _ in BING_ROUTES
        ]
        deny.assert_not_called()
    finally:
        bing_tools.configure_bing_tools()
        bing_auth.configure_bing_auth(None)
