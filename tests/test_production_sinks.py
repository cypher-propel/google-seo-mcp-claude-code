"""Allowed Google helpers fail closed without leaking nested provider errors."""

from __future__ import annotations

import asyncio
import json
import socket
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

import httpx
import pytest
from google.api_core.exceptions import GoogleAPIError

from google_seo_mcp import auth, server
from google_seo_mcp.bing import auth as bing_auth
from google_seo_mcp.bing import client as bing_client
from google_seo_mcp.bing import tools as bing_tools
from google_seo_mcp.bing.models import BingCredentialDocument
from google_seo_mcp.crossplatform import multi_property
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
def hosted(tmp_path):
    config = ProductionRuntimeConfig(
        profile="production",
        transport="streamable-http",
        google_auth_mode="service-account",
        service_account_file=tmp_path / "absent-service-account.json",
        consumer_keys_file=tmp_path / "unused-registry.json",
    )
    auth.configure_hosted_auth(config)
    return config


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (RuntimeError("credentials_missing"), "credentials_missing"),
        (RuntimeError("credentials_invalid"), "credentials_invalid"),
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
    forbidden = Mock(side_effect=AssertionError("unexpected credential/client fallback"))
    for name in (
        "_from_adc",
        "_from_service_account",
        "_from_oauth_flow",
        "_config_dir",
        "BetaAnalyticsDataClient",
    ):
        monkeypatch.setattr(auth, name, forbidden)
    result = multi_property.multi_property_comparison([123, 456])
    assert [row["error"] for row in result["data"]] == ["credentials_missing"] * 2
    forbidden.assert_not_called()


def test_hosted_real_report_path_redacts_humanized_google_error(hosted, monkeypatch, caplog):
    from google_seo_mcp.ga4 import data

    client = Mock()
    client.run_report.side_effect = GoogleAPIError("private-provider-sentinel")
    monkeypatch.setattr(data, "get_data_client", Mock(return_value=client))
    result = multi_property.multi_property_comparison([123])
    assert result["data"][0]["error"] == "provider_unavailable"
    assert "private-provider-sentinel" not in json.dumps(result)
    assert "private-provider-sentinel" not in caplog.text
    client.run_report.assert_called_once()


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


def test_hosted_read_sitemap_behavior_unchanged(hosted, monkeypatch):
    client = Mock()
    client.sitemaps.return_value.list.return_value.execute.return_value = {
        "sitemap": [{"path": "safe"}]
    }
    monkeypatch.setattr(sitemaps, "get_webmasters", Mock(return_value=client))
    result = sitemaps.list_sitemaps("https://example.com/")
    client.sitemaps.return_value.list.assert_called_once_with(siteUrl="https://example.com/")
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
    """Synthetic custody seam only; actual admission/client/normalizer execute."""

    allowed_sites = frozenset({SITE})

    def __init__(self):
        self.loads = 0

    def load(self):
        self.loads += 1
        return BingCredentialDocument(version=1, api_key="synthetic-policy-sink-key-8271")

    def authorize_site(self, site):
        assert site == SITE


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
    assert len(seen) == 11  # No discovery, redirect follow, retry or pagination.
    assert all(r.url.host == "ssl.bing.com" and r.method == "GET" for r in seen)


@pytest.mark.parametrize("row", BING_ROUTES, ids=[r[0] for r in BING_ROUTES])
def test_each_bing_backend_reaches_only_exact_fixed_bing_sink(bing_server, monkeypatch, row):
    seen, loader = [], SyntheticBingLoader()

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"d": synthetic_bing_wire(row)})

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
    assert value["data"]["status"] == ("ok" if row[0] == "bing_url_info" else "empty")
    assert value["_meta"]["source"] == "bing_webmaster"
    assert len(seen) == 1 and loader.loads == 2
    request = seen[0]
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
def test_pending_bing_calls_no_http_and_composition_is_lazy(tmp_path, monkeypatch, profile):
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
            "bing_credentials_file": tmp_path / "absent-synthetic-key.json",
            "bing_sites_file": tmp_path / "absent-synthetic-policy.json",
            "require_bing_credentials": False,
        }
    )
    deny = Mock(
        side_effect=AssertionError("pending provider constructed HTTP or composition read custody")
    )
    acquired = []
    acquire = bing_auth._HeldDocument.acquire

    def observe_acquire(held, descriptors):
        # Execute actual retained-pair acquisition on absent synthetic paths.
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
            (path, "pending", None, None)
            for _ in BING_ROUTES
            for path in (config.bing_credentials_file, config.bing_sites_file)
        ]
        deny.assert_not_called()
    finally:
        bing_tools.configure_bing_tools()
        bing_auth.configure_bing_auth(None)
