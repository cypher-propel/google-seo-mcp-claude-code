"""Allowed Google helpers fail closed without leaking nested provider errors."""
from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from google.api_core.exceptions import GoogleAPIError

from google_seo_mcp import auth
from google_seo_mcp.crossplatform import multi_property
from google_seo_mcp.gsc.tools import sitemaps
from google_seo_mcp.runtime_config import ProductionRuntimeConfig


@pytest.fixture(autouse=True)
def isolated_identity(monkeypatch):
    monkeypatch.delenv("GOOGLE_SEO_PROFILE", raising=False)
    monkeypatch.delenv("GSC_ALLOW_DESTRUCTIVE", raising=False)
    auth.configure_hosted_auth(ProductionRuntimeConfig())

    def reject_network(*args, **kwargs):
        pytest.fail("unexpected outbound connection")

    monkeypatch.setattr(socket.socket, "connect", reject_network)
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
        "_from_adc", "_from_service_account", "_from_oauth_flow", "_config_dir",
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
