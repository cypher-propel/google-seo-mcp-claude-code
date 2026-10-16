"""Independent write gates must run before parsing, ownership keys or outbound I/O."""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest

from google_seo_mcp import auth, indexing, security
from google_seo_mcp.indexing import tools
from google_seo_mcp.runtime_config import ProductionRuntimeConfig

OPERATIONS = [
    (indexing.generate_indexnow_key, {}),
    (indexing.submit_indexnow, {"urls": [], "host": "invalid", "key": "fixture"}),
    (tools.indexnow_generate_key, {}),
    (tools.indexnow_submit, {"urls": ["not a URL"], "site": "invalid", "key": "fixture"}),
    (
        tools.indexnow_submit_sitemap,
        {"sitemap_url": "not a URL", "site": "invalid", "key": "fixture"},
    ),
]


@pytest.fixture(autouse=True)
def clean_identity(monkeypatch):
    for name in ("GOOGLE_SEO_PROFILE", "GOOGLE_SEO_ALLOW_INDEXNOW", "GSC_ALLOW_DESTRUCTIVE"):
        monkeypatch.delenv(name, raising=False)
    auth.configure_hosted_auth(ProductionRuntimeConfig())
    monkeypatch.setattr(
        socket, "getaddrinfo", Mock(side_effect=AssertionError("live DNS forbidden"))
    )
    monkeypatch.setattr(
        socket.socket, "connect", Mock(side_effect=AssertionError("live network forbidden"))
    )
    yield
    auth.configure_hosted_auth(ProductionRuntimeConfig())


def capture_production():
    auth.configure_hosted_auth(
        ProductionRuntimeConfig(
            profile="production",
            transport="streamable-http",
            google_auth_mode="service-account",
            service_account_file=Path("absent-sa.json"),
            consumer_keys_file=Path("unused-registry.json"),
        )
    )


@pytest.mark.parametrize(
    "operation,arguments", OPERATIONS, ids=[fn.__name__ for fn, _ in OPERATIONS]
)
@pytest.mark.parametrize(
    "mode", ["default", "google-write-only", "environment-production", "captured-production"]
)
def test_gate_precedes_parsing_keys_fetch_and_submission(monkeypatch, operation, arguments, mode):
    if mode == "google-write-only":
        monkeypatch.setenv("GSC_ALLOW_DESTRUCTIVE", "true")
    elif mode == "environment-production":
        monkeypatch.setenv("GOOGLE_SEO_PROFILE", "production")
        monkeypatch.setenv("GOOGLE_SEO_ALLOW_INDEXNOW", "true")
    elif mode == "captured-production":
        capture_production()
        monkeypatch.setenv("GOOGLE_SEO_PROFILE", "legacy")
        monkeypatch.setenv("GOOGLE_SEO_ALLOW_INDEXNOW", "true")
        monkeypatch.setenv("GSC_ALLOW_DESTRUCTIVE", "true")
    forbidden = Mock(side_effect=AssertionError("work before independent IndexNow gate"))
    monkeypatch.setattr(indexing.secrets, "token_hex", forbidden)
    monkeypatch.setattr(indexing.httpx, "Client", forbidden)
    monkeypatch.setattr(tools, "urlparse", forbidden)
    monkeypatch.setattr(security, "assert_url_is_public", forbidden)
    # Tool checks must stand independently of the helper checks.
    monkeypatch.setattr(tools, "submit_indexnow", forbidden)
    monkeypatch.setattr(tools, "generate_indexnow_key", forbidden)
    expected = (
        "indexnow_disabled_in_production"
        if "production" in mode
        else "IndexNow requires GOOGLE_SEO_ALLOW_INDEXNOW=true"
    )
    with pytest.raises(RuntimeError, match="^" + expected + "$"):
        operation(**arguments)
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "value", ["True", "TRUE", "1", "yes", "on", "false", "", " true", "true\n"]
)
def test_only_literal_true_enables_legacy_indexnow(monkeypatch, value):
    monkeypatch.setenv("GOOGLE_SEO_ALLOW_INDEXNOW", value)
    forbidden = Mock(side_effect=AssertionError("key generated without opt-in"))
    monkeypatch.setattr(indexing.secrets, "token_hex", forbidden)
    with pytest.raises(RuntimeError, match="IndexNow requires"):
        indexing.generate_indexnow_key()
    forbidden.assert_not_called()


def test_explicit_legacy_optin_preserves_key_and_offline_submit(monkeypatch):
    monkeypatch.setenv("GOOGLE_SEO_ALLOW_INDEXNOW", "true")
    generator = Mock(return_value="synthetic-ownership-key")
    monkeypatch.setattr(indexing.secrets, "token_hex", generator)
    assert tools.indexnow_generate_key()["data"]["key"] == "synthetic-ownership-key"
    generator.assert_called_once_with(16)
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(202, text="accepted")

    original_client = httpx.Client
    client = Mock(
        side_effect=lambda **kw: original_client(transport=httpx.MockTransport(respond), **kw)
    )
    monkeypatch.setattr(indexing.httpx, "Client", client)
    result = tools.indexnow_submit(
        ["https://example.com/article"],
        site="example.com",
        key="synthetic-ownership-key",
        key_location="https://example.com/key.txt",
    )
    assert result["data"]["ok"] is True
    assert result["data"]["submitted_count"] == 1
    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert str(requests[0].url) == "https://api.indexnow.org/indexnow"
    import json

    assert json.loads(requests[0].content) == {
        "host": "example.com",
        "key": "synthetic-ownership-key",
        "urlList": ["https://example.com/article"],
        "keyLocation": "https://example.com/key.txt",
    }
    client.assert_called_once_with(timeout=30.0)


def test_explicit_legacy_optin_sitemap_uses_mocked_fetch_and_submit(monkeypatch):
    monkeypatch.setenv("GOOGLE_SEO_ALLOW_INDEXNOW", "true")
    security_check = Mock()
    monkeypatch.setattr(security, "assert_url_is_public", security_check)
    requests = []

    def respond(request):
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(
                200,
                text='<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/a</loc></url></urlset>',
            )
        return httpx.Response(200, text="accepted")

    original_client = httpx.Client
    monkeypatch.setattr(
        indexing.httpx,
        "Client",
        lambda **kw: original_client(transport=httpx.MockTransport(respond), **kw),
    )
    result = tools.indexnow_submit_sitemap(
        "https://example.com/sitemap.xml", "example.com", "synthetic-key"
    )
    assert result["data"]["ok"] is True
    assert result["data"]["total_urls_submitted"] == 1
    security_check.assert_called_once_with("https://example.com/sitemap.xml")
    assert [(request.method, str(request.url)) for request in requests] == [
        ("GET", "https://example.com/sitemap.xml"),
        ("POST", "https://api.indexnow.org/indexnow"),
    ]


@pytest.mark.parametrize(
    "operation",
    [
        lambda: indexing.submit_google_indexing("not a URL", notification_type="invalid"),
        lambda: tools.google_indexing_publish("not a URL"),
        lambda: tools.google_indexing_delete("not a URL"),
    ],
    ids=["helper", "publish", "delete"],
)
@pytest.mark.parametrize("mode", ["environment", "captured"])
def test_google_indexing_production_gate_precedes_credentials_and_network(
    monkeypatch, operation, mode
):
    if mode == "captured":
        capture_production()
        monkeypatch.setenv("GOOGLE_SEO_PROFILE", "legacy")
    else:
        monkeypatch.setenv("GOOGLE_SEO_PROFILE", "production")
    monkeypatch.setenv("GSC_ALLOW_DESTRUCTIVE", "true")
    forbidden = Mock(side_effect=AssertionError("work before Google Indexing production gate"))
    monkeypatch.setattr(auth, "_build_creds", forbidden)
    monkeypatch.setattr(indexing.httpx, "Client", forbidden)
    with pytest.raises(RuntimeError, match="^google_indexing_disabled_in_production$"):
        operation()
    forbidden.assert_not_called()
