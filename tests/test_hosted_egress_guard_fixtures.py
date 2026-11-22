"""Controlled independent custody inputs; the actual egress guard stays intact.

No credential files or HTTP are used. These are scanner/admission contracts,
not provider qualification or substitutes for the real custody-loader tests.
"""
from __future__ import annotations

import base64
import socket
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from google_seo_mcp import auth, pagespeed_auth, server
from google_seo_mcp.bing import auth as bing_auth
from google_seo_mcp.google_accounts.models import GoogleAccountError
from google_seo_mcp.runtime_config import ProductionRuntimeConfig, load_runtime_config

TOOLS = {
    "google": "gsc_list_sites", "bing": "bing_list_sites",
    "serp": "serp_check", "pagespeed": "crux_current",
}
SECRETS = {
    "google": "synthetic-egress-google-secret-94817",
    "bing": "synthetic-egress-bing-secret-82716",
    "serp": "synthetic-egress-serp-password-71615",
    "pagespeed": "synthetic-egress-pagespeed-key-60514",
}


@pytest.fixture
def custody(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("unexpected file or network access")

    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    auth.configure_hosted_auth(load_runtime_config(
        [], {"GOOGLE_SEO_TRANSPORT": "streamable-http"}))
    failed, loaded = set(), []

    def load(provider, value):
        loaded.append(provider)
        if provider in failed:
            raise RuntimeError("synthetic-custody-unavailable")
        return value

    # Two named Google slots plus a retained access token must all participate.
    google = tuple(SimpleNamespace(client_secret=SECRETS["google"],
                    refresh_token=f"synthetic-egress-refresh-slot-{slot}-94817",
                    token=f"synthetic-egress-retained-slot-{slot}-94817")
                   for slot in (1, 2))
    registry = SimpleNamespace(clients=SimpleNamespace(
        scan_credentials=lambda: load("google", google)))
    monkeypatch.setattr(auth, "get_google_account_registry", lambda: registry)
    monkeypatch.setattr(bing_auth.BingCredentialLoader, "load", lambda self:
                        load("bing", SimpleNamespace(api_key=SECRETS["bing"])))
    monkeypatch.setenv("DATAFORSEO_LOGIN", "synthetic-egress-serp-login-71615")
    monkeypatch.setenv("DATAFORSEO_PASSWORD", SECRETS["serp"])
    from google_seo_mcp import serp
    header = serp._auth_header
    monkeypatch.setattr(serp, "_auth_header", lambda:
                        load("serp", header()))
    monkeypatch.setattr(pagespeed_auth, "load_hosted_key", lambda:
                        load("pagespeed", SECRETS["pagespeed"]))
    yield failed, loaded, google
    auth.configure_hosted_auth(ProductionRuntimeConfig())


@pytest.mark.parametrize("provider", TOOLS)
def test_controlled_custody_admits_normal_values_and_loads_every_set(custody, provider):
    _, loaded, _ = custody
    result = {"ordinary": ["safe business value", 12, None]}
    assert server._protect_hosted_result(result, TOOLS[provider]) == result
    assert loaded == list(TOOLS)


@pytest.mark.parametrize("provider", TOOLS)
@pytest.mark.parametrize("source", SECRETS)
@pytest.mark.parametrize("encoding", ["raw", "percent", "base64"])
def test_every_provider_scans_each_independent_secret_in_nested_keys(
    custody, provider, source, encoding
):
    secret = SECRETS[source]
    if encoding == "percent":
        secret = "".join(f"%{byte:02X}" for byte in secret.encode())
    elif encoding == "base64":
        secret = base64.b64encode(secret.encode()).decode()
    with pytest.raises(GoogleAccountError):
        server._protect_hosted_result({"ordinary": [{secret: "safe"}]}, TOOLS[provider])


@pytest.mark.parametrize("provider", TOOLS)
@pytest.mark.parametrize("slot", [0, 1])
@pytest.mark.parametrize("field", ["refresh_token", "token"])
def test_refresh_and_retained_access_tokens_remain_cross_provider_controls(
    custody, provider, slot, field
):
    _, _, google = custody
    with pytest.raises(GoogleAccountError):
        server._protect_hosted_result(
            {"ordinary": [getattr(google[slot], field)]}, TOOLS[provider])


@pytest.mark.parametrize("provider", TOOLS)
@pytest.mark.parametrize("missing", TOOLS)
def test_custody_failure_refuses_only_its_own_provider(custody, provider, missing):
    failed, loaded, _ = custody
    failed.add(missing)
    if missing == provider:
        with pytest.raises(RuntimeError, match="^provider_unavailable$"):
            server._protect_hosted_result({"ordinary": "safe"}, TOOLS[provider])
    else:
        assert server._protect_hosted_result({"ordinary": "safe"}, TOOLS[provider]) == {
            "ordinary": "safe"}
        # A failed unrelated set must not disable any successfully loaded set.
        with pytest.raises(GoogleAccountError):
            server._protect_hosted_result({"ordinary": quote(SECRETS[provider])},
                                          TOOLS[provider])
    assert set(loaded) == set(TOOLS)
