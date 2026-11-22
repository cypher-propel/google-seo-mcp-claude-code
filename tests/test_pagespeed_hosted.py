"""Hosted PageSpeed contracts with fixture files and a closed HTTP transport only."""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest
from mcp import types
from pydantic import ValidationError

from google_seo_mcp import auth, pagespeed_auth, server
from google_seo_mcp.runtime_config import ProductionRuntimeConfig, load_runtime_config

KEY = "fixture-key"
NAMES = sorted(pagespeed_auth.PAGESPEED_TOOL_NAMES)
PSI = {"lighthouseResult": {
    "categories": {"performance": {"score": 0.91}, "seo": {"score": 0.98}},
    "audits": {"largest-contentful-paint": {"numericValue": 1250, "score": 1}},
}}


@pytest.fixture
def hosted(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_configure_hosted_logging", lambda: None)
    config = load_runtime_config([], {"GOOGLE_SEO_TRANSPORT": "streamable-http"})
    config = config.model_copy(update={
        "google_oauth_client_file": tmp_path / "client.json",
        "google_oauth_propel_dms_file": tmp_path / "a.json",
        "google_oauth_addourteam99_file": tmp_path / "b.json",
    })
    # Redirect only the fixed PageSpeed file to a fixture; never open a real key.
    fixture = tmp_path / "pagespeed"
    fixture.write_text(KEY + "\n")
    real_open = os.open

    def open_fixture(path, flags, *args, **kwargs):
        if path == config.pagespeed_api_key_file:
            path = fixture
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_fixture)
    instance = server.create_server(config)
    yield instance, fixture
    auth.configure_hosted_auth(ProductionRuntimeConfig())
    pagespeed_auth.configure_pagespeed_auth(ProductionRuntimeConfig())


def arguments(name):
    return ({"url_or_origin": "https://example.com", "is_origin": True}
            if name == "crux_current" else {"url": "https://example.com"})


def call(instance, name):
    async def exercise():
        handler = instance._mcp_server.request_handlers[types.CallToolRequest]
        response = await handler(types.CallToolRequest(
            method="tools/call", params=types.CallToolRequestParams(
                name=name, arguments=arguments(name))))
        return response.model_dump(mode="json")
    return asyncio.run(exercise())


def install_wire(monkeypatch, *, status=200, failure=None, reflected=False):
    calls = []
    real_client = httpx.Client

    def respond(request):
        calls.append(request)
        assert request.url.host in {"www.googleapis.com", "chromeuxreport.googleapis.com"}
        assert parse_qs(request.url.query.decode())["key"] == [KEY]
        if failure == "timeout":
            raise httpx.ReadTimeout(str(request.url) + " raw-upstream", request=request)
        if failure == "json":
            return httpx.Response(200, content=KEY + " raw-upstream")
        if status >= 400:
            return httpx.Response(status, text=KEY + " raw-upstream " + str(request.url))
        payload = ({"record": {"key": {"origin": "https://example.com"}, "metrics": {}}}
                   if request.url.host == "chromeuxreport.googleapis.com" else PSI)
        if reflected:
            payload = json.loads(json.dumps(payload).replace("https://example.com", KEY))
            if "lighthouseResult" in payload:
                payload["lighthouseResult"]["userAgent"] = KEY
        return httpx.Response(200, json=payload)

    def client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(respond)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "Client", client)
    return calls


def test_path_only_config_is_fixed_and_ignores_secret_environment():
    config = load_runtime_config([], {
        "GOOGLE_SEO_TRANSPORT": "streamable-http", "PAGESPEED_API_KEY": KEY,
        "GOOGLE_SEO_PAGESPEED_API_KEY_FILE": "/tmp/not-admitted",
    })
    assert config.pagespeed_api_key_file == Path("/run/secrets/pagespeed-api-key")
    assert KEY not in repr(config)
    with pytest.raises(ValidationError):
        ProductionRuntimeConfig(pagespeed_api_key_file="/tmp/not-admitted")


@pytest.mark.parametrize("name", NAMES)
def test_all_six_missing_key_are_not_configured_before_network(hosted, monkeypatch, name):
    instance, fixture = hosted
    fixture.unlink()
    monkeypatch.setenv("PAGESPEED_API_KEY", "ignored-fixture")
    monkeypatch.setenv("CRUX_API_KEY", "ignored-fixture")
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: pytest.fail("unexpected network"))
    response = call(instance, name)
    assert response["isError"] is True
    assert [item["text"] for item in response["content"]] == ["provider_not_configured"]
    assert len(instance._tool_manager.list_tools()) == 52


@pytest.mark.parametrize("content", ["", " \n", "bad key", "x" * 4097, "\N{SNOWMAN}"])
def test_invalid_fixture_file_is_safe_not_configured(hosted, content):
    _, fixture = hosted
    fixture.write_text(content)
    with pytest.raises(RuntimeError, match="^provider_not_configured$"):
        pagespeed_auth.load_hosted_key()


def test_symlink_is_not_followed(hosted, tmp_path):
    _, fixture = hosted
    fixture.unlink()
    target = tmp_path / "target"
    target.write_text(KEY)
    fixture.symlink_to(target)
    with pytest.raises(RuntimeError, match="^provider_not_configured$"):
        pagespeed_auth.load_hosted_key()


@pytest.mark.parametrize("name", NAMES)
def test_all_six_work_without_oauth_and_never_export_key(hosted, monkeypatch, name):
    instance, _ = hosted
    monkeypatch.delenv("PAGESPEED_API_KEY", raising=False)
    calls = install_wire(monkeypatch)
    response = call(instance, name)
    assert response["isError"] is False
    data = json.loads(response["content"][0]["text"])
    assert data["_meta"]["source"].startswith(("pagespeed_insights_v5", "crux."))
    if name == "lighthouse_audit":
        assert data["data"]["scores"]["performance"] == 91
        assert data["data"]["core_web_vitals_lab"]["lcp"]["value"] == 1250
    if name == "lighthouse_compare_mobile_desktop":
        assert data["data"]["mobile"]["scores"]["performance"] == 91
        assert data["data"]["desktop"]["scores"]["performance"] == 91
    assert len(calls) == (2 if name == "lighthouse_compare_mobile_desktop" else 1)
    assert KEY not in json.dumps(response)
    assert "PAGESPEED_API_KEY" not in os.environ


@pytest.mark.parametrize("name", ["lighthouse_audit", "crux_current"])
@pytest.mark.parametrize("mode", [400, 403, 429, 500, "timeout", "json", "reflection"])
def test_failure_and_reflection_are_sanitized(hosted, monkeypatch, name, mode):
    instance, _ = hosted
    install_wire(monkeypatch, status=mode if isinstance(mode, int) else 200,
                 failure=mode, reflected=mode == "reflection")
    response = call(instance, name)
    assert response["isError"] is True
    expected = "agency_discovery_incomplete" if mode == "reflection" else "provider_unavailable"
    assert [item["text"] for item in response["content"]] == [expected]
    assert KEY not in json.dumps(response)
    assert "raw-upstream" not in json.dumps(response)


def test_crux_no_data_remains_success(hosted, monkeypatch):
    instance, _ = hosted
    install_wire(monkeypatch, status=404)
    response = call(instance, "crux_current")
    assert response["isError"] is False
    assert json.loads(response["content"][0]["text"])["data"]["available"] is False


@pytest.mark.parametrize("oauth_present", [False, True])
def test_guard_releases_on_pagespeed_not_oauth_and_keeps_google_scan(
    hosted, monkeypatch, oauth_present
):
    instance, _ = hosted
    config = instance.runtime_config
    for path in (config.google_oauth_client_file, config.google_oauth_propel_dms_file,
                 config.google_oauth_addourteam99_file):
        if oauth_present:
            path.write_text("{}")  # Presence alone is not qualified OAuth custody.
        assert path.exists() == oauth_present
    assert server._protect_hosted_result({"ok": True}, "lighthouse_audit") == {"ok": True}
    with pytest.raises(RuntimeError):
        server._protect_hosted_result({"nested": [{KEY: "value"}]}, "lighthouse_audit")
    credentials = SimpleNamespace(client_secret="oauth-fixture", refresh_token=None, token=None)
    monkeypatch.setattr(auth, "get_google_account_registry", lambda: SimpleNamespace(
        clients=SimpleNamespace(scan_credentials=lambda: (credentials,))))
    with pytest.raises(RuntimeError):
        server._protect_hosted_result({"value": "oauth-fixture"}, "lighthouse_audit")
    # New key scanning also protects incumbent results; a missing PageSpeed key
    # must not become a new admission requirement for the existing Google tools.
    with pytest.raises(RuntimeError):
        server._protect_hosted_result({"value": KEY}, "gsc_list_sites")
    hosted[1].unlink()
    assert server._protect_hosted_result({"ok": True}, "gsc_list_sites") == {"ok": True}


def _assert_log_probe(instance, monkeypatch, mode, name):
    install_wire(monkeypatch, status=mode if isinstance(mode, int) else 200,
                 failure=mode, reflected=mode == "reflection")
    captured = io.StringIO()
    monkeypatch.setattr(server.sys, "stderr", captured)
    # Use the real delivery guard, not pytest's capture handler.
    server._restore_legacy_logging()
    try:
        # The fixture replaces the composition hook; call its saved implementation.
        REAL_CONFIGURE_LOGGING()
        response = call(instance, name)
        logging.getLogger("httpx").error("raw-upstream key=%s", KEY)
    finally:
        server._restore_legacy_logging()
    output = captured.getvalue()
    assert KEY not in output + json.dumps(response)
    assert "raw-upstream" not in output + json.dumps(response)
    records = [json.loads(line) for line in output.splitlines()]
    assert len(records) == 1
    assert set(records[0]) == {"request_id", "consumer", "tool", "outcome", "duration_ms"}
    assert records[0]["tool"] == name
    assert records[0]["outcome"] == ("success" if mode == 200 else "error")


REAL_CONFIGURE_LOGGING = server._configure_hosted_logging


@pytest.mark.parametrize("mode", [200, 429, "timeout", "reflection"])
@pytest.mark.parametrize("name", ["lighthouse_audit", "crux_current"])
def test_actual_hosted_logs_and_audit_never_contain_fixture_key(tmp_path, mode, name):
    # Process-wide logger disable/filter state from other suites must not turn
    # an empty capture into either a false pass or a false failure. Exercise the
    # actual composition/delivery guard in a clean process, as the hosted service
    # runs it; retain both the key-absence and positive audit-record assertions.
    root = Path(__file__).resolve().parents[1]
    script = """
import json, sys
from pathlib import Path
import pytest
from tests.test_pagespeed_hosted import hosted, _assert_log_probe
with pytest.MonkeyPatch.context() as patch:
    fixture = hosted.__wrapped__(patch, Path(sys.argv[1]))
    instance, _ = next(fixture)
    try:
        _assert_log_probe(instance, patch, json.loads(sys.argv[2]), sys.argv[3])
    finally:
        fixture.close()
"""
    environment = {
        "HOME": str(tmp_path), "TMPDIR": str(tmp_path), "LANG": "C.UTF-8",
        "PATH": f"{Path(sys.executable).parent}:/usr/local/bin:/usr/bin:/bin",
        "PYTHONPATH": os.pathsep.join((str(root), str(Path(server.__file__).parent.parent))),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path), json.dumps(mode), name],
        cwd=root, env=environment, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == result.stderr == ""
