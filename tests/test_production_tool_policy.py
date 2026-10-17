"""Static hosted admission, lowest SDK dispatch and controlled audit contracts."""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import socket
import subprocess
import sys
import threading
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import anyio
import pytest
from mcp import types
from mcp.server.fastmcp.exceptions import ToolError

from google_seo_mcp import auth, server, tool_policy
from google_seo_mcp.consumer_auth import AuthenticatedConsumer, consumer_context
from google_seo_mcp.runtime_config import ProductionRuntimeConfig, load_runtime_config
from google_seo_mcp.tool_policy import ProductionToolPolicy, ToolPolicyError

# The public golden historical fixture is independent of production_tools.json.
_golden = ast.parse(Path(__file__).with_name("test_production_startup.py").read_text())
BASELINE = frozenset(
    ast.literal_eval(
        next(
            node.value
            for node in _golden.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "LEGACY_NAMES"
                for target in node.targets
            )
        )
    )
)
EXPECTED = frozenset(
    name
    for name in BASELINE
    if name.startswith(("gsc_", "ga4_", "cross_")) and name != "gsc_submit_sitemap"
) | {
    "serp_check",
    "serp_aio_monitor",
    "serp_paa_extractor",
    "serp_competitor_intersect",
}
# Keep the historical 35-tool sink/semantics matrix separate from Bing.
ORIGINAL_EXPECTED = EXPECTED
BING_NAMES = frozenset({
    "bing_list_sites", "bing_rank_traffic_stats", "bing_query_stats",
    "bing_page_stats", "bing_page_query_stats", "bing_query_page_stats",
    "bing_crawl_stats", "bing_crawl_issues", "bing_url_info",
    "bing_list_sitemaps", "bing_sitemap_details",
})
EXPECTED = ORIGINAL_EXPECTED | BING_NAMES
EXCLUDED = BASELINE - ORIGINAL_EXPECTED
# Independent accepted-plan section 2/5 inventory: mutations (including GET
# FetchUrl), deferred reads, generic proxies, configuration seams and aliases.
BING_FORBIDDEN = [
    "bing_add_site", "bing_remove_site", "bing_verify_site",
    "bing_add_site_roles", "bing_remove_site_role",
    "bing_submit_url", "bing_submit_url_batch", "bing_submit_content",
    "bing_submit_feed", "bing_submit_sitemap", "bing_remove_feed",
    "bing_fetch_url", "bing_save_crawl_settings", "bing_add_blocked_url",
    "bing_remove_blocked_url", "bing_add_country_region_settings",
    "bing_remove_country_region_settings", "bing_add_query_parameter",
    "bing_remove_query_parameter", "bing_enable_disable_query_parameter",
    "bing_add_connected_page", "bing_submit_site_move", "bing_update_deep_link",
    "bing_block_page_preview", "bing_block_deep_link",
    "bing_query_page_detail_stats", "bing_query_traffic_stats",
    "bing_url_traffic", "bing_link_counts", "bing_url_links",
    "bing_keyword_stats", "bing_related_keywords", "bing_keyword",
    "bing_url_submission_quota", "bing_content_submission_quota",
    "bing_crawl_settings", "bing_call", "bing_request", "bing_api",
    "bing_get_user_sites", "bing_sites_list", "bing_feeds_list",
    "bing_feed_details", "bing_future_read", "configure_bing_tools",
    "configure_bing_auth", "BING_LIST_SITES", " bing_list_sites",
    "bing_list_sites ", "bing_list_sites/", "bing_list_sites\n",
    "tools/call/bing_list_sites", "../bing_list_sites", "GetUserSites",
    "SubmitUrl", "FetchUrl", "bing_indexnow_submit",
]
ALIASES = [
    "gsc_future_read",
    "ga4_future_read",
    "cross_future_read",
    "GSC_LIST_SITES",
    " gsc_list_sites",
    "gsc_list_sites ",
    "gsc_list_sites/",
    "tools/call/gsc_list_sites",
    "../gsc_list_sites",
    "gsc_list_sites\n",
    "SYNTHETIC_UNKNOWN_NAME",
]


@pytest.fixture
def hosted(monkeypatch):
    # Actual hosted logging is independently tested in a fresh subprocess below;
    # unit composition must not remove pytest's process-wide capture handlers.
    monkeypatch.setattr(server, "_configure_hosted_logging", lambda: None)
    monkeypatch.delenv("GOOGLE_SEO_PROFILE", raising=False)
    instance = server.create_server(
        load_runtime_config([], {"GOOGLE_SEO_TRANSPORT": "streamable-http"})
    )
    yield instance
    auth.configure_hosted_auth(ProductionRuntimeConfig())


def test_catalog_is_exact_static_baseline_expansion_and_stdio_is_intact(hosted):
    assert len(BASELINE) == 102
    assert len(ORIGINAL_EXPECTED) == 35
    assert len(BING_NAMES) == 11
    assert not BASELINE & BING_NAMES
    assert len(EXPECTED) == 46
    assert len(EXCLUDED) == 67
    assert ProductionToolPolicy().names == EXPECTED
    assert {tool.name for tool in hosted._tool_manager.list_tools()} == EXPECTED
    assert {tool.name for tool in server.mcp._tool_manager.list_tools()} == BASELINE | BING_NAMES
    manifest = json.loads(
        tool_policy.files("google_seo_mcp").joinpath("production_tools.json").read_text()
    )
    assert manifest == {"version": 1, "tools": sorted(EXPECTED)}
    assert hosted.settings.stateless_http is True
    assert hosted.settings.json_response is True
    assert hosted.settings.streamable_http_path == "/mcp"


@pytest.mark.parametrize("name", sorted(EXCLUDED) + ALIASES + BING_FORBIDDEN)
@pytest.mark.parametrize("seam", ["manager", "fastmcp", "sdk-handler"])
def test_every_excluded_name_and_alias_denied_before_open_dns_or_socket(hosted, name, seam):
    async def exercise():
        # Inject an alias below registration intentionally: dispatch must remain
        # closed even if a later code change bypasses the registration guard.
        hosted._tool_manager._tools[name] = hosted._tool_manager._tools["gsc_list_sites"]
        assert name not in {tool.name for tool in hosted._tool_manager.list_tools()}
        sink = Mock(side_effect=AssertionError("prohibited tool reached file or network sink"))
        arguments = {
            "path": "/run/secrets/SYNTHETIC_PRIVATE_PATH/../../key.json",
            "day": "../../SYNTHETIC_PRIVATE_PATH",
            "url": "http://169.254.169.254/metadata",
            "key": "SYNTHETIC_KEY_ARGUMENT",
        }
        with (
            patch("builtins.open", sink),
            patch.object(Path, "open", sink),
            patch.object(socket, "getaddrinfo", sink),
            patch.object(socket.socket, "connect", sink),
            patch.object(socket.socket, "connect_ex", sink),
        ):
            if seam == "manager":
                with pytest.raises(ToolError, match="^tool_not_allowed$"):
                    await hosted._tool_manager.call_tool(name, arguments)
            elif seam == "fastmcp":
                with pytest.raises(ToolError, match="^tool_not_allowed$"):
                    await hosted.call_tool(name, arguments)
            else:
                handler = hosted._mcp_server.request_handlers[types.CallToolRequest]
                response = await handler(
                    types.CallToolRequest(
                        method="tools/call",
                        params=types.CallToolRequestParams(name=name, arguments=arguments),
                    )
                )
                result = response.model_dump(mode="json")
                assert result["isError"] is True
                assert [item["text"] for item in result["content"]] == ["tool_not_allowed"]
                assert "SYNTHETIC" not in json.dumps(result)
        sink.assert_not_called()

    asyncio.run(exercise())


@pytest.mark.parametrize("seam", ["add_tool", "decorator", "manager", "register"])
@pytest.mark.parametrize(
    "name",
    ["gsc_future_read", "ga4_future_read", "cross_future_read", "serp_future_read", "logs_parse"]
    + BING_FORBIDDEN,
)
def test_future_prefix_and_forbidden_registration_cannot_expand_policy(
    hosted, monkeypatch, seam, name
):
    def harmless() -> dict:
        return {}

    sink = Mock(side_effect=AssertionError("forbidden registration reached file/network"))
    with (
        patch("builtins.open", sink),
        patch.object(Path, "open", sink),
        patch.object(socket, "getaddrinfo", sink),
        patch.object(socket.socket, "connect", sink),
        patch.object(socket.socket, "connect_ex", sink),
        pytest.raises(ToolPolicyError, match="^tool_not_allowed$"),
    ):
        if seam == "add_tool":
            hosted.add_tool(harmless, name=name)
        elif seam == "decorator":
            hosted.tool(name=name)(harmless)
        elif seam == "manager":
            hosted._tool_manager.add_tool(harmless, name=name)
        else:
            monkeypatch.setattr(server, "mcp", hosted)
            server._register(harmless, name=name)
    sink.assert_not_called()
    assert {tool.name for tool in hosted._tool_manager.list_tools()} == EXPECTED


def test_duplicate_cannot_replace_existing_allowed_backend(hosted):
    original = hosted._tool_manager.get_tool("gsc_list_sites")
    with pytest.raises(ToolPolicyError, match="^tool_already_registered$"):
        hosted.add_tool(lambda: {}, name="gsc_list_sites")
    assert hosted._tool_manager.get_tool("gsc_list_sites") is original


@pytest.mark.parametrize(
    "raw",
    [
        "{}",
        "[]",
        "not-json SYNTHETIC_MANIFEST_INPUT",
        '{"version":true,"tools":["gsc_list_sites"]}',
        '{"version":1,"tools":[]}',
        '{"version":1,"tools":["gsc_list_sites","gsc_list_sites"]}',
        '{"version":1,"tools":["../SYNTHETIC_MANIFEST_INPUT"]}',
        '{"version":1,"tools":["gsc_list_sites"],"extra":"SYNTHETIC_MANIFEST_INPUT"}',
    ],
)
def test_corrupt_manifest_fails_closed_and_sanitized(monkeypatch, raw):
    resource = SimpleNamespace(joinpath=lambda name: SimpleNamespace(read_text=lambda: raw))
    monkeypatch.setattr(tool_policy, "files", lambda *args: resource)
    with pytest.raises(ToolPolicyError, match="^invalid production tool manifest$") as error:
        ProductionToolPolicy()
    assert "SYNTHETIC" not in str(error.value)


class GoogleSinkStub:
    """Record only terminal Google methods; no request/client/network implementation."""

    def __init__(self, nonempty=False):
        self.calls, self.pending, self.nonempty = [], [], nonempty

    def __getattr__(self, name):
        def invoke(*args, **kwargs):
            self.pending.append((name, kwargs))
            if name == "execute":
                self.calls.append(self.pending)
                query = next((kw for method, kw in self.pending if method == "query"), None)
                self.pending = []
                if self.nonempty and query is not None:
                    keys = [
                        "offline query"
                        if dimension == "query"
                        else "http://169.254.169.254/../../key"
                        for dimension in query["body"]["dimensions"]
                    ]
                    return {
                        "rows": [
                            {
                                "keys": keys,
                                "clicks": 40,
                                "impressions": 1000,
                                "position": 7,
                                "ctr": 0.04,
                            }
                        ]
                    }
                return {}
            if name in ("run_report", "get_metadata", "list_account_summaries", "get_property"):
                self.calls.append(self.pending)
                self.pending = []
                if name == "list_account_summaries":
                    return []
                if name == "get_property":
                    return SimpleNamespace(
                        name="properties/1",
                        display_name="stub",
                        industry_category=None,
                        time_zone="UTC",
                        currency_code="USD",
                        create_time=None,
                        update_time=None,
                        service_level=None,
                        account="accounts/1",
                    )
                return SimpleNamespace(
                    row_count=0,
                    rows=[],
                    dimension_headers=[],
                    metric_headers=[],
                    totals=[],
                    metadata=None,
                    dimensions=[],
                    metrics=[],
                )
            return self

        return invoke


@pytest.mark.parametrize("name", sorted(ORIGINAL_EXPECTED))
def test_each_allowed_backend_reaches_only_fixed_mocked_google_or_vendor_sink(
    hosted, monkeypatch, name
):
    async def exercise():
        fn = next(fn for fn, tool_name in server._LEGACY_TOOL_DEFINITIONS if tool_name == name)
        # Metadata/private-looking URLs are API filter values, never local fetches.
        values = {
            "site_url": "http://169.254.169.254/../../key",
            "page_url": "http://127.0.0.1/key",
            "property_id": "1",
            "property_ids": ["1"],
            "landing_path": "http://127.0.0.1/key",
            "start_date": "2026-01-01",
            "end_date": "2026-01-28",
            "metrics": ["sessions"],
            "steps": ["page_view", "purchase"],
            "keyword": "offline fixture",
            "keywords": ["offline fixture"],
            "your_url": "http://127.0.0.1/key",
        }
        arguments = {
            key: values[key]
            for key, parameter in inspect.signature(fn).parameters.items()
            if parameter.default is inspect.Parameter.empty
        }
        nested = name in {
            "cross_opportunity_matrix",
            "cross_seo_to_revenue_attribution",
            "cross_landing_page_full_diagnosis",
        }
        google, vendor_calls = GoogleSinkStub(nonempty=nested), []

        def vendor(endpoint, payload, timeout=60):
            vendor_calls.append((endpoint, payload))
            return {
                "status_code": 20000,
                "tasks": [{"status_code": 20000, "result": [{"items": []}]}],
            }

        from google_seo_mcp.ga4 import data, schema

        monkeypatch.setattr(schema, "_schema_by_property", {})
        modules = [
            server.gsc_sites,
            server.gsc_sitemaps,
            server.gsc_analytics,
            server.gsc_intel,
            server.ga4_admin,
            server.cp_attr,
            server.cp_diag,
            server.cp_health,
            server.cp_journey,
            server.cp_matrix,
            data,
            schema,
        ]
        sink = Mock(
            side_effect=AssertionError("allowed backend attempted arbitrary file or network")
        )
        with ExitStack() as stack:
            for module in modules:
                for getter in (
                    "get_webmasters",
                    "get_searchconsole",
                    "get_data_client",
                    "get_admin_client",
                ):
                    if hasattr(module, getter):
                        stack.enter_context(patch.object(module, getter, return_value=google))
            stack.enter_context(
                patch.object(server.serp_tools, "call_dataforseo", side_effect=vendor)
            )
            stack.enter_context(patch("builtins.open", sink))
            stack.enter_context(patch.object(Path, "open", sink))
            stack.enter_context(patch.object(socket, "getaddrinfo", sink))
            stack.enter_context(patch.object(socket.socket, "connect", sink))
            stack.enter_context(patch.object(socket.socket, "connect_ex", sink))
            stack.enter_context(patch.object(server.bing_tools, "_read", sink))
            await hosted._tool_manager.call_tool(name, arguments)
        sink.assert_not_called()
        assert bool(vendor_calls) == name.startswith("serp_")
        assert bool(google.calls) == (not name.startswith("serp_"))
        assert all(endpoint == "/serp/google/organic/live/advanced" for endpoint, _ in vendor_calls)
        if nested:
            assert any(method == "run_report" for chain in google.calls for method, _ in chain)

    asyncio.run(exercise())


def test_worker_bound_retains_validated_consumer_context(hosted):
    async def exercise():
        hosted._tool_manager.remove_tool("gsc_list_sites")
        gate, lock, entered = threading.Event(), threading.Lock(), []

        def controlled() -> dict:
            with lock:
                entered.append(consumer_context.get().consumer_id)
            assert gate.wait(10)
            return {"ok": True}

        hosted.add_tool(controlled, name="gsc_list_sites")
        identity = consumer_context.set(
            AuthenticatedConsumer(consumer_id="validated-fixture", key_id="fixture-v1")
        )
        work = []
        try:
            work = [
                asyncio.create_task(hosted._tool_manager.call_tool("gsc_list_sites", {}))
                for _ in range(10)
            ]
            with anyio.fail_after(5):
                while len(entered) < 8:
                    await anyio.sleep(0.01)
            await anyio.sleep(0.05)
            assert len(entered) == hosted._tool_manager.worker_limiter.borrowed_tokens == 8
            assert not any(task.done() for task in work)
            gate.set()
            assert await asyncio.gather(*work) == [{"ok": True}] * 10
            assert entered == ["validated-fixture"] * 10
        finally:
            gate.set()
            if work:
                await asyncio.gather(*work, return_exceptions=True)
            consumer_context.reset(identity)

    asyncio.run(exercise())


AUDIT_PROBE = r"""
import asyncio, io, json, logging, socket, sys
from unittest.mock import patch
from mcp import types
from pydantic import BaseModel
from google_seo_mcp import server
from google_seo_mcp.consumer_auth import AuthenticatedConsumer, consumer_context, request_id_context
from google_seo_mcp.runtime_config import load_runtime_config

def denied(*args, **kwargs):
    raise AssertionError("UNEXPECTED_PROVIDER_ATTEMPT")
socket.getaddrinfo = denied
socket.socket.connect = denied
socket.socket.connect_ex = denied
server.auth_module.google_auth_default = denied
server.auth_module.SACredentials.from_service_account_file = denied

async def exercise():
    captured = io.StringIO()
    with patch('sys.stderr', captured):
        instance = server.create_server(load_runtime_config(
            [], {'GOOGLE_SEO_TRANSPORT': 'streamable-http'}))
        consumer = consumer_context.set(AuthenticatedConsumer(
            consumer_id='verified-fixture', key_id='fixture-v1'))
        request_id = request_id_context.set('SYNTHETIC_REQUEST_ID')
        handler = instance._mcp_server.request_handlers[types.CallToolRequest]
        results = []
        async def request(name, arguments):
            # This fixture deliberately replaces handlers; refresh the SDK's
            # schema cache as well so it describes the current fixture tool.
            instance._mcp_server._tool_cache.clear()
            response = await handler(types.CallToolRequest(
                method='tools/call', params=types.CallToolRequestParams(
                    name=name, arguments=arguments)))
            results.append(response.model_dump(mode='json'))
        try:
            await request('gsc_inspect_url', {'site_url': ['SYNTHETIC_ARGUMENT']})
            for tool_name, error_type in [('gsc_list_sites', OSError), ('serp_check', ValueError)]:
                instance._tool_manager.remove_tool(tool_name)
                def failing(argument: str = '') -> dict:
                    logging.getLogger('google.auth.transport.requests').error('SYNTHETIC_GOOGLE_LOG')
                    logging.getLogger('httpx').error('SYNTHETIC_VENDOR_LOG')
                    raise error_type('SYNTHETIC_UPSTREAM_EXCEPTION')
                instance.add_tool(failing, name=tool_name)
                await request(tool_name, {'argument': 'SYNTHETIC_BEARER_TOKEN'})
            instance._tool_manager.remove_tool('gsc_list_sites')
            class Result(BaseModel):
                count: int
            def bad_output() -> Result:
                return {'count': 'SYNTHETIC_RESULT'}
            instance.add_tool(bad_output, name='gsc_list_sites')
            await request('gsc_list_sites', {})
            await request('SYNTHETIC_UNKNOWN_TOOL', {'argument': 'SYNTHETIC_ARGUMENT'})
            instance._tool_manager.remove_tool('gsc_list_sites')
            def success(argument: str) -> dict:
                assert argument == 'SYNTHETIC_SUCCESS_ARGUMENT'
                return {'value': 'SYNTHETIC_SUCCESS_RESULT'}
            instance.add_tool(success, name='gsc_list_sites')
            await request('gsc_list_sites', {'argument': 'SYNTHETIC_SUCCESS_ARGUMENT'})
        finally:
            consumer_context.reset(consumer)
            request_id_context.reset(request_id)
    print(json.dumps({'results': results, 'logs': captured.getvalue(),
                      'server_file': server.__file__}))
asyncio.run(exercise())
"""


def test_actual_hosted_audit_redacts_args_results_provider_and_sdk_failures(tmp_path):
    home = tmp_path / "empty-home"
    home.mkdir()
    assert not list(home.iterdir())
    environment = {
        "HOME": str(home),
        "PATH": f"{Path(sys.executable).parent}:/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TMPDIR": str(home),
        "PYTHONUNBUFFERED": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        # Pin the same source tree OR installed wheel as the parent interpreter;
        # a clean env must not silently select an older installed distribution.
        "PYTHONPATH": str(Path(server.__file__).resolve().parent.parent),
    }
    result = subprocess.run(
        [sys.executable, "-c", AUDIT_PROBE],
        env=environment,
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    projection = json.loads(result.stdout)
    assert Path(projection["server_file"]).resolve() == Path(server.__file__).resolve()
    responses, log_text = projection["results"], projection["logs"]
    assert len(responses) == 6
    expected_errors = [
        "invalid_tool_arguments",
        "provider_unavailable",
        "provider_unavailable",
        "invalid_tool_arguments",
        "tool_not_allowed",
    ]
    for response, expected in zip(responses[:5], expected_errors, strict=True):
        assert response["isError"] is True
        assert [item["text"] for item in response["content"]] == [expected]
    assert "SYNTHETIC" not in json.dumps(responses[:5]) + log_text
    # Successful values belong in the response only; audit must omit them.
    assert responses[5]["isError"] is False
    assert "SYNTHETIC_SUCCESS_RESULT" in json.dumps(responses[5])
    records = [json.loads(line) for line in log_text.splitlines()]
    assert len(records) == 6
    for record in records:
        assert set(record) == {"request_id", "consumer", "tool", "outcome", "duration_ms"}
        assert record["consumer"] == "verified-fixture"
        assert len(record["request_id"]) == 32
        assert all(c in "0123456789abcdef" for c in record["request_id"])
        assert isinstance(record["duration_ms"], (int, float)) and record["duration_ms"] >= 0
    assert [record["outcome"] for record in records] == ["error"] * 4 + ["denied", "success"]
    assert records[4]["tool"] == "denied"
