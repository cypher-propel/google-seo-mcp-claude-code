"""Exact additive registration and real SDK reconstruction contracts."""

from __future__ import annotations

import asyncio
import inspect
import json
import socket
from unittest.mock import Mock, patch

import pytest
from mcp import types
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.tools.base import Tool

from google_seo_mcp import auth as google_auth
from google_seo_mcp import server
from google_seo_mcp.bing import auth, client, tools
from google_seo_mcp.runtime_config import ProductionRuntimeConfig, load_runtime_config
from google_seo_mcp.server import mcp
from tests.test_production_tool_policy import BASELINE, BING_NAMES, EXPECTED, ORIGINAL_EXPECTED

SITE = "https://kelleyconstructioninc.com/"
# Accepted section 5: independent of manifest, discovery, enum and signatures.
# Tool, provider method, required selector inputs, provider selector parameters.
BING_ROUTES = [
    ("bing_list_sites", "GetUserSites", {}, {}),
    ("bing_rank_traffic_stats", "GetRankAndTrafficStats", {}, {}),
    ("bing_query_stats", "GetQueryStats", {}, {}),
    ("bing_page_stats", "GetPageStats", {}, {}),
    ("bing_page_query_stats", "GetPageQueryStats", {"page_url": SITE + "a"}, {"page": SITE + "a"}),
    (
        "bing_query_page_stats",
        "GetQueryPageStats",
        {"query": "steel & café"},
        {"query": "steel & café"},
    ),
    ("bing_crawl_stats", "GetCrawlStats", {}, {}),
    ("bing_crawl_issues", "GetCrawlIssues", {}, {}),
    ("bing_url_info", "GetUrlInfo", {"url": SITE + "a"}, {"url": SITE + "a"}),
    ("bing_list_sitemaps", "GetFeeds", {}, {}),
    (
        "bing_sitemap_details",
        "GetFeedDetails",
        {"sitemap_url": SITE + "s.xml"},
        {"feedUrl": SITE + "s.xml"},
    ),
]
ANALYTICS = frozenset(
    {
        "bing_rank_traffic_stats",
        "bing_query_stats",
        "bing_page_stats",
        "bing_page_query_stats",
        "bing_query_page_stats",
        "bing_crawl_stats",
    }
)


def bing_arguments(row):
    return ({} if row[0] == "bing_list_sites" else {"site_url": SITE}) | row[2]


def sdk_call(instance, name, arguments):
    async def run():
        handler = instance._mcp_server.request_handlers[types.CallToolRequest]
        response = await handler(
            types.CallToolRequest(
                method="tools/call",
                params=types.CallToolRequestParams(name=name, arguments=arguments),
            )
        )
        return response.model_dump(mode="json")

    return asyncio.run(run())


@pytest.fixture(autouse=True)
def offline_registration(monkeypatch):
    deny = Mock(side_effect=AssertionError("unexpected DNS/socket/provider access"))
    for target, member in (
        (socket, "getaddrinfo"),
        (socket.socket, "connect"),
        (socket.socket, "connect_ex"),
    ):
        monkeypatch.setattr(target, member, deny)
    monkeypatch.setattr(server, "_configure_hosted_logging", lambda: None)
    monkeypatch.setattr(client, "_GLOBAL", client._Admission())
    tools.configure_bing_tools()
    yield
    tools.configure_bing_tools()
    auth.configure_bing_auth(None)
    google_auth.configure_hosted_auth(ProductionRuntimeConfig())
    deny.assert_not_called()


@pytest.fixture(params=["initial", "legacy", "production"])
def registered(request):
    if request.param == "initial":
        return mcp
    config = (
        ProductionRuntimeConfig()
        if request.param == "legacy"
        else load_runtime_config(
            [],
            {"GOOGLE_SEO_TRANSPORT": "streamable-http"},
        )
    )
    return server.create_server(config)


def test_tool_count():
    tools = list(mcp._tool_manager.list_tools())
    # 12 GSC + 14 GA4 + 6 cross + 5 LH + 3 CrUX + 3 Schema + 5 Idx + 5 Trends +
    # 21 migration core + 2 AEO + 3 meta (get_capabilities, reload_credentials,
    # reauthenticate alias) + v0.8.0: 3 history + 4 serp + 7 logs +
    # 4 migration crawl_advanced + 2 singular wrappers (migration_redirect_chain,
    # migration_image_alts) + v0.8.3: 1 migration_prerender_check_batch = 100
    # Approved additive delta only: historical102 + exact eleven Bing reads.
    assert len(tools) == 113, f"Expected 113 tools, got {len(tools)}"


def test_tool_names_have_expected_prefixes():
    tools = {t.name for t in mcp._tool_manager.list_tools()}
    # 6 cross-platform
    assert {
        "cross_gsc_to_ga4_journey",
        "cross_traffic_health_check",
        "cross_opportunity_matrix",
        "cross_seo_to_revenue_attribution",
        "cross_landing_page_full_diagnosis",
        "cross_multi_property_comparison",
    } <= tools
    assert sum(1 for t in tools if t.startswith("gsc_")) == 12
    assert sum(1 for t in tools if t.startswith("ga4_")) == 14
    assert sum(1 for t in tools if t.startswith("cross_")) == 6
    assert "get_capabilities" in tools
    assert "reload_credentials" in tools
    assert "reauthenticate" in tools  # deprecated alias kept for backward-compat


def test_diagnostic_tools_have_guardrail_suffix():
    """Every registered _diagnostic_ tool (gsc_/ga4_/cross_) must include the suffix.

    Meta tools (get_capabilities, reload_credentials, reauthenticate) are
    registered with @mcp.tool() directly without going through `_register`,
    so they don't carry the suffix — that's intentional since they don't
    return user-facing data.
    """
    suffix_marker = "Use ONLY the data returned by this tool"
    META_TOOLS = {"get_capabilities", "reload_credentials", "reauthenticate"}
    for tool in mcp._tool_manager.list_tools():
        if tool.name in META_TOOLS:
            continue
        desc = tool.description or ""
        assert suffix_marker in desc, f"Tool {tool.name} missing guardrail suffix"


def test_explicit_legacy_catalog_delta_all_reconstructions(registered, monkeypatch):
    names = {t.name for t in registered._tool_manager.list_tools()}
    assert len(BASELINE) == 102 and len(BING_NAMES) == 11
    assert names == (
        EXPECTED if isinstance(registered, server.ProductionFastMCP) else BASELINE | BING_NAMES
    )
    assert {r[0] for r in BING_ROUTES} == BING_NAMES
    monkeypatch.setattr(server, "mcp", registered)
    assert set(server._categorize_registered_tools()["bing"]) == BING_NAMES


@pytest.mark.parametrize("row", BING_ROUTES, ids=[r[0] for r in BING_ROUTES])
def test_bing_schema_annotations_and_suffix_all_reconstructions(registered, row):
    name, _, selectors, _ = row
    tool = registered._tool_manager.get_tool(name)
    required = ([] if name == "bing_list_sites" else ["site_url"]) + list(selectors)
    fields = required + (["start_date", "end_date"] if name in ANALYTICS else [])
    if name not in ("bing_list_sites", "bing_url_info"):
        fields += ["limit"]
    assert list(tool.parameters["properties"]) == fields
    assert set(tool.parameters.get("required", [])) == set(required)
    assert tool.parameters["additionalProperties"] is False
    if "limit" in fields:
        assert tool.parameters["properties"]["limit"]["type"] == "integer"
        assert tool.parameters["properties"]["limit"]["default"] == 100
    for date in ("start_date", "end_date"):
        if date in fields:
            assert tool.parameters["properties"][date]["default"] is None
    public = next(t for t in asyncio.run(registered.list_tools()) if t.name == name)
    assert public.inputSchema == tool.parameters and public.annotations == tool.annotations
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.openWorldHint is False
    assert tool.description.count("Use ONLY the data returned by this tool") == 1
    assert tool.description.rstrip().endswith(server.GUARDRAIL_SUFFIX.rstrip())


@pytest.mark.parametrize("row", BING_ROUTES, ids=[r[0] for r in BING_ROUTES])
def test_strict_bing_arguments_precede_file_dns_socket_and_custody(registered, row):
    name = row[0]
    # Each entry is dispatched separately, without a large Cartesian product.
    attacks = [{"client": "SYNTHETIC_PRIVATE_ARGUMENT"}, {"endpoint": "http://127.0.0.1/"}]
    if name != "bing_list_sites":
        attacks += [{"site_url": v} for v in (True, 1, [], None, "http://127.0.0.1/")]
    if name not in ("bing_list_sites", "bing_url_info"):
        attacks += [{"limit": v} for v in (True, False, "100", 1.0, None, {}, [], 0, 1001)]
    for selector in row[2]:
        attacks += [{selector: v} for v in (True, 1, [], None, "")]
        if selector != "query":
            attacks += [{selector: "http://169.254.169.254/metadata"}]
    if name in ANALYTICS:
        attacks += [
            {"start_date": True, "end_date": "2024-01-02"},
            {"start_date": "2024-01-01"},
            {"start_date": "2024-01-02", "end_date": "2024-01-01"},
            {"start_date": "2022-01-01", "end_date": "2024-01-01"},
        ]
    deny = Mock(side_effect=AssertionError("invalid arguments reached custody or HTTP"))
    with (
        patch.object(auth._Boundary, "inspect", deny),
        patch.object(auth._HeldDocument, "acquire", deny),
        patch.object(auth.os, "open", deny),
        patch.object(auth.os, "read", deny),
        patch.object(client, "BingCredentialLoader", deny),
        patch(
            "builtins.open",
            deny,
        ),
        patch("pathlib.Path.open", deny),
        patch("httpx.Client", deny),
    ):
        for extra in attacks:
            result = sdk_call(registered, name, bing_arguments(row) | extra)
            assert result["isError"] is True, (name, extra)
            assert result["content"][0]["text"] in ("invalid_tool_arguments", "invalid_request")
            assert "SYNTHETIC_PRIVATE" not in json.dumps(result)
        for missing in ([] if name == "bing_list_sites" else ["site_url"]) + list(row[2]):
            payload = bing_arguments(row)
            del payload[missing]
            assert sdk_call(registered, name, payload)["isError"] is True
    deny.assert_not_called()


@pytest.mark.parametrize(
    "code", ["provider_not_configured", "invalid_request", "provider_error", "SYNTHETIC_PRIVATE"]
)
def test_bing_safe_errors_at_both_sdk_and_manager_seams(registered, monkeypatch, code):
    def fail(*args, **kwargs):
        raise RuntimeError(code)

    monkeypatch.setattr(tools, "_read", fail)
    expected = code if code != "SYNTHETIC_PRIVATE" else "provider_unavailable"
    result = sdk_call(registered, "bing_list_sites", {})
    assert result["isError"] is True
    assert result["content"][0]["text"] == expected
    assert server._safe_tool_error(RuntimeError(code)) == expected
    if isinstance(registered, server.ProductionFastMCP):
        tool = registered._tool_manager.get_tool("bing_list_sites")

        async def failed_run(*args, **kwargs):
            raise ToolError(code)

        monkeypatch.setattr(type(tool), "run", failed_run)
        with pytest.raises(ToolError, match="^" + expected + "$"):
            asyncio.run(registered._tool_manager.call_tool("bing_list_sites", {}))


# Accepted-main registration targets, not a manifest/discovered expected set.
INCUMBENTS = {
    "gsc_list_sites": server.gsc_sites.list_sites,
    "gsc_inspect_url": server.gsc_sites.inspect_url,
    "gsc_list_sitemaps": server.gsc_sitemaps.list_sitemaps,
    "gsc_search_analytics": server.gsc_analytics.search_analytics,
    "gsc_site_snapshot": server.gsc_analytics.site_snapshot,
    "gsc_quick_wins": server.gsc_intel.quick_wins,
    "gsc_traffic_drops": server.gsc_intel.traffic_drops,
    "gsc_content_decay": server.gsc_intel.content_decay,
    "gsc_cannibalization": server.gsc_intel.cannibalization,
    "gsc_ctr_opportunities": server.gsc_intel.ctr_opportunities,
    "gsc_alerts": server.gsc_intel.alerts,
    "ga4_list_properties": server.ga4_admin.list_properties,
    "ga4_get_property_details": server.ga4_admin.get_property_details,
    "ga4_search_schema": server.ga4_reporting.search_ga4_schema,
    "ga4_list_schema_categories": server.ga4_reporting.list_schema_categories,
    "ga4_estimate_query_size": server.ga4_reporting.estimate_query_size,
    "ga4_query": server.ga4_reporting.query_ga4,
    "ga4_anomalies": server.ga4_intel.anomalies,
    "ga4_traffic_drops_by_channel": server.ga4_intel.traffic_drops_by_channel,
    "ga4_landing_page_health": server.ga4_intel.landing_page_health,
    "ga4_conversion_funnel": server.ga4_intel.conversion_funnel,
    "ga4_event_volume_comparison": server.ga4_intel.event_volume_comparison,
    "ga4_cohort_retention": server.ga4_intel.cohort_retention,
    "ga4_channel_attribution": server.ga4_intel.channel_attribution,
    "ga4_content_decay": server.ga4_intel.content_decay,
    "cross_gsc_to_ga4_journey": server.cp_journey.gsc_to_ga4_journey,
    "cross_traffic_health_check": server.cp_health.traffic_health_check,
    "cross_opportunity_matrix": server.cp_matrix.opportunity_matrix,
    "cross_seo_to_revenue_attribution": server.cp_attr.seo_to_revenue_attribution,
    "cross_landing_page_full_diagnosis": server.cp_diag.landing_page_full_diagnosis,
    "cross_multi_property_comparison": server.cp_multi.multi_property_comparison,
    "serp_check": server.serp_tools.serp_check,
    "serp_aio_monitor": server.serp_tools.serp_aio_monitor,
    "serp_paa_extractor": server.serp_tools.serp_paa_extractor,
    "serp_competitor_intersect": server.serp_tools.serp_competitor_intersect,
}


def test_original35_schema_coercion_output_and_callable_identity_preserved(registered):
    # Recreate the original SDK registration mechanism from explicit callables:
    # unlike Bing, incumbents retain permissive models and scalar preparsing.
    assert set(INCUMBENTS) == ORIGINAL_EXPECTED and len(INCUMBENTS) == 35

    def validate(metadata, payload):
        try:
            values = metadata.arg_model.model_validate(
                metadata.pre_parse_json(payload)
            ).model_dump_one_level()
            return "ok", values, {k: type(v) for k, v in values.items()}
        except Exception as exc:
            return "error", type(exc).__name__

    for name, fn in INCUMBENTS.items():
        reference = Tool.from_function(fn, name=name)
        current = registered._tool_manager.get_tool(name)
        actual_fn = (
            current.fn.__wrapped__
            if isinstance(registered, server.ProductionFastMCP)
            else current.fn
        )
        assert actual_fn is fn
        assert inspect.signature(current.fn, eval_str=True) == inspect.signature(fn, eval_str=True)
        assert current.parameters == reference.parameters
        assert (
            current.description == reference.description
            and current.annotations == reference.annotations
        )
        assert type(current.fn_metadata) is type(reference.fn_metadata)
        assert current.fn_metadata.output_schema == reference.fn_metadata.output_schema
        assert current.fn_metadata.wrap_output == reference.fn_metadata.wrap_output
        assert (
            current.fn_metadata.arg_model.model_config
            == reference.fn_metadata.arg_model.model_config
        )
        required = {
            n: "2024-01-01" if "date" in n else SITE
            for n, f in reference.fn_metadata.arg_model.model_fields.items()
            if f.is_required()
        }
        for field in reference.fn_metadata.arg_model.model_fields:
            for value in (True, False, 1.0, "100", "null", None, [], {}):
                payload = required | {field: value, "undeclared": "ignored"}
                assert current.fn_metadata.pre_parse_json(
                    payload
                ) == reference.fn_metadata.pre_parse_json(payload)
                assert validate(current.fn_metadata, payload) == validate(
                    reference.fn_metadata, payload
                ), (name, field)
