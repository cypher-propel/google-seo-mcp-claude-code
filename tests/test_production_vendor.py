"""Offline hosted vendor contract: no paid requests or real credentials."""

from __future__ import annotations

import json
from unittest.mock import Mock

import httpx
import pytest

from google_seo_mcp import auth, serp
from google_seo_mcp.serp import tools


@pytest.fixture
def hosted(monkeypatch):
    monkeypatch.setenv("GOOGLE_SEO_PROFILE", "production")
    monkeypatch.setattr(auth, "_hosted_auth_enabled", False)
    monkeypatch.delenv("DATAFORSEO_LOGIN", raising=False)
    monkeypatch.delenv("DATAFORSEO_PASSWORD", raising=False)


def payload():
    return tools._serp_payload("offline test", "es", "mobile", "es")


def deny_outbound(monkeypatch):
    dns = Mock(side_effect=AssertionError("DNS must not run"))
    client = Mock(side_effect=AssertionError("HTTP client must not be created"))
    monkeypatch.setattr(serp, "assert_url_is_public", dns)
    monkeypatch.setattr(serp.httpx, "Client", client)
    return dns, client


@pytest.mark.parametrize("present", [None, "DATAFORSEO_LOGIN", "DATAFORSEO_PASSWORD"])
@pytest.mark.parametrize(
    "tool,args",
    [
        (tools.serp_check, ("offline test",)),
        (tools.serp_aio_monitor, (["offline test"],)),
        (tools.serp_paa_extractor, ("offline test",)),
        (tools.serp_competitor_intersect, ("offline test", "https://example.com/")),
    ],
)
def test_missing_credentials_all_tools_before_dns_and_client(
    hosted, monkeypatch, present, tool, args
):
    if present:
        monkeypatch.setenv(present, "synthetic-fixture")
    dns, client = deny_outbound(monkeypatch)
    result = tool(*args)
    assert result["data"]["error"] == "credentials_missing"
    dns.assert_not_called()
    client.assert_not_called()


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://attacker.example/",
        "//attacker.example/",
        "/serp/google/organic/live/advanced?url=x",
        "/../other",
        "/serp/google/organic/live/regular",
        "/serp/google/organic/live/advanced/",
    ],
)
def test_exact_endpoint_rejected_before_dns(hosted, monkeypatch, endpoint):
    monkeypatch.setenv("DATAFORSEO_LOGIN", "synthetic-fixture")
    monkeypatch.setenv("DATAFORSEO_PASSWORD", "synthetic-fixture")
    dns, client = deny_outbound(monkeypatch)
    with pytest.raises(ValueError, match="invalid_serp_endpoint"):
        serp.call_dataforseo(endpoint, payload())
    dns.assert_not_called()
    client.assert_not_called()


@pytest.mark.parametrize(
    "change",
    [
        {"keyword": ""},
        {"keyword": "x" * 201},
        {"keyword": "line\nbreak"},
        {"keyword": " " * 200},
        {"keyword": "\ud800"},
        {"location_code": True},
        {"location_code": 0},
        {"location_code": 10_000_000},
        {"language_code": "es\n"},
        {"device": "crawler"},
        {"depth": 100},
        {"depth": True},
        {"url": "https://attacker.example/"},
        {"login": "override"},
        {"password": "override"},
    ],
)
def test_payload_override_or_unbounded_input_rejected_before_dns(hosted, monkeypatch, change):
    monkeypatch.setenv("DATAFORSEO_LOGIN", "synthetic-fixture")
    monkeypatch.setenv("DATAFORSEO_PASSWORD", "synthetic-fixture")
    body = payload()
    body[0].update(change)
    dns, client = deny_outbound(monkeypatch)
    with pytest.raises(ValueError, match="invalid_serp_input"):
        serp.call_dataforseo(serp.ORGANIC_LIVE_ENDPOINT, body)
    dns.assert_not_called()
    client.assert_not_called()


@pytest.mark.parametrize("timeout", [0, -1, True, 61, float("inf"), float("nan"), "60"])
def test_timeout_is_finite_and_bounded(hosted, monkeypatch, timeout):
    monkeypatch.setenv("DATAFORSEO_LOGIN", "synthetic-fixture")
    monkeypatch.setenv("DATAFORSEO_PASSWORD", "synthetic-fixture")
    dns, client = deny_outbound(monkeypatch)
    with pytest.raises(ValueError, match="invalid_serp_input"):
        serp.call_dataforseo(serp.ORGANIC_LIVE_ENDPOINT, payload(), timeout)
    dns.assert_not_called()
    client.assert_not_called()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"location": "https://attacker.example/"},
        {"location": "xx"},
        {"location": "0"},
        {"location": "12345678"},
        {"device": "crawler"},
        {"language_code": "en-US"},
    ],
)
def test_tool_input_validation_precedes_vendor_call(hosted, monkeypatch, kwargs):
    call = Mock(side_effect=AssertionError("vendor helper must not run"))
    monkeypatch.setattr(tools, "call_dataforseo", call)
    with pytest.raises(ValueError, match="invalid_serp_input"):
        tools.serp_check("offline test", **kwargs)
    call.assert_not_called()


@pytest.mark.parametrize("keywords", [[], ["valid", ""], ["x"] * 21, "not-a-list"])
def test_batch_validates_entire_input_before_first_billable_call(hosted, monkeypatch, keywords):
    call = Mock(side_effect=AssertionError("vendor helper must not run"))
    monkeypatch.setattr(tools, "call_dataforseo", call)
    with pytest.raises(ValueError, match="invalid_serp_input"):
        tools.serp_aio_monitor(keywords)
    call.assert_not_called()


@pytest.mark.parametrize(
    "your_url",
    [
        "file:///etc/passwd",
        "https://user:password@example.com/",
        "https://example.com:bad/",
        "https://example.com/\n",
        "https://example.com/" + "x" * 2048,
        [],
    ],
)
def test_competitor_input_validated_without_fetch(hosted, monkeypatch, your_url):
    call = Mock(side_effect=AssertionError("vendor helper must not run"))
    monkeypatch.setattr(tools, "call_dataforseo", call)
    with pytest.raises(ValueError, match="invalid_serp_input"):
        tools.serp_competitor_intersect("offline test", your_url)
    call.assert_not_called()


def install_transport(monkeypatch, handler):
    original = httpx.Client
    options = []

    def client(**kwargs):
        options.append(kwargs)
        return original(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(serp.httpx, "Client", client)
    monkeypatch.setattr(serp, "assert_url_is_public", Mock())
    monkeypatch.setenv("DATAFORSEO_LOGIN", "synthetic-fixture")
    monkeypatch.setenv("DATAFORSEO_PASSWORD", "synthetic-fixture")
    return options


@pytest.mark.parametrize(
    "kind", ["http-error", "redirect", "upstream-error", "bad-json", "task-error", "oversize"]
)
def test_provider_failure_text_never_leaks(hosted, monkeypatch, caplog, kind):
    sentinel = "SYNTHETIC_PRIVATE_SENTINEL"
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if kind == "http-error":
            raise httpx.ConnectError(sentinel)
        if kind == "redirect":
            return httpx.Response(
                302, headers={"location": "https://attacker.example/"}, text=sentinel
            )
        if kind == "upstream-error":
            return httpx.Response(500, text=sentinel)
        if kind == "bad-json":
            return httpx.Response(200, text=sentinel)
        if kind == "oversize":
            return httpx.Response(200, content=b"x" * (serp.HOSTED_MAX_RESPONSE_BYTES + 1))
        return httpx.Response(
            200,
            json={
                "status_code": 20000,
                "tasks": [{"status_code": 40100, "status_message": sentinel}],
            },
        )

    options = install_transport(monkeypatch, handler)
    with pytest.raises(RuntimeError) as error:
        serp.call_dataforseo(serp.ORGANIC_LIVE_ENDPOINT, payload())
    assert str(error.value) == "vendor_unavailable"
    assert sentinel not in caplog.text
    assert calls == ["https://api.dataforseo.com/v3/serp/google/organic/live/advanced"]
    assert options == [{"timeout": 60.0, "follow_redirects": False, "trust_env": False}]


def test_nested_batch_errors_and_status_are_sanitized(hosted, monkeypatch, caplog):
    sentinel = "SYNTHETIC_PRIVATE_SENTINEL"
    monkeypatch.setattr(tools, "call_dataforseo", Mock(side_effect=RuntimeError(sentinel)))
    result = tools.serp_aio_monitor(["offline test"])
    assert result["data"]["errors"] == [{"keyword": "offline test", "error": "vendor_unavailable"}]
    assert sentinel not in json.dumps(result) + caplog.text
    body = observation([])
    body["status_message"] = sentinel
    summary = tools._summarise_serp(body, keyword="offline test")
    assert summary["raw_status"] == "ok"
    assert sentinel not in json.dumps(summary) + caplog.text


def test_success_uses_fixed_endpoint_and_never_fetches_returned_urls(hosted, monkeypatch):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        assert json.loads(request.content)[0]["depth"] == 20
        return httpx.Response(
            200,
            json={
                "status_code": 20000,
                "status_message": "not-returned",
                "tasks": [
                    {
                        "status_code": 20000,
                        "result": [
                            {
                                "items": [
                                    {
                                        "type": "organic",
                                        "rank_absolute": 1,
                                        "url": "http://127.0.0.1/private",
                                        "title": "Result",
                                    },
                                    {
                                        "type": "people_also_ask",
                                        "items": [
                                            {
                                                "title": "Question",
                                                "expanded_element": [{"url": "file:///private"}],
                                            }
                                        ],
                                    },
                                ]
                            }
                        ],
                    }
                ],
            },
        )

    install_transport(monkeypatch, handler)
    for tool, args in [
        (tools.serp_check, ("offline test",)),
        (tools.serp_aio_monitor, (["offline test"],)),
        (tools.serp_paa_extractor, ("offline test",)),
        (tools.serp_competitor_intersect, ("offline test", "https://example.com/")),
    ]:
        assert "error" not in tool(*args)["data"]
    assert calls == ["https://api.dataforseo.com/v3/serp/google/organic/live/advanced"] * 4


def test_captured_hosted_identity_cannot_be_disabled_by_environment(hosted, monkeypatch):
    monkeypatch.setattr(auth, "_hosted_auth_enabled", True)
    monkeypatch.delenv("GOOGLE_SEO_PROFILE")
    with pytest.raises(ValueError, match="invalid_serp_input"):
        tools._serp_payload("", "es", "mobile")


def test_legacy_optional_credentials_shape_preserved(monkeypatch):
    monkeypatch.delenv("GOOGLE_SEO_PROFILE", raising=False)
    monkeypatch.setattr(auth, "_hosted_auth_enabled", False)
    monkeypatch.delenv("DATAFORSEO_LOGIN", raising=False)
    monkeypatch.delenv("DATAFORSEO_PASSWORD", raising=False)
    dns, client = deny_outbound(monkeypatch)
    result = tools.serp_check("offline test")["data"]
    assert result["error"] == "credentials_missing"
    assert "DATAFORSEO_LOGIN" in result["fix"]
    dns.assert_not_called()
    client.assert_not_called()


def observation(items):
    return {"status_code": 20000, "tasks": [{"status_code": 20000, "result": [{"items": items}]}]}


# Each fixture independently lacks enough evidence for a measured negative.
MALFORMED_OBSERVATIONS = [
    None,
    [],
    {},
    {"status_code": 20000, "tasks": None},
    {"status_code": 20000, "tasks": []},
    {"status_code": 20000, "tasks": [{"status_code": 20000}]},
    *[
        {"status_code": 20000, "tasks": [{"status_code": 20000, "result": result}]}
        for result in (
            None,
            [],
            {},
            [None],
            [{}],
            [{"items": None}],
            [{"items": {}}],
            [{"items": []}, {"items": []}],
        )
    ],
    {"status_code": 20000, "tasks": [None]},
    {"status_code": 20000, "tasks": [{"status_code": 20000, "result": [{"items": []}]}] * 2},
    observation([None]),
    observation(["unknown"]),
    observation([{}]),
    observation([{"type": None}]),
    observation([{"type": ""}]),
    *[
        observation([item])
        for item in (
            {"type": "organic", "rank_absolute": 1},
            {"type": "organic", "url": "https://example.com/"},
            {"type": "organic", "rank_absolute": True, "url": "https://example.com/"},
            {"type": "organic", "rank_absolute": 0, "url": "https://example.com/"},
            {"type": "organic", "rank_absolute": "1", "url": "https://example.com/"},
            {"type": "organic", "rank_absolute": 1, "url": None},
            {"type": "organic", "rank_absolute": 1, "url": ""},
            {"type": "organic", "rank_absolute": 1, "url": "https://example.com/", "title": []},
            {"type": "people_also_ask"},
            {"type": "people_also_ask", "items": None},
            {"type": "people_also_ask", "items": {}},
            {"type": "people_also_ask", "items": [None]},
            {"type": "people_also_ask", "items": [{}]},
            {"type": "people_also_ask", "items": [{"title": None}]},
            {"type": "people_also_ask", "items": [{"title": "Q", "expanded_element": [None]}]},
            {"type": "people_also_ask", "items": [{"title": "Q", "expanded_element": {}}]},
            {"type": "ai_overview", "references": [None]},
            {"type": "ai_overview", "references": {}},
            {"type": "featured_snippet", "description": []},
            {"type": "related_searches", "items": None},
            {"type": "related_searches", "items": [None]},
        )
    ],
]


SERP_TOOLS = [
    (tools.serp_check, ("offline test",)),
    (tools.serp_aio_monitor, (["offline test"],)),
    (tools.serp_paa_extractor, ("offline test",)),
    (tools.serp_competitor_intersect, ("offline test", "https://example.com/")),
]


@pytest.mark.parametrize("body", MALFORMED_OBSERVATIONS)
@pytest.mark.parametrize("tool,args", SERP_TOOLS)
def test_incomplete_observations_cannot_be_measured_absence(
    hosted, monkeypatch, caplog, body, tool, args
):
    calls = []

    def terminal(request):
        calls.append(str(request.url))
        return (
            httpx.Response(200, json=body)
            if body is not None
            else httpx.Response(200, content=b"null")
        )

    install_transport(monkeypatch, terminal)
    if tool is tools.serp_aio_monitor:
        data = tool(*args)["data"]
        assert data["checked"] == 0 and data["findings"] == []
        assert data["with_aio"] == data["with_paa"] == data["with_featured_snippet"] == 0
        assert data["errors"] == [{"keyword": "offline test", "error": "vendor_unavailable"}]
    else:
        with pytest.raises(RuntimeError, match="^vendor_unavailable$"):
            tool(*args)
    assert calls == ["https://api.dataforseo.com/v3/serp/google/organic/live/advanced"]
    assert "SYNTHETIC_PRIVATE_SENTINEL" not in caplog.text


@pytest.mark.parametrize("body", MALFORMED_OBSERVATIONS)
def test_direct_summary_parser_rejects_unqualified_observation(hosted, body):
    with pytest.raises(RuntimeError, match="^vendor_unavailable$"):
        tools._summarise_serp(body, keyword="offline test")


@pytest.mark.parametrize("tool,args", SERP_TOOLS)
@pytest.mark.parametrize("positive", [False, True])
def test_explicit_empty_and_positive_observations_all_tools(
    hosted, monkeypatch, tool, args, positive
):
    items = (
        [
            {
                "type": "ai_overview",
                "references": [{"url": "http://127.0.0.1/private", "title": "Source"}],
            },
            {"type": "featured_snippet", "url": "https://example.com/", "description": "Answer"},
            {
                "type": "organic",
                "rank_absolute": 1,
                "url": "https://example.com/",
                "title": "Result",
            },
            {"type": "people_also_ask", "items": [{"title": "Question", "expanded_element": None}]},
            {"type": "related_searches", "items": ["related query"]},
            {"type": "vendor_future_feature"},
        ]
        if positive
        else []
    )
    calls = []

    def terminal(request):
        calls.append(str(request.url))
        return httpx.Response(200, json=observation(items))

    install_transport(monkeypatch, terminal)
    data = tool(*args)["data"]
    assert "error" not in data
    if tool is tools.serp_check:
        assert data["has_aio"] is positive and bool(data["organic"]) is positive
        assert data["has_featured_snippet"] is positive and bool(data["paa"]) is positive
    elif tool is tools.serp_aio_monitor:
        assert data["checked"] == 1 and data["errors"] == []
        assert (
            data["with_aio"] == data["with_paa"] == data["with_featured_snippet"] == int(positive)
        )
    elif tool is tools.serp_paa_extractor:
        assert data["paa_count"] == int(positive)
    else:
        assert data["in_top_10"] is positive
        assert data["your_position"] == (1 if positive else None)
    assert calls == ["https://api.dataforseo.com/v3/serp/google/organic/live/advanced"]


def test_mixed_batch_counts_only_qualified_observations(hosted, monkeypatch, caplog):
    sentinel = "SYNTHETIC_PRIVATE_SENTINEL"
    bodies = {
        "empty": observation([]),
        "positive": observation([{"type": "ai_overview"}]),
        "incomplete": {
            "status_code": 20000,
            "status_message": sentinel,
            "tasks": [{"status_code": 20000}],
        },
        "error": {"status_code": 50000, "status_message": sentinel},
    }
    calls = []

    def terminal(request):
        keyword = json.loads(request.content)[0]["keyword"]
        calls.append((keyword, str(request.url)))
        return httpx.Response(200, json=bodies[keyword])

    install_transport(monkeypatch, terminal)
    data = tools.serp_aio_monitor(list(bodies))["data"]
    assert data["checked"] == 2 and data["with_aio"] == 1
    assert [item["keyword"] for item in data["findings"]] == ["empty", "positive"]
    assert data["errors"] == [
        {"keyword": kw, "error": "vendor_unavailable"} for kw in ("incomplete", "error")
    ]
    assert calls == [
        (kw, "https://api.dataforseo.com/v3/serp/google/organic/live/advanced") for kw in bodies
    ]
    assert sentinel not in json.dumps(data) + caplog.text


def test_legacy_summary_keeps_historical_missing_result_semantics(monkeypatch):
    monkeypatch.delenv("GOOGLE_SEO_PROFILE", raising=False)
    monkeypatch.setattr(auth, "_hosted_auth_enabled", False)
    data = tools._summarise_serp({"status_message": "legacy status"}, keyword="offline test")
    assert data["raw_status"] == "legacy status" and data["has_aio"] is False
    assert data["organic"] == data["paa"] == []


@pytest.mark.parametrize(
    "level,field,value",
    [
        ("response", "status_code", 20000.0),
        ("task", "status_code", 20000.0),
        ("response", "tasks_count", 0),
        ("response", "tasks_count", True),
        ("response", "tasks_error", 1),
        ("task", "result_count", 0),
        ("result", "items_count", 1),
        ("result", "items_count", None),
    ],
)
def test_contradictory_envelope_cannot_qualify_empty(hosted, monkeypatch, level, field, value):
    body = observation([])
    records = {"response": body, "task": body["tasks"][0], "result": body["tasks"][0]["result"][0]}
    records[level][field] = value
    calls = []

    def terminal(request):
        calls.append(str(request.url))
        return httpx.Response(200, json=body)

    install_transport(monkeypatch, terminal)
    with pytest.raises(RuntimeError, match="^vendor_unavailable$"):
        tools.serp_check("offline test")
    with pytest.raises(RuntimeError, match="^vendor_unavailable$"):
        tools._summarise_serp(body, keyword="offline test")
    assert len(calls) == 1


def test_coherent_explicit_counts_and_empty_nested_collections(hosted, monkeypatch):
    body = observation(
        [
            {"type": "people_also_ask", "items": []},
            {"type": "ai_overview", "references": []},
            {"type": "related_searches", "items": []},
        ]
    )
    body.update(tasks_count=1, tasks_error=0)
    body["tasks"][0]["result_count"] = 1
    body["tasks"][0]["result"][0]["items_count"] = 3
    install_transport(monkeypatch, lambda request: httpx.Response(200, json=body))
    data = tools.serp_check("offline test")["data"]
    assert data["raw_status"] == "ok" and data["has_aio"] is True
    assert data["paa"] == data["related_searches"] == data["aio_sources"] == []
