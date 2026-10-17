"""Synthetic offline tool contracts, real client/normalizer and HTTPX transport.

The golden inventory/fixtures are independent of tools/client routing tables.
Only custody and HTTP transport are replaced; no provider captures or live keys.
"""

import inspect
import json
import os
import socket
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest

from google_seo_mcp.bing import client as boundary
from google_seo_mcp.bing import tools
from google_seo_mcp.bing.auth import BingAuthError, configure_bing_auth
from google_seo_mcp.bing.client import BingReadClient
from google_seo_mcp.bing.models import BingCredentialDocument, BingOperation, BingReadResult
from google_seo_mcp.runtime_config import ProductionRuntimeConfig

SITE = "https://kelleyconstructioninc.com/"
KEY = 'synthetic-tools+/"é-8271'
DATE = "/Date(1704067200000-0700)/"
QUERY = dict(Date=DATE, Clicks=2, Impressions=8, Query="steel & concrete café",
             AvgClickPosition=18, AvgImpressionPosition=17)
FEED = dict(Compressed=False, FileSize=42, LastCrawled=DATE, Submitted=DATE,
            Status="Success", Type="Sitemap", Url=SITE + "sitemap.xml", UrlCount=2)
CRAWL = {name: 2 for name in (
    "AllOtherCodes", "BlockedByRobotsTxt", "Code2xx", "Code301", "Code302", "Code4xx", "Code5xx",
    "ConnectionTimeout", "ContainsMalware", "CrawledPages", "CrawlErrors", "DnsFailures",
    "InIndex", "InLinks",
)}
CRAWL["Date"] = DATE
URL = dict(AnchorCount=1, DiscoveryDate=DATE, DocumentSize=123, HttpStatus=200, IsPage=True,
           LastCrawledDate=DATE, TotalChildUrlCount=3, Url=SITE + "page")
# name, exact upstream method, tool selectors, provider selectors, wire data, record kind, cadence
CASES = [
    ("bing_list_sites", "GetUserSites", {}, {},
     [{"Url": SITE, "IsVerified": True, "AuthenticationCode": "discard-code",
       "DnsVerificationCode": "discard-code"}, {"Url": SITE, "IsVerified": False},
      {"Url": "https://other.com/", "IsVerified": True}], "site", "unknown"),
    ("bing_rank_traffic_stats", "GetRankAndTrafficStats", {}, {},
     [dict(Date=DATE, Clicks=2, Impressions=8)], "traffic", "daily"),
    ("bing_query_stats", "GetQueryStats", {}, {}, [QUERY], "query", "weekly"),
    ("bing_page_stats", "GetPageStats", {}, {}, [QUERY], "query", "weekly"),
    ("bing_page_query_stats", "GetPageQueryStats", {"page_url": SITE + "page?a=1&b=é"},
     {"page": SITE + "page?a=1&b=é"}, [QUERY], "query", "weekly"),
    ("bing_query_page_stats", "GetQueryPageStats", {"query": "steel & concrete café"},
     {"query": "steel & concrete café"}, [QUERY], "query", "weekly"),
    ("bing_crawl_stats", "GetCrawlStats", {}, {}, [CRAWL], "crawl", "daily"),
    ("bing_crawl_issues", "GetCrawlIssues", {}, {},
     [dict(HttpCode=404, InLinks=2, Issues=1029, Url=SITE)], "crawl_issue", "unknown"),
    ("bing_url_info", "GetUrlInfo", {"url": SITE + "page"}, {"url": SITE + "page"},
     URL, "url_info", "unknown"),
    ("bing_list_sitemaps", "GetFeeds", {}, {}, [FEED], "feed", "unknown"),
    ("bing_sitemap_details", "GetFeedDetails", {"sitemap_url": SITE + "sitemap.xml"},
     {"feedUrl": SITE + "sitemap.xml"}, [FEED], "feed", "unknown"),
]


class Loader:
    def __init__(self, fail=None):
        self.loads = 0
        self.fail = fail

    def load(self):
        self.loads += 1
        if self.fail:
            raise BingAuthError(self.fail)
        return BingCredentialDocument(version=1, api_key=KEY)

    @property
    def allowed_sites(self):
        return frozenset({SITE})

    def authorize_site(self, site):
        if site != SITE:
            raise BingAuthError("site_denied")


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def deny(*args, **kwargs):
        pytest.fail("unexpected real network")
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(boundary, "_GLOBAL", boundary._Admission())
    tools.configure_bing_tools()
    yield
    tools.configure_bing_tools()
    configure_bing_auth(None)


def inject(payload, *, status=200, loader=None):
    seen = []
    loader = loader or Loader()

    def upstream(request):
        seen.append(request)
        return httpx.Response(status, json=payload)

    tools.configure_bing_tools(BingReadClient(
        loader, transport=httpx.MockTransport(upstream), max_retries=0,
    ))
    return seen, loader


def call(case, **extra):
    name, op, selectors, *_ = case
    inputs = {} if op == "GetUserSites" else {"site_url": SITE}
    return getattr(tools, name)(**(inputs | selectors | extra))


def assert_meta(result, cadence):
    data, meta = result["data"], result["_meta"]
    assert set(result) == {"data", "_meta"}
    assert meta["source"] == data["source"] == "bing_webmaster"
    assert meta["provider_cadence"] == data["provider_cadence"] == cadence
    for name in ("operation", "status", "extracted_at", "requested_period", "observed_period",
                 "source_rows", "returned_rows", "dropped_rows", "local_truncated",
                 "provider_completeness", "position_scale", "warnings"):
        assert meta[name] == data[name]
    assert meta["provider_completeness"] == "unknown"
    assert datetime.fromisoformat(meta["fetched_at"].replace("Z", "+00:00")).utcoffset() is not None
    if data["site_url"] is not None:
        assert meta["site_url"] == data["site_url"]
    if data["requested_period"] is not None:
        assert meta["period"] == data["requested_period"]
    # Exercises the genuine typed result roundtrip, not an arbitrary dict fixture.
    BingReadResult.model_validate_json(json.dumps(data))
    return data


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_every_candidate_hits_exact_read_method(case):
    name, op, selectors, params, wire, kind, cadence = case
    seen, _ = inject({"d": wire})
    extra = (
        {"start_date": "2024-01-01", "end_date": "2024-01-02", "limit": 1}
        if cadence != "unknown" else {}
    )
    data = assert_meta(call(case, **extra), cadence)
    assert data["operation"] == op and data["status"] == "ok"
    assert data["returned_rows"] == 1 and data["records"][0]["kind"] == kind
    assert len(seen) == 1  # no discovery, fan-out, paging, selector enrichment or retries
    sent = seen[0]
    assert sent.method == "GET" and not sent.content
    assert sent.url.scheme == "https" and sent.url.host == "ssl.bing.com"
    assert sent.url.port in (None, 443)
    assert sent.url.path == "/webmaster/api.svc/json/" + op
    assert dict(sent.url.params) == {
        "apikey": KEY, **({} if op == "GetUserSites" else {"siteUrl": SITE}), **params,
    }
    assert sent.headers["Content-Type"] == "application/json; charset=utf-8"
    rendered = json.dumps(data)
    assert "discard-code" not in rendered and "AuthenticationCode" not in rendered
    assert "DnsVerificationCode" not in rendered and KEY not in rendered
    row = data["records"][0]
    assert "indexed" not in row and "total_clicks" not in data
    if cadence != "unknown":
        assert row["date"] == DATE and row["date_utc"].startswith("2024-01-01T00:00:00")
    if kind == "query":
        assert row["avg_click_position"] == 18 and row["avg_impression_position"] == 17
        assert row["average_position"] is None and row["position_scale"] == "undocumented"
        assert row["query"] == QUERY["Query"] and row["ctr"] == 0.25
        assert row["page_url"] == selectors.get("page_url")
        assert row["selector_query"] == selectors.get("query")
        assert "raw_query_identity" in data["warnings"]
    if kind == "crawl_issue":
        assert row["issues"] == 1029 and row["unknown_bits"] == 1024
        assert row["known_issues"] == ["Code301", "Code4xx"]


def test_exact_exports_and_typed_signatures():
    expected_names = [c[0] for c in CASES]
    assert set(tools.__all__) == set(expected_names) and len(tools.__all__) == 11
    assert sorted(n for n in vars(tools) if n.startswith("bing_")) == sorted(expected_names)
    for name, op, selectors, _, _, _, cadence in CASES:
        expected = [] if op == "GetUserSites" else ["site_url"]
        expected += list(selectors)
        if cadence != "unknown":
            expected += ["start_date", "end_date", "limit"]
        elif op not in ("GetUserSites", "GetUrlInfo"):
            expected += ["limit"]
        sig = inspect.signature(getattr(tools, name))
        assert list(sig.parameters) == expected
        assert sig.return_annotation is dict
        for param in sig.parameters.values():
            assert param.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD
            if param.name == "limit":
                assert param.annotation is int and param.default == 100
            elif param.name in ("start_date", "end_date"):
                assert param.annotation == str | None and param.default is None
            else:
                assert param.annotation is str and param.default is inspect.Parameter.empty


@pytest.mark.parametrize("query", [None, "", "x" * 513, True, 1, "bad\x00query", "\ud800"])
def test_query_page_requires_query(query):
    seen, loader = inject({"d": []})
    with pytest.raises(RuntimeError, match="^invalid_request$"):
        tools.bing_query_page_stats(SITE, query)
    assert not seen and loader.loads == 0


def test_omitted_query_and_unsupported_arguments_fail_pre_io():
    seen, loader = inject({"d": []})
    with pytest.raises(TypeError):
        tools.bing_query_page_stats(SITE)
    for case in CASES:
        with pytest.raises(TypeError):
            call(case, country="US")
    assert not seen and loader.loads == 0


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_explicit_empty_not_zero_business_claim(case):
    seen, _ = inject({"d": []})
    data = assert_meta(call(case), case[-1])
    assert data["status"] == ("provider_error" if case[1] == "GetUrlInfo" else "empty")
    assert data["records"] == [] and data["returned_rows"] == 0
    assert data["observed_period"] is None and not data["local_truncated"]
    assert not {"clicks", "impressions", "indexed", "total", "average_position"} & data.keys()
    assert len(seen) == 1


@pytest.mark.parametrize("overrides", [
    {"site_url": "http://127.0.0.1/"}, {"site_url": "https://user:password@host.com/"},
    {"site_url": "https://host.local/"}, {"site_url": "domain:bing.com"},
    {"site_url": "\ud800"}, {"site_url": True},
    {"start_date": "2024-01-01"}, {"end_date": "2024-01-01"},
    {"start_date": "2024-02-30", "end_date": "2024-03-01"},
    {"start_date": "2024-02-01", "end_date": "2024-01-01"},
    {"start_date": "2024-01-01", "end_date": "2025-01-02"},
    {"start_date": True, "end_date": "2024-01-01"},
    {"limit": True}, {"limit": False}, {"limit": "1"}, {"limit": 1.0},
    {"limit": 0}, {"limit": 1001},
])
def test_invalid_site_url_window_fails_pre_io(overrides):
    seen, loader = inject({"d": []})
    with pytest.raises(RuntimeError, match="^invalid_request$") as exc:
        tools.bing_query_stats(**({"site_url": SITE} | overrides))
    assert not seen and loader.loads == 0
    assert exc.value.__cause__ is None
    assert not hasattr(exc.value, "errors")


@pytest.mark.parametrize("name,field", [
    ("bing_page_query_stats", "page_url"), ("bing_url_info", "url"),
    ("bing_sitemap_details", "sitemap_url"),
])
@pytest.mark.parametrize("selector", [
    "https://other.com/page", "http://kelleyconstructioninc.com/page", "domain:bing.com",
    SITE + "page#frag", SITE + "../outside", SITE + "%252e%252e/outside",
    "http://10.0.0.1/", SITE + "x" * 2048, "\ud800", True,
])
def test_selector_denials_use_actual_request_fields(name, field, selector):
    seen, loader = inject({"d": []})
    with pytest.raises(RuntimeError, match="^invalid_request$"):
        getattr(tools, name)(SITE, **{field: selector})
    assert not seen and loader.loads == 0


@pytest.mark.parametrize("case", [c for c in CASES if c[1] not in ("GetUserSites", "GetUrlInfo")])
@pytest.mark.parametrize("limit", [True, False, "2", 2.0])
def test_every_limit_rejects_bool_and_coercion(case, limit):
    seen, loader = inject({"d": []})
    with pytest.raises(RuntimeError, match="^invalid_request$"):
        call(case, limit=limit)
    assert not seen and loader.loads == 0


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("fault", ["credentials_missing", "credentials_invalid"])
def test_unavailable_provider_never_silent_success(case, fault):
    seen, _ = inject({"d": []}, loader=Loader(fault))
    data = assert_meta(call(case), case[-1])
    assert data["status"] == "unavailable" and data["records"] == []
    assert data["error"]["code"] == (
        "provider_not_configured" if fault == "credentials_missing" else fault
    )
    assert not seen


def test_default_lazy_client_missing_optional_config(tmp_path):
    config = ProductionRuntimeConfig(bing_credentials_file=tmp_path / "absent-key.json",
                           bing_sites_file=tmp_path / "absent-sites.json")
    configure_bing_auth(config)
    assert tools._client is None
    data = assert_meta(tools.bing_query_stats(SITE, "2024-01-01", "2024-01-02"), "weekly")
    assert data["status"] == "unavailable" and data["error"]["code"] == "provider_not_configured"
    assert data["requested_period"] is None
    assert data["observed_period"] is None
    assert data["site_url"] == ""


@pytest.mark.parametrize("payload,status,expected", [
    ({}, 200, "invalid_response"), ({"d": None}, 200, "invalid_response"),
    ({"d": 0}, 200, "invalid_response"), ({"d": {}}, 200, "invalid_response"),
    ({"ErrorCode": "InvalidApiKey", "Message": "untrusted input"}, 400, "provider_error"),
    ({"ErrorCode": 2, "Message": "untrusted input"}, 200, "provider_error"),
    ({"Message": "untrusted input"}, 403, "access_denied"),
])
def test_faults_are_not_empty_and_keep_analytics_metadata(payload, status, expected):
    seen, _ = inject(payload, status=status)
    data = assert_meta(tools.bing_query_stats(SITE, "2024-01-01", "2024-01-02"), "weekly")
    assert data["status"] in ("provider_error", "denied")
    assert data["error"]["code"] == expected and data["records"] == []
    assert "untrusted input" not in json.dumps(data) and len(seen) == 1


def test_local_window_limit_and_partial_disclosures():
    seen, _ = inject({"d": [QUERY, QUERY, {**QUERY, "Date": "/Date(1704672000000)/"},
                           {**QUERY, "Clicks": True}]})
    data = assert_meta(tools.bing_query_stats(SITE, "2024-01-01", "2024-01-02", 1), "weekly")
    assert data["status"] == "partial" and data["local_truncated"]
    assert data["source_rows"] == 4 and data["returned_rows"] == data["dropped_rows"] == 1
    assert data["observed_period"] == {"start_date": "2024-01-01", "end_date": "2024-01-08"}
    assert {"weekly_buckets", "local_date_filter", "utc_date_filter", "local_limit",
            "invalid_rows_dropped", "window_not_exact"} <= set(data["warnings"])
    assert len(seen) == 1
    seen, _ = inject({"d": [QUERY]})
    data = assert_meta(tools.bing_query_stats(SITE, "2025-01-01", "2025-01-02"), "weekly")
    assert data["status"] == "empty" and data["source_rows"] == 1
    assert data["observed_period"]["start_date"] == "2024-01-01"
    assert len(seen) == 1


@pytest.mark.parametrize("row", [
    {**QUERY, "Clicks": True}, {**QUERY, "Clicks": 9}, {**QUERY, "Clicks": None},
    {k: v for k, v in QUERY.items() if k != "Clicks"}, {**QUERY, "Date": "bad-date"},
])
def test_invalid_source_never_manufactures_zero(row):
    inject({"d": [row]})
    data = assert_meta(tools.bing_query_stats(SITE), "weekly")
    assert data["status"] == "provider_error" and data["records"] == []
    assert data["source_rows"] == data["dropped_rows"] == 1


def test_true_zero_denominator_is_null_not_invented_ctr():
    inject({"d": [{**QUERY, "Clicks": 0, "Impressions": 0}]})
    row = tools.bing_query_stats(SITE)["data"]["records"][0]
    assert row["clicks"] == row["impressions"] == 0 and row["ctr"] is None


@pytest.mark.parametrize("reflection", [KEY, quote(KEY, safe=""),
                                          "".join(f"\\u{ord(c):04x}" for c in KEY)])
def test_real_client_reflection_never_reintroduced_in_metadata(reflection, caplog):
    # Reflection even in discarded unknown metadata must fail, not serialize.
    inject({"d": [QUERY], "unknown": {"nested": reflection}})
    result = tools.bing_query_stats(SITE)
    data = assert_meta(result, "weekly")
    assert data["status"] == "provider_error" and data["error"]["code"] == "credential_reflection"
    assert data["site_url"] == "" and result["_meta"]["site_url"] == ""
    assert KEY not in json.dumps(result) and reflection not in json.dumps(result)
    assert not caplog.records


def test_request_selector_reflection_does_not_echo_outside_client():
    seen, _ = inject({"d": [QUERY]})
    result = tools.bing_query_page_stats(SITE, KEY)
    assert result["data"]["error"]["code"] == "credential_reflection"
    assert not seen and KEY not in json.dumps(result)


@pytest.mark.parametrize("bad", [
    {"records": [{"secret": "never-emit"}]}, object(),
    BingReadResult.model_construct(status="empty", operation=BingOperation.GET_QUERY_STATS,
                                   site_url=SITE, extracted_at=datetime.now(UTC),
                                   records=[{"kind": "query", "query": "never-emit"}]),
    BingReadResult.model_construct(status="empty", operation=BingOperation.GET_QUERY_STATS,
                                   site_url=SITE, extracted_at="never-emit"),
    BingReadResult(status="empty", operation=BingOperation.GET_PAGE_STATS,
                   site_url=SITE, extracted_at=datetime.now(UTC)),
])
def test_injected_interface_must_return_true_valid_typed_result(bad, caplog):
    class Broken:
        def read(self, operation, request):
            return bad
    tools.configure_bing_tools(Broken())
    with pytest.raises(RuntimeError, match="^provider_error$") as exc:
        tools.bing_query_stats(SITE)
    assert exc.value.__cause__ is None and not caplog.records


def test_foreign_client_exceptions_are_static(caplog):
    class Broken:
        def read(self, operation, request):
            raise ValueError("never-emit-secret")
    tools.configure_bing_tools(Broken())
    with pytest.raises(RuntimeError, match="^provider_error$") as exc:
        tools.bing_query_stats(SITE)
    assert exc.value.__cause__ is None and not caplog.records


@pytest.mark.parametrize("case", [c for c in CASES if c[-1] != "unknown"])
@pytest.mark.parametrize("outcome", ["empty", "partial", "denied", "provider_error", "unavailable"])
def test_every_analytics_outcome_keeps_requested_and_observed_contract(case, outcome):
    row = case[4][0]
    payload, status, loader = {"d": []}, 200, Loader()
    if outcome == "partial":
        payload = {"d": [row, {}]}
    elif outcome == "provider_error":
        payload = {"d": None}
    elif outcome == "denied":
        status = 403
        payload = {"Message": "never-emit"}
    elif outcome == "unavailable":
        loader = Loader("credentials_missing")
    seen, _ = inject(payload, status=status, loader=loader)
    data = assert_meta(call(case, start_date="2024-01-01", end_date="2024-01-02"), case[-1])
    assert data["status"] == outcome
    if outcome in ("denied", "provider_error", "unavailable"):
        assert data["requested_period"] is None
        assert data["site_url"] == ""
    else:
        assert data["requested_period"] == {"start_date": "2024-01-01", "end_date": "2024-01-02"}
    assert data["observed_period"] == (
        {"start_date": "2024-01-01", "end_date": "2024-01-01"} if outcome == "partial" else None
    )
    assert len(seen) == (0 if outcome == "unavailable" else 1)


def test_unapproved_public_site_is_denial_without_hidden_discovery():
    seen, loader = inject({"d": [QUERY]})
    data = assert_meta(tools.bing_query_stats("https://other.com/"), "weekly")
    assert data["status"] == "denied" and data["error"]["code"] == "site_denied"
    assert loader.loads == 1 and not seen


@pytest.mark.parametrize("limit", [1, 1000])
def test_inclusive_window_and_limit_boundaries_are_local(limit):
    seen, _ = inject({"d": [QUERY]})
    data = assert_meta(tools.bing_query_stats(SITE, "2024-01-01", "2025-01-01", limit), "weekly")
    assert data["status"] == "ok" and len(seen) == 1
    assert set(seen[0].url.params) == {"apikey", "siteUrl"}


def test_import_and_composition_are_lazy_no_client_or_credential_work():
    # Fresh interpreter: forbid file opens/network after imports of stdlib;
    # audit the tooling import specifically for default-client/auth loading.
    script = '''
import socket, sys
from pathlib import Path
socket.getaddrinfo = lambda *a, **k: (_ for _ in ()).throw(AssertionError("DNS"))
from google_seo_mcp.bing import tools
assert "google_seo_mcp.bing.client" not in sys.modules
assert "google_seo_mcp.bing.auth" not in sys.modules
assert tools._client is None
Path.open = lambda *a, **k: (_ for _ in ()).throw(AssertionError("credential read"))
tools.configure_bing_tools()
try:
    tools.bing_query_stats("invalid")
except RuntimeError as exc:
    assert str(exc) == "invalid_request"
else:
    raise AssertionError("validation missing")
assert "google_seo_mcp.bing.client" not in sys.modules
assert tools._client is None
'''
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(tools.__file__).resolve().parents[2])
    result = subprocess.run([sys.executable, "-c", script], env=env,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


def default_transport(monkeypatch, case, failure=None):
    """Replace custody and lowest HTTPX transport, NOT the default Bing client.

    A retry would receive valid data, exposing both an extra dispatch and a
    wrongly successful outcome. All fixtures are synthetic and network-free.
    """
    seen, constructed = [], []
    loader = Loader()

    def upstream(request):
        seen.append(request)
        if len(seen) == 1 and failure is not None:
            if failure == "connect_error":
                raise httpx.ConnectError("synthetic connect failure", request=request)
            if failure == "connect_timeout":
                raise httpx.ConnectTimeout("synthetic connect timeout", request=request)
            return httpx.Response(failure, json={"d": []}, headers={"Retry-After": "0"})
        return httpx.Response(200, json={"d": case[4]})

    def transport(**kwargs):
        constructed.append(kwargs)
        return httpx.MockTransport(upstream)

    monkeypatch.setattr(boundary, "BingCredentialLoader", lambda: loader)
    monkeypatch.setattr(boundary.httpx, "HTTPTransport", transport)
    assert tools._client is None
    return seen, constructed, loader


def assert_default_dispatch(case, seen, constructed, loader):
    # This is the actual lazy constructor, real read/admission/retry loop,
    # real HTTPX Client and gated transport, not a constructor-call mock.
    assert type(tools._client) is BingReadClient
    assert tools._client._max_retries == 0
    assert tools._client._transport is None
    assert loader.loads == 2  # initial admission plus the single attempt
    assert constructed == [{"trust_env": False}]
    assert len(seen) == 1
    sent = seen[0]
    assert sent.method == "GET" and not sent.content
    assert sent.url.scheme == "https" and sent.url.host == "ssl.bing.com"
    assert sent.url.port in (None, 443)
    assert sent.url.path == "/webmaster/api.svc/json/" + case[1]
    assert dict(sent.url.params) == {
        "apikey": KEY, **({} if case[1] == "GetUserSites" else {"siteUrl": SITE}), **case[3],
    }


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("failure", [429, 502, 503, 504, "connect_error", "connect_timeout"])
def test_default_real_client_retryable_failure_is_one_transport_attempt(monkeypatch, case, failure):
    seen, constructed, loader = default_transport(monkeypatch, case, failure)
    data = assert_meta(call(case), case[-1])
    assert data["status"] == "provider_error" and data["records"] == []
    assert data["error"]["code"] == (
        "rate_limited" if failure == 429 else
        "transport_error" if isinstance(failure, str) else "provider_error"
    )
    assert_default_dispatch(case, seen, constructed, loader)


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_default_real_client_positive_effect_without_extra_discovery(monkeypatch, case):
    seen, constructed, loader = default_transport(monkeypatch, case)
    data = assert_meta(call(case), case[-1])
    assert data["status"] == "ok" and data["operation"] == case[1]
    assert data["returned_rows"] == 1 and data["records"][0]["kind"] == case[5]
    assert_default_dispatch(case, seen, constructed, loader)


def test_injected_reusable_client_retains_explicit_retry_behavior():
    seen = []

    def upstream(request):
        seen.append(request)
        return httpx.Response(503 if len(seen) == 1 else 200,
                              json={"d": [QUERY]}, headers={"Retry-After": "0"})

    client = BingReadClient(Loader(), transport=httpx.MockTransport(upstream),
                            max_retries=1, sleep=lambda _: None)
    tools.configure_bing_tools(client)
    data = assert_meta(tools.bing_query_stats(SITE), "weekly")
    assert tools._client is client and client._max_retries == 1
    assert data["status"] == "ok" and data["returned_rows"] == 1
    assert len(seen) == 2
    assert all(request.url.path.endswith("/GetQueryStats") for request in seen)
