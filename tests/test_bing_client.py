"""Synthetic offline contracts: real client/HTTPX/schema/normalizer, no Bing.

Independent route/shape fixtures derive from the accepted Microsoft inventory,
not the implementation mapping. No provider captures or real credentials.
"""

import gzip
import json
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.parse import quote

import httpx
import pytest

from google_seo_mcp.bing import client as boundary
from google_seo_mcp.bing.auth import BingAuthError, BingCredentialLoader, configure_bing_auth
from google_seo_mcp.bing.client import BingClientError, BingReadClient
from google_seo_mcp.bing.models import BingCredentialDocument, BingOperation, BingToolRequest

SITE = "https://kelleyconstructioninc.com/"
KEY = 'synthetic-key+/"é-9372'
DATE = "/Date(1704067200000-0700)/"
QUERY = dict(Date=DATE, Clicks=2, Impressions=8, Query="steel & concrete café",
             AvgClickPosition=18, AvgImpressionPosition=17)
FEED = dict(Compressed=False, FileSize=42, LastCrawled=DATE, Status="Success",
            Submitted=DATE, Type="Sitemap", Url=SITE + "sitemap.xml", UrlCount=2)
CRAWL = dict.fromkeys(("AllOtherCodes", "BlockedByRobotsTxt", "Code2xx", "Code301", "Code302",
                       "Code4xx", "Code5xx", "ConnectionTimeout", "ContainsMalware",
                       "CrawledPages", "CrawlErrors", "DnsFailures", "InIndex", "InLinks"), 2)
CRAWL["Date"] = DATE
URL = dict(AnchorCount=1, DiscoveryDate=DATE, DocumentSize=123, HttpStatus=200, IsPage=True,
           LastCrawledDate=DATE, TotalChildUrlCount=3, Url=SITE + "page")
CASES = [
    ("GetUserSites", {}, {}, [{"Url": SITE, "IsVerified": True,
                               "AuthenticationCode": "discard", "DnsVerificationCode": "discard"}],
     "site"),
    ("GetRankAndTrafficStats", {}, {}, [dict(Date=DATE, Clicks=2, Impressions=8)], "traffic"),
    ("GetQueryStats", {}, {}, [QUERY], "query"),
    ("GetPageStats", {}, {}, [QUERY], "query"),
    ("GetPageQueryStats", {"page_url": SITE + "page?a=1&b=é"},
     {"page": SITE + "page?a=1&b=é"}, [QUERY], "query"),
    ("GetQueryPageStats", {"query": "steel & concrete café"},
     {"query": "steel & concrete café"}, [QUERY], "query"),
    ("GetCrawlStats", {}, {}, [CRAWL], "crawl"),
    ("GetCrawlIssues", {}, {}, [dict(HttpCode=404, InLinks=2, Issues=1029, Url=SITE)],
     "crawl_issue"),
    ("GetUrlInfo", {"url": SITE + "page"}, {"url": SITE + "page"}, URL, "url_info"),
    ("GetFeeds", {}, {}, [FEED], "feed"),
    ("GetFeedDetails", {"sitemap_url": SITE + "sitemap.xml"},
     {"feedUrl": SITE + "sitemap.xml"}, [FEED], "feed"),
]


class Loader(BingCredentialLoader):
    """Count calls while inheriting real key-only generation/custody admission."""
    def __init__(self):
        super().__init__()
        self.loads = 0
        self.fail = None
        self.actual = self

    def load(self):
        self.loads += 1
        if self.fail:
            raise BingAuthError(self.fail)
        return super().load()


class Clock:
    def __init__(self):
        self.value = 0.0
        self.sleeps = []

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    # Synthetic protected custody; no real credentials or provider network.
    tmp_path.chmod(0o700)
    key = tmp_path / "key.json"
    key.write_text(json.dumps({"version": 1, "api_key": KEY}))
    key.chmod(0o600)
    configure_bing_auth(SimpleNamespace(bing_credentials_file=key))
    attempts = []
    def deny(*args, **kwargs):
        attempts.append(True)
        raise RuntimeError("forbidden_network")
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(boundary, "_GLOBAL", boundary._Admission())
    yield
    assert attempts == []


def request(op="GetQueryStats", **kwargs):
    return BingToolRequest(operation=BingOperation(op),
                           **({} if op == "GetUserSites" else {"site_url": SITE}), **kwargs)


def make(payload=None, *, status=200, handler=None, loader=None, clock=None,
         discovery=True, **kwargs):
    seen = []
    def upstream(req):
        seen.append(req)
        if discovery and req.url.path.endswith("/GetUserSites"):
            return httpx.Response(200, json={"d": [{"Url": SITE, "IsVerified": True}]})
        return handler(req) if handler else httpx.Response(status, json=payload)
    clock = clock or Clock()
    return (BingReadClient(loader or Loader(), transport=httpx.MockTransport(upstream),
                           clock=clock, **kwargs), seen)


@pytest.mark.parametrize("op,inputs,params,rows,kind", CASES)
def test_exact_get_operation_params(op, inputs, params, rows, kind):
    client, seen = make({"d": rows})
    req = request(op, **inputs)
    result = client.read(BingOperation(op), req)
    assert result.status == "ok"
    assert [row.kind for row in result.records] == [kind]
    assert len(seen) == (1 if op == "GetUserSites" else 2)
    if op != "GetUserSites":
        assert seen[0].url.path.endswith("/GetUserSites")
        assert set(seen[0].url.params) == {"apikey"}
    sent = seen[-1]
    assert sent.method == "GET"
    assert sent.url.scheme == "https" and sent.url.host == "ssl.bing.com"
    assert sent.url.port in (None, 443)
    assert sent.url.path == "/webmaster/api.svc/json/" + op
    expected = {"apikey": KEY, **({} if op == "GetUserSites" else {"siteUrl": SITE}), **params}
    assert dict(sent.url.params) == expected
    assert sent.content == b""
    assert sent.headers["Content-Type"] == "application/json; charset=utf-8"
    serialized = result.model_dump_json()
    assert "discard" not in serialized and "AuthenticationCode" not in serialized
    assert KEY not in serialized
    if kind == "query":
        assert result.records[0].average_position is None
        assert result.records[0].avg_click_position == 18
        assert result.provider_cadence == "weekly"
    if kind in ("traffic", "crawl"):
        assert result.provider_cadence == "daily"


@pytest.mark.parametrize("op,inputs,params,rows,kind", CASES)
def test_every_operation_empty_vs_null(op, inputs, params, rows, kind):
    client, _ = make({"d": []}, discovery=(op != "GetUserSites"))
    result = client.read(BingOperation(op), request(op, **inputs))
    assert result.status == ("provider_error" if kind == "url_info" else "empty")
    client, _ = make({"d": None}, discovery=(op != "GetUserSites"))
    result = client.read(BingOperation(op), request(op, **inputs))
    assert result.status == "provider_error"


@pytest.mark.parametrize("payload", [{}, {"d": None}, {"d": ""}, {"d": 0}, {"d": True},
                                     {"d": {}}, [], None, {"d": [{"Clicks": 1}]}])
def test_d_empty_distinct_from_null_fault_malformed(payload):
    client, seen = make(payload)
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.status == "provider_error"
    assert result.error.code == "invalid_response"
    assert len(seen) == 2
    assert result.provider_cadence == "weekly"
    assert result.provider_completeness == "unknown"


@pytest.mark.parametrize("value", [True, False, -1, "2", 1.5, None, float("inf"), float("nan")])
def test_malformed_numeric_never_zero_or_empty(value):
    client, _ = make({"d": [{**QUERY, "Clicks": value}]})
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.status == "provider_error"
    # Non-standard JSON constants invalidate the whole envelope.
    if value not in (float("inf"),) and not (isinstance(value, float) and value != value):
        assert result.source_rows == result.dropped_rows == 1


@pytest.mark.parametrize("status,payload", [
    (400, {"ErrorCode": "InvalidApiKey", "Message": "foreign untrusted text"}),
    (200, {"ErrorCode": 2, "Message": "foreign untrusted text"}),
    (200, {"d": {"ErrorCode": "InvalidApiKey", "Message": "foreign untrusted text"}}),
    (401, {"ErrorCode": 98765, "Message": "foreign untrusted text"}),
    (403, {"d": []}),
])
def test_http400_invalid_api_key_and_http200_faults(status, payload):
    client, seen = make(payload, status=status)
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.status == ("denied" if status in (401, 403) else "provider_error")
    assert result.error.code == ("access_denied" if status in (401, 403) else "provider_error")
    assert "foreign" not in result.model_dump_json()
    assert len(seen) == 2  # no undocumented ErrorCode semantics, no auth retry


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_never_follow(status):
    client, seen = make(handler=lambda req: httpx.Response(
        status, headers={"Location": "https://attacker.net/?apikey=" + quote(KEY)}))
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.error.code == "credential_reflection" and len(seen) == 2


@pytest.mark.parametrize("status", [429, 502, 503, 504])
@pytest.mark.parametrize("after,expected", [("999999", 5.0), ("0", 0.0), ("garbage", 0.5)])
def test_retry_after_budget_and_deadline(status, after, expected):
    clock = Clock()
    client, seen = make(handler=lambda req: httpx.Response(status, headers={"Retry-After": after}),
                        clock=clock)
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert len(seen) == 2 and clock.sleeps == []
    assert result.error.code == ("rate_limited" if status == 429 else "provider_error")


@pytest.mark.parametrize("error,retries,code", [
    (httpx.ConnectError, 2, "transport_error"), (httpx.ConnectTimeout, 2, "timeout"),
    (httpx.ReadTimeout, 2, "timeout"), (httpx.ReadError, 2, "transport_error"),
    (httpx.RemoteProtocolError, 2, "transport_error"),
])
def test_only_transient_connect_errors_retry(error, retries, code):
    def upstream(req):
        raise error("private " + str(req.url), request=req)
    client, seen = make(handler=upstream)
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.error.code == code and len(seen) == retries
    assert KEY not in result.model_dump_json()


@pytest.mark.parametrize("status", [400, 404, 408, 500, 501])
def test_other_http_failures_never_retry(status):
    client, seen = make({"d": []}, status=status)
    assert client.read(BingOperation.GET_QUERY_STATS, request()).status == "provider_error"
    assert len(seen) == 2


def test_retry_success_and_every_attempt_reauthorizes():
    loader = Loader()
    client, seen = make({"d": [QUERY]}, loader=loader)
    assert client.read(BingOperation.GET_QUERY_STATS, request()).status == "ok"
    assert [r.url.path.rsplit("/", 1)[-1] for r in seen] == ["GetUserSites", "GetQueryStats"]
    # Every transition rechecks actual custody; failure never enters wire.
    loads = loader.loads
    assert loads == 13
    loader.fail = "credentials_invalid"
    assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "credentials_invalid"
    assert loader.loads == loads + 1 and len(seen) == 2


def test_missing_config_precedes_dns_and_client_creation(monkeypatch):
    configure_bing_auth(SimpleNamespace(bing_credentials_file=None, bing_sites_file=None))
    monkeypatch.setattr(httpx, "Client", lambda **kw: pytest.fail("client before config"))
    client = BingReadClient()
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.status == "unavailable" and result.error.code == "provider_not_configured"
    assert result.provider_cadence == "weekly"


def test_default_loader_is_lazy_after_composition():
    client = BingReadClient()
    assert client._loader is None
    configure_bing_auth(SimpleNamespace(bing_credentials_file=None, bing_sites_file=None))
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.error.code == "provider_not_configured"


@pytest.mark.parametrize("mutation", [{"limit": True}, {"url": "https://evil.net/"},
                                      {"start_date": "2024-01-01"},
                                      {"site_url": "http://127.0.0.1/"}])
def test_validated_input_before_any_io(mutation):
    loader = Loader()
    client, seen = make({"d": []}, loader=loader)
    bad = request().model_copy(update=mutation)
    with pytest.raises(BingClientError, match="^invalid_request$") as caught:
        client.read(BingOperation.GET_QUERY_STATS, bad)
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert loader.loads == 0 and not seen


@pytest.mark.parametrize("operation", ["SubmitUrl", "FetchUrl", "../../SubmitUrl", None, 1])
def test_unknown_operations_no_io(operation):
    loader = Loader()
    client, seen = make({"d": []}, loader=loader)
    with pytest.raises(BingClientError, match="^invalid_request$"):
        client.read(operation, request())
    assert not seen and loader.loads == 0


def test_operation_disagreement_and_site_authorization_before_io():
    loader = Loader()
    client, seen = make({"d": []}, loader=loader)
    result = client.read(BingOperation.GET_PAGE_STATS, request())
    assert result.error.code == "invalid_request" and loader.loads == 0
    other = BingToolRequest(operation=BingOperation.GET_QUERY_STATS, site_url="https://bing.com/")
    assert client.read(other.operation, other).error.code == "site_denied"
    assert len(seen) == 1 and seen[0].url.path.endswith("/GetUserSites")


@pytest.mark.parametrize("variant", [KEY, quote(KEY, safe=""), quote(quote(KEY, safe=""), safe=""),
                                     KEY.replace('"', r'\"'),
                                     "".join(rf"\u{ord(c):04x}" for c in KEY)])
@pytest.mark.parametrize("location", ["known", "unknown", "key", "nested", "fault"])
def test_bounded_body_and_raw_decoded_key_reflection(variant, location):
    row = dict(QUERY)
    if location == "known":
        row["Query"] = variant
    elif location == "unknown":
        row["FutureField"] = variant
    elif location == "key":
        row[variant] = "safe"
    else:
        row["FutureField"] = {"nested": [variant]}
    payload = {"d": [row]} if location != "fault" else {"ErrorCode": 2, "Message": variant}
    client, seen = make(payload)
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.error.code == "credential_reflection" and len(seen) == 2
    assert not result.records and KEY not in result.model_dump_json()


class Chunks(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks

    def __iter__(self):
        yield from self.chunks


@pytest.mark.parametrize("compressed", [False, True])
def test_decompressed_stream_body_cap(compressed):
    content = b" " * (2 * 1024 * 1024 + 1)
    def upstream(req):
        data = gzip.compress(content) if compressed else content
        return httpx.Response(200, headers={"Content-Encoding": "gzip"} if compressed else {},
                              stream=Chunks([data[i:i + 1024] for i in range(0, len(data), 1024)]))
    client, seen = make(handler=upstream)
    assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "response_too_large"
    assert len(seen) == 2


def test_partial_all_invalid_and_local_window_limit_preserve_diagnostics():
    client, seen = make({"d": [QUERY, {**QUERY, "Date": "bad"}, {**QUERY, "Clicks": True}, QUERY]})
    req = request(start_date="2024-01-01", end_date="2024-01-02", limit=1)
    result = client.read(req.operation, req)
    assert result.status == "partial"
    assert (result.source_rows, result.returned_rows, result.dropped_rows) == (4, 1, 2)
    assert result.local_truncated and result.provider_cadence == "weekly"
    assert result.requested_period.start_date.isoformat() == "2024-01-01"
    assert result.observed_period.start_date.isoformat() == "2024-01-01"
    assert {"invalid_rows_dropped", "invalid_dates_dropped", "local_limit", "weekly_buckets",
            "window_not_exact", "provider_completeness_unknown"} <= set(result.warnings)
    assert set(seen[-1].url.params) == {"apikey", "siteUrl"}


def test_discovery_only_approved_verified_and_codes_stripped():
    rows = [{"Url": SITE, "IsVerified": True, "AuthenticationCode": "discard-code"},
            {"Url": "https://bing.com/", "IsVerified": False},
            {"Url": "https://new-public.com/", "IsVerified": True},
            {"Url": SITE, "IsVerified": True}]
    client, seen = make({"d": rows}, discovery=False)
    result = client.read(BingOperation.GET_USER_SITES, request("GetUserSites"))
    assert result.status == "ok"
    assert (result.source_rows, result.returned_rows, result.dropped_rows) == (4, 3, 0)
    assert [(r.url, r.is_verified) for r in result.records] == [
        ("https://bing.com/", False), (SITE, True), ("https://new-public.com/", True)]
    assert "discard-code" not in result.model_dump_json()
    assert result.provider_completeness == "unknown" and len(seen) == 1


def test_fixed_httpx_constructor_flags_and_logger_constructor_privacy(monkeypatch, caplog):
    original = httpx.Client
    constructors = []
    def factory(**kwargs):
        constructors.append(kwargs)
        logging.getLogger("arbitrary.constructor").warning("private %s", KEY)
        return original(**kwargs)
    monkeypatch.setattr(httpx, "Client", factory)
    caplog.set_level(logging.DEBUG)
    def upstream(req):
        for name in ("httpx", "httpcore.connection", "custom.provider"):
            logging.getLogger(name).warning("private %s", req.url)
        raise RuntimeError("private " + str(req.url))
    client, _ = make(handler=upstream)
    assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "transport_error"
    assert constructors[0]["trust_env"] is False
    assert constructors[0]["follow_redirects"] is False
    assert 0 < constructors[0]["timeout"] <= 15
    assert not caplog.records
    logging.getLogger("unrelated").warning("ordinary unrelated log")
    assert "ordinary unrelated log" in caplog.text


def test_global_rate_budget_includes_retries_and_new_instances():
    sends = []
    for _ in range(6):
        client, seen = make(status=503)
        assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "provider_error"
        sends.extend(r.url.path.rsplit("/", 1)[-1] for r in seen)
    client, seen = make(status=503)
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.error.code == "rate_limited" and seen == []
    assert sends == ["GetUserSites", "GetQueryStats"] * 6
    assert len(boundary._GLOBAL.attempts) == 12


def test_midstream_delay_is_per_attempt_total_not_per_chunk():
    clock = Clock()
    class Slow(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(5):
                clock.value += 4
                yield b" " * 8192
    client, seen = make(handler=lambda req: httpx.Response(200, stream=Slow()), clock=clock)
    assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "timeout"
    assert len(seen) == 2 and clock.value == 16


def test_deadline_includes_retry_sleep_and_stops_second_attempt(monkeypatch):
    # No retry/sleep exists. Discovery and business MUST share the same budget.
    clock = Clock()
    original = boundary._Budget
    class Budget(original):
        def __init__(self, clock):
            super().__init__(clock)
            self.end = clock() + 10
    monkeypatch.setattr(boundary, "_Budget", Budget)
    def upstream(req):
        clock.value += 11
        return httpx.Response(503)
    client, seen = make(handler=upstream, clock=clock, discovery=False)
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.error.code == "timeout" and len(seen) == 1
    assert clock.sleeps == []


def test_concurrency_global_across_instances_and_retries():
    state = {"active": 0, "peak": 0, "count": 0, "business": 0}
    lock = threading.Lock()
    def upstream(req):
        discovery = req.url.path.endswith("/GetUserSites")
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
            state["count"] += 1
            if not discovery:
                state["business"] += 1
            number = state["business"]
        time.sleep(0.005)
        with lock:
            state["active"] -= 1
        return httpx.Response(200 if discovery or number != 1 else 503,
            json={"d": [{"Url": SITE, "IsVerified": True}] if discovery else []})
    clients = [make(handler=upstream, discovery=False)[0] for _ in range(4)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(
            lambda c: c.read(BingOperation.GET_QUERY_STATS, request()), clients))
    assert sorted(r.status for r in results) == ["empty", "empty", "empty", "provider_error"]
    assert state == {"active": 0, "peak": 1, "count": 8, "business": 4}


def test_concurrency_wait_consumes_deadline_and_rechecks_authorization(monkeypatch):
    clock = Clock()
    class Slot:
        def acquire(self, timeout):
            assert 0 < timeout <= 60
            clock.value += 61
            return True
        def release(self):
            pass
    monkeypatch.setattr(boundary._GLOBAL, "slot", Slot())
    client, seen = make({"d": []}, clock=clock)
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.error.code == "timeout" and not seen


def test_stalled_stream_real_watchdog_retains_slot(monkeypatch):
    # First call uses the actual production15s attempt/60s total deadlines.
    # Shorten ONLY the SECOND call's lock-wait deadline, while the first worker
    # remains stalled, to prove returning timeout did not relinquish admission.
    original = boundary._Budget
    class ShortBudget(original):
        def __init__(self, clock):
            super().__init__(clock)
            self.end = clock() + 0.08
            self.real_end = time.monotonic() + 0.08

    release, started, closed = threading.Event(), threading.Event(), threading.Event()
    class Stalled(httpx.SyncByteStream):
        def __iter__(self):
            started.set()
            release.wait(20)
            yield b'{"d": []}'
        def close(self):
            closed.set()
    client, seen = make(handler=lambda req: httpx.Response(200, stream=Stalled()))
    start = time.monotonic()
    try:
        assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "timeout"
        elapsed = time.monotonic() - start
        assert started.is_set() and 14.5 <= elapsed < 17
        monkeypatch.setattr(boundary, "_Budget", ShortBudget)
        other, other_seen = make({"d": []})
        assert other.read(BingOperation.GET_QUERY_STATS, request()).error.code == "timeout"
        assert not other_seen and len(seen) == 2
    finally:
        release.set()
        assert closed.wait(1)
        # Worker must actually relinquish admission before this test finishes.
        assert boundary._GLOBAL.slot.acquire(timeout=1)
        boundary._GLOBAL.slot.release()


@pytest.mark.parametrize("raw", [b'{"d": [], "d": []}', b'{"d": [NaN]}', b'not-json', b'\xff'])
def test_invalid_json_and_duplicates_fail_closed(raw):
    client, _ = make(handler=lambda req: httpx.Response(200, content=raw))
    assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "invalid_response"


@pytest.mark.parametrize("status", ["empty", "error"])
def test_failure_and_filtered_empty_always_have_analytics_diagnostics(status):
    client, _ = make({"d": [QUERY]} if status == "empty" else {"ErrorCode": "unknown"})
    req = request(start_date="2025-01-01", end_date="2025-01-02")
    result = client.read(req.operation, req)
    assert result.status == ("empty" if status == "empty" else "provider_error")
    payload = result.model_dump(mode="json")
    assert {"requested_period", "observed_period", "provider_cadence", "source_rows",
            "returned_rows", "local_truncated", "provider_completeness"} <= payload.keys()
    if status == "empty":
        assert result.requested_period.start_date.isoformat() == "2025-01-01"
    else:
        assert result.requested_period is None  # LA-02: no caller windows on faults.
        assert result.site_url == ""
    assert result.provider_cadence == "weekly"
    assert "weekly_buckets" in result.warnings and "utc_date_filter" in result.warnings


@pytest.mark.parametrize("variant", [
    KEY.replace("é", "&#233;"), KEY.replace("é", "&eacute;"),
    "".join(rf"\x{ord(c):02x}" for c in KEY),
    quote(KEY, safe="").lower(),
])
def test_additional_escaped_reflection_is_closed_error(variant):
    # Lowercase percent-hex only; literal ASCII key letters retain their case.
    client, _ = make({"d": [{**QUERY, "Unknown": {variant: ["ignored"]}}]})
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.error.code == "credential_reflection"


@pytest.mark.parametrize("stage", ["constructor", "stream", "close", "send_hook", "loader"])
def test_direct_exception_paths_never_log_or_expose_foreign_context(
        stage, monkeypatch, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    def fail(*args, **kwargs):
        logging.getLogger("any.private.logger").exception("secret %s", KEY)
        raise RuntimeError("raw-error:" + KEY)
    loader = Loader()
    client, seen = make({"d": []}, loader=loader)
    if stage == "constructor":
        monkeypatch.setattr(httpx, "Client", fail)
    elif stage == "loader":
        loader.load = fail
    elif stage == "send_hook":
        original = httpx.Client
        def factory(**kwargs):
            return original(**kwargs, event_hooks={"request": [fail]})
        monkeypatch.setattr(httpx, "Client", factory)
    else:
        class Exploding(httpx.SyncByteStream):
            def __iter__(self):
                if stage == "stream":
                    fail()
                yield b'{"d": []}'
            def close(self):
                if stage == "close":
                    fail()
        client, seen = make(handler=lambda req: httpx.Response(200, stream=Exploding()))
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.status == "provider_error"
    assert "raw-error" not in result.model_dump_json()
    assert KEY not in result.model_dump_json()
    assert not caplog.records and KEY not in capsys.readouterr().err
    assert len(seen) == (2 if stage in ("stream", "close") else 0)
    assert result.error.code == "transport_error"


def test_no_logrecord_is_constructed_in_private_boundary(monkeypatch):
    def deny_factory(*args, **kwargs):
        pytest.fail("private LogRecord created")
    monkeypatch.setattr(logging, "_logRecordFactory", deny_factory)
    def upstream(req):
        logging.getLogger("httpx").error("%s", req.url)
        logging.getLogger("arbitrary").error("%s", KEY)
        return httpx.Response(200, json={"d": []})
    client, _ = make(handler=upstream)
    assert client.read(BingOperation.GET_QUERY_STATS, request()).status == "empty"


def test_privacy_install_is_idempotent_and_other_threads_are_not_suppressed(caplog):
    installed = logging.Logger._log
    assert boundary._install_privacy() is boundary._PRIVATE
    assert logging.Logger._log is installed
    caplog.set_level(logging.WARNING)
    ready, release = threading.Event(), threading.Event()
    def upstream(req):
        ready.set()
        release.wait(1)
        return httpx.Response(200, json={"d": []})
    client, _ = make(handler=upstream)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(client.read, BingOperation.GET_QUERY_STATS, request())
        assert ready.wait(1)
        logging.getLogger("unrelated.thread").warning("ordinary parallel log")
        release.set()
        assert future.result(timeout=2).status == "empty"
    assert "ordinary parallel log" in caplog.text


def test_sensitive_selector_fails_closed_without_http():
    client, seen = make({"d": []})
    req = request("GetQueryPageStats", query=KEY)
    result = client.read(req.operation, req)
    assert result.error.code == "credential_reflection" and not seen
    assert KEY not in result.model_dump_json()


def test_loader_revocation_during_retry_and_concurrency_wait(monkeypatch):
    loader = Loader()
    def upstream(req):
        loader.fail = "credentials_invalid"
        return httpx.Response(200, json={"d": [{"Url": SITE, "IsVerified": True}]})
    client, seen = make(handler=upstream, loader=loader, discovery=False)
    assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "credentials_invalid"
    assert len(seen) == 1
    loader.fail = None
    real_slot = boundary._GLOBAL.slot
    class Revoke:
        def acquire(self, timeout):
            acquired = real_slot.acquire(timeout=timeout)
            loader.fail = "credentials_invalid"
            return acquired
        def release(self):
            real_slot.release()
    monkeypatch.setattr(boundary._GLOBAL, "slot", Revoke())
    client, seen = make({"d": []}, loader=loader)
    assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "credentials_invalid"
    assert not seen


def test_actual_auth_loader_rotation_denies_real_client_reuse(tmp_path):
    tmp_path.chmod(0o700)
    key, sites = tmp_path / "key.json", tmp_path / "sites.json"
    key.write_text(json.dumps({"version": 1, "api_key": KEY}))
    sites.write_text(json.dumps({"version": 1, "sites": [SITE]}))
    key.chmod(0o600)
    sites.chmod(0o600)
    configure_bing_auth(SimpleNamespace(bing_credentials_file=key, bing_sites_file=sites))
    seen = []
    def upstream(req):
        seen.append(req)
        return httpx.Response(200, json={"d": ([{"Url": SITE, "IsVerified": True}]
            if req.url.path.endswith("/GetUserSites") else [])})
    client = BingReadClient(transport=httpx.MockTransport(upstream))
    assert client.read(BingOperation.GET_QUERY_STATS, request()).status == "empty"
    key.write_text(json.dumps({"version": 1, "api_key": "synthetic-rotated"}))
    assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "credentials_invalid"
    assert len(seen) == 2
    configure_bing_auth(SimpleNamespace(bing_credentials_file=None, bing_sites_file=None))


def test_rate_budget_expires_but_client_clock_cannot_reset_it():
    client, seen = make(status=503)
    for _ in range(6):
        assert client.read(BingOperation.GET_QUERY_STATS, request()).status == "provider_error"
    client._clock = lambda: 100000000.0
    assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "rate_limited"
    assert len(seen) == 12
    # Model elapsed process time explicitly, without weakening public injection.
    with boundary._GLOBAL.lock:
        boundary._GLOBAL.attempts = boundary.deque(t - 61 for t in boundary._GLOBAL.attempts)
    client, seen2 = make({"d": []})
    assert client.read(BingOperation.GET_QUERY_STATS, request()).status == "empty"
    assert len(seen2) == 2


def test_stream_exact_body_cap_is_admitted():
    content = b'{"d": []}'
    content += b" " * (2 * 1024 * 1024 - len(content))
    client, _ = make(handler=lambda req: httpx.Response(200, stream=Chunks([content])))
    assert client.read(BingOperation.GET_QUERY_STATS, request()).status == "empty"


def test_httpdate_retry_after_bounded_and_jitter_clamped():
    client, seen = make(handler=lambda req: httpx.Response(
        503, headers={"Retry-After": "Thu, 01 Jan 2099 00:00:00 GMT"}))
    assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "provider_error"
    assert len(seen) == 2 and client._clock.sleeps == []
    for forbidden in ("sleep", "jitter"):
        with pytest.raises(TypeError):
            BingReadClient(**{forbidden: lambda *a: pytest.fail("retired_callback")})


def test_total_deadline_supervises_slow_loader_without_late_network(monkeypatch):
    original = boundary._Budget
    class ShortBudget(original):
        def __init__(self, clock):
            super().__init__(clock)
            self.end = clock() + 0.05
            self.real_end = time.monotonic() + 0.05
    monkeypatch.setattr(boundary, "_Budget", ShortBudget)
    release, loaded = threading.Event(), threading.Event()
    loader = Loader()
    original_load = loader.load
    def slow_load():
        release.wait(1)
        loaded.set()
        return original_load()
    loader.load = slow_load
    client, seen = make({"d": []}, loader=loader)
    start = time.monotonic()
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.error.code == "timeout" and time.monotonic() - start < 0.5
    release.set()
    assert loaded.wait(1)
    # No late request may begin after supervision has cancelled the budget.
    time.sleep(0.02)
    assert not seen


@pytest.mark.parametrize("escaped", [r"synthetic-\ud83d\udd11-key", r"synthetic-\U0001f511-key"])
def test_astral_unicode_escaped_key_reflections(escaped):
    loader = Loader()
    loader.load = lambda: BingCredentialDocument(version=1, api_key="synthetic-🔑-key")
    client, _ = make({"d": [{**QUERY, "Query": escaped}]}, loader=loader)
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.error.code == "credential_reflection"


def test_deeply_wrapped_key_is_rejected_not_returned_as_encoded_data():
    wrapped = KEY
    for _ in range(20):
        wrapped = quote(wrapped, safe="")
    client, _ = make({"d": [{**QUERY, "Query": wrapped}]})
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.error.code == "credential_reflection"


@pytest.mark.parametrize("forbidden", ["api_key", "endpoint", "base_url", "proxy", "method"])
def test_no_arbitrary_key_endpoint_or_method_constructor(forbidden):
    with pytest.raises(TypeError):
        BingReadClient(**{forbidden: "synthetic-forbidden"})


@pytest.mark.parametrize("status", [429, 502, 503, 504])
def test_qualification_composition_can_disable_all_http_retries(status):
    client, seen = make(status=status, max_retries=0)
    result = client.read(BingOperation.GET_QUERY_STATS, request())
    assert result.status == "provider_error" and len(seen) == 2
    assert not client._clock.sleeps


def test_qualification_composition_disables_transient_connect_retry():
    def upstream(req):
        raise httpx.ConnectError("synthetic-connect-failure", request=req)
    client, seen = make(handler=upstream, max_retries=0)
    assert client.read(BingOperation.GET_QUERY_STATS, request()).error.code == "transport_error"
    assert len(seen) == 2 and not client._clock.sleeps


@pytest.mark.parametrize("value", [True, False, -1, 1, 2, 1.0, "0", None])
def test_retry_composition_cannot_expand_the_accepted_bound(value):
    with pytest.raises(BingClientError, match="^invalid_request$"):
        BingReadClient(max_retries=value)


def test_no_new_request_after_actual_attempt_timeout():
    """Stall transport entry, not a request already in progress; never kill a worker."""
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    calls = []
    class EntryStall(httpx.MockTransport):
        def __enter__(self):
            entered.set()
            release.wait(22)
            return self

        def close(self):
            closed.set()
            super().close()

    def handler(req):
        calls.append(time.monotonic())
        return httpx.Response(200, json={"d": []})

    transport = EntryStall(handler)
    client = BingReadClient(Loader(), transport=transport, max_retries=0)
    req = request()
    started = time.monotonic()
    result = client.read(req.operation, req)
    returned = time.monotonic()
    try:
        assert entered.is_set() and result.error.code == "timeout"
        assert 14.5 <= returned - started < 18
        assert not calls, "no upstream request had begun when caller timed out"
    finally:
        release.set()
        assert closed.wait(2), "worker cleans up normally after release"
    assert not calls, "NEW upstream request began after caller had already received timeout"


@pytest.mark.parametrize("stage", ["constructor", "entry", "params", "build",
                                   "initial_credentials", "attempt_credentials", "slot"])
def test_total_timeout_closes_all_pre_dispatch_stages(stage, monkeypatch):
    """Resume each blocked stage only AFTER the total supervisor returned timeout."""
    original_budget = boundary._Budget
    class ShortBudget(original_budget):
        def __init__(self, clock):
            super().__init__(clock)
            self.end = clock() + 0.08
            self.real_end = time.monotonic() + 0.08
    monkeypatch.setattr(boundary, "_Budget", ShortBudget)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    def stall():
        entered.set()
        assert release.wait(2)
    original_client = httpx.Client
    class Client(original_client):
        def __init__(self, **kwargs):
            if stage == "constructor":
                stall()
            super().__init__(**kwargs)
        def build_request(self, *args, **kwargs):
            result = super().build_request(*args, **kwargs)
            if stage == "build":
                stall()
            return result
    monkeypatch.setattr(httpx, "Client", Client)
    calls = []
    class Transport(httpx.MockTransport):
        def __enter__(self):
            if stage == "entry":
                stall()
            return super().__enter__()
    loader = Loader()
    load = loader.load
    def load_with_stall():
        if ((stage == "initial_credentials" and loader.loads == 0)
                or (stage == "attempt_credentials" and loader.loads == 1)):
            stall()
        return load()
    loader.load = load_with_stall
    params = boundary._params
    def params_with_stall(*args):
        if stage == "params":
            stall()
        return params(*args)
    monkeypatch.setattr(boundary, "_params", params_with_stall)
    slot = boundary._GLOBAL.slot
    class Slot:
        def acquire(self, timeout):
            acquired = slot.acquire(timeout=timeout)
            if acquired and stage == "slot":
                stall()
            return acquired
        def release(self):
            slot.release()
    monkeypatch.setattr(boundary._GLOBAL, "slot", Slot())
    def handler(req):
        calls.append(req)
        return httpx.Response(200, json={"d": []})
    client = BingReadClient(loader, transport=Transport(handler), max_retries=0)
    read = client._read
    def tracked_read(*args):
        try:
            return read(*args)
        finally:
            finished.set()
    monkeypatch.setattr(client, "_read", tracked_read)
    try:
        result = client.read(request().operation, request())
        assert entered.is_set() and result.error.code == "timeout" and not calls
        if stage != "initial_credentials":
            assert not slot.acquire(blocking=False), "slot retained until actual cleanup"
    finally:
        release.set()
        assert finished.wait(2)
        assert slot.acquire(timeout=2)
        slot.release()
    assert not calls


@pytest.mark.parametrize("stage", ["constructor", "entry", "params", "build"])
@pytest.mark.parametrize("elapsed", [16, 61])
def test_elapsed_attempt_or_total_deadline_gates_final_dispatch(stage, elapsed, monkeypatch):
    """Clock expiration alone suffices, even before either watchdog is scheduled."""
    clock = Clock()
    original = httpx.Client
    class Client(original):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            if stage == "constructor":
                clock.value += elapsed
        def build_request(self, *args, **kwargs):
            req = super().build_request(*args, **kwargs)
            if stage == "build":
                clock.value += elapsed
            return req
    monkeypatch.setattr(httpx, "Client", Client)
    class Transport(httpx.MockTransport):
        def __enter__(self):
            if stage == "entry":
                clock.value += elapsed
            return super().__enter__()
    params = boundary._params
    def delayed_params(*args):
        if stage == "params":
            clock.value += elapsed
        return params(*args)
    monkeypatch.setattr(boundary, "_params", delayed_params)
    calls = []
    def handler(req):
        calls.append(req)
        return httpx.Response(200, json={"d": []})
    client = BingReadClient(Loader(), transport=Transport(handler), clock=clock, max_retries=0)
    assert client.read(request().operation, request()).error.code == "timeout"
    assert not calls


@pytest.mark.parametrize("stage,code", [
    ("missing", "provider_not_configured"), ("invalid", "credentials_invalid"),
    ("denied", "site_denied"), ("mismatch", "invalid_request"),
    ("local", "transport_error"), ("busy", "timeout"),
    ("timeout", "timeout"), ("rate", "rate_limited"),
    ("provider", "provider_error"), ("schema", "invalid_response"),
    ("rows", "invalid_response"), ("reflection", "credential_reflection"),
])
def test_every_failure_has_input_free_provenance(stage, code, monkeypatch):
    """Keep authorization/dispatch order; failure rendering needs no key lookup."""
    loader = Loader()
    # Noncredential caller markers must disappear too, including ISO windows.
    req = request(start_date="2025-03-04", end_date="2025-03-05", limit=7)
    if stage == "denied":
        req = req.model_copy(update={"site_url": "https://bing.com/caller-marker"})
    if stage in ("missing", "invalid"):
        loader.fail = "credentials_missing" if stage == "missing" else "credentials_invalid"
    if stage == "local":
        def fail():
            raise RuntimeError("caller-marker")
        loader.load = fail
    payload = ({"d": [{"Clicks": True}]} if stage == "rows" else
               {"d": [{**QUERY, "Unknown": KEY}]} if stage == "reflection" else
               {"d": None} if stage == "schema" else {"ErrorCode": "private"})
    client, seen = make(payload, loader=loader, max_retries=0)
    if stage == "busy":
        class Busy:
            def acquire(self, timeout):
                return False
        monkeypatch.setattr(boundary._GLOBAL, "slot", Busy())
    if stage == "rate":
        boundary._GLOBAL.attempts.extend([time.monotonic()] * 12)
    if stage == "timeout":
        class Expired(boundary._Budget):
            def remaining(self):
                return 0
        monkeypatch.setattr(boundary, "_Budget", Expired)
    operation = BingOperation.GET_PAGE_STATS if stage == "mismatch" else req.operation
    result = client.read(operation, req)
    assert result.error.code == code
    assert result.site_url == ""  # Existing schema requires a string for site reads.
    assert result.requested_period is None and result.observed_period is None
    text = result.model_dump_json()
    assert "caller-marker" not in text and "2025-03-04" not in text
    assert "2025-03-05" not in text and SITE not in text and KEY not in text
    assert not result.records and result.provider_cadence == "weekly"
    assert {"weekly_buckets", "utc_date_filter", "window_not_exact"} <= set(result.warnings)
    if stage in ("missing", "invalid", "mismatch", "local", "busy", "timeout", "rate"):
        assert not seen
    if stage == "mismatch":
        assert loader.loads == 0
    if stage == "denied":
        assert len(seen) == 1 and seen[0].url.path.endswith("/GetUserSites")
        assert loader.loads == 7
    if stage in ("missing", "invalid"):
        assert loader.loads == 1  # No credential read added for sanitization.
    if stage == "rows":
        assert result.source_rows == result.dropped_rows == 1


@pytest.mark.parametrize("op,inputs,params,rows,kind", CASES)
@pytest.mark.parametrize("failure", ["missing", "rows"])
def test_all_operations_failure_context_is_empty(op, inputs, params, rows, kind, failure):
    loader = Loader()
    if failure == "missing":
        loader.fail = "credentials_missing"
    payload = {"d": {} if kind == "url_info" else [{}]}
    client, seen = make(payload, loader=loader, max_retries=0, discovery=(op != "GetUserSites"))
    req = request(op, **inputs)
    result = client.read(req.operation, req)
    assert result.error.code == ("provider_not_configured" if failure == "missing"
                                 else "invalid_response")
    assert result.site_url == (None if op == "GetUserSites" else "")
    assert result.requested_period is None and result.observed_period is None
    assert not result.records
    assert SITE not in result.model_dump_json()
    assert len(seen) == (0 if failure == "missing" else (1 if op == "GetUserSites" else 2))


@pytest.mark.parametrize("stage", ["clock", "worker", "unchecked", "operation"])
def test_static_exception_exits_never_carry_request_context(stage):
    loader = Loader()
    client, seen = make({"d": []}, loader=loader)
    req = request(start_date="2025-03-04", end_date="2025-03-05")
    def fail(*args):
        raise RuntimeError("caller-marker:" + SITE)
    if stage == "clock":
        client._clock = fail
    elif stage == "worker":
        client._read = fail
    elif stage == "unchecked":
        req = req.model_copy(update={"site_url": "caller-marker"})
    if stage == "worker":
        result = client.read(req.operation, req)
        assert result.error.code == "transport_error"
        assert "caller-marker" not in result.model_dump_json()
        assert result.site_url == "" and result.requested_period is None
    else:
        with pytest.raises(BingClientError) as caught:
            client.read("caller-marker" if stage == "operation" else req.operation, req)
        assert str(caught.value) == "invalid_request"
        assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert not seen and loader.loads == 0


def test_dispatch_gate_cancel_linearization_and_live_control():
    """Cancel is terminal; an already admitted dispatch is not forcibly killed."""
    budget = boundary._Budget(Clock())
    gate = boundary._Attempt(budget, 15)
    calls = []
    def handler(req):
        calls.append(req)
        return httpx.Response(200, json={"d": []})
    loader = Loader()
    transport = boundary._GatedTransport(
        httpx.MockTransport(handler), gate, loader, loader.actual._boundary.generation)
    req = httpx.Request("GET", "https://ssl.bing.com/")
    assert transport.handle_request(req).status_code == 200
    gate.cancel()
    with pytest.raises(boundary._Stop):
        transport.handle_request(req)
    assert len(calls) == 1
    other = boundary._Attempt(budget, 15)
    budget.cancel()
    with pytest.raises(boundary._Stop):
        boundary._GatedTransport(
            httpx.MockTransport(handler), other, loader,
            loader.actual._boundary.generation).handle_request(req)
    assert len(calls) == 1


# Permanent offline integration regressions, appended by the owned migration.
@pytest.mark.parametrize("op,inputs,params,rows,kind", CASES[1:])
@pytest.mark.parametrize("membership", [
    "true", "false", "absent", "unknown", "conflict", "partial"])
def test_every_property_path_real_custody_fresh_union_admission(
    op, inputs, params, rows, kind, membership,
):
    site = "https://new-agency-public.com/"
    selectors = {name: value.replace(SITE, site) for name, value in inputs.items()}
    req = BingToolRequest(operation=BingOperation(op), site_url=site, **selectors)
    listed = [{"Url": SITE, "IsVerified": True},
              {"Url": "https://visible-unverified.com/", "IsVerified": False}]
    if membership != "absent":
        listed.append({"Url": site, "IsVerified": membership != "false"})
    if membership == "unknown":
        listed[-1]["IsVerified"] = "true"
    elif membership == "conflict":
        listed.append({"Url": site, "IsVerified": False})
    elif membership == "partial":
        listed.append({"Url": "not-a-public-property", "IsVerified": True})
    def handler(wire):
        assert wire.method == "GET" and wire.url.host == "ssl.bing.com"
        if wire.url.path.endswith("/GetUserSites"):
            assert set(wire.url.params) == {"apikey"}
            return httpx.Response(200, json={"d": listed})
        assert wire.url.path.endswith("/" + op)
        assert wire.url.params["siteUrl"] == site
        return httpx.Response(200, json={"d": rows})
    actual, seen = make(handler=handler, discovery=False)
    assert isinstance(actual._loader.actual, BingCredentialLoader)
    result = actual.read(req.operation, req)
    if membership == "true":
        assert result.status == "ok" and result.error is None
        assert [r.kind for r in result.records] == [kind] and len(seen) == 2
    else:
        code = "site_denied" if membership in {"false", "absent"} else "invalid_response"
        assert result.error.code == code and result.records == [] and len(seen) == 1
    assert seen[0].url.path.endswith("/GetUserSites")
    assert len(boundary._GLOBAL.attempts) == len(seen)


@pytest.mark.parametrize("op,inputs,params,rows,kind", CASES[1:])
def test_business_admission_charges_same_twelve_attempt_quota(op, inputs, params, rows, kind):
    boundary._GLOBAL.attempts.extend([time.monotonic()] * 11)
    actual, seen = make({"d": rows})
    req = request(op, **inputs)
    result = actual.read(req.operation, req)
    assert result.error.code == "rate_limited" and result.records == []
    assert len(seen) == 1 and seen[0].url.path.endswith("/GetUserSites")
    assert len(boundary._GLOBAL.attempts) == 12
    assert boundary._GLOBAL.slot.acquire(timeout=1)
    boundary._GLOBAL.slot.release()


@pytest.mark.parametrize("op,inputs,params,rows,kind", CASES[1:])
@pytest.mark.parametrize("stage", ["entry", "send_hook"])
@pytest.mark.parametrize("elapsed", [16, 61])
def test_business_entry_deadline_recheck_every_property_path(
    op, inputs, params, rows, kind, stage, elapsed, monkeypatch,
):
    clock = Clock()
    wire, delayed = [], []
    class Transport(httpx.MockTransport):
        def __enter__(self):
            result = super().__enter__()
            if wire and stage == "entry":
                clock.value += elapsed
                delayed.append(True)
            return result
    def hook(req):
        if not req.url.path.endswith("/GetUserSites") and stage == "send_hook":
            clock.value += elapsed
            delayed.append(True)
    original = httpx.Client
    def factory(**kwargs):
        return original(**kwargs, event_hooks={"request": [hook]})
    def handler(req):
        wire.append(req.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json={"d": [{"Url": SITE, "IsVerified": True}]})
    monkeypatch.setattr(httpx, "Client", factory)
    actual = BingReadClient(BingCredentialLoader(), transport=Transport(handler), clock=clock)
    req = request(op, **inputs)
    result = actual.read(req.operation, req)
    assert delayed == [True] and wire == ["GetUserSites"]
    assert result.error.code == "timeout" and not result.records
    assert len(boundary._GLOBAL.attempts) == 2
    assert boundary._GLOBAL.slot.acquire(timeout=1)
    boundary._GLOBAL.slot.release()


def test_list_complete_union_false_visible_exact_dedup_no_limit():
    rows = [{"Url": f"https://agency-{i:03d}.com/", "IsVerified": i % 2 == 0,
             "AuthenticationCode": "discard", "DnsVerificationCode": "discard"}
            for i in range(140)]
    client, seen = make({"d": list(reversed(rows)) + rows[:3]}, discovery=False)
    result = client.read(BingOperation.GET_USER_SITES, request("GetUserSites"))
    assert result.status == "ok" and result.error is None
    assert [(r.url, r.is_verified) for r in result.records] == [
        (row["Url"], row["IsVerified"]) for row in rows]
    assert (result.source_rows, result.returned_rows, result.dropped_rows) == (143, 140, 0)
    assert not result.local_truncated and result.provider_completeness == "unknown"
    assert "discard" not in result.model_dump_json() and len(seen) == 1


def test_next_request_rediscovers_revocation_without_cached_authority():
    discoveries = []
    def handler(wire):
        if wire.url.path.endswith("/GetUserSites"):
            discoveries.append(True)
            return httpx.Response(200, json={"d": [{"Url": SITE,
                "IsVerified": len(discoveries) == 1}]})
        return httpx.Response(200, json={"d": [QUERY]})
    client, seen = make(handler=handler, discovery=False)
    assert client.read(request().operation, request()).status == "ok"
    second = client.read(request().operation, request())
    assert second.error.code == "site_denied" and not second.records
    assert [r.url.path.rsplit("/", 1)[-1] for r in seen] == [
        "GetUserSites", "GetQueryStats", "GetUserSites"]


@pytest.mark.parametrize("op,inputs,params,rows,kind", CASES[1:])
@pytest.mark.parametrize("fault,code", [("http403", "access_denied"),
    ("http429", "rate_limited"), ("http503", "provider_error"),
    ("timeout", "timeout"), ("invalid", "invalid_response")])
def test_discovery_fault_is_typed_not_empty_or_site_denied(
    op, inputs, params, rows, kind, fault, code,
):
    def handler(wire):
        assert wire.url.path.endswith("/GetUserSites")
        if fault == "timeout":
            raise httpx.ReadTimeout("synthetic_timeout")
        if fault == "invalid":
            return httpx.Response(200, content=b'{"d":null}')
        return httpx.Response(int(fault[4:]), json={"d": []})
    client, seen = make(handler=handler, discovery=False)
    req = request(op, **inputs)
    result = client.read(req.operation, req)
    assert result.error.code == code and not result.records
    assert result.status != "empty" and len(seen) == 1
    assert len(boundary._GLOBAL.attempts) == 1


@pytest.mark.parametrize("op,inputs,params,rows,kind", CASES[1:])
@pytest.mark.parametrize("expire", [False, True])
def test_two_attempts_share_one_budget_deadline_and_quota(
    monkeypatch, expire, op, inputs, params, rows, kind,
):
    clock = Clock()
    budgets, observed = [], []
    original = boundary._Budget
    class Budget(original):
        def __init__(self, clock):
            super().__init__(clock)
            self.end = clock() + 10
            budgets.append(self)
    class Client(BingReadClient):
        def _attempt(self, req, budget, **kwargs):
            observed.append((req.operation, budget, budget.end, budget.remaining()))
            return super()._attempt(req, budget, **kwargs)
    def handler(wire):
        discovery = wire.url.path.endswith("/GetUserSites")
        clock.value += 4 if discovery else (7 if expire else 4)
        return httpx.Response(200, json={"d": [{"Url": SITE, "IsVerified": True}]
                                      if discovery else rows})
    monkeypatch.setattr(boundary, "_Budget", Budget)
    actual = Client(BingCredentialLoader(), transport=httpx.MockTransport(handler), clock=clock)
    req = request(op, **inputs)
    result = actual.read(req.operation, req)
    assert len(budgets) == 1 and len(observed) == 2
    assert all(row[1] is budgets[0] and row[2] == 10 for row in observed)
    assert [row[3] for row in observed] == [10, 6]
    assert len(boundary._GLOBAL.attempts) == 2
    if expire:
        assert result.error.code == "timeout" and not result.records
    else:
        assert result.status == "ok" and result.error is None


@pytest.mark.parametrize("op,inputs,params,rows,kind", CASES[1:])
@pytest.mark.parametrize("stage", ["entry", "send_hook"])
@pytest.mark.parametrize("change", ["replace", "permissions", "reconfigure"])
def test_custody_after_entry_and_httpx_hooks_blocks_every_business_path(
    op, inputs, params, rows, kind, stage, change, monkeypatch,
):
    loader = BingCredentialLoader()
    path = loader._boundary.key
    events, wire = [], []
    def mutate():
        events.append("mutation")
        if change == "replace":
            replacement = path.with_name("replacement.json")
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(path)
        elif change == "permissions":
            path.chmod(0o666)
        else:
            configure_bing_auth(SimpleNamespace(bing_credentials_file=path))
    class Transport(httpx.MockTransport):
        def __enter__(self):
            result = super().__enter__()
            if stage == "entry" and wire:
                mutate()
            return result
    def hook(req):
        if stage == "send_hook" and not req.url.path.endswith("/GetUserSites"):
            mutate()
    original = httpx.Client
    def factory(**kwargs):
        return original(**kwargs, event_hooks={"request": [hook]})
    def handler(req):
        wire.append(req.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json={"d": [{"Url": SITE, "IsVerified": True}]})
    monkeypatch.setattr(httpx, "Client", factory)
    actual = BingReadClient(loader, transport=Transport(handler))
    req = request(op, **inputs)
    result = actual.read(req.operation, req)
    assert events == ["mutation"] and wire == ["GetUserSites"]
    assert result.error.code == "credentials_invalid" and not result.records
    with pytest.raises(BingAuthError):
        loader.load()
    assert boundary._GLOBAL.slot.acquire(timeout=1)
    boundary._GLOBAL.slot.release()


@pytest.mark.parametrize("policy", ["always", "error"])
@pytest.mark.parametrize("stage", ["entry", "send_hook", "handler", "close"])
def test_dependency_warnings_before_real_logrecords_are_static(
    policy, stage, monkeypatch, caplog, capsys,
):
    import warnings
    records, delivered, sites = [], [], []
    original_factory = logging.getLogRecordFactory()
    def factory(*args, **kwargs):
        record = original_factory(*args, **kwargs)
        records.append(record)
        return record
    class Observer(logging.Handler):
        def emit(self, record):
            delivered.append(record)
    def warn():
        warnings.warn(KEY, RuntimeWarning, stacklevel=1)
    class Transport(httpx.MockTransport):
        def __enter__(self):
            if stage == "entry":
                warn()
            return super().__enter__()
        def close(self):
            if stage == "close":
                warn()
            return super().close()
    def hook(req):
        if stage == "send_hook":
            warn()
    def handler(req):
        sites.append(req.url.path.rsplit("/", 1)[-1])
        if stage == "handler":
            warn()
        return httpx.Response(200, json={"d": [{"Url": SITE, "IsVerified": True}]
            if req.url.path.endswith("/GetUserSites") else []})
    original_client = httpx.Client
    def client_factory(**kwargs):
        return original_client(**kwargs, event_hooks={"request": [hook]})
    monkeypatch.setattr(httpx, "Client", client_factory)
    monkeypatch.setattr(logging, "_logRecordFactory", factory)
    logger = logging.getLogger("py.warnings")
    observer = Observer()
    logger.addHandler(observer)
    caplog.set_level(logging.WARNING)
    previous = warnings.showwarning
    try:
        logging.captureWarnings(True)
        with warnings.catch_warnings():
            warnings.simplefilter(policy)
            actual = BingReadClient(BingCredentialLoader(), transport=Transport(handler))
            result = actual.read(request().operation, request())
        if policy == "always":
            assert result.status == "empty" and result.error is None
            assert sites == ["GetUserSites", "GetQueryStats"]
            assert len(records) == len(delivered) == 2
            for record in records:
                assert "bing_dependency_warning" in record.getMessage()
                assert KEY not in repr(vars(record)) and record.exc_info is None
        else:
            assert result.error.code == "transport_error" and not result.records
            assert records == delivered == []
            assert sites == (["GetUserSites"] if stage in {"handler", "close"} else [])
        assert KEY not in caplog.text
        captured = capsys.readouterr()
        assert KEY not in captured.out + captured.err
    finally:
        logging.captureWarnings(False)
        warnings.showwarning = previous
        logger.removeHandler(observer)
    logging.getLogger("unrelated.warning.boundary").warning("ordinary_unrelated_record")
    assert records[-1].getMessage() == "ordinary_unrelated_record"


@pytest.mark.parametrize("location", ["raw_ignored", "parsed_ignored", "headers"])
@pytest.mark.parametrize("encoding", ["literal", "percent", "base64", "hex"])
def test_actual_raw_producer_checks_private_fields_before_return(location, encoding, monkeypatch):
    import base64
    reflected = {"literal": KEY, "percent": quote(KEY, safe=""),
                 "base64": base64.b64encode(KEY.encode()).decode(),
                 "hex": KEY.encode().hex()}[encoding]
    returned, sent, scanned = [], [], []
    original_scan = boundary._reject_reflection

    def scanner(value, key):
        if isinstance(value, str):
            scanned.append("raw")
            if location == "parsed_ignored":
                # Isolate the later parsed-ignored guard: the full raw guard is
                # independently exercised by raw_ignored with no bypass.
                return
        if isinstance(value, dict) and "d" in value:
            scanned.append("parsed")
        return original_scan(value, key)

    monkeypatch.setattr(boundary, "_reject_reflection", scanner)
    class Client(BingReadClient):
        def _attempt(self, req, budget, **kwargs):
            raw = super()._attempt(req, budget, **kwargs)
            returned.append(raw)
            return raw
    def handler(req):
        sent.append(True)
        headers = (httpx.Headers([(b"X-Ignored", reflected.encode("utf-8"))])
                   if location == "headers" else {})
        data = {"d": [{"Url": SITE, "IsVerified": True,
                       "AuthenticationCode": reflected if location != "headers" else "discard"}]}
        if location == "raw_ignored":
            body = json.dumps(data, ensure_ascii=True).encode()
            return httpx.Response(200, content=body, headers=headers)
        return httpx.Response(200, json=data, headers=headers)
    actual = Client(BingCredentialLoader(), transport=httpx.MockTransport(handler))
    result = actual.read(request().operation, request())
    assert result.error.code == "credential_reflection" and not result.records
    assert sent == [True] and returned == [] and KEY not in result.model_dump_json()
    if location == "parsed_ignored":
        assert scanned == ["raw", "parsed"]
    elif location == "raw_ignored":
        assert scanned == ["raw"]
    else:
        assert scanned == []  # Headers refuse before either body scan.


def test_actual_raw_response_typed_attributes_not_merely_empty_dump():
    from google_seo_mcp.bing.models import BingRawResponse
    loader = BingCredentialLoader()
    body = b'{"d":[]}'
    sent = []
    def handler(req):
        sent.append(req.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, content=body, headers={"Retry-After": "3"})
    actual = BingReadClient(loader, transport=httpx.MockTransport(handler))
    raw = actual._attempt(request("GetUserSites"), boundary._Budget(Clock()))
    assert type(raw) is BingRawResponse
    assert raw.body == body and raw.retry_after == "3" and raw.status_code == 200
    assert raw.credential_generation == loader.generation()
    assert raw.model_dump() == {} and raw.model_dump_json() == "{}"
    assert not hasattr(raw, "api_key") and KEY not in repr(raw)
    assert sent == ["GetUserSites"]


@pytest.mark.parametrize("kind", ["keyboard", "system", "async"])
def test_caller_control_cancels_claimed_worker_retains_slot_no_late_wire(kind, monkeypatch):
    import asyncio
    control = {"keyboard": KeyboardInterrupt, "system": SystemExit,
               "async": asyncio.CancelledError}[kind]()
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    sent = []
    class Transport(httpx.MockTransport):
        def __enter__(self):
            entered.set()
            assert release.wait(3)
            return super().__enter__()
        def close(self):
            closed.set()
            return super().close()
    original = threading.Thread
    workers = []
    class Thread(original):
        def start(self):
            super().start()
            if self.name == "bing-read":
                workers.append(self)
                assert entered.wait(1)
                raise control
    monkeypatch.setattr(boundary.threading, "Thread", Thread)
    actual = BingReadClient(BingCredentialLoader(), transport=Transport(
        lambda req: (sent.append(True), httpx.Response(200, json={"d": []}))[1]))
    try:
        with pytest.raises(BaseException) as caught:
            actual.read(request().operation, request())
        assert caught.value is control
        assert not boundary._GLOBAL.slot.acquire(blocking=False)
        assert sent == []
    finally:
        release.set()
        for worker in workers:
            worker.join(2)
            assert not worker.is_alive()
    assert closed.is_set() and sent == []
    assert boundary._GLOBAL.slot.acquire(timeout=1)
    boundary._GLOBAL.slot.release()


@pytest.mark.parametrize("stage", ["construction", "unclaimed_start"])
def test_worker_partial_startup_revokes_before_late_target(stage, monkeypatch):
    released, actions, targets = [], [], []
    budget = boundary._Budget(Clock())
    if stage == "construction":
        def fail(*args):
            raise OSError("synthetic_startup")
        monkeypatch.setattr(boundary, "_Ownership", fail)
    else:
        class Thread:
            def __init__(self, *, target, **kwargs):
                targets.append(target)
            def start(self):
                raise OSError("synthetic_startup")
        monkeypatch.setattr(boundary.threading, "Thread", Thread)
    with pytest.raises(OSError):
        boundary._worker(lambda: actions.append(True), budget, budget.remaining,
                         release=lambda: released.append(True))
    assert budget.remaining() == 0 and released == [True]
    for target in targets:
        target()
    assert actions == [] and released == [True]
