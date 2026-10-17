"""Permanent offline documentation-derived SYNTHETIC fixtures, never Bing receipts.

Provenance: accepted step54 plan Appendix A §§3–5,8. Microsoft QueryStats
example values 18/17 establish raw fields, not scale; WCF specifies epoch ms
and ignored suffix. Expected aliases/flags/routes below are independent goldens.
"""

import json
import socket
from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from google_seo_mcp.bing.models import BingOperation, BingToolRequest
from google_seo_mcp.bing.normalization import (
    decode_bing_crawl_issues,
    normalize_bing_rows,
    parse_bing_datetime,
)
from google_seo_mcp.bing.wire_models import (
    RawBingCrawlIssue,
    RawBingCrawlStats,
    RawBingFeed,
    RawBingQueryStats,
    RawBingSite,
    RawBingTrafficStats,
    RawBingUrlInfo,
)

SITE = "https://kelleyconstructioninc.com/"
TOKEN = "/Date(1316156400000-0700)/"
TRAFFIC = {"Date": TOKEN, "Clicks": 2, "Impressions": 8}
QUERY = {
    **TRAFFIC,
    "Query": "raw row identity",
    "AvgClickPosition": 18,
    "AvgImpressionPosition": 17,
}
CRAWL = {
    "Date": TOKEN,
    "AllOtherCodes": 1,
    "BlockedByRobotsTxt": 2,
    "Code2xx": 3,
    "Code301": 4,
    "Code302": 5,
    "Code4xx": 6,
    "Code5xx": 7,
    "ConnectionTimeout": 8,
    "ContainsMalware": 9,
    "CrawledPages": 10,
    "CrawlErrors": 11,
    "DnsFailures": 12,
    "InIndex": 13,
    "InLinks": 14,
}
ISSUE = {"HttpCode": 404, "InLinks": 2, "Issues": 548, "Url": SITE + "page"}
URL = {
    "AnchorCount": 2,
    "DiscoveryDate": TOKEN,
    "DocumentSize": 128,
    "HttpStatus": 200,
    "IsPage": True,
    "LastCrawledDate": TOKEN,
    "TotalChildUrlCount": 3,
    "Url": SITE + "page",
}
FEED = {
    "Compressed": False,
    "FileSize": 12,
    "LastCrawled": TOKEN,
    "Status": "synthetic-status",
    "Submitted": TOKEN,
    "Type": "synthetic-type",
    "Url": SITE + "sitemap.xml",
    "UrlCount": 7,
}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("normalization must never use network")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def request(operation="GetQueryStats", **kwargs):
    return BingToolRequest(
        operation=operation, **({} if operation == "GetUserSites" else {"site_url": SITE}), **kwargs
    )


def normalize(rows, req=None, **kwargs):
    req = req or request()
    return normalize_bing_rows(req.operation, rows, req, **kwargs)


def test_official_offset_date_not_double_applied():
    expected = datetime(2011, 9, 16, 7, tzinfo=UTC)
    assert parse_bing_datetime(TOKEN) == expected
    assert parse_bing_datetime("/Date(1316156400000+0530)/") == expected
    assert parse_bing_datetime("/Date(1316156400000)/") == expected
    assert parse_bing_datetime("/Date(-1-0700)/") == datetime(
        1969, 12, 31, 23, 59, 59, 999000, tzinfo=UTC
    )
    assert parse_bing_datetime("/Date(1)/").microsecond == 1000
    record = normalize([RawBingQueryStats(**QUERY)]).records[0]
    assert record.date == TOKEN and record.date_utc == expected


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "bad secret token",
        "/Date()/",
        "/Date(1.5)/",
        "/Date(1+07)/",
        " /Date(1)/",
        "/Date(1)/\n",
        "/Date(999999999999999999)/",
        "2011-09-16",
        0,
        "/Date(١)/",
        "/Date(+1)/",
    ],
)
def test_invalid_dates_never_become_epoch(raw):
    with pytest.raises(ValueError, match="^invalid_bing_datetime$"):
        parse_bing_datetime(raw)


def test_raw_positions_never_scaled():
    result = normalize([RawBingQueryStats(**QUERY)])
    data = json.loads(result.model_dump_json())
    record = data["records"][0]
    assert (record["avg_click_position"], record["avg_impression_position"]) == (18, 17)
    assert record["average_position"] is None
    assert record["position_scale"] == data["position_scale"] == "undocumented"
    assert record["ctr"] == 0.25
    assert record["query"] == "raw row identity" and "page" not in record
    assert {"weekly_buckets", "raw_query_identity", "position_scale_undocumented"} <= set(
        result.warnings
    )
    assert not any(k in data for k in ("totals", "average_position", "indexed"))


@pytest.mark.parametrize("value", [-1, True, 1.0, "1", None, float("nan"), float("inf")])
@pytest.mark.parametrize(
    "field", ["Clicks", "Impressions", "AvgClickPosition", "AvgImpressionPosition"]
)
def test_strict_finite_nonnegative_metrics(value, field):
    # Raw Int32 positions are signed; only count metrics are nonnegative.
    if field in {"AvgClickPosition", "AvgImpressionPosition"} and type(value) is int and value < 0:
        row = RawBingQueryStats(**{**QUERY, field: value})
        name = "avg_click_position" if field == "AvgClickPosition" else "avg_impression_position"
        assert row.model_dump()[name] == value
        return
    with pytest.raises(ValidationError):
        RawBingQueryStats(**{**QUERY, field: value})


def test_zero_missing_impossible_counts_not_fabricated():
    zero = RawBingQueryStats(**{**QUERY, "Clicks": 0, "Impressions": 0})
    impossible = RawBingQueryStats(**{**QUERY, "Clicks": 9})
    result = normalize([zero, impossible], invalid_wire_rows=1, invalid_wire_metrics=1)
    assert result.status == "partial"
    assert result.records[0].ctr is None
    assert (result.source_rows, result.returned_rows, result.dropped_rows) == (3, 1, 2)
    assert "invalid_metrics_dropped" in result.warnings
    with pytest.raises(ValidationError):
        RawBingQueryStats(**{k: v for k, v in QUERY.items() if k != "Clicks"})
    failed = normalize([impossible])
    assert failed.status == "provider_error" and failed.error.code == "invalid_response"
    assert failed.records == [] and failed.dropped_rows == 1


def test_weekly_partial_window_and_local_limit_disclosed():
    rows = [
        RawBingQueryStats(**{**QUERY, "Date": token})
        for token in ("/Date(0)/", "/Date(86400000)/", "/Date(172800000)/", "/Date(259200000)/")
    ]
    result = normalize(rows, request(start_date="1970-01-02", end_date="1970-01-03", limit=1))
    assert result.provider_cadence == "weekly"
    assert result.provider_completeness == "unknown"
    assert result.requested_period.model_dump() == {
        "start_date": date(1970, 1, 2),
        "end_date": date(1970, 1, 3),
    }
    # Observed extent describes valid fetched source BEFORE either local operation.
    assert result.observed_period.model_dump() == {
        "start_date": date(1970, 1, 1),
        "end_date": date(1970, 1, 4),
    }
    assert result.records[0].date == "/Date(86400000)/"
    assert (result.source_rows, result.returned_rows, result.dropped_rows) == (4, 1, 0)
    assert result.local_truncated
    assert {
        "local_date_filter",
        "utc_date_filter",
        "window_not_exact",
        "local_limit",
        "weekly_buckets",
        "provider_completeness_unknown",
    } <= set(result.warnings)
    assert result.status == "ok"  # local selection is disclosed, not a provider failure


def test_crawl_flags_unknown_bits_preserved():
    names = [
        "Code301",
        "Code302",
        "Code4xx",
        "Code5xx",
        "BlockedByRobotsTxt",
        "ContainsMalware",
        "ImportantUrlBlockedByRobotsTxt",
        "DnsErrors",
        "TimeOutErrors",
    ]
    for bit, name in zip((1, 2, 4, 8, 16, 32, 64, 128, 256), names, strict=True):
        assert decode_bing_crawl_issues(bit) == ([name], 0)
    assert decode_bing_crawl_issues(0) == (["None"], 0)
    assert decode_bing_crawl_issues(511 | 4096) == (names, 4096)
    assert decode_bing_crawl_issues(512) == ([], 512)
    result = normalize([RawBingCrawlIssue(**ISSUE)], request("GetCrawlIssues"))
    assert result.records[0].model_dump() == {
        "http_code": 404,
        "in_links": 2,
        "issues": 548,
        "url": SITE + "page",
        "kind": "crawl_issue",
        "known_issues": ["Code4xx", "ContainsMalware"],
        "unknown_bits": 512,
    }
    assert result.warnings == [
        "provider_completeness_unknown",
        "crawl_issue_lag",
        "unknown_issue_bits",
    ]


@pytest.mark.parametrize("mask", [-1, True, 1.0, "32", None])
def test_invalid_mask(mask):
    with pytest.raises(ValueError, match="^invalid_bing_issue_mask$"):
        decode_bing_crawl_issues(mask)


# Independently spelled eleven-operation/shape golden, not generated from enum/mapping.
@pytest.mark.parametrize(
    "op,raw_type,payload,selectors,kind,cadence",
    [
        ("GetUserSites", RawBingSite, {"Url": SITE, "IsVerified": True}, {}, "site", "unknown"),
        ("GetRankAndTrafficStats", RawBingTrafficStats, TRAFFIC, {}, "traffic", "daily"),
        ("GetQueryStats", RawBingQueryStats, QUERY, {}, "query", "weekly"),
        ("GetPageStats", RawBingQueryStats, QUERY, {}, "query", "weekly"),
        (
            "GetPageQueryStats",
            RawBingQueryStats,
            QUERY,
            {"page_url": SITE + "page"},
            "query",
            "weekly",
        ),
        ("GetQueryPageStats", RawBingQueryStats, QUERY, {"query": "selector"}, "query", "weekly"),
        ("GetCrawlStats", RawBingCrawlStats, CRAWL, {}, "crawl", "daily"),
        ("GetCrawlIssues", RawBingCrawlIssue, ISSUE, {}, "crawl_issue", "unknown"),
        ("GetUrlInfo", RawBingUrlInfo, URL, {"url": SITE + "page"}, "url_info", "unknown"),
        ("GetFeeds", RawBingFeed, FEED, {}, "feed", "unknown"),
        (
            "GetFeedDetails",
            RawBingFeed,
            FEED,
            {"sitemap_url": SITE + "sitemap.xml"},
            "feed",
            "unknown",
        ),
    ],
)
def test_every_eleven_shape_golden(op, raw_type, payload, selectors, kind, cadence):
    req = request(op, **selectors)
    raw = raw_type(**{**payload, "Unknown": "must disappear"})
    result = normalize([raw], req, approved_sites={SITE})
    assert result.status == "ok" and result.records[0].kind == kind
    assert result.provider_cadence == cadence and result.provider_completeness == "unknown"
    assert (result.source_rows, result.returned_rows, result.dropped_rows) == (1, 1, 0)
    assert not result.local_truncated and result.extracted_at.utcoffset().total_seconds() == 0
    assert result.requested_period is None
    assert result.model_validate_json(result.model_dump_json()) == result
    output = result.records[0].model_dump()
    assert {k: output[k] for k in raw.model_dump()} == raw.model_dump()
    assert "Unknown" not in output and "indexed" not in output
    if kind in {"traffic", "query", "crawl"}:
        assert result.observed_period.start_date == date(2011, 9, 16)
    else:
        assert result.observed_period is None
    if kind == "query":
        assert output["page_url"] == selectors.get("page_url")
        assert output["selector_query"] == selectors.get("query")
        assert output["query"] == QUERY["Query"]
    empty = normalize([], req, approved_sites={SITE})
    assert empty.status == "empty" and empty.provider_cadence == cadence
    assert empty.source_rows == empty.returned_rows == empty.dropped_rows == 0
    assert empty.observed_period is None


def test_discovery_exact_approved_verified_and_auth_codes_stripped():
    req = request("GetUserSites")
    rows = [
        RawBingSite(
            Url=url,
            IsVerified=verified,
            AuthenticationCode="SYNTHETIC-CODE",
            DnsVerificationCode="SYNTHETIC-DNS",
        )
        for url, verified in (
            (SITE, True),
            (SITE, False),
            ("https://unapproved.com/", True),
            (SITE.rstrip("/"), True),
        )
    ]
    assert normalize(rows, req).status == "invalid_request"
    result = normalize(rows, req, approved_sites={SITE})
    assert result.source_rows == 4 and result.returned_rows == 1 and result.dropped_rows == 0
    assert result.records[0].model_dump() == {"url": SITE, "is_verified": True, "kind": "site"}
    assert "SYNTHETIC" not in result.model_dump_json()
    assert normalize(rows, req, approved_sites=set()).status == "empty"


def test_dates_partial_all_invalid_and_filtered_empty():
    good = RawBingQueryStats(**QUERY)
    bad = RawBingQueryStats(**{**QUERY, "Date": "SYNTHETIC malformed date"})
    result = normalize([bad, good])
    assert result.status == "partial" and result.dropped_rows == 1
    assert "invalid_dates_dropped" in result.warnings
    assert normalize([bad]).status == "provider_error"
    assert normalize([], invalid_wire_rows=2, invalid_wire_dates=1).status == "provider_error"
    req = request(start_date="2020-01-01", end_date="2020-01-01")
    filtered = normalize([good], req)
    assert filtered.status == "empty" and filtered.source_rows == 1
    assert filtered.returned_rows == 0 and not filtered.local_truncated
    assert filtered.observed_period.start_date == date(2011, 9, 16)
    # Cannot represent a partial with no records; do not disguise rejected rows as empty.
    assert normalize([bad, good], req).status == "provider_error"


@pytest.mark.parametrize(
    "op,raw_type,payload,selectors,field",
    [
        ("GetUrlInfo", RawBingUrlInfo, URL, {"url": SITE + "page"}, "DiscoveryDate"),
        ("GetUrlInfo", RawBingUrlInfo, URL, {"url": SITE + "page"}, "LastCrawledDate"),
        ("GetFeeds", RawBingFeed, FEED, {}, "Submitted"),
        ("GetFeeds", RawBingFeed, FEED, {}, "LastCrawled"),
        ("GetCrawlStats", RawBingCrawlStats, CRAWL, {}, "Date"),
    ],
)
def test_other_family_dates_fail_explicitly(op, raw_type, payload, selectors, field):
    result = normalize([raw_type(**{**payload, field: "bad"})], request(op, **selectors))
    assert result.status == "provider_error" and result.records == []
    assert "invalid_dates_dropped" in result.warnings


def test_wrong_family_and_mismatched_operation_fail_safely():
    wrong = normalize([RawBingTrafficStats(**TRAFFIC)])
    assert wrong.status == "provider_error" and wrong.dropped_rows == 1
    req = request()
    result = normalize_bing_rows(BingOperation.GET_CRAWL_STATS, [], req)
    assert result.status == "invalid_request" and result.error.code == "invalid_request"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"invalid_wire_rows": -1},
        {"invalid_wire_rows": True},
        {"invalid_wire_rows": 1.0},
        {"invalid_wire_dates": 1},
        {"invalid_wire_rows": 1, "invalid_wire_dates": 1, "invalid_wire_metrics": 1},
    ],
)
def test_wire_drop_counters_strict_and_disjoint(kwargs):
    with pytest.raises(ValueError, match="^invalid_wire_counters$"):
        normalize([], **kwargs)


def test_synthetic_query_full_golden_snapshot():
    data = json.loads(normalize([RawBingQueryStats(**QUERY)]).model_dump_json())
    assert data.pop("extracted_at").endswith("Z")
    assert data == {
        "status": "ok",
        "source": "bing_webmaster",
        "operation": "GetQueryStats",
        "site_url": SITE,
        "records": [
            {
                "clicks": 2,
                "date": TOKEN,
                "impressions": 8,
                "query": "raw row identity",
                "avg_click_position": 18,
                "avg_impression_position": 17,
                "kind": "query",
                "date_utc": "2011-09-16T07:00:00Z",
                "ctr": 0.25,
                "average_position": None,
                "position_scale": "undocumented",
                "page_url": None,
                "selector_query": None,
            }
        ],
        "requested_period": None,
        "observed_period": {"start_date": "2011-09-16", "end_date": "2011-09-16"},
        "provider_cadence": "weekly",
        "source_rows": 1,
        "returned_rows": 1,
        "dropped_rows": 0,
        "local_truncated": False,
        "provider_completeness": "unknown",
        "position_scale": "undocumented",
        "warnings": [
            "provider_completeness_unknown",
            "weekly_buckets",
            "position_scale_undocumented",
            "raw_query_identity",
        ],
        "error": None,
    }


def test_discovery_has_no_implicit_100_site_cap():
    sites = {f"https://site-{n}.com/" for n in range(101)}
    rows = [RawBingSite(Url=site, IsVerified=True) for site in sorted(sites)]
    result = normalize(rows, request("GetUserSites"), approved_sites=sites)
    assert result.returned_rows == 101 and not result.local_truncated


def test_unchecked_wire_copy_revalidated_and_safe_errors(caplog):
    bad = RawBingQueryStats(**QUERY).model_copy(update={"clicks": "SYNTHETIC-FOREIGN"})
    result = normalize([bad, RawBingQueryStats(**QUERY)])
    assert result.status == "partial" and result.dropped_rows == 1
    assert "SYNTHETIC-FOREIGN" not in result.model_dump_json() + caplog.text


@pytest.mark.parametrize(
    "op,raw_type,payload",
    [
        ("GetFeeds", RawBingFeed, FEED),
        ("GetCrawlIssues", RawBingCrawlIssue, ISSUE),
    ],
)
def test_nonanalytics_local_limit_disclosed(op, raw_type, payload):
    result = normalize([raw_type(**payload), raw_type(**payload)], request(op, limit=1))
    assert result.status == "ok" and result.local_truncated
    assert result.source_rows == 2 and result.returned_rows == 1 and result.dropped_rows == 0
    assert "local_limit" in result.warnings


def test_provider_order_preserved_no_aggregation_and_zero_ctr():
    rows = [
        RawBingTrafficStats(**{**TRAFFIC, "Date": token, "Clicks": 0})
        for token in ("/Date(86400000)/", "/Date(0)/")
    ]
    result = normalize(rows, request("GetRankAndTrafficStats", limit=1))
    assert result.records[0].date == "/Date(86400000)/"
    assert result.records[0].ctr == 0.0
    assert "all_verticals" in result.warnings
    assert result.observed_period.start_date == date(1970, 1, 1)
    assert result.local_truncated
