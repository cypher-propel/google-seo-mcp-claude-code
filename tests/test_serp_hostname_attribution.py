"""Offline public-intersect identity regressions; no result URL is a fetch target."""
from unittest.mock import Mock

import pytest

from google_seo_mcp.serp import tools


@pytest.fixture(params=[False, True], ids=["legacy", "hosted"])
def intersect(request, monkeypatch):
    monkeypatch.setattr(tools, "hosted_serp_enabled", lambda: request.param)
    # Trap both HTTP transports and DNS, even though the provider is substituted.
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "create_connection"):
        monkeypatch.setattr(
            f"socket.{name}", Mock(side_effect=AssertionError("DNS/network forbidden"))
        )
    for name in ("Client", "AsyncClient", "request", "get", "post", "stream"):
        monkeypatch.setattr(f"httpx.{name}", Mock(side_effect=AssertionError("HTTP forbidden")))

    def run(urls, target="https://example.org/"):
        items = [dict(type="organic", rank_absolute=i, url=url, title=f"Result {i}")
                 for i, url in enumerate(urls, 1)]
        observation = {"status_code": 20000, "tasks": [{"status_code": 20000,
                       "result": [{"items": items}]}]}
        provider = Mock(return_value=observation)
        monkeypatch.setattr(tools, "call_dataforseo", provider)
        result = tools.serp_competitor_intersect("offline identity", target)["data"]
        provider.assert_called_once_with(tools.ORGANIC_LIVE_ENDPOINT, [{
            "keyword": "offline identity", "location_code": 2724,
            "language_code": "es", "device": "mobile", "depth": 20,
        }])
        return result

    run.hosted = request.param
    return run


IMPOSTORS = [
    "https://example.org.other.test/",  # Historical false-match observation.
    "https://notexample.org/",
    "https://example.org-impostor.test/",
    "https://other.test/example.org/",
    "https://other.test/?next=https://example.org/",
    "https://other.test/#example.org",
    "https://example.org@other.test/",
]


@pytest.mark.parametrize("url", IMPOSTORS)
def test_impostor_is_absent_and_all_competitors_above(intersect, url):
    urls = [url, "https://unrelated.test/"]
    data = intersect(urls)
    assert (data["your_position"], data["in_top_10"]) == (None, False)
    assert [r["url"] for r in data["competitors_above"]] == urls
    assert data["competitors_below"] == []


@pytest.mark.parametrize(("target", "url"), [
    ("https://example.org/", "https://example.org/page"),
    ("https://example.org/", "https://shop.example.org/page"),
    ("https://EXAMPLE.ORG/", "https://Shop.Example.Org/page"),
    ("https://example.org./", "https://example.org/page"),
    ("https://example.org/", "https://shop.example.org./page"),
    ("https://example.org/", "https://www.example.org/"),
    ("https://www.example.org/", "https://www.example.org/page"),
    ("https://www.example.org/", "https://shop.www.example.org/"),
    ("https://example.org:8443/path?ignored=yes", "http://example.org:8080/"),
])
def test_positive_identity_and_partitions(intersect, target, url):
    urls = ["https://other.test/", url, "https://below.test/"]
    data = intersect(urls, target)
    assert (data["your_position"], data["in_top_10"]) == (2, True)
    assert [r["url"] for r in data["competitors_above"]] == urls[:1]
    assert [r["url"] for r in data["competitors_below"]] == urls[2:]
    assert data["your_url"] == target


@pytest.mark.parametrize("target", ["https://www.example.org/", "https://shop.example.org/"])
@pytest.mark.parametrize("url", ["https://example.org/", "https://other.example.org/"])
def test_explicit_labels_are_not_stripped(intersect, target, url):
    assert intersect([url], target)["your_position"] is None


def test_first_genuine_match_after_impostors(intersect):
    urls = IMPOSTORS[:4] + ["https://www.example.org/", "https://example.org/", "https://below.test/"]
    data = intersect(urls)
    assert (data["your_position"], data["in_top_10"]) == (5, True)
    assert [r["position"] for r in data["competitors_above"]] == [1, 2, 3, 4]
    assert [r["position"] for r in data["competitors_below"]] == [6, 7]


@pytest.mark.parametrize("url", [
    "example.org/path", "//example.org/path", "/example.org", "https:///example.org",
    "https://[example.org/", "https://example.org:bad/", "https://example.org:99999/",
    "https://example.org../", "https://.example.org/", "https://example.org /",
    "https://example.org\n/", "javascript:example.org", "https://example.org%2e/",
])
def test_malformed_result_identity_does_not_match(intersect, url):
    assert intersect([url])["your_position"] is None


@pytest.mark.parametrize("target", [
    "example.org", "EXAMPLE.ORG/path", "example.org./path", "www.example.org/path",
])
def test_legacy_bare_target_compatibility(monkeypatch, target):
    # A separate legacy-only fixture avoids relaxing hosted URL validation.
    monkeypatch.setattr(tools, "hosted_serp_enabled", lambda: False)
    provider = Mock(return_value={"tasks": [{"result": [{"items": [
        {"type": "organic", "rank_absolute": 1, "url": "https://www.example.org/"},
    ]}]}]})
    monkeypatch.setattr(tools, "call_dataforseo", provider)
    monkeypatch.setattr("socket.getaddrinfo", Mock(side_effect=AssertionError("DNS forbidden")))
    monkeypatch.setattr("httpx.Client", Mock(side_effect=AssertionError("HTTP forbidden")))
    data = tools.serp_competitor_intersect("offline identity", target)["data"]
    assert (data["your_position"], data["in_top_10"]) == (1, True)


@pytest.mark.parametrize("url", [None, "", 42, {}, []])
def test_legacy_missing_or_nontext_result_is_nonmatch(monkeypatch, url):
    monkeypatch.setattr(tools, "hosted_serp_enabled", lambda: False)
    observation = {"tasks": [{"result": [{"items": [
        {"type": "organic", "rank_absolute": 1, "url": url},
    ]}]}]}
    monkeypatch.setattr(tools, "call_dataforseo", Mock(return_value=observation))
    data = tools.serp_competitor_intersect("offline identity", "https://example.org/")["data"]
    assert data["your_position"] is None


def test_only_first_ten_organic_and_five_below(intersect):
    urls = ["https://example.org/"] + [f"https://other{i}.test/" for i in range(11)]
    data = intersect(urls)
    assert [r["position"] for r in data["competitors_below"]] == [2, 3, 4, 5, 6]
    urls[0], urls[10] = urls[10], urls[0]
    assert intersect(urls)["your_position"] is None
