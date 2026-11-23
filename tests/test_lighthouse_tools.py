"""Lighthouse speed checks from captured PSI 13 responses; no provider calls."""
from __future__ import annotations

import copy
import inspect
import json
import socket
from pathlib import Path
from unittest.mock import Mock

import pytest

from google_seo_mcp.lighthouse import tools

FIXTURE = Path(__file__).with_name("fixtures") / "psi13_fixture.json"
AUDITS = {
    "images": "image-delivery-insight",
    "caching": "cache-insight",
    "minify_css": "unminified-css",
    "minify_javascript": "unminified-javascript",
    "text_compression": "document-latency-insight.usesCompression",
    "server_response": "server-response-time",
}
DESCRIPTION = (
    "Run a full Lighthouse audit (mobile or desktop) via PageSpeed Insights v5. "
    "Returns scores (perf/a11y/best-practices/SEO 0-100), Core Web Vitals, and "
    "speed_checks: the image-delivery, cache-lifetime, minify CSS, minify "
    "JavaScript, text-compression and server-response-time results that the "
    "audit workbook's checks 22.6 to 22.10 read."
)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("unexpected network call")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket.socket, "connect", fail)
    monkeypatch.setattr(socket.socket, "connect_ex", fail)


@pytest.fixture
def psi():
    return json.loads(FIXTURE.read_text())


def run_audit(monkeypatch, payload, strategy="mobile"):
    call = Mock(return_value=payload)
    monkeypatch.setattr(tools, "call_psi", call)
    original = copy.deepcopy(payload)
    result = tools.lighthouse_audit("https://example.com/", strategy=strategy)
    call.assert_called_once_with("https://example.com/", strategy=strategy)
    assert payload == original
    assert result["_meta"]["source"] == f"pagespeed_insights_v5.{strategy}"
    assert result["_meta"]["site_url"] == "https://example.com/"
    summary = dict(result["data"])
    checks = summary.pop("speed_checks")
    assert summary == tools._audit_summary(payload)
    return checks


@pytest.mark.parametrize("strategy", ["mobile", "desktop"])
@pytest.mark.parametrize("site, image_score, image_bytes, cache_score, cache_count, css_score, css_bytes, ms", [
    ("seacoast", 0.5, 47224, 1, 0, 1, 0, 65),
    ("vistaprojects", 0, 611830, 0.5, 6, 0.5, 7592, 71),
])
def test_fixture_speed_checks(monkeypatch, psi, strategy, site, image_score,
                              image_bytes, cache_score, cache_count, css_score, css_bytes, ms):
    payload = psi[site]
    checks = run_audit(monkeypatch, payload, strategy)
    assert set(checks) == {"lighthouse_version", *AUDITS}
    assert checks["lighthouse_version"] == "13.6.0"
    audits = payload["lighthouseResult"]["audits"]
    images = audits["image-delivery-insight"]["details"]["items"]
    caching = audits["cache-insight"]["details"]["items"]
    assert checks["images"] == {
        "audit": AUDITS["images"], "score": image_score,
        "estimated_savings_bytes": image_bytes,
        "items": [{"url": x["url"], "total_bytes": x["totalBytes"],
                   "wasted_bytes": x["wastedBytes"]}
                  for x in sorted(images, key=lambda x: x["wastedBytes"], reverse=True)[:10]],
    }
    assert checks["caching"] == {
        "audit": AUDITS["caching"], "score": cache_score, "item_count": cache_count,
        "items": [{"url": x["url"], "cache_lifetime_ms": x["cacheLifetimeMs"],
                   "total_bytes": x["totalBytes"]}
                  for x in sorted(caching, key=lambda x: x["totalBytes"], reverse=True)[:10]],
    }
    assert checks["minify_css"] == {
        "audit": AUDITS["minify_css"], "score": css_score,
        "estimated_savings_bytes": css_bytes,
    }
    assert checks["minify_javascript"] == {
        "audit": AUDITS["minify_javascript"], "score": 1, "estimated_savings_bytes": 0,
    }
    assert checks["text_compression"] == {"audit": AUDITS["text_compression"], "passed": True}
    assert checks["server_response"] == {"audit": AUDITS["server_response"], "ms": ms}


@pytest.mark.parametrize("site", ["seacoast", "vistaprojects"])
def test_top_ten_sorted_independently_and_totals_include_all_items(monkeypatch, psi, site):
    payload = psi[site]
    audits = payload["lighthouseResult"]["audits"]
    items = [{"url": f"https://example.com/{i}", "totalBytes": 200 - i,
              "wastedBytes": i, "cacheLifetimeMs": i * 1000}
             for i in [5, 0, 12, 3, 9, 1, 7, 11, 2, 10, 6, 4, 8]]
    audits["image-delivery-insight"]["details"]["items"] = copy.deepcopy(items)
    audits["cache-insight"]["details"]["items"] = copy.deepcopy(items)
    # Neither the audit numericValue nor subitems are the image savings total.
    audits["image-delivery-insight"]["numericValue"] = 999999
    audits["image-delivery-insight"]["details"]["items"][0]["subItems"] = {
        "items": [{"wastedBytes": 999999}],
    }
    checks = run_audit(monkeypatch, payload)
    assert checks["images"]["estimated_savings_bytes"] == 78
    assert checks["images"]["items"] == [
        {"url": f"https://example.com/{i}", "total_bytes": 200 - i, "wasted_bytes": i}
        for i in range(12, 2, -1)
    ]
    assert checks["caching"]["item_count"] == 13
    assert checks["caching"]["items"] == [
        {"url": f"https://example.com/{i}", "cache_lifetime_ms": i * 1000,
         "total_bytes": 200 - i} for i in range(10)
    ]


@pytest.mark.parametrize("field, audit_id", AUDITS.items())
def test_each_absent_audit_is_explicit(monkeypatch, psi, field, audit_id):
    payload = psi["seacoast"]
    del payload["lighthouseResult"]["audits"][audit_id.split(".")[0]]
    checks = run_audit(monkeypatch, payload)
    assert checks[field] == {"audit": audit_id, "status": "audit_absent"}
    assert all("status" not in checks[name] for name in AUDITS if name != field)


def test_missing_lighthouse_result_has_no_guessed_values(monkeypatch):
    assert run_audit(monkeypatch, {}) == {
        "lighthouse_version": None,
        **{field: {"audit": audit_id, "status": "audit_absent"}
           for field, audit_id in AUDITS.items()},
    }


@pytest.mark.parametrize("value", [False, None])
def test_compression_value_not_inferred_from_overall_score(monkeypatch, psi, value):
    payload = psi["seacoast"]
    payload["lighthouseResult"]["audits"]["document-latency-insight"]["details"]["items"][
        "usesCompression"]["value"] = value
    assert run_audit(monkeypatch, payload)["text_compression"] == {
        "audit": AUDITS["text_compression"], "passed": value,
    }


def test_missing_compression_check_is_absent(monkeypatch, psi):
    payload = psi["seacoast"]
    del payload["lighthouseResult"]["audits"]["document-latency-insight"]["details"][
        "items"]["usesCompression"]
    assert run_audit(monkeypatch, payload)["text_compression"] == {
        "audit": AUDITS["text_compression"], "status": "audit_absent",
    }


def test_description_is_exact_and_returns_explains_image_sum():
    description = inspect.getdoc(tools.lighthouse_audit)
    assert description.split("\n\n")[0] == DESCRIPTION
    assert 'url: The page to audit (must be publicly reachable).' in description
    assert 'strategy: "mobile" (default, what Google uses for ranking) or "desktop".' in description
    assert "sum of all item wastedBytes" in description.split("Returns:")[1]


def test_other_tools_do_not_gain_speed_checks(monkeypatch, psi):
    monkeypatch.setattr(tools, "call_psi", Mock(return_value=psi["seacoast"]))
    for tool in (tools.lighthouse_core_web_vitals, tools.lighthouse_lcp_opportunities,
                 tools.lighthouse_compare_mobile_desktop, tools.lighthouse_seo_score):
        assert "speed_checks" not in json.dumps(tool("https://example.com/"))
