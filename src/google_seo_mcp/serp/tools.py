"""SERP tools registered with the MCP server."""
from __future__ import annotations

from typing import Any
import re
from urllib.parse import urlsplit

from ..guardrails import with_meta
from . import (HOSTED_MAX_KEYWORDS, ORGANIC_LIVE_ENDPOINT, SerpCredentialsMissing,
               call_dataforseo, hosted_serp_enabled, validate_hosted_keyword,
               validate_hosted_observation)


# Common location codes (DataForSEO uses these — full list at
# https://docs.dataforseo.com/v3/serp/google/locations)
LOCATION_CODES = {
    "es": 2724,    # Spain
    "us": 2840,    # United States
    "uk": 2826,    # United Kingdom
    "fr": 2250,    # France
    "de": 2276,    # Germany
    "mx": 2484,    # Mexico
    "ar": 2032,    # Argentina
    "br": 2076,    # Brazil
    "co": 2170,    # Colombia
}


def _resolve_location(code: str) -> int:
    """Translate a 2-letter code into DataForSEO's location_code."""
    if code.isdigit():
        return int(code)
    return LOCATION_CODES.get(code.lower(), 2840)  # default US


def _serp_payload(
    keyword: str,
    location: str,
    device: str,
    language_code: str = "es",
) -> list[dict]:
    if hosted_serp_enabled():
        validate_hosted_keyword(keyword)
        if (not isinstance(location, str) or len(location) > 7
                or (location not in LOCATION_CODES
                    and re.fullmatch(r"[1-9][0-9]{0,6}", location) is None)
                or device not in ("mobile", "desktop")
                or not isinstance(language_code, str)
                or re.fullmatch(r"[a-z]{2}", language_code) is None):
            raise ValueError("invalid_serp_input")
    return [{
        "keyword": keyword,
        "location_code": _resolve_location(location),
        "language_code": language_code,
        "device": device,
        "depth": 20,  # top 20 results
    }]


def serp_check(
    keyword: str,
    location: str = "es",
    device: str = "mobile",
    language_code: str = "es",
) -> dict:
    """Live Google SERP for one keyword. Returns organic results + AI Overview
    presence + People Also Ask + featured snippet + related searches.

    Use this to confirm whether a query that LOST CTR over time has gained an
    AI Overview that's eating the click — the explanation our gsc_ctr_opportunities
    tool can only INFER.

    Args:
        keyword: the query to check (e.g. ``"running shoes for flat feet"``).
        location: 2-letter country code or DataForSEO location_code as string.
        device: ``"mobile"`` (default — what Google indexes) or ``"desktop"``.
        language_code: 2-letter language code (default ``"es"``).
    """
    try:
        resp = call_dataforseo(
            ORGANIC_LIVE_ENDPOINT,
            _serp_payload(keyword, location, device, language_code),
        )
    except SerpCredentialsMissing as e:
        return with_meta(
            {"error": "credentials_missing", "fix": str(e)},
            source="serp.serp_check",
        )

    # Parse the result
    out = _summarise_serp(resp, keyword=keyword)
    return with_meta(
        out,
        source="serp.serp_check",
        extra={"keyword": keyword, "location": location, "device": device},
    )


def serp_aio_monitor(
    keywords: list[str],
    location: str = "es",
    device: str = "mobile",
    language_code: str = "es",
) -> dict:
    """Batch AI Overview presence check for a list of keywords.

    Useful as the answer to "which of my top GSC queries have AI Overview
    eating the click". Pair with ``gsc_ctr_opportunities`` to confirm
    your hypothesis: high-impressions, low-CTR queries with AIO present
    are the ones that need rewriting for citation, not just title tweaks.
    """
    if hosted_serp_enabled():
        if not isinstance(keywords, list) or not 1 <= len(keywords) <= HOSTED_MAX_KEYWORDS:
            raise ValueError("invalid_serp_input")
        # Validate the whole batch before its first billable request.
        for keyword in keywords:
            _serp_payload(keyword, location, device, language_code)
    if not keywords:
        return with_meta({"error": "keywords list is empty"}, source="serp.serp_aio_monitor")
    if len(keywords) > 100:
        return with_meta(
            {"error": f"too many keywords ({len(keywords)}); cap at 100 to control cost"},
            source="serp.serp_aio_monitor",
        )

    findings = []
    errors = []
    for kw in keywords:
        try:
            resp = call_dataforseo(
                ORGANIC_LIVE_ENDPOINT,
                _serp_payload(kw, location, device, language_code),
            )
            summary = _summarise_serp(resp, keyword=kw)
            findings.append({
                "keyword": kw,
                "has_aio": summary["has_aio"],
                "has_featured_snippet": summary["has_featured_snippet"],
                "has_paa": bool(summary["paa"]),
                "paa_count": len(summary["paa"]),
                "top_organic": summary["organic"][:3],
                "aio_sources": summary.get("aio_sources", []),
            })
        except SerpCredentialsMissing as e:
            return with_meta(
                {"error": "credentials_missing", "fix": str(e)},
                source="serp.serp_aio_monitor",
            )
        except Exception as e:  # noqa: BLE001 — collect per-query errors
            errors.append({
                "keyword": kw,
                "error": "vendor_unavailable" if hosted_serp_enabled() else str(e)[:200],
            })

    aio_count = sum(1 for f in findings if f["has_aio"])
    return with_meta(
        {
            "checked": len(findings),
            "with_aio": aio_count,
            "with_featured_snippet": sum(1 for f in findings if f["has_featured_snippet"]),
            "with_paa": sum(1 for f in findings if f["has_paa"]),
            "findings": findings,
            "errors": errors,
        },
        source="serp.serp_aio_monitor",
        extra={
            "queries": len(keywords),
            "location": location,
            "device": device,
        },
    )


def serp_paa_extractor(
    keyword: str,
    location: str = "es",
    device: str = "mobile",
    language_code: str = "es",
) -> dict:
    """Extract People Also Ask questions from a Google SERP.

    Each PAA is a content brief opportunity — Google literally tells you
    what users want to know around your topic. Pair with your migration
    plan: each PAA is a candidate FAQ entry on the new site.
    """
    try:
        resp = call_dataforseo(
            ORGANIC_LIVE_ENDPOINT,
            _serp_payload(keyword, location, device, language_code),
        )
    except SerpCredentialsMissing as e:
        return with_meta(
            {"error": "credentials_missing", "fix": str(e)},
            source="serp.serp_paa_extractor",
        )
    summary = _summarise_serp(resp, keyword=keyword)
    return with_meta(
        {
            "keyword": keyword,
            "paa": summary["paa"],
            "paa_count": len(summary["paa"]),
        },
        source="serp.serp_paa_extractor",
        extra={"keyword": keyword, "location": location},
    )


def _identity_hostname(value: Any, *, allow_bare: bool = False) -> str | None:
    """Parse observation identity locally; never resolve or fetch a URL.

    Only legacy targets may be bare hosts. Explicit labels (including www)
    remain part of the identity; a single DNS root dot is insignificant.
    """
    if (not isinstance(value, str) or not value
            or any(ord(char) < 33 or ord(char) == 127 for char in value)):
        return None
    try:
        parsed = urlsplit(value)
        if allow_bare and "://" not in value and not value.startswith("//"):
            parsed = urlsplit("//" + value)
        elif parsed.scheme not in ("http", "https"):
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        _ = parsed.port  # Invalid ports are malformed observations, not identities.
        host = parsed.hostname
        if not host:
            return None
        host = host.lower().removesuffix(".")
        if (not host or host.startswith(".") or host.endswith(".")
                or ".." in host or re.search(r"[\s/@\\?#%]", host)):
            return None
        return host
    except (TypeError, ValueError, AttributeError):
        return None


def _matches_hostname(result_url: Any, target_host: str | None) -> bool:
    """Match an exact host or a genuine dot-boundary subdomain."""
    result_host = _identity_hostname(result_url)
    return bool(target_host and result_host and (
        result_host == target_host or result_host.endswith("." + target_host)
    ))


def serp_competitor_intersect(
    keyword: str,
    your_url: str,
    location: str = "es",
    device: str = "mobile",
    language_code: str = "es",
) -> dict:
    """Who ranks above you for a query? Useful in migration: confirm your
    competitors haven't migrated to a stack you can't beat (or did and won).

    Returns top 10 organic with positions + your_url's position (if any) +
    domains above and below you.
    """
    if hosted_serp_enabled():
        try:
            if not isinstance(your_url, str) or not 1 <= len(your_url) <= 2048:
                raise ValueError
            parsed = urlsplit(your_url)
            if (parsed.scheme not in ("http", "https") or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or any(ord(char) < 33 or ord(char) == 127 for char in your_url)):
                raise ValueError
            _ = parsed.port  # Reject malformed ports without DNS or URL fetch.
        except (TypeError, ValueError, AttributeError):
            raise ValueError("invalid_serp_input") from None
    try:
        resp = call_dataforseo(
            ORGANIC_LIVE_ENDPOINT,
            _serp_payload(keyword, location, device, language_code),
        )
    except SerpCredentialsMissing as e:
        return with_meta(
            {"error": "credentials_missing", "fix": str(e)},
            source="serp.serp_competitor_intersect",
        )
    summary = _summarise_serp(resp, keyword=keyword)
    organic = summary["organic"][:10]

    your_host = _identity_hostname(your_url, allow_bare=True)
    your_position = None
    for r in organic:
        if _matches_hostname(r.get("url"), your_host):
            your_position = r.get("position")
            break

    above = [r for r in organic if r.get("position") and (your_position is None or r["position"] < your_position)]
    below = [r for r in organic if r.get("position") and your_position is not None and r["position"] > your_position]

    return with_meta(
        {
            "keyword": keyword,
            "your_url": your_url,
            "your_position": your_position,
            "in_top_10": your_position is not None,
            "competitors_above": [{"position": r["position"], "url": r["url"], "title": r.get("title", "")[:120]} for r in above],
            "competitors_below": [{"position": r["position"], "url": r["url"], "title": r.get("title", "")[:120]} for r in below[:5]],
            "has_aio": summary["has_aio"],
        },
        source="serp.serp_competitor_intersect",
        extra={"keyword": keyword, "your_url": your_url},
    )


def _summarise_serp(resp: dict[str, Any], *, keyword: str) -> dict[str, Any]:
    """Extract the high-signal fields from a DataForSEO SERP response."""
    hosted = hosted_serp_enabled()
    # Defend this boundary as well when the transport is substituted or reused.
    if hosted:
        items = validate_hosted_observation(resp)
    out: dict[str, Any] = {
        "keyword": keyword,
        "has_aio": False,
        "has_featured_snippet": False,
        "aio_sources": [],
        "organic": [],
        "paa": [],
        "related_searches": [],
        "raw_status": "ok" if hosted else resp.get("status_message"),
    }
    if not hosted:
        tasks = resp.get("tasks") or []
        if not tasks:
            return out
        items = (tasks[0].get("result") or [{}])[0].get("items") or []
    for item in items:
        item_type = item.get("type", "")
        if item_type == "ai_overview":
            out["has_aio"] = True
            refs = item.get("references") or []
            out["aio_sources"] = [
                {"url": r.get("url"), "title": (r.get("title") or "")[:200]}
                for r in refs[:10]
            ]
        elif item_type == "featured_snippet":
            out["has_featured_snippet"] = True
            out["featured_snippet"] = {
                "url": item.get("url"),
                "title": item.get("title"),
                "description": (item.get("description") or "")[:500],
            }
        elif item_type == "organic":
            out["organic"].append({
                "position": item.get("rank_absolute"),
                "url": item.get("url"),
                "title": (item.get("title") or "")[:200],
                "description": (item.get("description") or "")[:300],
            })
        elif item_type == "people_also_ask":
            for q in (item.get("items") or []):
                out["paa"].append({
                    "question": q.get("title"),
                    "answer_url": (q.get("expanded_element") or [{}])[0].get("url"),
                    "answer_snippet": ((q.get("expanded_element") or [{}])[0].get("description") or "")[:300],
                })
        elif item_type == "related_searches":
            out["related_searches"] = list(item.get("items") or [])[:10]
    return out
