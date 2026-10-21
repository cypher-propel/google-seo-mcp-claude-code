#!/usr/bin/env python3
"""Operator-only hosted Bing checks. Default: catalog/readiness, ZERO Bing calls.

Live mode requires a bounded nonsecret trusted-operator preflight receipt BEFORE
bearer lookup/network. It is NOT cryptographic authority: the parent must first
read back its actual authorization records, image and deployed composition.
Source readiness is not permission to execute; no receipt is generated here.
--synthetic exercises the real SDK/HTTPX protocol with in-memory fixtures only;
its receipts are never provider qualification. No credential file or argv input.
"""

from __future__ import annotations

import argparse
import asyncio
import html
import json
import logging
import os
import re
import stat
from datetime import UTC, date, datetime
from importlib.resources import files
from pathlib import Path
from urllib.parse import unquote

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

TARGET = "https://google-seo.mcp.propel.marketing/mcp"
PILOT = "https://kelleyconstructioninc.com/"
BING = (
    "bing_list_sites",
    "bing_rank_traffic_stats",
    "bing_query_stats",
    "bing_page_stats",
    "bing_crawl_stats",
    "bing_crawl_issues",
    "bing_list_sitemaps",
    "bing_page_query_stats",
    "bing_query_page_stats",
    "bing_url_info",
    "bing_sitemap_details",
)
OLD = frozenset(
    [
        "cross_gsc_to_ga4_journey",
        "cross_landing_page_full_diagnosis",
        "cross_multi_property_comparison",
        "cross_opportunity_matrix",
        "cross_seo_to_revenue_attribution",
        "cross_traffic_health_check",
        "ga4_anomalies",
        "ga4_channel_attribution",
        "ga4_cohort_retention",
        "ga4_content_decay",
        "ga4_conversion_funnel",
        "ga4_estimate_query_size",
        "ga4_event_volume_comparison",
        "ga4_get_property_details",
        "ga4_landing_page_health",
        "ga4_list_properties",
        "ga4_list_schema_categories",
        "ga4_query",
        "ga4_search_schema",
        "ga4_traffic_drops_by_channel",
        "gsc_alerts",
        "gsc_cannibalization",
        "gsc_content_decay",
        "gsc_ctr_opportunities",
        "gsc_inspect_url",
        "gsc_list_sitemaps",
        "gsc_list_sites",
        "gsc_quick_wins",
        "gsc_search_analytics",
        "gsc_site_snapshot",
        "gsc_traffic_drops",
        "serp_aio_monitor",
        "serp_check",
        "serp_competitor_intersect",
        "serp_paa_extractor",
    ]
)
EXPECTED = OLD | frozenset(BING)
SYNTHETIC_TOKEN = "SYNTHETIC-not-a-real-consumer-key"
TOOLS_SHA256 = "181c6c512c7e42820d2565c2047338609a667eca3e2332fcd5b41c1ccb1f79bf"
OPERATIONS = dict(
    zip(
        BING,
        (
            "GetUserSites",
            "GetRankAndTrafficStats",
            "GetQueryStats",
            "GetPageStats",
            "GetCrawlStats",
            "GetCrawlIssues",
            "GetFeeds",
            "GetPageQueryStats",
            "GetQueryPageStats",
            "GetUrlInfo",
            "GetFeedDetails",
        ),
        strict=True,
    )
)


class SmokeFailure(Exception):
    """Fixed diagnostics only; never contains exception/response text."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise SmokeFailure("invalid_options")


def packaged_catalog():
    """Derive names from the installed manifest; retain independent old/Bing guards."""
    doc = json.loads(files("google_seo_mcp").joinpath("production_tools.json").read_text())
    names = doc["tools"]
    if (
        doc["version"] != 1 or type(names) is not list
        or any(type(name) is not str for name in names)
        or len(names) != len(set(names)) or OLD & frozenset(BING)
        or set(names) != EXPECTED
    ):
        raise SmokeFailure("catalog_manifest_mismatch")
    return frozenset(names)


def validate_target(target, pilot):
    if target != TARGET or pilot != PILOT:
        raise SmokeFailure("unapproved_target_or_pilot")


def safe_selector(value):
    from google_seo_mcp.bing.models import validate_site_selector

    try:
        return validate_site_selector(PILOT, value) == value
    except (ValueError, TypeError, UnicodeError):
        return False


def validate_request(name, args):
    from google_seo_mcp.bing.models import BingToolRequest

    try:
        return BingToolRequest(operation=OPERATIONS[name], **args)
    except Exception:
        raise SmokeFailure("invalid_tool_request") from None


def qualification(options):
    """Shape-check trusted parent readbacks, not signatures or authority.

    Every reference must be read back by the parent BEFORE creating this file;
    this harness cannot verify a Memory Bank record or remote image offline.
    Exact schema intentionally excludes free text, URLs beyond pinned literals,
    secrets, paths, tokens, and arbitrary provider payloads.
    """
    if not options.qualification_file:
        if options.live:
            raise SmokeFailure("qualification_receipt_required")
        return None

    def exact(obj, fields):
        if type(obj) is not dict or set(obj) != set(fields):
            raise ValueError

    def match(value, pattern):
        if type(value) is not str or re.fullmatch(pattern, value) is None:
            raise ValueError

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        if not (options.live or options.synthetic):
            raise ValueError
        fd = os.open(options.qualification_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError
            raw = source.read(8193)
        if len(raw) > 8192:
            raise ValueError
        doc = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        exact(
            doc,
            (
                "version",
                "evidence_class",
                "target",
                "pilot",
                "image_digest",
                "revision",
                "image_qualification_record",
                "composition",
                "authorization",
            ),
        )
        if type(doc["version"]) is not int or doc["version"] != 1:
            raise ValueError
        if doc["evidence_class"] != ("SYNTHETIC" if options.synthetic else "OPERATOR_READBACK"):
            raise ValueError
        validate_target(doc["target"], doc["pilot"])
        match(doc["image_digest"], r"sha256:[0-9a-f]{64}")
        match(doc["revision"], r"[0-9a-f]{40}")
        match(doc["image_qualification_record"], r"record_[0-9a-f]{16}")
        c = doc["composition"]
        exact(c, ("tools_sha256", "max_retries", "review_evidence", "deployed_evidence"))
        if (
            c["tools_sha256"] != TOOLS_SHA256
            or type(c["max_retries"]) is not int
            or c["max_retries"] != 0
        ):
            raise ValueError
        for key in ("review_evidence", "deployed_evidence"):
            match(c[key], r"(?:record|artifact)_[0-9a-f]{16}")
        a = doc["authorization"]
        exact(a, ("hold_record", "hold_at", "coordinator_key_enrolled_record", "key_enrolled_at"))
        for key in ("hold_record", "coordinator_key_enrolled_record"):
            match(a[key], r"record_[0-9a-f]{16}")
        if a["hold_record"] == a["coordinator_key_enrolled_record"]:
            raise ValueError
        for key in ("hold_at", "key_enrolled_at"):
            match(a[key], r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
        hold, enrolled = (
            datetime.fromisoformat(a[k].replace("Z", "+00:00"))
            for k in ("hold_at", "key_enrolled_at")
        )
        if not hold < enrolled <= datetime.now(UTC):
            raise ValueError
        return doc
    except Exception:
        raise SmokeFailure("invalid_qualification_receipt") from None


def sanitize(value, token, _depth=0):
    """Drop sensitive fields; redact whole reflected strings, never raw errors.

    The same bounded check guards selectors and the artifact/stdout boundary.
    Decode percent/HTML and escaped slash/backslash, hex, short/long Unicode
    without evaluating arbitrary escape codecs. Unknown URLs are not evidence
    we may persist; retain only approved pilot URLs. Limits fail closed.
    """
    if _depth > 32:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            k: sanitize(v, token, _depth + 1)
            for k, v in value.items()
            if isinstance(k, str)
            and not re.search(r"auth|cookie|key|token|secret|password|verification|header", k, re.I)
            and sanitize(k, token) == k
        }
    if isinstance(value, list):
        return [sanitize(v, token, _depth + 1) for v in value]
    if isinstance(value, str):
        if len(value) > 65536:
            return "[REDACTED]"
        decoded = value
        needles = {token, unquote(token), html.unescape(token)} - {""}
        for _ in range(8):
            if any(n in decoded for n in needles) or re.search(
                r"bearer\s|apikey[=:%]|authorization", decoded, re.I
            ):
                return "[REDACTED]"
            new = html.unescape(unquote(decoded))
            new = new.replace("\\\\", "\\").replace("\\/", "/")
            try:
                new = re.sub(
                    r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8}))",
                    lambda m: chr(int(next(g for g in m.groups() if g is not None), 16)),
                    new,
                )
            except (ValueError, OverflowError):  # Invalid long Unicode, no raw diagnostics.
                return "[REDACTED]"
            if new == decoded:
                break
            decoded = new
        else:
            # Do not persist strings still transforming at the decoding cap.
            return "[REDACTED]"
        if re.search(r"[a-z][a-z0-9+.-]*://|^//", decoded, re.I) and not safe_selector(decoded):
            return "[REDACTED_URL]"
        return value
    return value if value is None or isinstance(value, (bool, int, float)) else "[REDACTED]"


def payload(result):
    if result.isError:
        raise SmokeFailure("tool_error")
    value = result.structuredContent
    if value is None:
        blocks = [c.text for c in result.content if c.type == "text"]
        if len(blocks) != 1:
            raise SmokeFailure("invalid_tool_payload")
        value = json.loads(blocks[0])
    if not isinstance(value, dict):
        raise SmokeFailure("invalid_tool_payload")
    return value.get("data", value)


async def business(session, receipt, options, *, token):
    """One sequential SDK call/name; upstream bound relies on parent proof."""
    from google_seo_mcp.bing.models import BingReadResult

    attempted = set()

    async def call(name, args):
        # Do not forward a reflected credential (or a redaction placeholder) as
        # a selector. This also covers explicitly supplied operator selectors.
        if sanitize(args, token) != args:
            raise SmokeFailure("unsafe_tool_selector")
        validate_request(name, args)
        if name not in BING or name in attempted or len(attempted) >= 11:
            raise SmokeFailure("call_budget_exceeded")
        attempted.add(name)
        receipt["bing_sdk_calls"] = len(attempted)
        entry = {
            "tool": name,
            "inputs": args,
            "sdk_calls": 1,
            "upstream_attempts": "unobservable_from_hosted_protocol",
        }
        receipt["tools"].append(entry)
        try:
            raw = payload(await session.call_tool(name, args))
            # Real provider contract, not an invented SDK response shape.
            data = BingReadResult.model_validate_json(json.dumps(raw)).model_dump(mode="json")
            if data["operation"] != OPERATIONS[name] or data["site_url"] != args.get("site_url"):
                raise SmokeFailure("mismatched_tool_payload")
        except Exception:
            entry["outcome"] = "protocol_or_tool_error"
            raise SmokeFailure("business_call_failed") from None
        entry.update(
            outcome=data["status"],
            result=data,
            staleness="unqualified_no_freshness_SLA",
            completeness="unknown",
        )
        # A partial MCP success can still carry a typed provider/rate fault.
        # Keep its sanitized result and consume this name, then STOP; no replay.
        if data["error"] is not None:
            raise SmokeFailure("provider_not_qualified")
        return data

    discovery = await call(BING[0], {})
    if discovery["status"] not in ("ok", "partial") or not any(
        row.get("url") == PILOT and row.get("is_verified") is True for row in discovery["records"]
    ):
        raise SmokeFailure("explicit_pilot_not_verified")
    window = {"start_date": options.start_date, "end_date": options.end_date, "limit": 100}
    results = {}
    for name in BING[1:7]:
        args = {"site_url": PILOT, "limit": 100}
        if name in BING[1:5]:
            args.update(window)
        results[name] = await call(name, args)
        if results[name]["status"] not in ("ok", "empty", "partial"):
            raise SmokeFailure("provider_not_qualified")
    # Page identity in raw Query remains unqualified: do not infer a URL from it.
    page = options.page_url
    query = options.query
    sitemap = options.sitemap_url
    if query is None:
        query = next(
            (
                r.get("query")
                for r in results["bing_query_stats"]["records"]
                if isinstance(r.get("query"), str)
                and 1 <= len(r["query"]) <= 512
                and sanitize(r["query"], token) == r["query"]
            ),
            None,
        )
    if sitemap is None:
        sitemap = next(
            (
                r.get("url")
                for r in results["bing_list_sitemaps"]["records"]
                if safe_selector(r.get("url")) and sanitize(r["url"], token) == r["url"]
            ),
            None,
        )
    for name, selector, field in (
        (BING[7], page, "page_url"),
        (BING[8], query, "query"),
        (BING[9], page, "url"),
        (BING[10], sitemap, "sitemap_url"),
    ):
        if selector is None:
            receipt["tools"].append(
                {
                    "tool": name,
                    "outcome": "deferred_missing_approved_selector",
                    "sdk_calls": 0,
                    "upstream_attempts": 0,
                }
            )
            continue
        args = {"site_url": PILOT, field: selector}
        if name != BING[9]:
            args["limit"] = 100
        if name in BING[7:9]:
            args.update(window)
        result = await call(name, args)
        if result["status"] not in ("ok", "empty", "partial"):
            raise SmokeFailure("provider_not_qualified")
    complete = len(attempted) == 11 and all(
        entry["outcome"] in ("ok", "empty") for entry in receipt["tools"]
    )
    receipt["read_smoke_complete"] = complete
    receipt["positive_business_observation"] = any(
        entry["tool"] in BING[1:4] + BING[7:9]
        and any(
            row.get("clicks", 0) > 0 or row.get("impressions", 0) > 0
            for row in entry.get("result", {}).get("records", [])
        )
        for entry in receipt["tools"]
    )
    # This process cannot verify portal/semantic comparison, freshness, host
    # postchecks or Coordinator public re-smoke. Never elevate SDK success.
    receipt["qualification_remaining"] = [
        "provider_semantics_and_freshness_review",
        "host_registry_sibling_image_postchecks",
        "coordinator_independent_public_resmoke",
    ]
    receipt["status"] = (
        "SYNTHETIC_ONLY"
        if options.synthetic
        else "LIVE_READ_SMOKE_COMPLETE"
        if complete
        else "LIVE_READ_SMOKE_PARTIAL_DEFERRED"
    )


def validate_options(options):
    validate_target(options.url, options.pilot)  # BEFORE any credential lookup.
    for value in (options.page_url, options.sitemap_url):
        if value is not None and not safe_selector(value):
            raise SmokeFailure("invalid_selector")
    if options.query is not None and (
        not 1 <= len(options.query) <= 512 or not options.query.isprintable()
    ):
        raise SmokeFailure("invalid_query")
    if (
        options.synthetic
        or options.live
        or options.start_date is not None
        or options.end_date is not None
    ):
        try:
            start, end = (
                date.fromisoformat(options.start_date),
                date.fromisoformat(options.end_date),
            )
            if not 0 <= (end - start).days <= 366:
                raise ValueError()
        except (ValueError, TypeError):
            raise SmokeFailure("explicit_window_required") from None
    # Validate actual shared tool contracts before any bearer or HTTP client.
    validate_request(BING[0], {})
    window = {"start_date": options.start_date, "end_date": options.end_date}
    validate_request(BING[1], {"site_url": PILOT, **window})
    for name, value, field in (
        (BING[7], options.page_url, "page_url"),
        (BING[8], options.query, "query"),
        (BING[9], options.page_url, "url"),
        (BING[10], options.sitemap_url, "sitemap_url"),
    ):
        if value is not None:
            args = {"site_url": PILOT, field: value}
            if name in BING[7:9]:
                args.update(window)
            validate_request(name, args)
    return qualification(options)


async def run(options, *, transport=None):
    logging.disable(logging.CRITICAL)  # SDK/HTTP exceptions may contain secrets.
    receipt = {
        "status": "FAIL",
        "started_at": datetime.now(UTC).isoformat(),
        "mode": "SYNTHETIC" if options.synthetic else "LIVE" if options.live else "PENDING",
        "bing_sdk_calls": 0,
        "tools": [],
        "business_qualified": False,
    }
    token = ""
    try:
        qualified = validate_options(options)
        expected = packaged_catalog()  # Before bearer lookup or network.
        if qualified:
            receipt["trusted_operator_preflight"] = {
                k: v for k, v in qualified.items() if k != "authorization"
            }
            receipt["trusted_operator_preflight"].update(
                hold_record=qualified["authorization"]["hold_record"],
                hold_at=qualified["authorization"]["hold_at"],
                enrollment_record=qualified["authorization"]["coordinator_key_enrolled_record"],
                enrollment_at=qualified["authorization"]["key_enrolled_at"],
            )
            receipt["attempt_bound_basis"] = (
                "parent_readback_zero_retry_1_listing_plus_10_fresh_discovery_and_business_not_SDK_count"
            )
            # Theoretical full-sequence bound, NOT observed sends or budget authority.
            receipt["qualified_upstream_attempts_upper_bound"] = 21
        if transport is not None and not options.synthetic:
            raise SmokeFailure("fixture_transport_requires_synthetic")
        if options.synthetic and transport is None:
            transport = synthetic_transport()
        token = SYNTHETIC_TOKEN if options.synthetic else os.environ.get("GOOGLE_SEO_SMOKE_KEY", "")
        if re.fullmatch(r"[\x21-\x7e]{1,1024}", token) is None:
            raise SmokeFailure("missing_or_invalid_process_bearer")

        async def request_hook(request):
            if str(request.url) not in (
                TARGET,
                TARGET.rsplit("/mcp", 1)[0] + "/healthz",
                TARGET.rsplit("/mcp", 1)[0] + "/readyz",
            ):
                raise SmokeFailure("egress_target_refused")

        async def response_hook(response):
            if 300 <= response.status_code < 400:
                raise SmokeFailure("redirect_refused")

        common = dict(
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(15),
            transport=transport,
            event_hooks={"request": [request_hook], "response": [response_hook]},
        )
        async with httpx.AsyncClient(**common) as anonymous:
            denied = await anonymous.post(TARGET, json={})
            if denied.status_code != 401 or denied.headers.get("www-authenticate") != "Bearer":
                raise SmokeFailure("anonymous_fence_failed")
            base = TARGET.rsplit("/mcp", 1)[0]
            health, ready = (
                await anonymous.get(base + "/healthz"),
                await anonymous.get(base + "/readyz"),
            )
            state = ready.json()
            if health.status_code != 200 or health.json() != {"status": "ok"}:
                raise SmokeFailure("health_failed")
            if (
                ready.status_code != 200
                or state.get("transport_ready") is not True
                or state.get("bing_credentials_state") not in ("pending", "invalid", "available")
            ):
                raise SmokeFailure("readiness_failed")
            if qualified and (
                state.get("revision") != qualified["revision"]
                or state.get("bing_credentials_state") != "available"
            ):
                raise SmokeFailure("qualified_deployment_readiness_mismatch")
            # Never copy opaque probe metadata into an artifact.
            receipt["readiness"] = {
                k: state[k]
                for k in ("google_credentials_state", "bing_credentials_state")
                if state.get(k) in ("pending", "invalid", "available")
            }
            revision = state.get("revision")
            if isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision):
                receipt["readiness"]["revision"] = revision
        async with (
            httpx.AsyncClient(headers={"Authorization": "Bearer " + token}, **common) as http,
            streamable_http_client(TARGET, http_client=http) as (read, write, _),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            names, cursors, cursor = [], set(), None
            for _ in range(len(expected) + 1):
                listed = await session.list_tools(cursor=cursor)
                names.extend(t.name for t in listed.tools)
                cursor = listed.nextCursor
                if cursor is None:
                    break
                if cursor in cursors:
                    raise SmokeFailure("catalog_cursor_cycle")
                cursors.add(cursor)
            else:
                raise SmokeFailure("catalog_page_budget")
            if len(names) != len(expected) or set(names) != expected:
                raise SmokeFailure("catalog_not_exact_manifest")
            receipt["catalog_count"] = len(names)
            # Pending means ZERO tools/call, including discovery/fence probes.
            if options.synthetic or options.live:
                await business(session, receipt, options, token=token)
            else:
                receipt["status"] = "PENDING_CATALOG_ONLY"
                receipt["host_pending_fence_and_provider_probes"] = "parent_owned_not_run_here"
    except BaseExceptionGroup as group:

        def safe_reason(exc):
            if isinstance(exc, SmokeFailure):
                return str(exc)
            if isinstance(exc, BaseExceptionGroup):
                return next(
                    (reason for child in exc.exceptions if (reason := safe_reason(child))), None
                )
            return None

        receipt["error"] = safe_reason(group) or "transport_or_protocol_failure"
    except SmokeFailure as exc:
        receipt["error"] = str(exc)  # Only locally constructed closed diagnostics.
    except (Exception, KeyboardInterrupt):
        receipt["error"] = "transport_or_protocol_failure"  # Never str(exception).
    if options.live and receipt["status"] == "FAIL" and receipt["bing_sdk_calls"]:
        receipt["status"] = "LIVE_READ_SMOKE_PARTIAL_DEFERRED"
    receipt["finished_at"] = datetime.now(UTC).isoformat()
    return sanitize(receipt, token)


def synthetic_transport():
    """In-memory HTTP MCP peer; SYNTHETIC empty data, never vendor evidence."""

    def handler(request):
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/readyz":
            return httpx.Response(
                200,
                json={
                    "status": "transport-ready",
                    "transport_ready": True,
                    "bing_credentials_state": "pending",
                },
            )
        if "authorization" not in request.headers:
            return httpx.Response(401, headers={"www-authenticate": "Bearer"})
        if request.method != "POST":
            return httpx.Response(405)
        body = json.loads(request.content)
        method = body["method"]
        if "id" not in body:
            return httpx.Response(202)
        if method == "initialize":
            result = {
                "protocolVersion": body["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "SYNTHETIC", "version": "1"},
            }
        elif method == "tools/list":
            result = {
                "tools": [{"name": n, "inputSchema": {"type": "object"}} for n in sorted(packaged_catalog())]
            }
        else:
            # No fabricated provider rows: default dry run aborts discovery as empty.
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "empty",
                                "operation": "GetUserSites",
                                "records": [],
                                "extracted_at": "2026-01-01T00:00:00Z",
                            }
                        ),
                    }
                ]
            }
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    return httpx.MockTransport(handler)


def parser():
    p = SafeParser(description=__doc__)
    p.add_argument("--url", default=TARGET)
    p.add_argument("--pilot", required=True)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--synthetic", action="store_true")
    mode.add_argument("--live", action="store_true")
    p.add_argument(
        "--qualification-file", help="Nonsecret trusted parent preflight JSON; not authority"
    )
    for flag in ("start-date", "end-date", "page-url", "query", "sitemap-url", "output"):
        p.add_argument("--" + flag)
    return p


def main(argv=None):
    logging.disable(logging.CRITICAL)
    try:
        options = parser().parse_args(argv)
        receipt = asyncio.run(asyncio.wait_for(run(options), timeout=240))
        encoded = json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False)
        if options.output:
            Path(options.output).write_text(encoded + "\n")  # Already sanitized.
        print(encoded)
        if receipt["status"] == "FAIL" or "error" in receipt:
            return 1
        return 2 if receipt["status"] == "LIVE_READ_SMOKE_PARTIAL_DEFERRED" else 0
    except (Exception, KeyboardInterrupt):
        print('{"status":"FAIL","error":"operator_smoke_failed"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
