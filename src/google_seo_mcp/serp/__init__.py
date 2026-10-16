"""SERP intelligence — direct queries to Google SERPs via DataForSEO.

DataForSEO is the cheapest pay-as-you-go SERP API in 2026:
  - Live SERP (organic + AI Overview + PAA + featured snippet): ~$0.0006/call
  - Bulk: $0.0009/call advanced
  - 30 queries × 12 months = ~$0.20/year per client

Set ``DATAFORSEO_LOGIN`` and ``DATAFORSEO_PASSWORD`` env vars to enable.
Without them, every tool returns ``{"error": "credentials_missing", "fix": ...}``
so the agent fails gracefully and explains how to enable.

API docs: https://docs.dataforseo.com/v3/serp/google/organic/live/advanced/
"""
from __future__ import annotations

import base64
import json
import math
import os
import re
from typing import Any

import httpx

from ..security import assert_url_is_public

DATAFORSEO_BASE = "https://api.dataforseo.com/v3"
ORGANIC_LIVE_ENDPOINT = "/serp/google/organic/live/advanced"
HOSTED_MAX_KEYWORDS = 20
HOSTED_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def hosted_serp_enabled() -> bool:
    """Use the configured identity even if the environment is changed later."""
    from ..auth import hosted_auth_enabled

    return hosted_auth_enabled() or os.getenv("GOOGLE_SEO_PROFILE", "").lower() == "production"


def validate_hosted_keyword(keyword: str) -> None:
    if (not isinstance(keyword, str) or not 1 <= len(keyword) <= 200 or not keyword.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in keyword)):
        raise ValueError("invalid_serp_input")
    try:
        if len(keyword.encode("utf-8")) > 800:
            raise ValueError("invalid_serp_input")
    except UnicodeError:
        raise ValueError("invalid_serp_input") from None


def _validate_hosted_request(endpoint: str, payload: list[dict[str, Any]], timeout: float) -> None:
    """Reject overrides at the final outbound boundary, before DNS/client creation."""
    if endpoint != ORGANIC_LIVE_ENDPOINT:
        raise ValueError("invalid_serp_endpoint")
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0 < timeout <= 60):
        raise ValueError("invalid_serp_input")
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise ValueError("invalid_serp_input")
    task = payload[0]
    if set(task) != {"keyword", "location_code", "language_code", "device", "depth"}:
        raise ValueError("invalid_serp_input")
    validate_hosted_keyword(task["keyword"])
    if (type(task["location_code"]) is not int or not 1 <= task["location_code"] <= 9_999_999
            or not isinstance(task["language_code"], str)
            or re.fullmatch(r"[a-z]{2}", task["language_code"]) is None
            or task["device"] not in ("mobile", "desktop")
            or type(task["depth"]) is not int or task["depth"] != 20):
        raise ValueError("invalid_serp_input")


class SerpCredentialsMissing(RuntimeError):
    """Raised when DATAFORSEO_LOGIN/PASSWORD are not configured."""


def validate_hosted_observation(resp: Any) -> list[dict[str, Any]]:
    """Qualify one observed SERP before reporting presence or absence.

    Status codes alone do not prove that observation data arrived. Only an
    explicit items list (including []) qualifies as an observed result. Keep
    this validation shared by the terminal helper and the defensive parser.
    Unknown named feature types are permitted; fields consumed by our tools
    must have coherent shapes. Returned URLs are data, never fetch targets.
    """
    def require(condition: bool) -> None:
        if not condition:
            raise RuntimeError("vendor_unavailable")

    def text_fields(record: dict, fields: tuple[str, ...]) -> None:
        for field in fields:
            require(record.get(field) is None or isinstance(record[field], str))

    def nonempty_text(value: Any) -> bool:
        return isinstance(value, str) and bool(value.strip())

    def count(record: dict, field: str, expected: int) -> None:
        if field in record:
            require(type(record[field]) is int and record[field] == expected)

    require(isinstance(resp, dict))
    require(type(resp.get("status_code")) is int and resp["status_code"] == 20000)
    tasks = resp.get("tasks")
    require(isinstance(tasks, list) and len(tasks) == 1 and isinstance(tasks[0], dict))
    count(resp, "tasks_count", 1)
    count(resp, "tasks_error", 0)
    task = tasks[0]
    require(type(task.get("status_code")) is int and task["status_code"] == 20000)
    results = task.get("result")
    require(isinstance(results, list) and len(results) == 1 and isinstance(results[0], dict))
    count(task, "result_count", 1)
    result = results[0]
    items = result.get("items")
    require(isinstance(items, list))
    count(result, "items_count", len(items))
    for item in items:
        require(isinstance(item, dict) and nonempty_text(item.get("type")))
        kind = item["type"]
        if kind == "organic":
            require(type(item.get("rank_absolute")) is int and item["rank_absolute"] > 0)
            require(nonempty_text(item.get("url")))
            text_fields(item, ("title", "description"))
        elif kind == "people_also_ask":
            questions = item.get("items")
            require(isinstance(questions, list))
            for question in questions:
                require(isinstance(question, dict) and nonempty_text(question.get("title")))
                # Unexpanded questions are valid observations even without an answer.
                expanded = question.get("expanded_element")
                require(expanded is None or isinstance(expanded, list))
                for answer in expanded or []:
                    require(isinstance(answer, dict))
                    text_fields(answer, ("url", "description"))
        elif kind == "ai_overview":
            references = item.get("references")
            require(references is None or isinstance(references, list))
            for reference in references or []:
                require(isinstance(reference, dict))
                text_fields(reference, ("url", "title"))
        elif kind == "featured_snippet":
            text_fields(item, ("url", "title", "description"))
        elif kind == "related_searches":
            related = item.get("items")
            require(isinstance(related, list) and all(nonempty_text(query) for query in related))
    return items


def _auth_header() -> dict[str, str]:
    login = os.getenv("DATAFORSEO_LOGIN")
    password = os.getenv("DATAFORSEO_PASSWORD")
    if not login or not password:
        raise SerpCredentialsMissing(
            "DataForSEO credentials missing. Set DATAFORSEO_LOGIN and "
            "DATAFORSEO_PASSWORD env vars (sign up free at "
            "https://dataforseo.com/register — pay-as-you-go, ~$0.0006/SERP)."
        )
    token = base64.b64encode(f"{login}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}


def call_dataforseo(endpoint: str, payload: list[dict[str, Any]], timeout: float = 60.0) -> dict[str, Any]:
    """POST a payload to DataForSEO. Returns the parsed JSON response."""
    # Credential-pending operation must never resolve DNS or create an HTTP client.
    headers = _auth_header()
    if hosted_serp_enabled():
        _validate_hosted_request(endpoint, payload, timeout)
        # Keep the hosted destination independent of any caller-provided URLs.
        url = "https://api.dataforseo.com/v3/serp/google/organic/live/advanced"
        try:
            assert_url_is_public(url)
            with (
                httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client,
                client.stream("POST", url, headers=headers, json=payload) as response,
            ):
                if not 200 <= response.status_code < 300:
                    raise RuntimeError("vendor_unavailable")
                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body) + len(chunk) > HOSTED_MAX_RESPONSE_BYTES:
                        raise RuntimeError("vendor_unavailable")
                    body.extend(chunk)
                parsed = json.loads(body)
            validate_hosted_observation(parsed)
            return parsed
        except Exception:
            # No response text, URL, credential or upstream exception values escape.
            raise RuntimeError("vendor_unavailable") from None
    url = f"{DATAFORSEO_BASE}{endpoint}"
    assert_url_is_public(url)
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as e:
        raise RuntimeError(f"DataForSEO request failed: {type(e).__name__}: {e}") from None
    if r.status_code >= 400:
        raise RuntimeError(f"DataForSEO returned {r.status_code}: {r.text[:300]}")
    return r.json()
