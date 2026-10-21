"""Eleven passive Bing reads; registration owns annotations and guardrail suffix.

configure_bing_tools is a process-composition/test seam, never a tool argument.
The default client is imported/constructed only after complete request validation.
Only the key-aware client may produce records; this layer never echoes requests.
"""

from typing import TYPE_CHECKING

from pydantic import ValidationError

from ..guardrails import with_meta
from .models import BingOperation, BingReadResult, BingToolRequest

if TYPE_CHECKING:
    from .client import IBingReadClient

__all__ = [
    "bing_list_sites", "bing_rank_traffic_stats", "bing_query_stats", "bing_page_stats",
    "bing_page_query_stats", "bing_query_page_stats", "bing_crawl_stats", "bing_crawl_issues",
    "bing_url_info", "bing_list_sitemaps", "bing_sitemap_details",
]

_client: "IBingReadClient | None" = None


def configure_bing_tools(client: "IBingReadClient | None" = None) -> None:
    """Inject a trusted process client, or reset to lazy default; performs no I/O."""
    global _client
    _client = client


def _read(operation: BingOperation, **inputs) -> dict:
    try:
        request = BingToolRequest(operation=operation, **inputs)
    except ValidationError:
        raise RuntimeError("invalid_request") from None
    global _client
    if _client is None:
        from .client import BingReadClient

        _client = BingReadClient(max_retries=0)
    try:
        result = _client.read(operation, request)
        # Protocol annotations alone are not runtime contracts. Reject dicts,
        # subclasses and unchecked/mutated model contents before with_meta can
        # stringify anything. Suppress serialization warnings containing values.
        if type(result) is not BingReadResult:
            raise ValueError
        result = BingReadResult.model_validate(result.model_dump(warnings=False))
        if result.operation != operation:
            raise ValueError
        payload = result.model_dump(mode="json", warnings=False)
    except Exception:
        raise RuntimeError("provider_error") from None
    # In particular, unavailable is an explicit typed error, NEVER empty/ok.
    # Do not rebuild site/selector context from inputs: the client can deliberately
    # clear reflected credentials from its failure provenance.
    return with_meta(
        payload,
        source=result.source,
        site_url=result.site_url,
        period=payload["requested_period"],
        extra={name: payload[name] for name in (
            "operation", "status", "extracted_at", "requested_period", "observed_period",
            "provider_cadence", "source_rows", "returned_rows", "dropped_rows",
            "local_truncated", "provider_completeness", "position_scale", "warnings",
        )},
    )


def bing_list_sites() -> dict:
    """List valid provider-listed Bing properties, including unverified entries.

    Verification codes are omitted; provider completeness remains unknown.
    Business reads require exact membership with strict IsVerified=true in fresh
    discovery; listing alone does not establish read eligibility or permission.
    """
    return _read(BingOperation.GET_USER_SITES)


def bing_rank_traffic_stats(
    site_url: str, start_date: str | None = None, end_date: str | None = None, limit: int = 100,
) -> dict:
    """Read daily all-vertical traffic; dates/limit are local, no rank is inferred."""
    return _read(BingOperation.GET_RANK_AND_TRAFFIC_STATS, site_url=site_url,
                 start_date=start_date, end_date=end_date, limit=limit)


def bing_query_stats(
    site_url: str, start_date: str | None = None, end_date: str | None = None, limit: int = 100,
) -> dict:
    """Read weekly top queries with raw, unscaled positions and unknown completeness."""
    return _read(BingOperation.GET_QUERY_STATS, site_url=site_url,
                 start_date=start_date, end_date=end_date, limit=limit)


def bing_page_stats(
    site_url: str, start_date: str | None = None, end_date: str | None = None, limit: int = 100,
) -> dict:
    """Read weekly top pages, retaining raw Query identity and unscaled positions."""
    return _read(BingOperation.GET_PAGE_STATS, site_url=site_url,
                 start_date=start_date, end_date=end_date, limit=limit)


def bing_page_query_stats(
    site_url: str, page_url: str, start_date: str | None = None,
    end_date: str | None = None, limit: int = 100,
) -> dict:
    """Read weekly queries for one same-property page; no enrichment or fan-out."""
    return _read(BingOperation.GET_PAGE_QUERY_STATS, site_url=site_url, page_url=page_url,
                 start_date=start_date, end_date=end_date, limit=limit)


def bing_query_page_stats(
    site_url: str, query: str, start_date: str | None = None,
    end_date: str | None = None, limit: int = 100,
) -> dict:
    """Read weekly pages for one explicit query; retain raw Query and selector context."""
    return _read(BingOperation.GET_QUERY_PAGE_STATS, site_url=site_url, query=query,
                 start_date=start_date, end_date=end_date, limit=limit)


def bing_crawl_stats(
    site_url: str, start_date: str | None = None, end_date: str | None = None, limit: int = 100,
) -> dict:
    """Read daily Bing crawl counts; date window/limit are local, never fetch a URL."""
    return _read(BingOperation.GET_CRAWL_STATS, site_url=site_url,
                 start_date=start_date, end_date=end_date, limit=limit)


def bing_crawl_issues(site_url: str, limit: int = 100) -> dict:
    """Read crawl issues with raw flags/unknown bits; findings can lag fixes."""
    return _read(BingOperation.GET_CRAWL_ISSUES, site_url=site_url, limit=limit)


def bing_url_info(site_url: str, url: str) -> dict:
    """Read limited Bing URL metadata, not live inspection or an indexed verdict."""
    return _read(BingOperation.GET_URL_INFO, site_url=site_url, url=url)


def bing_list_sitemaps(site_url: str, limit: int = 100) -> dict:
    """Read sitemap metadata only; never submit or enumerate sitemap contents."""
    return _read(BingOperation.GET_FEEDS, site_url=site_url, limit=limit)


def bing_sitemap_details(site_url: str, sitemap_url: str, limit: int = 100) -> dict:
    """Read same-property sitemap-index metadata, not its individual URL contents."""
    return _read(BingOperation.GET_FEED_DETAILS, site_url=site_url,
                 sitemap_url=sitemap_url, limit=limit)
