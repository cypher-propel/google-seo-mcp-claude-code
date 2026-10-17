"""Pure Bing semantics; documentation-derived, not live-provider qualification.

Observed period is the UTC date extent of valid source analytics rows BEFORE
local filtering/limiting. Source rows includes rejected wire rows reported by
the client; drops excludes policy/window/limit exclusions. No aggregation occurs.
"""

import re
from collections.abc import Collection, Sequence
from datetime import UTC, date, datetime, timedelta

from pydantic import ValidationError

from .models import (
    ANALYTICS_OPERATIONS,
    BingCrawlIssueRecord,
    BingCrawlRecord,
    BingFeedRecord,
    BingOperation,
    BingPeriod,
    BingProviderFault,
    BingQueryRecord,
    BingReadResult,
    BingSiteRecord,
    BingToolRequest,
    BingTrafficRecord,
    BingUrlInfoRecord,
    CrawlIssueName,
    validate_public_url,
)
from .wire_models import (
    BingWireModel,
    RawBingCrawlIssue,
    RawBingCrawlStats,
    RawBingFeed,
    RawBingQueryStats,
    RawBingSite,
    RawBingTrafficStats,
    RawBingUrlInfo,
)

_WCF_DATE = re.compile(r"/Date\((-?[0-9]{1,18})(?:[+-][0-9]{4})?\)/", re.ASCII)
_FLAGS: tuple[tuple[int, CrawlIssueName], ...] = (
    (1, "Code301"),
    (2, "Code302"),
    (4, "Code4xx"),
    (8, "Code5xx"),
    (16, "BlockedByRobotsTxt"),
    (32, "ContainsMalware"),
    (64, "ImportantUrlBlockedByRobotsTxt"),
    (128, "DnsErrors"),
    (256, "TimeOutErrors"),
)
_QUERY_OPERATIONS = frozenset(
    {
        BingOperation.GET_QUERY_STATS,
        BingOperation.GET_PAGE_STATS,
        BingOperation.GET_PAGE_QUERY_STATS,
        BingOperation.GET_QUERY_PAGE_STATS,
    }
)
_RAW_TYPES = {
    BingOperation.GET_USER_SITES: RawBingSite,
    BingOperation.GET_RANK_AND_TRAFFIC_STATS: RawBingTrafficStats,
    BingOperation.GET_CRAWL_STATS: RawBingCrawlStats,
    BingOperation.GET_CRAWL_ISSUES: RawBingCrawlIssue,
    BingOperation.GET_URL_INFO: RawBingUrlInfo,
    BingOperation.GET_FEEDS: RawBingFeed,
    BingOperation.GET_FEED_DETAILS: RawBingFeed,
    **dict.fromkeys(_QUERY_OPERATIONS, RawBingQueryStats),
}


def parse_bing_datetime(raw: str) -> datetime:
    """Parse WCF epoch milliseconds to aware UTC, ignoring optional offset.

    The suffix is serializer metadata, NOT another shift of the epoch instant.
    Only documented WCF tokens are admitted; absent/malformed/out-of-range data
    raises static ValueError, never an invented date or a reflected raw token.
    """
    match = _WCF_DATE.fullmatch(raw) if type(raw) is str else None
    if match is None:
        raise ValueError("invalid_bing_datetime")
    try:
        return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(milliseconds=int(match[1]))
    except (OverflowError, ValueError):
        raise ValueError("invalid_bing_datetime") from None


def decode_bing_crawl_issues(raw_mask: int) -> tuple[list[CrawlIssueName], int]:
    """Return official names in bit order and unrecognized bits, without loss."""
    if type(raw_mask) is not int or raw_mask < 0:
        raise ValueError("invalid_bing_issue_mask")
    known = [name for bit, name in _FLAGS if raw_mask & bit] if raw_mask else ["None"]
    return known, raw_mask & ~511


def _record(row, request):
    data = row.model_dump()
    if isinstance(row, RawBingSite):
        return BingSiteRecord(**data)
    if isinstance(row, RawBingQueryStats | RawBingTrafficStats):
        if row.clicks > row.impressions:
            raise ArithmeticError("invalid_metrics")
        parsed = parse_bing_datetime(row.date)
        ctr = row.clicks / row.impressions if row.impressions else None
        if isinstance(row, RawBingQueryStats):
            return BingQueryRecord(
                **data,
                date_utc=parsed,
                ctr=ctr,
                page_url=request.page_url,
                selector_query=request.query,
            )
        return BingTrafficRecord(**data, date_utc=parsed, ctr=ctr)
    if isinstance(row, RawBingCrawlStats):
        return BingCrawlRecord(**data, date_utc=parse_bing_datetime(row.date))
    if isinstance(row, RawBingCrawlIssue):
        known, unknown = decode_bing_crawl_issues(row.issues)
        return BingCrawlIssueRecord(**data, known_issues=known, unknown_bits=unknown)
    if isinstance(row, RawBingUrlInfo):
        return BingUrlInfoRecord(
            **data,
            discovery_date_utc=parse_bing_datetime(row.discovery_date),
            last_crawled_date_utc=parse_bing_datetime(row.last_crawled_date),
        )
    return BingFeedRecord(
        **data,
        last_crawled_utc=parse_bing_datetime(row.last_crawled),
        submitted_utc=parse_bing_datetime(row.submitted),
    )


def normalize_bing_rows(
    operation: BingOperation,
    validated_wire_rows: Sequence[BingWireModel],
    request: BingToolRequest,
    *,
    approved_sites: Collection[str] | None = None,
    invalid_wire_rows: int = 0,
    invalid_wire_dates: int = 0,
    invalid_wire_metrics: int = 0,
) -> BingReadResult:
    """Normalize one validated response; never fetch, sort, aggregate or fan out.

    Client MUST pass configured approved_sites on discovery (missing fails closed).
    It MUST report rows rejected during wire validation using invalid_wire_rows.
    Optional date/metric counters are disjoint subsets of that total and affect
    safe diagnostics only. Invalid counters raise static ValueError (caller bug).
    Client owns envelope/null/fault validation and key-aware reflection rejection.
    """
    counters = (invalid_wire_rows, invalid_wire_dates, invalid_wire_metrics)
    if (
        any(type(n) is not int or n < 0 for n in counters)
        or invalid_wire_dates + invalid_wire_metrics > invalid_wire_rows
    ):
        raise ValueError("invalid_wire_counters")
    # Revalidate captured models rather than trust unchecked construction/copy.
    request = BingToolRequest.model_validate(request.model_dump())
    if not isinstance(operation, BingOperation) or operation != request.operation:
        return BingReadResult(
            status="invalid_request",
            operation=request.operation,
            site_url=request.site_url,
            extracted_at=datetime.now(UTC),
            error=BingProviderFault(code="invalid_request"),
        )
    if operation == BingOperation.GET_USER_SITES:
        try:
            if approved_sites is None or isinstance(approved_sites, str | bytes):
                raise ValueError
            approved_sites = frozenset(validate_public_url(site) for site in approved_sites)
        except (ValueError, TypeError):
            return BingReadResult(
                status="invalid_request",
                operation=operation,
                extracted_at=datetime.now(UTC),
                error=BingProviderFault(code="invalid_request"),
            )
    requested = (
        None
        if request.start_date is None
        else BingPeriod(
            start_date=date.fromisoformat(request.start_date),
            end_date=date.fromisoformat(request.end_date),
        )
    )
    warnings = ["provider_completeness_unknown"]
    cadence = "unknown"
    if operation in ANALYTICS_OPERATIONS:
        cadence = "weekly" if operation in _QUERY_OPERATIONS else "daily"
    if operation in _QUERY_OPERATIONS:
        warnings.extend(["weekly_buckets", "position_scale_undocumented", "raw_query_identity"])
        if request.page_url is not None or request.query is not None:
            warnings.append("selector_context")
    if operation == BingOperation.GET_RANK_AND_TRAFFIC_STATS:
        warnings.append("all_verticals")
    if operation == BingOperation.GET_CRAWL_ISSUES:
        warnings.append("crawl_issue_lag")
    if operation == BingOperation.GET_URL_INFO:
        warnings.append("url_info_limited")
    if operation in {BingOperation.GET_FEEDS, BingOperation.GET_FEED_DETAILS}:
        warnings.append("sitemap_metadata_only")
    if requested is not None:
        warnings.extend(["local_date_filter", "utc_date_filter", "window_not_exact"])
    records, dates = [], []
    dropped, bad_dates, bad_metrics = counters
    for row in validated_wire_rows:
        if type(row) is not _RAW_TYPES[operation]:
            dropped += 1
            continue
        try:
            row = _RAW_TYPES[operation].model_validate(row.model_dump(warnings=False))
        except ValidationError:
            dropped += 1
            continue
        try:
            record = _record(row, request)
        except ArithmeticError:
            dropped += 1
            bad_metrics += 1
            continue
        except ValueError:
            dropped += 1
            bad_dates += 1
            continue
        if operation == BingOperation.GET_USER_SITES and (
            not record.is_verified or record.url not in approved_sites
        ):
            continue
        if operation in ANALYTICS_OPERATIONS:
            day = record.date_utc.date()
            dates.append(day)
            if requested is not None and not requested.start_date <= day <= requested.end_date:
                continue
        if (
            isinstance(record, BingCrawlIssueRecord)
            and record.unknown_bits
            and "unknown_issue_bits" not in warnings
        ):
            warnings.append("unknown_issue_bits")
        records.append(record)
    observed = BingPeriod(start_date=min(dates), end_date=max(dates)) if dates else None
    # Discovery has no public limit; do not silently cap approved site discovery.
    truncated = operation != BingOperation.GET_USER_SITES and len(records) > request.limit
    if truncated:
        records = records[: request.limit]
        warnings.append("local_limit")
    if dropped:
        warnings.append("invalid_rows_dropped")
    if bad_dates:
        warnings.append("invalid_dates_dropped")
    if bad_metrics:
        warnings.append("invalid_metrics_dropped")
    status = (
        ("partial" if records else "provider_error") if dropped else ("ok" if records else "empty")
    )
    return BingReadResult(
        status=status,
        operation=operation,
        site_url=request.site_url,
        extracted_at=datetime.now(UTC),
        records=records,
        requested_period=requested,
        observed_period=observed,
        provider_cadence=cadence,
        source_rows=len(validated_wire_rows) + invalid_wire_rows,
        returned_rows=len(records),
        dropped_rows=dropped,
        local_truncated=truncated,
        provider_completeness="unknown",
        position_scale="undocumented" if operation in _QUERY_OPERATIONS else None,
        warnings=warnings,
        error=BingProviderFault(code="invalid_response") if status == "provider_error" else None,
    )
