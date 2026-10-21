"""Search Analytics tools — basic queries."""
from __future__ import annotations

import time

from ...auth import get_google_account_registry, get_webmasters, is_hosted_production
from ...google_accounts.models import GoogleRequestDeadline
from ...guardrails import with_meta
from ..analytics import aggregate_totals, query_search_analytics
from ..dates import period, prior_period


class _BoundRead:
    """Request-local property executor, never an unbound hosted SDK handle."""

    def __init__(self, executor):
        self.executor = executor


def _read_client(site_url, legacy_getter):
    if not is_hosted_production():
        return legacy_getter()
    deadline = GoogleRequestDeadline(end=time.monotonic() + 60.0)
    return _BoundRead(get_google_account_registry().router.for_gsc(site_url, deadline))


def _run_query(client, query, *args, **kwargs):
    # Consume the entire helper's paging loop inside the selected identity lock.
    # Reusing this executor across windows also reuses its original deadline;
    # each execution rechecks current generation and fresh property membership.
    if isinstance(client, _BoundRead):
        return client.executor.execute(lambda sdk: query(sdk.gsc, *args, **kwargs))
    return query(client, *args, **kwargs)


def search_analytics(
    site_url: str,
    start_date: str,
    end_date: str,
    dimensions: list[str] | None = None,
    row_limit: int = 1000,
    search_type: str = "web",
    country: str | None = None,
    device: str | None = None,
) -> dict:
    """Custom Search Analytics query.

    Args:
        site_url: Property URL.
        start_date / end_date: ISO YYYY-MM-DD.
        dimensions: e.g. ["query"], ["page"], ["query","page"], ["country"], ["device"].
        row_limit: Max rows (server-side cap 25000).
        search_type: "web" | "image" | "video" | "news".
        country: ISO-3166 alpha-3 (e.g. "esp", "mex", "arg") to filter
            results to a single market. Critical for multi-region post-
            migration audits ("did I lose LATAM?"). Lowercased automatically.
        device: "DESKTOP" | "MOBILE" | "TABLET" filter.
    """
    filters: list[dict] = []
    if country:
        filters.append({
            "dimension": "country",
            "operator": "equals",
            "expression": country.lower(),
        })
    if device:
        filters.append({
            "dimension": "device",
            "operator": "equals",
            "expression": device.upper(),
        })
    dim_filter_groups = (
        [{"filters": filters}] if filters else None
    )
    rows = _run_query(
        _read_client(site_url, get_webmasters), query_search_analytics,
        site_url,
        start_date,
        end_date,
        dimensions=dimensions or [],
        row_limit=row_limit,
        search_type=search_type,
        dimension_filter_groups=dim_filter_groups,
    )
    return with_meta(
        rows,
        source="webmasters.searchanalytics.query",
        site_url=site_url,
        period={"start": start_date, "end": end_date},
        extra={"filters": {"country": country, "device": device}},
    )


def site_snapshot(site_url: str, days: int = 28) -> dict:
    """Aggregated totals (clicks/impressions/CTR/position) for the last N days vs prior period."""
    cur_start, cur_end = period(days)
    prev_start, prev_end = prior_period(days)
    wm = _read_client(site_url, get_webmasters)
    cur = aggregate_totals(_run_query(wm, query_search_analytics, site_url, cur_start, cur_end))
    prev = aggregate_totals(_run_query(wm, query_search_analytics, site_url, prev_start, prev_end))

    def delta(a: float, b: float) -> dict:
        diff = a - b
        pct = (diff / b * 100) if b else 0.0
        return {"absolute": diff, "percent": pct}

    return with_meta(
        {
            "current": cur,
            "previous": prev,
            "delta": {
                "clicks": delta(cur["clicks"], prev["clicks"]),
                "impressions": delta(cur["impressions"], prev["impressions"]),
                "ctr": delta(cur["ctr"], prev["ctr"]),
                "position": delta(cur["position"], prev["position"]),
            },
        },
        source="webmasters.searchanalytics.query (snapshot)",
        site_url=site_url,
        period={
            "current": {"start": cur_start, "end": cur_end},
            "previous": {"start": prev_start, "end": prev_end},
        },
    )
