"""Site listing & inspection tools."""
from __future__ import annotations

import time

from ...auth import (
    get_google_account_registry,
    get_searchconsole,
    get_webmasters,
    is_hosted_production,
)
from ...google_accounts.models import GoogleRequestDeadline
from ...guardrails import with_meta


def list_sites() -> dict:
    """List all Search Console properties the authenticated user has access to.

    Returns each site's URL, permission level, and whether it's a domain or URL property.
    """
    if is_hosted_production():
        deadline = GoogleRequestDeadline(end=time.monotonic() + 60.0)
        rows = get_google_account_registry().discovery.list_rows("gsc", deadline)
    else:
        wm = get_webmasters()
        resp = wm.sites().list().execute()
        sites = resp.get("siteEntry", [])
        rows = [
            {
                "site_url": s.get("siteUrl"),
                "permission_level": s.get("permissionLevel"),
                "type": "domain" if (s.get("siteUrl") or "").startswith("sc-domain:") else "url",
            }
            for s in sites
        ]
    return with_meta(
        rows,
        source="webmasters.sites.list",
        site_url="*",
    )


def inspect_url(site_url: str, page_url: str, language: str = "en-US") -> dict:
    """Inspect a single URL against Google's index.

    Args:
        site_url: Property URL (e.g. `https://example.com/` or `sc-domain:example.com`).
        page_url: Full URL to inspect (must belong to `site_url`).
        language: BCP-47 lang for human-readable strings.

    Returns indexing status, last-crawl, canonical, mobile usability, rich-results.
    """
    body = {"inspectionUrl": page_url, "siteUrl": site_url, "languageCode": language}
    if is_hosted_production():
        deadline = GoogleRequestDeadline(end=time.monotonic() + 60.0)
        executor = get_google_account_registry().router.for_gsc(site_url, deadline)
        resp = executor.execute(
            lambda sdk: sdk.gsc.urlInspection().index().inspect(body=body).execute(num_retries=0)
        )
    else:
        sc = get_searchconsole()
        resp = sc.urlInspection().index().inspect(body=body).execute()
    return with_meta(
        resp.get("inspectionResult", {}),
        source="searchconsole.urlInspection.index.inspect",
        site_url=site_url,
    )
