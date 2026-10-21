"""Admin API tools — list properties, accounts, custom dims, etc."""
from __future__ import annotations

import time

from ...auth import (
    get_admin_client,
    get_google_account_registry,
    is_hosted_production,
    normalize_property,
)
from ...google_accounts.models import GoogleRequestDeadline
from ...guardrails import with_meta


def list_properties() -> dict:
    """List every GA4 account + property the authenticated user has access to.

    Returns a flat structure with account name, property id, display name, time zone,
    currency, and create time.
    """
    if is_hosted_production():
        deadline = GoogleRequestDeadline(end=time.monotonic() + 60.0)
        out = get_google_account_registry().discovery.list_rows("ga4", deadline)
    else:
        admin = get_admin_client()
        out = []
        for summary in admin.list_account_summaries():
            for ps in summary.property_summaries:
                out.append({
                    "account": summary.account,
                    "account_display_name": summary.display_name,
                    "property": ps.property,
                    "property_display_name": ps.display_name,
                    "property_type": (
                        ps.property_type.name if ps.property_type is not None else None
                    ),
                })
    return with_meta(out, source="admin.account_summaries.list", property="*")


def get_property_details(property_id: int | str) -> dict:
    """Fetch detailed metadata for one GA4 property: timezone, currency, industry, etc."""
    if is_hosted_production():
        deadline = GoogleRequestDeadline(end=time.monotonic() + 60.0)
        executor = get_google_account_registry().router.for_ga4(property_id, deadline)
        pid = executor.property_id
        details = executor.execute(
            lambda sdk: _serialize_property(sdk.ga4_admin.get_property(name=pid))
        )
    else:
        admin = get_admin_client()
        pid = normalize_property(property_id)
        details = _serialize_property(admin.get_property(name=pid))
    return with_meta(details, source="admin.properties.get", property=pid)


def _serialize_property(p) -> dict:
    """Serialize before the hosted callback releases its identity lock."""
    return {
        "name": p.name,
        "display_name": p.display_name,
        "industry_category": p.industry_category.name if p.industry_category is not None else None,
        "time_zone": p.time_zone,
        "currency_code": p.currency_code,
        "create_time": p.create_time.isoformat() if p.create_time else None,
        "update_time": p.update_time.isoformat() if p.update_time else None,
        "service_level": p.service_level.name if p.service_level is not None else None,
        "account": p.account,
    }
