"""Schema cache & search — adapted from surendranb's schema discovery.

Caches GA4 dimension/metric metadata at first use and exposes TF-IDF-style
keyword search to avoid dumping the full ~10k-token catalog into the LLM.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from copy import deepcopy
from typing import Any

from ..auth import (
    get_data_client,
    get_google_account_registry,
    is_hosted_production,
    normalize_property,
)
from ..google_accounts.models import GoogleRequestDeadline

log = logging.getLogger(__name__)

_schema_by_property: dict[str, dict] = {}
# Hosted values never share the legacy property-only cache or caller-owned data.
_schema_by_partition: dict[tuple, dict] = {}
_schema_lock = threading.Lock()
_schema_epoch = 0


def _metadata_executor(property_id):
    deadline = GoogleRequestDeadline(end=time.monotonic() + 60.0)
    return get_google_account_registry().router.for_ga4(property_id, deadline)


def _fetch_bound_metadata(sdk, property_id):
    return _serialize_metadata(sdk.ga4_data.get_metadata(name=f"{property_id}/metadata"))


def _fetch_metadata(property_id: int | str) -> dict:
    if is_hosted_production():
        executor = _metadata_executor(property_id)
        return executor.execute(lambda sdk: _fetch_bound_metadata(sdk, executor.property_id))
    pid = normalize_property(property_id)
    name = f"{pid}/metadata"
    md = get_data_client().get_metadata(name=name)
    return _serialize_metadata(md)


def _serialize_metadata(md) -> dict:
    """Keep protobuf reads inside the account execution lock."""
    dims = []
    for d in md.dimensions:
        dims.append({
            "api_name": d.api_name,
            "ui_name": d.ui_name,
            "description": d.description,
            "category": d.category,
            "custom_definition": d.custom_definition,
        })
    metrics = []
    for m in md.metrics:
        metrics.append({
            "api_name": m.api_name,
            "ui_name": m.ui_name,
            "description": m.description,
            "category": m.category,
            "type": m.type_.name if m.type_ is not None else "TYPE_UNSPECIFIED",
            "custom_definition": m.custom_definition,
        })
    return {"dimensions": dims, "metrics": metrics}


def get_schema(property_id: int | str) -> dict:
    """Returns the cached schema for a property, fetching once."""
    if is_hosted_production():
        executor = _metadata_executor(property_id)
        key = (*executor.cache_partition, "metadata")
        with _schema_lock:
            epoch = _schema_epoch

        def read(sdk):
            # execute re-admits fresh membership even on a cache hit. Copy both
            # ways so caller mutation cannot poison another authorized request.
            with _schema_lock:
                cached = _schema_by_partition.get(key)
                if cached is not None:
                    return deepcopy(cached)
            return _fetch_bound_metadata(sdk, executor.property_id)

        result = executor.execute(read)
        # Only commit after executor JSON/privacy/generation/deadline validation.
        # A concurrent invalidation must not be undone by an in-flight fetch.
        with _schema_lock:
            if epoch == _schema_epoch:
                _schema_by_partition[key] = deepcopy(result)
        return result
    pid = normalize_property(property_id)
    if pid not in _schema_by_property:
        log.info("Fetching GA4 metadata for %s (cached afterwards)", pid)
        _schema_by_property[pid] = _fetch_metadata(pid)
    return _schema_by_property[pid]


def invalidate_schema(property_id: int | str | None = None) -> None:
    global _schema_epoch
    pid = normalize_property(property_id) if property_id is not None else None
    with _schema_lock:
        _schema_epoch += 1
        if pid is None:
            _schema_by_property.clear()
            _schema_by_partition.clear()
        else:
            _schema_by_property.pop(pid, None)
            for key in tuple(_schema_by_partition):
                if key[3] == pid:
                    _schema_by_partition.pop(key, None)


def _score(item: dict, terms: list[str]) -> int:
    """Field-weighted scoring: api_name=10, ui_name=5, description=2, category=1."""
    s = 0
    name = (item.get("api_name") or "").lower()
    ui = (item.get("ui_name") or "").lower()
    desc = (item.get("description") or "").lower()
    cat = (item.get("category") or "").lower()
    for t in terms:
        if t in name:
            s += 10
        if t in ui:
            s += 5
        if t in desc:
            s += 2
        if t in cat:
            s += 1
    return s


def search_schema(property_id: int | str, keyword: str, top_n: int = 10) -> dict:
    """Returns top-N dimensions and metrics matching the keyword by weighted score."""
    schema = get_schema(property_id)
    terms = [t for t in re.split(r"\W+", keyword.lower()) if t]
    if not terms:
        return {"dimensions": [], "metrics": []}
    dims = sorted(
        ((it, _score(it, terms)) for it in schema["dimensions"]),
        key=lambda x: x[1],
        reverse=True,
    )
    mets = sorted(
        ((it, _score(it, terms)) for it in schema["metrics"]),
        key=lambda x: x[1],
        reverse=True,
    )
    return {
        "dimensions": [{**it, "_score": s} for it, s in dims[:top_n] if s > 0],
        "metrics": [{**it, "_score": s} for it, s in mets[:top_n] if s > 0],
    }


def categories(property_id: int | str) -> dict:
    """Returns dimension/metric categories with counts (cheap discovery)."""
    schema = get_schema(property_id)
    dim_cats: dict[str, int] = {}
    for d in schema["dimensions"]:
        c = d.get("category") or "Other"
        dim_cats[c] = dim_cats.get(c, 0) + 1
    met_cats: dict[str, int] = {}
    for m in schema["metrics"]:
        c = m.get("category") or "Other"
        met_cats[c] = met_cats.get(c, 0) + 1
    return {"dimension_categories": dim_cats, "metric_categories": met_cats}
