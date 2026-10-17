"""SYNTHETIC signed-Int32 regression; no provider row values or sentinel claims.

The shape-only diagnostic observed an integer rejected by the old ge=0 guard.
The arbitrary negative integers here are not captured values or normalized ranks.
"""

import json
import socket

import pytest
from pydantic import ValidationError

from google_seo_mcp.bing.models import BingToolRequest
from google_seo_mcp.bing.normalization import normalize_bing_rows
from google_seo_mcp.bing.wire_models import RawBingQueryStats

SITE = "https://kelleyconstructioninc.com/"
SYNTHETIC_ROW = {
    "Date": "/Date(1704067200000)/",
    "Clicks": 2,
    "Impressions": 8,
    "Query": "synthetic signed-position shape",
    "AvgClickPosition": -37,
    "AvgImpressionPosition": -23,
}
POSITION_FIELDS = ["AvgClickPosition", "AvgImpressionPosition"]
OPERATIONS = [
    ("GetQueryStats", {}),
    ("GetPageStats", {}),
    ("GetPageQueryStats", {"page_url": SITE + "synthetic-page"}),
    ("GetQueryPageStats", {"query": "synthetic selector"}),
]


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def deny(*args, **kwargs):
        pytest.fail("signed-position normalization must not use network")

    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)


@pytest.mark.parametrize("field", POSITION_FIELDS)
@pytest.mark.parametrize("value", [-2147483648, -37, 0, 18, 2147483647])
def test_strict_signed_int32_positions_preserved(field, value):
    payload = {**SYNTHETIC_ROW, "AvgClickPosition": 18, "AvgImpressionPosition": 17, field: value}
    row = RawBingQueryStats.model_validate_json(json.dumps(payload))
    assert row.model_dump(by_alias=True) == payload
    assert type(row.model_dump(by_alias=True)[field]) is int


@pytest.mark.parametrize("field", POSITION_FIELDS)
@pytest.mark.parametrize(
    "value", [-2147483649, 2147483648, True, False, -37.0, 0.0, "-37", None]
)
def test_positions_reject_out_of_range_and_nonintegers(field, value):
    # Keep the other position valid even on the pre-fix implementation so this
    # assertion proves rejection of the selected field, not another row member.
    payload = {**SYNTHETIC_ROW, "AvgClickPosition": 18, "AvgImpressionPosition": 17}
    with pytest.raises(ValidationError) as caught:
        RawBingQueryStats.model_validate_json(json.dumps({**payload, field: value}))
    assert [error["loc"] for error in caught.value.errors(include_input=False)] == [(field,)]


@pytest.mark.parametrize("field", POSITION_FIELDS)
def test_positions_required(field):
    payload = {**SYNTHETIC_ROW, "AvgClickPosition": 18, "AvgImpressionPosition": 17}
    del payload[field]
    with pytest.raises(ValidationError) as caught:
        RawBingQueryStats.model_validate(payload)
    errors = caught.value.errors(include_input=False)
    assert [(error["loc"], error["type"]) for error in errors] == [((field,), "missing")]


@pytest.mark.parametrize("field", ["Clicks", "Impressions"])
@pytest.mark.parametrize("value", [-37, True, 1.0, "1", None])
def test_count_contract_unchanged(field, value):
    payload = {**SYNTHETIC_ROW, "AvgClickPosition": 18, "AvgImpressionPosition": 17}
    with pytest.raises(ValidationError) as caught:
        RawBingQueryStats.model_validate_json(json.dumps({**payload, field: value}))
    assert [error["loc"] for error in caught.value.errors(include_input=False)] == [(field,)]


@pytest.mark.parametrize("operation,selectors", OPERATIONS)
@pytest.mark.parametrize("positions", [(-37, -23), (0, 0), (-2147483648, 2147483647)])
def test_all_query_families_preserve_raw_signed_positions(operation, selectors, positions):
    request = BingToolRequest(operation=operation, site_url=SITE, **selectors)
    payload = dict(
        SYNTHETIC_ROW, AvgClickPosition=positions[0], AvgImpressionPosition=positions[1]
    )
    row = RawBingQueryStats.model_validate_json(json.dumps(payload))
    result = normalize_bing_rows(request.operation, [row], request)
    data = json.loads(result.model_dump_json())
    assert data["status"] == "ok" and data["error"] is None
    assert (data["source_rows"], data["returned_rows"], data["dropped_rows"]) == (1, 1, 0)
    assert data["provider_cadence"] == "weekly"
    assert data["provider_completeness"] == "unknown" and not data["local_truncated"]
    assert data["observed_period"] == {"start_date": "2024-01-01", "end_date": "2024-01-01"}
    record = data["records"][0]
    assert record["avg_click_position"] == positions[0]
    assert record["avg_impression_position"] == positions[1]
    assert record["average_position"] is None
    assert record["position_scale"] == data["position_scale"] == "undocumented"
    assert (record["clicks"], record["impressions"], record["ctr"]) == (2, 8, 0.25)
    assert record["query"] == SYNTHETIC_ROW["Query"]
    assert record["date"] == SYNTHETIC_ROW["Date"]
    assert record["page_url"] == selectors.get("page_url")
    assert record["selector_query"] == selectors.get("query")
    assert "position_scale_undocumented" in data["warnings"]
    assert not any(warning.startswith("invalid_") for warning in data["warnings"])
    assert result.model_validate_json(result.model_dump_json()) == result
