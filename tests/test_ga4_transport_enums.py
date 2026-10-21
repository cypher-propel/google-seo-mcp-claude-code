"""Seq404 transport enum encoding and retained strictness; entirely synthetic data."""
from copy import deepcopy
from types import SimpleNamespace
import time

import pytest
from google.analytics.admin_v1beta.types import ListAccountSummariesResponse

from google_seo_mcp.google_accounts.discovery import _ga4, _raw_ga4
from google_seo_mcp.google_accounts.models import GoogleAccountError, GoogleRequestDeadline


def complete():
    return {'account_summaries': [{
        'name': 'accountSummaries/1', 'account': 'accounts/1', 'display_name': 'Synthetic',
        'property_summaries': [{
            'property': 'properties/101', 'display_name': 'Synthetic property',
            'property_type': 'PROPERTY_TYPE_ORDINARY', 'parent': 'accounts/1',
            'can_edit': False,
        }],
    }], 'next_page_token': ''}


def invoke(monkeypatch, wires):
    # Preserve the actual SDK page-type check; vary only the conversion result.
    pages = [ListAccountSummariesResponse() for _ in wires]
    by_id = {id(page): deepcopy(wire) for page, wire in zip(pages, wires)}
    monkeypatch.setattr(ListAccountSummariesResponse, 'to_dict',
                        lambda page, **kwargs: by_id[id(page)])
    sdk = SimpleNamespace(ga4_admin=SimpleNamespace(
        list_account_summaries=lambda request: SimpleNamespace(pages=iter(pages))))
    return _ga4(sdk, GoogleRequestDeadline(end=time.monotonic()+20))


@pytest.mark.parametrize('missing', [
    'account_summaries', 'next_page_token', 'property_summaries', 'can_edit',
])
def test_postconversion_omissions_stay_refused(monkeypatch, missing):
    wire = complete()
    expected_rows = 1
    if missing in {'account_summaries', 'next_page_token'}:
        del wire[missing]
        if missing == 'account_summaries':
            expected_rows = 0
    elif missing == 'property_summaries':
        del wire['account_summaries'][0][missing]
        expected_rows = 0
    else:
        del wire['account_summaries'][0]['property_summaries'][0][missing]
    with pytest.raises(GoogleAccountError, match='^agency_discovery_incomplete$'):
        invoke(monkeypatch, [wire])


@pytest.mark.parametrize('shape', ['empty_page', 'zero_property_account', 'can_edit_absent'])
def test_real_sdk_omission_shape(shape):
    # Raw wire shapes are derived from seq402's named omissions; no capture copied.
    wire = {} if shape == 'empty_page' else {'accountSummaries': [{
        'name': 'accountSummaries/1', 'account': 'accounts/1', 'displayName': 'Synthetic',
    }]}
    if shape == 'can_edit_absent':
        wire['accountSummaries'][0]['propertySummaries'] = [{
            'property': 'properties/101', 'displayName': 'Synthetic property',
            'propertyType': 'PROPERTY_TYPE_ORDINARY', 'parent': 'accounts/1',
        }]
    assert 'nextPageToken' not in wire
    _raw_ga4(wire)
    page = ListAccountSummariesResponse.from_json(__import__('json').dumps(wire))
    sdk = SimpleNamespace(ga4_admin=SimpleNamespace(
        list_account_summaries=lambda request: SimpleNamespace(pages=iter([page]))))
    rows = _ga4(sdk, GoogleRequestDeadline(end=time.monotonic()+20))
    assert len(rows) == (1 if shape == 'can_edit_absent' else 0)


@pytest.mark.parametrize('level', ['page', 'summary', 'property'])
def test_unknown_key_refused(monkeypatch, level):
    wire = complete()
    node = wire if level == 'page' else wire['account_summaries'][0]
    if level == 'property':
        node = node['property_summaries'][0]
    node['unknown_key'] = False
    with pytest.raises(GoogleAccountError, match='^agency_discovery_incomplete$'):
        invoke(monkeypatch, [wire])


@pytest.mark.parametrize('value', [0, 1, 'false', None, [], {}])
def test_nonbool_can_edit_refused(monkeypatch, value):
    wire = complete()
    wire['account_summaries'][0]['property_summaries'][0]['can_edit'] = value
    with pytest.raises(GoogleAccountError, match='^agency_discovery_incomplete$'):
        invoke(monkeypatch, [wire])


@pytest.mark.parametrize('field,value', [
    ('account_summaries', None), ('account_summaries', {}),
    ('next_page_token', None), ('next_page_token', 0),
    ('property_summaries', None), ('property_summaries', {}),
])
def test_present_invalid_default_field_refused(monkeypatch, field, value):
    wire = complete()
    node = wire['account_summaries'][0] if field == 'property_summaries' else wire
    node[field] = value
    with pytest.raises(GoogleAccountError, match='^agency_discovery_incomplete$'):
        invoke(monkeypatch, [wire])


@pytest.mark.parametrize('level,field', [
    ('summary', 'name'), ('summary', 'account'), ('summary', 'display_name'),
    ('property', 'property'), ('property', 'display_name'),
    ('property', 'property_type'), ('property', 'parent'),
])
def test_other_required_fields_stay_required(monkeypatch, level, field):
    wire = complete()
    node = wire['account_summaries'][0]
    if level == 'property':
        node = node['property_summaries'][0]
    del node[field]
    with pytest.raises(GoogleAccountError, match='^agency_discovery_incomplete$'):
        invoke(monkeypatch, [wire])


def test_postconversion_empty_terminal_page_stays_refused(monkeypatch):
    first = complete()
    first['next_page_token'] = 'synthetic-next'
    with pytest.raises(GoogleAccountError, match='^agency_discovery_incomplete$'):
        invoke(monkeypatch, [first, {}])


def test_token_replay_stays_refused(monkeypatch):
    wire = complete()
    wire['next_page_token'] = 'synthetic-replay'
    with pytest.raises(GoogleAccountError, match='^agency_discovery_incomplete$'):
        invoke(monkeypatch, [wire, wire])


def test_explicit_bool_values_stay_valid(monkeypatch):
    wire = complete()
    false_rows = invoke(monkeypatch, [wire])
    wire['account_summaries'][0]['property_summaries'][0]['can_edit'] = True
    assert invoke(monkeypatch, [wire]) == false_rows


NAMES = ['PROPERTY_TYPE_UNSPECIFIED', 'PROPERTY_TYPE_ORDINARY',
         'PROPERTY_TYPE_SUBPROPERTY', 'PROPERTY_TYPE_ROLLUP']


def raw(value):
    return {'accountSummaries': [{
        'name': 'accountSummaries/1', 'account': 'accounts/1', 'displayName': 'Synthetic',
        'propertySummaries': [{'property': 'properties/101', 'displayName': 'Synthetic',
                               'parent': 'accounts/1', 'propertyType': value, 'canEdit': False}],
    }]}


@pytest.mark.parametrize('value', [0, 1, 2, 3] + NAMES,
                         ids=['int0', 'int1', 'int2', 'int3', 'name0', 'name1', 'name2', 'name3'])
def test_transport_enum_accepted(value):
    _raw_ga4(raw(value))


@pytest.mark.parametrize('value', [4, -1, '1', True, 1.0],
                         ids=['int4', 'negative', 'string1', 'bool', 'float'])
def test_transport_enum_refused(value):
    with pytest.raises(GoogleAccountError, match='^agency_discovery_incomplete$'):
        _raw_ga4(raw(value))


@pytest.mark.parametrize('value', [0, 1, 2, 3])
def test_integer_transport_to_actual_sdk(value):
    wire = raw(value)
    _raw_ga4(wire)
    page = ListAccountSummariesResponse.from_json(__import__('json').dumps(wire))
    sdk = SimpleNamespace(ga4_admin=SimpleNamespace(
        list_account_summaries=lambda request: SimpleNamespace(pages=iter([page]))))
    rows = _ga4(sdk, GoogleRequestDeadline(end=time.monotonic()+20))
    assert rows[0]['property_type'] == NAMES[value]


@pytest.mark.parametrize('level', ['page', 'summary', 'property'])
def test_raw_unknown_key_refused(level):
    wire = raw(1)
    node = wire if level == 'page' else wire['accountSummaries'][0]
    if level == 'property':
        node = node['propertySummaries'][0]
    node['unknown_key'] = False
    with pytest.raises(GoogleAccountError, match='^agency_discovery_incomplete$'):
        _raw_ga4(wire)


@pytest.mark.parametrize('value', [0, 1, 'false', None, [], {}])
def test_raw_nonbool_can_edit_refused(value):
    wire = raw(1)
    wire['accountSummaries'][0]['propertySummaries'][0]['canEdit'] = value
    with pytest.raises(GoogleAccountError, match='^agency_discovery_incomplete$'):
        _raw_ga4(wire)
