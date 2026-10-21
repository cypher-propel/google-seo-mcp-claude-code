"""Hosted Google identity contracts; no live Google APIs or enrolled credentials."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from google_seo_mcp import auth
from google_seo_mcp.google_accounts import clients
from google_seo_mcp.google_accounts import credentials as custody
from google_seo_mcp.google_accounts.models import ACCOUNT_IDS, GoogleRequestDeadline
from google_seo_mcp.runtime_config import ProductionRuntimeConfig

READONLY_SCOPES = [
    "https://www.googleapis.com/auth/webmasters.readonly",
    "https://www.googleapis.com/auth/analytics.readonly",
]
GETTERS = [auth.get_searchconsole, auth.get_webmasters, auth.get_data_client, auth.get_admin_client]
SENTINEL = "SYNTHETIC_GOOGLE_PRIVATE_VALUE"


@pytest.fixture(autouse=True)
def isolated_identity(monkeypatch):
    monkeypatch.delenv("GOOGLE_SEO_PROFILE", raising=False)
    auth.configure_hosted_auth(ProductionRuntimeConfig())

    def deny(*args, **kwargs):
        pytest.fail("unexpected provider network, credential fallback or HOME access")

    for name in (
        "_from_adc",
        "_from_service_account",
        "_from_oauth_flow",
        "_config_dir",
        "google_auth_default",
        "Request",
    ):
        monkeypatch.setattr(auth, name, deny)
    monkeypatch.setattr(auth.InstalledAppFlow, "from_client_secrets_file", deny)
    monkeypatch.setattr(auth.InstalledAppFlow, "from_client_config", deny)
    monkeypatch.setattr(Path, "home", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)
    yield
    auth.configure_hosted_auth(ProductionRuntimeConfig())


@pytest.fixture
def service_account(tmp_path, monkeypatch):
    """Historical fixture name; only protected synthetic OAuth, no SA/PEM.

    Start the real descriptor walk at an explicit synthetic root: pytest /tmp
    and some checkout ancestors are writable. All subsequent leaf, directory,
    ownership, link, read and generation checks remain real filesystem syscalls.
    """
    original_open = os.open

    def fixture_open(path, flags, *args, **kwargs):
        return original_open(str(tmp_path) if path == "/" else path, flags, *args, **kwargs)

    monkeypatch.setattr(custody.os, "open", fixture_open)
    records = [
        {
            "installed": {
                "client_id": "synthetic.apps.googleusercontent.com",
                "client_secret": SENTINEL,
                "project_id": "synthetic-project",
                "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        }
    ]
    records.extend(
        {
            "version": 1,
            "account_id": label,
            "client_id": "synthetic.apps.googleusercontent.com",
            "client_secret": SENTINEL,
            "refresh_token": SENTINEL + "-slot-" + str(index),
            "token_uri": "https://oauth2.googleapis.com/token",
            "scopes": READONLY_SCOPES,
        }
        for index, label in enumerate(ACCOUNT_IDS)
    )
    for name, record in zip(("client.json", "first.json", "second.json"), records, strict=True):
        path = tmp_path / name
        path.write_text(json.dumps(record), encoding="utf-8")
        path.chmod(0o600)
    return tmp_path / "first.json"


def hosted(path):
    return ProductionRuntimeConfig(
        profile="production",
        transport="streamable-http",
        google_auth_mode="dual-user-oauth",
        google_oauth_client_file=Path("/client.json"),
        google_oauth_propel_dms_file=Path("/") / path.name,
        google_oauth_addourteam99_file=Path("/second.json"),
        google_approved_client_id="synthetic.apps.googleusercontent.com",
        google_approved_project_id="synthetic-project",
        consumer_keys_file=Path("/unused-registry.json"),
    )


def deadline():
    return GoogleRequestDeadline(end=time.monotonic() + 30.0)


def bound(getter):
    registry = auth.get_google_account_registry()
    if getter in (auth.get_searchconsole, auth.get_webmasters):
        executor = registry.router.for_gsc("https://example.com/", deadline())
        if getter is auth.get_searchconsole:
            return executor.execute(
                lambda sdk: (
                    sdk.gsc.urlInspection()
                    .index()
                    .inspect(
                        body={
                            "inspectionUrl": "https://example.com/a",
                            "siteUrl": "https://example.com/",
                        }
                    )
                    .execute()
                )
            )
        return executor.execute(
            lambda sdk: sdk.gsc.sitemaps().list(siteUrl="https://example.com/").execute()
        )
    executor = registry.router.for_ga4("properties/123", deadline())
    if getter is auth.get_data_client:
        return executor.execute(
            lambda sdk: dict(
                row_count=sdk.ga4_data.run_report(request={"property": "properties/123"}).row_count
            )
        )
    return executor.execute(
        lambda sdk: dict(name=sdk.ga4_admin.get_property(request={"name": "properties/123"}).name)
    )


@pytest.fixture
def wire(monkeypatch, service_account):
    """Real OAuth refresh + SDKs; only requests' adapter is synthetic."""
    class WireCalls(list):
        def __init__(self):
            super().__init__()
            self.refresh_observations = []

    calls = WireCalls()
    # Bind private refresh material to public identities only in memory.
    refresh_accounts = {
        json.loads((service_account.parent / name).read_text())["refresh_token"]: account_id
        for name, account_id in zip(("first.json", "second.json"), ACCOUNT_IDS, strict=True)
    }

    def send(adapter, request, **kwargs):
        calls.append((request.method, request.url))
        assert kwargs["proxies"] == {} and kwargs["stream"] is True
        assert 0 < kwargs["timeout"] <= 15
        assert request.url.startswith(
            (
                "https://oauth2.googleapis.com/",
                "https://www.googleapis.com/",
                "https://searchconsole.googleapis.com/",
                "https://analyticsadmin.googleapis.com/",
                "https://analyticsdata.googleapis.com/",
            )
        )
        target = urlsplit(request.url)
        assert (request.method, target.netloc, target.path) in {
            ("POST", "oauth2.googleapis.com", "/token"),
            ("GET", "www.googleapis.com", "/webmasters/v3/sites"),
            (
                "GET",
                "www.googleapis.com",
                "/webmasters/v3/sites/https%3A%2F%2Fexample.com%2F/sitemaps",
            ),
            ("POST", "searchconsole.googleapis.com", "/v1/urlInspection/index:inspect"),
            ("GET", "analyticsadmin.googleapis.com", "/v1beta/accountSummaries"),
            ("GET", "analyticsadmin.googleapis.com", "/v1beta/properties/123"),
            ("POST", "analyticsdata.googleapis.com", "/v1beta/properties/123:runReport"),
        }
        if request.url == "https://oauth2.googleapis.com/token":
            # This is the actual PreparedRequest after real Credentials.refresh,
            # not the constructor scopes or the synthetic response grant.
            body = request.body.decode("utf-8") if isinstance(request.body, bytes) else request.body
            form = parse_qs(body, keep_blank_values=True, strict_parsing=True)
            refresh = form.get("refresh_token", [])
            known_identity = len(refresh) == 1 and refresh[0] in refresh_accounts
            assert known_identity, "prepared refresh request has unknown identity"
            account_id = refresh_accounts[refresh[0]]
            scopes = form.get("scope", [])
            exact_scope = (
                len(scopes) == 1
                and len(scopes[0].split()) == len(READONLY_SCOPES)
                and set(scopes[0].split()) == set(READONLY_SCOPES)
            )
            calls.refresh_observations.append((account_id, exact_scope))
            assert exact_scope, "prepared refresh request scope mismatch"
            payload = {
                "access_token": "synthetic-access-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": " ".join(READONLY_SCOPES),
            }
        elif "/accountSummaries" in request.url:
            payload = {
                "accountSummaries": [
                    {
                        "account": "accounts/1",
                        "propertySummaries": [
                            {
                                "property": "properties/123",
                                "displayName": "Synthetic",
                                "parent": "accounts/1",
                            }
                        ],
                    }
                ]
            }
        elif urlsplit(request.url).path.endswith("/sites"):
            payload = {
                "siteEntry": [{"siteUrl": "https://example.com/", "permissionLevel": "siteOwner"}]
            }
        elif "/properties/123:runReport" in request.url:
            payload = {"rowCount": 7}
        elif "/properties/123" in request.url:
            payload = {"name": "properties/123"}
        else:
            payload = {}
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(payload).encode()
        response._content_consumed = True
        response.headers["content-type"] = "application/json"
        response.request = request
        return response

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)
    return calls


def test_configure_is_lazy_and_readiness_never_constructs_or_refreshes(
    service_account, monkeypatch
):
    factory = Mock(side_effect=AssertionError("credential constructor during readiness"))
    monkeypatch.setattr(clients, "Credentials", factory)
    # Configuration must not even open/stat the identity file.
    with monkeypatch.context() as guard:
        guard.setattr(Path, "stat", Mock(side_effect=AssertionError("startup stat")))
        guard.setattr(Path, "open", Mock(side_effect=AssertionError("startup open")))
        guard.setattr(custody.os, "open", Mock(side_effect=AssertionError("startup descriptor")))
        auth.configure_hosted_auth(hosted(service_account))
    assert auth.google_credentials_state() == "available"
    assert auth.current_credential_type() == "dual-user-oauth"
    reset = auth.reset_clients()
    assert reset["deleted_oauth_token"] is False
    assert auth.google_credentials_state() == "invalid"
    auth.configure_hosted_auth(hosted(service_account))
    assert auth.google_credentials_state() == "available"
    factory.assert_not_called()


@pytest.mark.parametrize("getter", GETTERS, ids=lambda f: f.__name__)
def test_missing_sa_ignores_legacy_environment_and_home(
    getter, service_account, monkeypatch, caplog
):
    path = service_account.with_name(SENTINEL + ".json")
    auth.configure_hosted_auth(hosted(path))
    for variable in (
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_SEO_SERVICE_ACCOUNT_FILE",
        "GOOGLE_SEO_OAUTH_CLIENT_FILE",
    ):
        monkeypatch.setenv(variable, "/untrusted/" + SENTINEL)
    # Mutating profile after composition cannot switch identities or scopes.
    monkeypatch.setenv("GOOGLE_SEO_PROFILE", "legacy")
    monkeypatch.setenv("GSC_ALLOW_DESTRUCTIVE", "true")
    factories = []
    for name in ("build", "BetaAnalyticsDataClient", "AnalyticsAdminServiceClient"):
        factory = Mock(side_effect=AssertionError("client with no credentials"))
        factories.append(factory)
        monkeypatch.setattr(clients, name, factory)
    with pytest.raises(RuntimeError, match="^credentials_missing$") as error:
        auth.get_google_account_registry().clients.execute(
            ACCOUNT_IDS[0], lambda sdk: bound(getter), deadline()
        )
    assert error.value.__suppress_context__
    assert SENTINEL not in str(error.value) + caplog.text
    assert error.value.__cause__ is error.value.__context__ is None
    assert auth.google_credentials_state() == "missing"
    assert auth.google_credentials_state() == "missing"
    assert auth._scopes() == READONLY_SCOPES
    for factory in factories:
        factory.assert_not_called()


def test_all_four_clients_share_exact_readonly_identity_without_refresh(
    service_account, monkeypatch, wire
):
    auth.configure_hosted_auth(hosted(service_account))
    monkeypatch.setenv("GSC_ALLOW_DESTRUCTIVE", "true")
    monkeypatch.setenv("GOOGLE_SEO_PROFILE", "legacy")
    monkeypatch.setenv("GOOGLE_SEO_SERVICE_ACCOUNT_FILE", "/not/the/captured/identity")
    registry = auth.get_google_account_registry()
    credential = registry.loader.load_accounts()[0]
    factory = Mock(wraps=clients.Credentials)
    discovery = Mock(wraps=clients.build)
    data, admin = (
        Mock(wraps=clients.BetaAnalyticsDataClient),
        Mock(wraps=clients.AnalyticsAdminServiceClient),
    )
    monkeypatch.setattr(clients, "Credentials", factory)
    monkeypatch.setattr(clients, "build", discovery)
    monkeypatch.setattr(clients, "BetaAnalyticsDataClient", data)
    monkeypatch.setattr(clients, "AnalyticsAdminServiceClient", admin)
    bundle = clients._Bundle(credential, registry.clients.generation(), registry.clients)
    try:
        assert wire == []  # actual constructors perform no refresh/network
        factory.assert_called_once()
        assert factory.call_args.kwargs["scopes"] == sorted(READONLY_SCOPES)
        assert (
            factory.call_args.kwargs["refresh_token"] == credential.refresh_token.get_secret_value()
        )
        assert (
            factory.call_args.kwargs["client_secret"] == credential.client_secret.get_secret_value()
        )
        assert [call.args for call in discovery.call_args_list] == [
            ("webmasters", "v3"),
            ("searchconsole", "v1"),
        ]
        for call in discovery.call_args_list:
            assert call.kwargs["cache_discovery"] is False
            assert call.kwargs["static_discovery"] is True
            assert call.kwargs["http"]._session is bundle.session
        for constructor in (data, admin):
            constructor.assert_called_once()
            assert constructor.call_args.kwargs["transport"]._credentials is bundle.credentials
            assert constructor.call_args.kwargs["transport"]._session is bundle.session
    finally:
        bundle.close()
    for getter in GETTERS:
        assert bound(getter) == bound(getter)
    assert auth.SCOPES_READ == auth._scopes() == READONLY_SCOPES
    assert len([call for call in wire if call[1] == "https://oauth2.googleapis.com/token"]) == 2
    assert factory.call_count == 3  # isolated constructor plus two cached accounts
    assert set(registry.clients._bundles) == set(ACCOUNT_IDS)
    assert wire.refresh_observations == [(account_id, True) for account_id in ACCOUNT_IDS]


@pytest.mark.parametrize("account_id", ACCOUNT_IDS)
def test_each_identity_prepared_refresh_has_exact_readonly_scopes(
    service_account, wire, account_id
):
    """Independent cases ensure a first-slot failure cannot hide the second."""
    auth.configure_hosted_auth(hosted(service_account))
    registry = auth.get_google_account_registry()
    assert wire == []
    result = registry.clients.execute(
        account_id, lambda sdk: sdk.gsc.sites().list().execute(), deadline()
    )
    assert result["siteEntry"][0]["siteUrl"] == "https://example.com/"
    assert wire.refresh_observations == [(account_id, True)]
    assert set(registry.clients._bundles) == {account_id}


@pytest.mark.parametrize(
    "getter,factory_name",
    [
        (auth.get_searchconsole, "build"),
        (auth.get_webmasters, "build"),
        (auth.get_data_client, "BetaAnalyticsDataClient"),
        (auth.get_admin_client, "AnalyticsAdminServiceClient"),
    ],
)
def test_client_constructor_failure_is_sanitized(
    service_account, monkeypatch, caplog, getter, factory_name
):
    auth.configure_hosted_auth(hosted(service_account))
    factory = Mock(side_effect=ValueError(SENTINEL))
    monkeypatch.setattr(clients, factory_name, factory)
    refresh = Mock(side_effect=AssertionError("refresh after failed constructor"))
    monkeypatch.setattr(clients.Credentials, "refresh", refresh)
    registry = auth.get_google_account_registry()
    with pytest.raises(RuntimeError, match="^agency_discovery_incomplete$") as error:
        registry.clients.execute(ACCOUNT_IDS[0], lambda sdk: None, deadline())
    assert error.value.__suppress_context__
    assert error.value.__context__ is error.value.__cause__ is None
    assert SENTINEL not in str(error.value) + caplog.text
    factory.assert_called_once()
    refresh.assert_not_called()


def test_sa_constructor_failure_is_sanitized_and_marks_invalid(
    service_account, monkeypatch, caplog
):
    auth.configure_hosted_auth(hosted(service_account))
    factory = Mock(side_effect=ValueError(SENTINEL))
    monkeypatch.setattr(clients, "Credentials", factory)
    registry = auth.get_google_account_registry()
    with pytest.raises(RuntimeError, match="^agency_discovery_incomplete$") as error:
        registry.clients.execute(ACCOUNT_IDS[0], lambda sdk: None, deadline())
    assert error.value.__suppress_context__
    assert error.value.__context__ is error.value.__cause__ is None
    assert SENTINEL not in str(error.value) + caplog.text
    factory.assert_called_once()
    assert registry.clients._bundles == {}
    # Constructor failure is not document invalidity. Malformed custody still
    # poisons this same registry before any future SDK construction.
    info = json.loads(service_account.read_text())
    info["refresh_token"] = ""
    service_account.write_text(json.dumps(info))
    assert auth.google_credentials_state() == "invalid"


def test_production_environment_before_composition_cannot_use_legacy_sa_path(
    service_account, monkeypatch
):
    # Truly never composed, not a private capture-flag reset.
    script = """
import socket
from pathlib import Path
from google_seo_mcp import auth
calls=[]
def deny(*a, **kw):
    calls.append(True)
    raise AssertionError('ambient fallback')
auth.SACredentials.from_service_account_file=deny
auth.google_auth_default=deny
Path.home=deny
socket.getaddrinfo=deny
socket.socket.connect=deny
try:
    auth._build_creds()
except RuntimeError as error:
    assert str(error) == 'property_binding_required'
    assert error.__cause__ is error.__context__ is None
else:
    raise AssertionError('uncaptured legacy access')
assert auth.google_credentials_state() == 'missing'
assert not calls
"""
    env = dict(
        os.environ,
        GOOGLE_SEO_PROFILE="production",
        GOOGLE_SEO_SERVICE_ACCOUNT_FILE=str(service_account),
        PYTHONDONTWRITEBYTECODE="1",
    )
    result = subprocess.run(
        [sys.executable, "-W", "error", "-c", script], env=env, capture_output=True
    )
    assert result.returncode == 0
    assert result.stdout == result.stderr == b""


@pytest.mark.parametrize("kind", ["directory", "permission-denied"])
def test_nonregular_or_unreadable_sa_is_sanitized(
    service_account, tmp_path, monkeypatch, caplog, kind
):
    path = service_account
    if kind == "directory":
        path = tmp_path / "directory"
        path.mkdir()
    auth.configure_hosted_auth(hosted(path))
    factory = Mock(side_effect=AssertionError("unreadable identity constructed"))
    monkeypatch.setattr(clients, "Credentials", factory)
    if kind == "permission-denied":
        original_open = custody.os.open

        def denied_open(name, flags, *args, **kwargs):
            if name == service_account.name:
                raise PermissionError(SENTINEL)
            return original_open(name, flags, *args, **kwargs)

        monkeypatch.setattr(custody.os, "open", denied_open)
    assert auth.google_credentials_state() == "invalid"
    with pytest.raises(RuntimeError, match="^credentials_invalid$") as error:
        auth.get_google_account_registry().clients.execute(
            ACCOUNT_IDS[0], lambda sdk: None, deadline()
        )
    assert error.value.__context__ is error.value.__cause__ is None
    assert SENTINEL not in str(error.value) + caplog.text
    factory.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        "not-json-" + SENTINEL,
        "[]",
        "{}",
        '{"type":"service_account","type":"service_account"}',
        "x" * 131073,
    ],
)
def test_invalid_or_oversized_file_never_reaches_constructor(service_account, monkeypatch, payload):
    path = service_account
    path.write_text(payload)
    factory = Mock(side_effect=AssertionError("invalid file reached Google constructor"))
    monkeypatch.setattr(clients, "Credentials", factory)
    auth.configure_hosted_auth(hosted(path))
    assert auth.google_credentials_state() == "invalid"
    with pytest.raises(RuntimeError, match="^credentials_invalid$"):
        auth.get_google_account_registry().clients.execute(
            ACCOUNT_IDS[0], lambda sdk: None, deadline()
        )
    factory.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [
        ("token_uri", "http://169.254.169.254/token"),
        ("token_uri", "https://attacker.invalid/token"),
        ("universe_domain", "attacker.invalid"),
        ("type", "authorized_user"),
        ("client_email", "private\n@example.invalid"),
        ("private_key", "not-a-key"),
        ("private_key", "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n"),
    ],
)
def test_malformed_key_or_alternate_token_destination_refused_before_constructor(
    service_account, monkeypatch, field, value
):
    info = json.loads(service_account.read_text())
    # Preserve historical parameter IDs; key syntax/placeholder rejection moves
    # to required OAuth refresh material and approved client-secret equality.
    if field == "private_key":
        field, value = (
            ("refresh_token", "") if value == "not-a-key" else ("client_secret", "mismatched")
        )
    info[field] = value
    service_account.write_text(json.dumps(info))
    factory = Mock(side_effect=AssertionError("unqualified credentials constructed"))
    monkeypatch.setattr(clients, "Credentials", factory)
    auth.configure_hosted_auth(hosted(service_account))
    assert auth.google_credentials_state() == "invalid"
    with pytest.raises(RuntimeError, match="^credentials_invalid$"):
        auth.get_google_account_registry().clients.execute(
            ACCOUNT_IDS[0], lambda sdk: None, deadline()
        )
    factory.assert_not_called()


def test_offline_validation_cache_revalidates_file_change(service_account, monkeypatch):
    auth.configure_hosted_auth(hosted(service_account))
    from unittest.mock import patch

    with patch.object(
        custody._Held, "read", autospec=True, side_effect=custody._Held.read
    ) as reads:
        assert auth.google_credentials_state() == auth.google_credentials_state() == "available"
        assert reads.call_count == 6
        info = json.loads(service_account.read_text())
        info["refresh_token"] += "-rotated"
        service_account.write_text(json.dumps(info))
        assert auth.google_credentials_state() == "invalid"
        assert reads.call_count == 9
        assert auth.google_credentials_state() == "invalid"
        assert reads.call_count == 9  # sticky epoch, no automatic identity replacement


def test_atomic_identity_replacement_invalidates_all_client_caches(
    service_account, monkeypatch, wire
):
    auth.configure_hosted_auth(hosted(service_account))
    registry = auth.get_google_account_registry()
    for getter in GETTERS:
        bound(getter)
    first_bundles = tuple(registry.clients._bundles.values())
    assert len(first_bundles) == 2
    old_sessions = [bundle.session for bundle in first_bundles]
    closes = [Mock(wraps=session.close) for session in old_sessions]
    for session, close in zip(old_sessions, closes, strict=True):
        monkeypatch.setattr(session, "close", close)
    assert all(bundle._sessions for bundle in first_bundles)
    replacement = service_account.with_suffix(".replacement")
    replacement.write_bytes(service_account.read_bytes())
    replacement.chmod(0o600)
    replacement.replace(service_account)
    before = len(wire)
    with pytest.raises(RuntimeError, match="^credentials_changed$"):
        registry.clients.generation()
    with pytest.raises(RuntimeError, match="^agency_discovery_incomplete$"):
        bound(auth.get_data_client)
    assert len(wire) == before
    assert registry.clients._bundles == {}
    assert all(bundle.retired and bundle._sessions == [] for bundle in first_bundles)
    for close in closes:
        close.assert_called_once_with()
    auth.configure_hosted_auth(hosted(service_account))
    new_registry = auth.get_google_account_registry()
    for getter in GETTERS:
        bound(getter)
    assert set(new_registry.clients._bundles) == set(ACCOUNT_IDS)
    assert all(
        new.session is not old
        for new in new_registry.clients._bundles.values()
        for old in old_sessions
    )
    assert new_registry.clients.generation() != registry.clients._generation


@pytest.mark.parametrize("slot", ["client.json", "first.json", "second.json"])
@pytest.mark.parametrize("fault", ["missing", "invalid-json", "symlink", "writable"])
def test_every_document_is_required_before_any_sdk_or_network(
    service_account, monkeypatch, slot, fault, caplog
):
    target = service_account.parent / slot
    if fault == "missing":
        target.unlink()
    elif fault == "invalid-json":
        target.write_text("invalid-" + SENTINEL)
    elif fault == "symlink":
        saved = target.with_suffix(".saved")
        target.rename(saved)
        target.symlink_to(saved)
    else:
        target.chmod(0o666)
    factory = Mock(side_effect=AssertionError("SDK before complete custody"))
    monkeypatch.setattr(clients, "Credentials", factory)
    auth.configure_hosted_auth(hosted(service_account))
    registry = auth.get_google_account_registry()
    callback = Mock(side_effect=AssertionError("callback before custody"))
    expected = "credentials_missing" if fault == "missing" else "credentials_invalid"
    with pytest.raises(RuntimeError, match="^" + expected + "$") as error:
        registry.clients.execute(ACCOUNT_IDS[0], callback, deadline())
    assert error.value.__cause__ is error.value.__context__ is None
    assert SENTINEL not in str(error.value) + caplog.text
    for getter in GETTERS:
        with pytest.raises(RuntimeError, match="^agency_discovery_incomplete$"):
            bound(getter)
    callback.assert_not_called()
    factory.assert_not_called()


@pytest.mark.parametrize("slot", ["first.json", "second.json"])
@pytest.mark.parametrize(
    "fault",
    [
        "missing-scope",
        "write-scope",
        "duplicate-scope",
        "extra-scope",
        "account-label",
        "client-id",
        "client-secret",
        "same-refresh",
        "sa-field",
    ],
)
def test_both_oauth_slots_require_exact_scopes_labels_and_client_binding(
    service_account, monkeypatch, slot, fault
):
    target = service_account.parent / slot
    info = json.loads(target.read_text())
    if fault == "missing-scope":
        info["scopes"] = READONLY_SCOPES[:1]
    elif fault == "write-scope":
        info["scopes"] = ["https://www.googleapis.com/auth/webmasters", READONLY_SCOPES[1]]
    elif fault == "duplicate-scope":
        info["scopes"] = [READONLY_SCOPES[0]] * 2
    elif fault == "extra-scope":
        info["scopes"] = READONLY_SCOPES + ["openid"]
    elif fault == "account-label":
        info["account_id"] = ACCOUNT_IDS[1] if slot == "first.json" else ACCOUNT_IDS[0]
    elif fault == "client-id":
        info["client_id"] = "other.apps.googleusercontent.com"
    elif fault == "client-secret":
        info["client_secret"] = "mismatched"
    elif fault == "same-refresh":
        other = service_account.parent / ("second.json" if slot == "first.json" else "first.json")
        info["refresh_token"] = json.loads(other.read_text())["refresh_token"]
    else:
        info["type"] = "service_account"
    target.write_text(json.dumps(info))
    factory = Mock(side_effect=AssertionError("constructor before validated pair"))
    monkeypatch.setattr(clients, "Credentials", factory)
    auth.configure_hosted_auth(hosted(service_account))
    with pytest.raises(RuntimeError, match="^credentials_invalid$") as error:
        auth.get_google_account_registry().clients.execute(
            ACCOUNT_IDS[0], lambda sdk: None, deadline()
        )
    assert error.value.__cause__ is error.value.__context__ is None
    factory.assert_not_called()


@pytest.mark.parametrize("getter", GETTERS, ids=lambda f: f.__name__)
def test_hosted_unbound_getters_refuse_before_custody_even_with_valid_pair(
    service_account, monkeypatch, getter
):
    auth.configure_hosted_auth(hosted(service_account))
    forbidden = Mock(side_effect=AssertionError("unbound getter accessed custody"))
    monkeypatch.setattr(custody.os, "open", forbidden)
    with pytest.raises(RuntimeError, match="^property_binding_required$") as error:
        getter()
    assert error.value.__cause__ is error.value.__context__ is None
    forbidden.assert_not_called()


def test_missing_approved_binding_never_infers_identity_from_documents(
    service_account, monkeypatch
):
    config = hosted(service_account).model_copy(
        update={
            "google_approved_client_id": None,
            "google_approved_project_id": None,
        }
    )
    auth.configure_hosted_auth(config)
    forbidden = Mock(side_effect=AssertionError("unapproved binding read documents"))
    monkeypatch.setattr(custody.os, "open", forbidden)
    assert auth.google_credentials_state() == "missing"
    forbidden.assert_not_called()
