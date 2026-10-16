"""Hosted Google identity contracts; no live Google APIs or enrolled credentials."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from google_seo_mcp import auth
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


@pytest.fixture(scope="module")
def ephemeral_pem():
    # This ephemeral signing fixture belongs to no Google account.
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


@pytest.fixture
def service_account(tmp_path, ephemeral_pem):
    path = tmp_path / "synthetic-sa.json"
    path.write_text(
        json.dumps(
            {
                "type": "service_account",
                "client_email": "fixture@example.invalid",
                "private_key": ephemeral_pem,
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        )
    )
    return path


def hosted(path):
    return ProductionRuntimeConfig(
        profile="production",
        transport="streamable-http",
        google_auth_mode="service-account",
        service_account_file=path,
        consumer_keys_file=Path("unused-registry.json"),
    )


def test_configure_is_lazy_and_readiness_never_constructs_or_refreshes(
    service_account, monkeypatch
):
    factory = Mock(side_effect=AssertionError("credential constructor during readiness"))
    monkeypatch.setattr(auth.SACredentials, "from_service_account_file", factory)
    # Configuration must not even open/stat the identity file.
    with monkeypatch.context() as guard:
        guard.setattr(Path, "stat", Mock(side_effect=AssertionError("startup stat")))
        guard.setattr(Path, "open", Mock(side_effect=AssertionError("startup open")))
        auth.configure_hosted_auth(hosted(service_account))
    assert auth.google_credentials_state() == "available"
    assert auth.current_credential_type() == "service_account"
    reset = auth.reset_clients()
    assert reset["deleted_oauth_token"] is False
    assert auth.google_credentials_state() == "available"
    factory.assert_not_called()


@pytest.mark.parametrize("getter", GETTERS, ids=lambda f: f.__name__)
def test_missing_sa_ignores_legacy_environment_and_home(getter, tmp_path, monkeypatch, caplog):
    path = tmp_path / (SENTINEL + ".json")
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
    for name in ("build", "BetaAnalyticsDataClient", "AnalyticsAdminServiceClient"):
        monkeypatch.setattr(
            auth, name, Mock(side_effect=AssertionError("client with no credentials"))
        )
    with pytest.raises(RuntimeError, match="^credentials_missing$") as error:
        getter()
    assert error.value.__suppress_context__
    assert SENTINEL not in str(error.value) + caplog.text
    assert auth.google_credentials_state() == "pending"
    assert auth._scopes() == READONLY_SCOPES


def test_all_four_clients_share_exact_readonly_identity_without_refresh(
    service_account, monkeypatch
):
    auth.configure_hosted_auth(hosted(service_account))
    monkeypatch.setenv("GSC_ALLOW_DESTRUCTIVE", "true")
    monkeypatch.setenv("GOOGLE_SEO_PROFILE", "legacy")
    monkeypatch.setenv("GOOGLE_SEO_SERVICE_ACCOUNT_FILE", "/not/the/captured/identity")
    credentials = Mock()
    factory = Mock(return_value=credentials)
    discovery, data, admin = Mock(), Mock(), Mock()
    monkeypatch.setattr(auth.SACredentials, "from_service_account_file", factory)
    monkeypatch.setattr(auth, "build", discovery)
    monkeypatch.setattr(auth, "BetaAnalyticsDataClient", data)
    monkeypatch.setattr(auth, "AnalyticsAdminServiceClient", admin)
    for getter in GETTERS:
        assert getter() is getter()  # singleton reuse after the identity check
    factory.assert_called_once_with(str(service_account), scopes=READONLY_SCOPES)
    assert auth.SCOPES_READ == auth._scopes() == READONLY_SCOPES
    assert [call.args for call in discovery.call_args_list] == [
        ("searchconsole", "v1"),
        ("webmasters", "v3"),
    ]
    for call in discovery.call_args_list:
        assert call.kwargs == {
            "credentials": credentials,
            "cache_discovery": False,
            "static_discovery": True,
        }
    data.assert_called_once_with(credentials=credentials)
    admin.assert_called_once_with(credentials=credentials)
    credentials.refresh.assert_not_called()


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
    credentials = Mock()
    monkeypatch.setattr(
        auth.SACredentials, "from_service_account_file", Mock(return_value=credentials)
    )
    monkeypatch.setattr(auth, factory_name, Mock(side_effect=ValueError(SENTINEL)))
    with pytest.raises(RuntimeError, match="^google_client_unavailable$") as error:
        getter()
    assert error.value.__suppress_context__
    assert SENTINEL not in str(error.value) + caplog.text
    credentials.refresh.assert_not_called()


def test_sa_constructor_failure_is_sanitized_and_marks_invalid(
    service_account, monkeypatch, caplog
):
    auth.configure_hosted_auth(hosted(service_account))
    monkeypatch.setattr(
        auth.SACredentials, "from_service_account_file", Mock(side_effect=ValueError(SENTINEL))
    )
    with pytest.raises(RuntimeError, match="^credentials_invalid$") as error:
        auth.get_data_client()
    assert error.value.__suppress_context__
    assert SENTINEL not in str(error.value) + caplog.text
    assert auth.google_credentials_state() == "invalid"


def test_production_environment_before_composition_cannot_use_legacy_sa_path(
    service_account, monkeypatch
):
    monkeypatch.setenv("GOOGLE_SEO_PROFILE", "production")
    monkeypatch.setenv("GOOGLE_SEO_SERVICE_ACCOUNT_FILE", str(service_account))
    factory = Mock(side_effect=AssertionError("uncaptured identity used"))
    monkeypatch.setattr(auth.SACredentials, "from_service_account_file", factory)
    with pytest.raises(RuntimeError, match="^credentials_missing$"):
        auth._build_creds()
    assert auth.google_credentials_state() == "pending"
    factory.assert_not_called()


@pytest.mark.parametrize("kind", ["directory", "permission-denied"])
def test_nonregular_or_unreadable_sa_is_sanitized(
    service_account, tmp_path, monkeypatch, caplog, kind
):
    path = tmp_path if kind == "directory" else service_account
    auth.configure_hosted_auth(hosted(path))
    factory = Mock(side_effect=AssertionError("unreadable identity constructed"))
    monkeypatch.setattr(auth.SACredentials, "from_service_account_file", factory)
    if kind == "permission-denied":
        monkeypatch.setattr(Path, "open", Mock(side_effect=PermissionError(SENTINEL)))
    assert auth.google_credentials_state() == "invalid"
    with pytest.raises(RuntimeError, match="^credentials_invalid$") as error:
        auth.get_admin_client()
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
def test_invalid_or_oversized_file_never_reaches_constructor(tmp_path, monkeypatch, payload):
    path = tmp_path / "invalid.json"
    path.write_text(payload)
    factory = Mock(side_effect=AssertionError("invalid file reached Google constructor"))
    monkeypatch.setattr(auth.SACredentials, "from_service_account_file", factory)
    auth.configure_hosted_auth(hosted(path))
    assert auth.google_credentials_state() == "invalid"
    with pytest.raises(RuntimeError, match="^credentials_invalid$"):
        auth._build_creds()
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
    info[field] = value
    service_account.write_text(json.dumps(info))
    factory = Mock(side_effect=AssertionError("unqualified credentials constructed"))
    monkeypatch.setattr(auth.SACredentials, "from_service_account_file", factory)
    auth.configure_hosted_auth(hosted(service_account))
    assert auth.google_credentials_state() == "invalid"
    with pytest.raises(RuntimeError, match="^credentials_invalid$"):
        auth.get_searchconsole()
    factory.assert_not_called()


def test_offline_validation_cache_revalidates_file_change(service_account, monkeypatch):
    auth.configure_hosted_auth(hosted(service_account))
    signer = Mock(wraps=auth.RSASigner.from_string)
    monkeypatch.setattr(auth.RSASigner, "from_string", signer)
    assert auth.google_credentials_state() == auth.google_credentials_state() == "available"
    assert signer.call_count == 1
    info = json.loads(service_account.read_text())
    info["project_id"] = "different-synthetic-project"
    service_account.write_text(json.dumps(info))
    assert auth.google_credentials_state() == "available"
    assert signer.call_count == 2


def test_atomic_identity_replacement_invalidates_all_client_caches(service_account, monkeypatch):
    auth.configure_hosted_auth(hosted(service_account))
    first_credentials, second_credentials = Mock(), Mock()
    factory = Mock(side_effect=[first_credentials, second_credentials])
    monkeypatch.setattr(auth.SACredentials, "from_service_account_file", factory)
    constructors = [Mock(side_effect=lambda *a, **kw: object()) for _ in range(3)]
    for name, constructor in zip(
        ("build", "BetaAnalyticsDataClient", "AnalyticsAdminServiceClient"),
        constructors,
        strict=True,
    ):
        monkeypatch.setattr(auth, name, constructor)
    first_clients = [getter() for getter in GETTERS]
    replacement = service_account.with_suffix(".replacement")
    replacement.write_text(service_account.read_text())
    replacement.replace(service_account)
    second_clients = [getter() for getter in GETTERS]
    assert all(
        first is not second for first, second in zip(first_clients, second_clients, strict=True)
    )
    assert factory.call_count == 2
    assert [call.kwargs["credentials"] for call in constructors[0].call_args_list] == [
        first_credentials
    ] * 2 + [second_credentials] * 2
    for constructor in constructors[1:]:
        assert [call.kwargs["credentials"] for call in constructor.call_args_list] == [
            first_credentials,
            second_credentials,
        ]
