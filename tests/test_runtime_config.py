"""Offline contracts for the environment/CLI production boundary."""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from pydantic import ValidationError

from google_seo_mcp.runtime_config import (
    ProductionRuntimeConfig,
    RuntimeConfigurationError,
    load_runtime_config,
)


def hosted(**changes):
    return {"GOOGLE_SEO_TRANSPORT": "streamable-http", **changes}


def test_default_is_legacy_stdio_and_config_does_not_parse_process_arguments():
    with patch("sys.argv", ["pytest", "--unknown"]):
        config = load_runtime_config([], {})
    assert config.transport == "stdio"
    assert config.profile == "legacy"
    assert config.google_auth_mode == "legacy"
    assert config.consumer_keys_file is None and config.service_account_file is None


def test_cli_transport_host_port_profile_override_environment():
    config = load_runtime_config(
        ["--transport", "stdio", "--host", "127.0.0.1", "--port", "9123", "--profile", "legacy"],
        hosted(GOOGLE_SEO_HOST="0.0.0.0", GOOGLE_SEO_PORT="8000", GOOGLE_SEO_PROFILE="production"),
    )
    assert (config.transport, config.host, config.port, config.profile) == (
        "stdio", "127.0.0.1", 9123, "legacy"
    )


def test_http_defaults_service_account_with_exact_local_and_public_authorities():
    config = load_runtime_config([], hosted())
    assert config.profile == "production" and config.google_auth_mode == "dual-user-oauth"
    assert config.host == "0.0.0.0" and config.port == 8000
    assert config.consumer_keys_file == Path("/run/secrets/consumer-keys.json")
    assert config.service_account_file is None
    assert config.google_oauth_client_file == Path("/run/secrets/google-seo-oauth-client.json")
    assert config.google_oauth_propel_dms_file == Path(
        "/run/secrets/google-seo-oauth-propel-dms.json"
    )
    assert config.google_oauth_addourteam99_file == Path(
        "/run/secrets/google-seo-oauth-addourteam99.json"
    )
    assert config.accepted_hosts == (
        "google-seo.mcp.propel.marketing", "localhost:8000", "127.0.0.1:8000", "[::1]:8000"
    )
    assert config.accepted_origins == ("https://google-seo.mcp.propel.marketing",)
    assert not config.require_google_credentials
    assert not any((config.debug, config.allow_destructive, config.allow_indexnow,
                    config.allow_local_files, config.allow_private_fetch))


def test_operator_exact_hosts_origins_and_custom_paths():
    config = load_runtime_config([], hosted(
        GOOGLE_SEO_PUBLIC_BASE_URL="https://Example.COM:9443",
        GOOGLE_SEO_ACCEPTED_HOSTS=(
            "EXAMPLE.com:9443, 192.0.2.10:3006,[2001:db8::1]:3006,EXAMPLE.com:9443"
        ),
        GOOGLE_SEO_ACCEPTED_ORIGINS="https://example.com:9443,http://localhost:8000",
        GOOGLE_SEO_CONSUMER_KEYS_FILE="/protected/registry.json",
        GOOGLE_SEO_OAUTH_PROPEL_DMS_FILE="/protected/absent.json",
        GOOGLE_SEO_REQUIRE_GOOGLE_CREDENTIALS="yes",
    ))
    assert config.accepted_hosts == ("example.com:9443", "192.0.2.10:3006", "[2001:db8::1]:3006")
    assert config.accepted_origins == ("https://example.com:9443", "http://localhost:8000")
    assert config.require_google_credentials
    assert config.google_oauth_propel_dms_file == Path("/protected/absent.json")
    assert "protected" not in repr(config)


@pytest.mark.parametrize("variable", [
    "GSC_ALLOW_DESTRUCTIVE", "GOOGLE_SEO_ALLOW_INDEXNOW", "GOOGLE_SEO_ALLOW_LOCAL_FILES",
    "GOOGLE_SEO_ALLOW_PRIVATE_FETCH", "GOOGLE_SEO_DEBUG",
])
@pytest.mark.parametrize("truthy", ["true", "TRUE", "True", "1", "yes", "on", "y", "t"])
def test_production_rejects_every_truthy_unsafe_gate(variable, truthy):
    with pytest.raises(RuntimeConfigurationError, match="^invalid runtime configuration$"):
        load_runtime_config([], hosted(**{variable: truthy}))


@pytest.mark.parametrize("falsey", ["false", "FALSE", "0", "no", "off", "n", "f"])
def test_production_accepts_false_gate_spellings(falsey):
    assert not load_runtime_config([], hosted(GSC_ALLOW_DESTRUCTIVE=falsey)).allow_destructive


@pytest.mark.parametrize("changes", [
    {"GOOGLE_SEO_TRANSPORT": "http"}, {"GOOGLE_SEO_TRANSPORT": "sse"},
    {"GOOGLE_SEO_PROFILE": "legacy"}, {"GOOGLE_SEO_PROFILE": "unknown"},
    {"GOOGLE_SEO_AUTH_MODE": "adc"}, {"GOOGLE_SEO_AUTH_MODE": "oauth"},
    {"GOOGLE_SEO_AUTH_MODE": "legacy"}, {"GOOGLE_SEO_PORT": "0"},
    {"GOOGLE_SEO_PORT": "65536"}, {"GOOGLE_SEO_PORT": "8.1"},
    {"GOOGLE_SEO_HOST": "https://example.com"}, {"GOOGLE_SEO_HOST": "example.com:8000"},
    {"GOOGLE_SEO_REQUIRE_GOOGLE_CREDENTIALS": "sometimes"}, {"GOOGLE_SEO_DEBUG": " true "},
])
def test_invalid_hosted_settings_are_sanitized(changes):
    with pytest.raises(RuntimeConfigurationError, match="^invalid runtime configuration$"):
        load_runtime_config([], hosted(**changes))


@pytest.mark.parametrize("authority", [
    "*", "*.example.com", "example.com:*", "example.com/", "example.com/path",
    "user@example.com", "example.com?secret", "example.com#fragment", "example.com:",
    "example.com:65536", "example.com:0", "example.com,", "", "example.com\n",
    "example.com\\evil", "https://example.com", "a%2eb.example", "exämple.com",
])
def test_host_authorities_reject_wildcards_urls_controls_and_ambiguous_ports(authority):
    with pytest.raises(RuntimeConfigurationError, match="^invalid runtime configuration$"):
        load_runtime_config([], hosted(GOOGLE_SEO_ACCEPTED_HOSTS=authority))


@pytest.mark.parametrize("origin", [
    "*", "https://*.example.com", "null", "https://example.com/", "https://example.com/path",
    "https://user@example.com", "https://example.com?secret", "https://example.com#secret",
    "https://example.com:", "file://example.com", "https://example.com\n", "",
])
def test_origins_must_be_exact(origin):
    with pytest.raises(RuntimeConfigurationError, match="^invalid runtime configuration$"):
        load_runtime_config([], hosted(GOOGLE_SEO_ACCEPTED_ORIGINS=origin))


@pytest.mark.parametrize("url", ["http://example.com", "https://example.com/", "https://*.example.com"])
def test_public_url_must_be_exact_https_origin(url):
    with pytest.raises(RuntimeConfigurationError):
        load_runtime_config([], hosted(GOOGLE_SEO_PUBLIC_BASE_URL=url))


@pytest.mark.parametrize("argv", [
    ["--unknown", "private-sentinel"], ["--port", "private-sentinel"],
    ["--transport", "private-sentinel"], ["--trans", "stdio"], ["--host"],
])
def test_cli_errors_never_echo_raw_values(argv, capsys):
    with pytest.raises(RuntimeConfigurationError) as error:
        load_runtime_config(argv, {})
    assert str(error.value) == "invalid runtime configuration"
    assert "private-sentinel" not in str(error.value)
    assert capsys.readouterr() == ("", "")


def test_model_is_frozen_extra_forbidden_and_paths_hidden():
    config = load_runtime_config(
        [], hosted(GOOGLE_SEO_OAUTH_PROPEL_DMS_FILE="/private-sentinel/key.json")
    )
    assert "private-sentinel" not in repr(config)
    with pytest.raises(ValidationError):
        config.port = 9000
    with pytest.raises(ValidationError):
        ProductionRuntimeConfig.model_validate({"unknown": "private-sentinel"})
    with pytest.raises(ValidationError):
        ProductionRuntimeConfig(port=True)


def test_stdio_main_selects_only_stdio_without_http_listener(monkeypatch):
    from google_seo_mcp import server

    monkeypatch.setattr(server, "load_runtime_config", lambda argv: load_runtime_config(argv, {}))
    instance = Mock()
    with (
        patch.object(server, "create_server", return_value=instance),
        patch("uvicorn.run") as listener,
    ):
        server.main([])
    instance.run.assert_called_once_with(transport="stdio")
    listener.assert_not_called()


def test_build_release_revision_accepts_exact_sha(monkeypatch):
    from google_seo_mcp.http_app import _release_revision

    sha = "fb3124486d2927376d89d3b7bca46433b23641ab"
    monkeypatch.setenv("GOOGLE_SEO_REVISION", sha)
    assert _release_revision() == sha


@pytest.mark.parametrize("revision", ["", "A" * 40, "a" * 39, "a" * 41, "private-sentinel"])
def test_build_release_revision_rejects_untrusted_values_without_echo(monkeypatch, revision):
    from google_seo_mcp.http_app import _release_revision

    monkeypatch.setenv("GOOGLE_SEO_REVISION", revision)
    with pytest.raises(ValueError, match="^invalid HTTP application configuration$") as error:
        _release_revision()
    assert "private-sentinel" not in str(error.value)


@pytest.mark.parametrize("revision", [None, "unknown"])
def test_local_release_revision_fallback_is_explicit(monkeypatch, revision):
    from google_seo_mcp.http_app import _release_revision

    if revision is None:
        monkeypatch.delenv("GOOGLE_SEO_REVISION", raising=False)
    else:
        monkeypatch.setenv("GOOGLE_SEO_REVISION", revision)
    with patch("google_seo_mcp.http_app.version", return_value="0.8.5"):
        assert _release_revision() == "0.8.5"


@pytest.mark.parametrize("environment", [{}, hosted()])
def test_bing_exact_defaults_preserve_legacy_and_hosted_configuration(environment):
    config = load_runtime_config([], environment)
    assert config.bing_credentials_file == Path("/run/secrets/bing-webmaster.json")
    assert "bing_sites_file" not in type(config).model_fields
    assert config.require_bing_credentials is False
    direct = ProductionRuntimeConfig()
    assert direct.bing_credentials_file == config.bing_credentials_file
    assert "bing_sites_file" not in type(direct).model_fields
    assert direct.require_bing_credentials is False


def test_bing_model_has_exactly_three_additive_fields():
    original = {
        "transport", "profile", "host", "port", "public_base_url", "accepted_hosts",
        "accepted_origins", "consumer_keys_file", "service_account_file", "google_auth_mode",
        "require_google_credentials", "allow_indexnow", "allow_local_files",
        "allow_private_fetch", "allow_destructive", "debug",
        "google_oauth_client_file", "google_oauth_propel_dms_file",
        "google_oauth_addourteam99_file", "google_approved_client_id",
        "google_approved_project_id",
    }
    assert set(ProductionRuntimeConfig.model_fields) == original | {
        "bing_credentials_file", "require_bing_credentials",
    }


@pytest.mark.parametrize("required", [False, True])
def test_bing_strict_path_boolean_repr_and_no_file_or_network_io(required):
    environment = hosted(
        GOOGLE_SEO_BING_CREDENTIALS_FILE="/synthetic-private-sentinel/key.json",
        GOOGLE_SEO_OAUTH_ADDOURTEAM99_FILE="/synthetic-private-sentinel/sites.json",
        GOOGLE_SEO_REQUIRE_BING_CREDENTIALS=str(required),
    )
    with (
        patch("builtins.open", side_effect=AssertionError("unexpected open")),
        patch.object(Path, "open", side_effect=AssertionError("unexpected path open")),
        patch.object(Path, "stat", side_effect=AssertionError("unexpected stat")),
        patch.object(Path, "resolve", side_effect=AssertionError("unexpected resolve")),
        patch("socket.getaddrinfo", side_effect=AssertionError("unexpected DNS")),
        patch("socket.socket", side_effect=AssertionError("unexpected socket")),
    ):
        config = load_runtime_config([], environment)
        direct = ProductionRuntimeConfig(
            bing_credentials_file=Path("/synthetic-private-sentinel/key.json"),
            google_oauth_addourteam99_file="/synthetic-private-sentinel/sites.json",
            require_bing_credentials=required,
        )
    for result in (config, direct):
        assert result.bing_credentials_file == Path("/synthetic-private-sentinel/key.json")
        assert result.google_oauth_addourteam99_file == Path(
            "/synthetic-private-sentinel/sites.json"
        )
        assert result.require_bing_credentials is required
        assert "synthetic-private-sentinel" not in repr(result)
        assert "synthetic-private-sentinel" not in str(result)
    assert config.google_auth_mode == "dual-user-oauth"
    assert config.require_google_credentials is False


@pytest.mark.parametrize("field,variable", [
    ("bing_credentials_file", "GOOGLE_SEO_BING_CREDENTIALS_FILE"),
    ("bing_sites_file", "GOOGLE_SEO_BING_SITES_FILE"),
])
@pytest.mark.parametrize("value", [
    "", "private-sentinel.json", "~/private-sentinel.json", "/", "//private-sentinel/x",
    "/private-sentinel/../x", "/private-sentinel/./x", "/private-sentinel//x",
    "/private-sentinel/", "/private-sentinel\n/x", "/private-sentinel\x00/x",
    "/private-sentinel\x7f/x", "/private-sentinel\\x", "/private-sentinel /x",
    "https://private-sentinel/x", "file:///private-sentinel/x", "/private-sentinel/\ud800",
    None, True, 1, b"/private-sentinel/x", [], {},
])
def test_bing_paths_are_strict_absolute_and_errors_hide_values(field, variable, value, capsys):
    # Preserve historical IDs; retired policy paths now exercise OAuth custody.
    if field == "bing_sites_file":
        with pytest.raises(ValidationError):
            ProductionRuntimeConfig(**{field: value})
        field, variable = "google_oauth_addourteam99_file", "GOOGLE_SEO_OAUTH_ADDOURTEAM99_FILE"
    with pytest.raises(ValidationError) as direct:
        ProductionRuntimeConfig(**{field: value})
    assert "private-sentinel" not in str(direct.value)
    assert "private-sentinel" not in repr(direct.value)
    with pytest.raises(RuntimeConfigurationError) as loaded:
        load_runtime_config([], {variable: value})
    assert str(loaded.value) == "invalid runtime configuration"
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("value", ["true", "false", "1", "0", 1, 0, 1.0, None, [], {}])
def test_bing_required_direct_model_rejects_non_boolean_values(value):
    with pytest.raises(ValidationError):
        ProductionRuntimeConfig(require_bing_credentials=value)


@pytest.mark.parametrize("value,expected", [
    ("true", True), ("TRUE", True), ("True", True), ("1", True), ("yes", True),
    ("on", True), ("y", True), ("t", True), ("false", False), ("FALSE", False),
    ("0", False), ("no", False), ("off", False), ("n", False), ("f", False),
])
def test_bing_required_env_uses_existing_explicit_boolean_parser(value, expected):
    config = load_runtime_config([], hosted(GOOGLE_SEO_REQUIRE_BING_CREDENTIALS=value))
    assert config.require_bing_credentials is expected


@pytest.mark.parametrize("value", ["", " true ", "sometimes", "private-sentinel", "2"])
def test_bing_required_env_invalid_boolean_is_sanitized(value):
    with pytest.raises(RuntimeConfigurationError, match="^invalid runtime configuration$"):
        load_runtime_config([], {"GOOGLE_SEO_REQUIRE_BING_CREDENTIALS": value})


@pytest.mark.parametrize("option", [
    "--bing-credentials-file", "--bing-sites-file", "--require-bing-credentials",
])
def test_bing_adds_no_cli_options(option, capsys):
    with pytest.raises(RuntimeConfigurationError, match="^invalid runtime configuration$"):
        load_runtime_config([option, "private-sentinel"], {})
    assert capsys.readouterr() == ("", "")


def test_bing_configuration_is_frozen_path_only_without_key_or_home_fallback():
    config = load_runtime_config([], {
        "HOME": "/synthetic-private-sentinel",
        "BING_API_KEY": "synthetic-private-sentinel",
        "BING_WEBMASTER_API_KEY": "synthetic-private-sentinel",
        "GOOGLE_SEO_BING_API_KEY": "synthetic-private-sentinel",
    })
    assert config.bing_credentials_file == Path("/run/secrets/bing-webmaster.json")
    assert "bing_sites_file" not in type(config).model_fields
    assert "synthetic-private-sentinel" not in repr(config)
    for field, value in (
        ("bing_credentials_file", Path("/synthetic/key.json")),
        ("google_oauth_addourteam99_file", Path("/synthetic/sites.json")),
        ("require_bing_credentials", True),
    ):
        with pytest.raises(ValidationError):
            setattr(config, field, value)
    for field in ("bing_api_key", "bing_base_url", "bing_auth_mode"):
        with pytest.raises(ValidationError):
            ProductionRuntimeConfig(**{field: "synthetic-private-sentinel"})


@pytest.mark.parametrize(
    "changes",
    [
        {"GOOGLE_SEO_AUTH_MODE": "service-account"},
        {"GOOGLE_SEO_SERVICE_ACCOUNT_FILE": "/synthetic/key.json"},
        {
            "GOOGLE_SEO_AUTH_MODE": "dual-user-oauth",
            "GOOGLE_SEO_SERVICE_ACCOUNT_FILE": "/synthetic/key.json",
        },
        {"GOOGLE_SEO_APPROVED_CLIENT_ID": "synthetic.apps.googleusercontent.com"},
        {"GOOGLE_SEO_APPROVED_PROJECT_ID": "synthetic-project"},
        {
            "GOOGLE_SEO_APPROVED_CLIENT_ID": "invalid",
            "GOOGLE_SEO_APPROVED_PROJECT_ID": "synthetic-project",
        },
        {
            "GOOGLE_SEO_OAUTH_CLIENT_FILE": "/same.json",
            "GOOGLE_SEO_OAUTH_PROPEL_DMS_FILE": "/same.json",
        },
        {
            "GOOGLE_SEO_OAUTH_PROPEL_DMS_FILE": "/same.json",
            "GOOGLE_SEO_OAUTH_ADDOURTEAM99_FILE": "/same.json",
        },
        {
            "GOOGLE_SEO_OAUTH_CLIENT_FILE": "/same.json",
            "GOOGLE_SEO_OAUTH_ADDOURTEAM99_FILE": "/same.json",
        },
    ],
)
def test_dual_oauth_refuses_sa_mixed_incomplete_binding_and_aliased_slots(changes, capsys):
    forbidden = Mock(side_effect=AssertionError("configuration performed I/O"))
    with (
        patch.object(Path, "open", forbidden),
        patch("os.open", forbidden),
        patch("socket.getaddrinfo", forbidden),
        pytest.raises(RuntimeConfigurationError, match="^invalid runtime configuration$"),
    ):
        load_runtime_config([], hosted(**changes))
    forbidden.assert_not_called()
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "field",
    ["google_oauth_client_file", "google_oauth_propel_dms_file", "google_oauth_addourteam99_file"],
)
@pytest.mark.parametrize(
    "value",
    [
        "",
        "relative.json",
        "/",
        "/synthetic/../key.json",
        "/synthetic//key.json",
        "/synthetic/key\n.json",
        None,
        True,
    ],
)
def test_each_oauth_slot_keeps_strict_path_validation(field, value):
    with pytest.raises(ValidationError):
        ProductionRuntimeConfig(**{field: value})


def test_retired_bing_policy_is_not_a_config_field_or_authority():
    config = load_runtime_config(
        [], hosted(GOOGLE_SEO_BING_SITES_FILE="relative-invalid-retired-policy")
    )
    assert "bing_sites_file" not in config.model_dump()
    with pytest.raises(ValidationError):
        ProductionRuntimeConfig(bing_sites_file="/synthetic/retired-policy.json")
