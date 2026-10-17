"""Credential-free subprocess checks for startup redaction and stdio compatibility."""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
SENTINEL = "SYNTHETIC_STARTUP_PRIVATE_VALUE"

# Captured historical stdio catalog; independent of the production manifest.
LEGACY_NAMES = (
    'aeo_ai_bots_robots_audit',
    'aeo_llms_txt_check',
    'alerts_rss_parse',
    'cross_gsc_to_ga4_journey',
    'cross_landing_page_full_diagnosis',
    'cross_multi_property_comparison',
    'cross_opportunity_matrix',
    'cross_seo_to_revenue_attribution',
    'cross_traffic_health_check',
    'crux_compare_origins',
    'crux_current',
    'crux_history',
    'ga4_anomalies',
    'ga4_channel_attribution',
    'ga4_cohort_retention',
    'ga4_content_decay',
    'ga4_conversion_funnel',
    'ga4_estimate_query_size',
    'ga4_event_volume_comparison',
    'ga4_get_property_details',
    'ga4_landing_page_health',
    'ga4_list_properties',
    'ga4_list_schema_categories',
    'ga4_query',
    'ga4_search_schema',
    'ga4_traffic_drops_by_channel',
    'get_capabilities',
    'google_indexing_delete',
    'google_indexing_publish',
    'google_suggest',
    'google_suggest_alphabet',
    'google_trends_keyword',
    'google_trends_related',
    'gsc_alerts',
    'gsc_cannibalization',
    'gsc_content_decay',
    'gsc_ctr_opportunities',
    'gsc_inspect_url',
    'gsc_list_sitemaps',
    'gsc_list_sites',
    'gsc_quick_wins',
    'gsc_search_analytics',
    'gsc_site_snapshot',
    'gsc_submit_sitemap',
    'gsc_traffic_drops',
    'history_diff',
    'history_list',
    'history_save_snapshot',
    'indexnow_generate_key',
    'indexnow_submit',
    'indexnow_submit_sitemap',
    'lighthouse_audit',
    'lighthouse_compare_mobile_desktop',
    'lighthouse_core_web_vitals',
    'lighthouse_lcp_opportunities',
    'lighthouse_seo_score',
    'logs_bot_ratio',
    'logs_crawl_waste',
    'logs_googlebot_crawl_budget',
    'logs_parse',
    'logs_spider_trap_detector',
    'logs_status_distribution',
    'logs_verify_googlebot_ip',
    'migration_broken_internal_links',
    'migration_calibration_check',
    'migration_export_redirects_apache',
    'migration_export_redirects_cloudflare',
    'migration_export_redirects_nginx',
    'migration_googlebot_diff',
    'migration_hreflang_cluster_audit',
    'migration_image_alt_coverage',
    'migration_image_alts',
    'migration_indexation_recovery_monitor',
    'migration_meta_validate_golden_set',
    'migration_multi_bot_diff',
    'migration_prerender_check',
    'migration_prerender_check_batch',
    'migration_prerender_vs_hydrated',
    'migration_redirect_chain',
    'migration_redirect_chains',
    'migration_redirects_plan',
    'migration_response_times',
    'migration_robots_audit',
    'migration_robots_diff',
    'migration_schema_parity_check',
    'migration_seo_equity_report',
    'migration_sitemap_diff',
    'migration_sitemap_validate',
    'migration_verify_googlebot_ip',
    'migration_wayback_baseline',
    'migration_wp_audit_site',
    'migration_wp_extract_redirects',
    'migration_wp_internal_links_graph',
    'reauthenticate',
    'reload_credentials',
    'schema_extract_url',
    'schema_suggest_for_page',
    'schema_validate_url',
    'serp_aio_monitor',
    'serp_check',
    'serp_competitor_intersect',
    'serp_paa_extractor',
)

# Independent additive golden; LEGACY_NAMES above remains the historical AST fixture.
BING_NAMES = (
    'bing_list_sites', 'bing_rank_traffic_stats', 'bing_query_stats',
    'bing_page_stats', 'bing_page_query_stats', 'bing_query_page_stats',
    'bing_crawl_stats', 'bing_crawl_issues', 'bing_url_info',
    'bing_list_sitemaps', 'bing_sitemap_details',
)


def _package_hashes(package):
    return {
        str(path.relative_to(package)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(package.rglob('*'))
        if path.is_file() and '__pycache__' not in path.parts
        and not any(part.endswith('.egg-info') for part in path.parts)
        and path.suffix != '.pyc'
    }


def _child_provenance(environment, executable, *, installed=False, receipt_name='child'):
    """Select source explicitly, or a noneditable install without source PYTHONPATH.

    Receipts are separate owned files, never stdout/stderr protocol/log evidence.
    A child records its full package tree and every actually imported module on exit.
    The parent reads it back against current source bytes even for rejected startup.
    """
    import google_seo_mcp

    source = ROOT / 'src/google_seo_mcp'
    parent_package = Path(google_seo_mcp.__file__).resolve().parent
    installed = installed or parent_package != source
    environment = dict(environment)
    if installed:
        environment.pop('PYTHONPATH', None)
        expected_package = None
    else:
        environment['PYTHONPATH'] = str(ROOT / 'src')
        expected_package = str(source)
    receipt = Path(environment['HOME']) / (receipt_name + '-provenance.json')
    assert not receipt.exists()
    # No parent environment or receipt filename is passed through application argv.
    code = '''
import atexit
import hashlib
import json
import sys
from importlib import metadata
from pathlib import Path
import google_seo_mcp

_proof_root = Path(google_seo_mcp.__file__).resolve().parent
_proof_files = {
    str(p.relative_to(_proof_root)): hashlib.sha256(p.read_bytes()).hexdigest()
    for p in sorted(_proof_root.rglob('*'))
    if p.is_file() and '__pycache__' not in p.parts
    and not any(part.endswith('.egg-info') for part in p.parts) and p.suffix != '.pyc'
}
_proof = {'executable': sys.executable, 'prefix': sys.prefix,
          'package': str(_proof_root), 'files': _proof_files, 'sys_path': sys.path,
          'pythonpath': __import__('os').environ.get('PYTHONPATH')}
_proof_dist = metadata.distribution('google-seo-mcp')
_proof['direct_url'] = json.loads(_proof_dist.read_text('direct_url.json') or '{}')
_proof['distribution_root'] = str(Path(_proof_dist.locate_file('')).resolve())

def _write_child_proof():
    _proof['modules'] = {
        name: str(Path(module.__file__).resolve())
        for name, module in tuple(sys.modules.items())
        if (name == 'google_seo_mcp' or name.startswith('google_seo_mcp.'))
        and getattr(module, '__file__', None)
    }
    Path(RECEIPT).write_text(json.dumps(_proof, sort_keys=True))

atexit.register(_write_child_proof)
'''.replace('RECEIPT', repr(str(receipt)))
    return environment, code, (receipt, executable, expected_package)


def _assert_child_provenance(proof):
    receipt, executable, expected_package = proof
    actual = json.loads(receipt.read_text())
    assert actual['executable'] == executable
    package = Path(actual['package'])
    assert actual['files'] == _package_hashes(ROOT / 'src/google_seo_mcp'), (
        'child package differs from current source; rebuild/install the current wheel', receipt
    )
    if expected_package is not None:
        assert package == Path(expected_package)
        assert actual['pythonpath'] == str(ROOT / 'src')
    else:
        prefix = Path(executable).absolute().parent.parent.resolve()
        assert Path(actual['prefix']).resolve() == prefix
        assert prefix in package.parents and ROOT / 'src' not in package.parents
        assert Path(actual['distribution_root']) == package.parent
        assert not actual['direct_url'].get('dir_info', {}).get('editable', False)
        assert actual['pythonpath'] is None
        assert str(ROOT / 'src') not in actual['sys_path']
    assert 'google_seo_mcp' in actual['modules']
    for name, filename in actual['modules'].items():
        path = Path(filename)
        assert package in path.parents, (name, path, package)
        relative = str(path.relative_to(package))
        assert relative in actual['files'], (name, path)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == actual['files'][relative]
    return actual


# Install guards before importing the application. Startup/listing must neither
# listen nor contact providers, even when their credentials are unavailable.
GUARDED_BOOT = """
import runpy
import socket
import google.auth
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow

def forbidden(*args, **kwargs):
    raise AssertionError("PROVIDER_OR_LISTENER_ATTEMPT")

socket.socket.bind = forbidden
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden
socket.getaddrinfo = forbidden
google.auth.default = forbidden
service_account.Credentials.from_service_account_file = forbidden
InstalledAppFlow.from_client_config = forbidden
InstalledAppFlow.from_client_secrets_file = forbidden
"""


@pytest.fixture
def clean_environment(tmp_path):
    # Equivalent to the qualification wrapper: allowlist, never os.environ.copy().
    home = tmp_path / "empty-home"
    home.mkdir()
    assert not list(home.iterdir())
    return {
        "HOME": str(home),
        "PATH": f"{Path(sys.executable).parent}:/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TMPDIR": str(home),
        "PYTHONUNBUFFERED": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def run_startup(environment, *, code=None, arguments=()):
    environment, provenance, proof = _child_provenance(environment, sys.executable)
    source = GUARDED_BOOT + provenance + (
        code or "runpy.run_module('google_seo_mcp', run_name='__main__')"
    )
    result = subprocess.run(
        [sys.executable, "-c", source, *arguments],
        cwd=environment['HOME'],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    _assert_child_provenance(proof)
    return result


@pytest.mark.parametrize(
    ("variable", "value", "arguments"),
    [
        ("GOOGLE_SEO_LOG_LEVEL", SENTINEL, ()),
        ("GOOGLE_SEO_LOG_LEVEL", "", ()),
        ("GOOGLE_SEO_LOG_LEVEL", "INFO\n" + SENTINEL, ()),
        ("GOOGLE_SEO_TRANSPORT", SENTINEL, ()),
        ("GOOGLE_SEO_PROFILE", SENTINEL, ()),
        ("GOOGLE_SEO_PORT", SENTINEL, ()),
        ("GOOGLE_SEO_ACCEPTED_HOSTS", SENTINEL + "/private", ()),
        ("GOOGLE_SEO_ALLOW_LOCAL_FILES", SENTINEL, ()),
        (None, None, ("--transport", SENTINEL)),
        (None, None, ("--" + SENTINEL,)),
    ],
)
def test_invalid_startup_is_sanitized_before_listener_or_provider(
    clean_environment, variable, value, arguments
):
    if variable:
        clean_environment[variable] = value
    result = run_startup(clean_environment, arguments=arguments)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "invalid runtime configuration" in result.stderr
    assert SENTINEL not in result.stderr
    assert "PROVIDER_OR_LISTENER_ATTEMPT" not in result.stderr
    assert "During handling of the above exception" not in result.stderr
    assert "The above exception was the direct cause" not in result.stderr


@pytest.mark.parametrize("registry_kind", ["missing", "empty", "corrupt", "invalid", "extra"])
def test_invalid_registry_startup_is_sanitized(clean_environment, tmp_path, registry_kind):
    path = tmp_path / (SENTINEL + ".json")
    if registry_kind == "empty":
        path.write_text("")
    elif registry_kind == "corrupt":
        path.write_text("{" + SENTINEL)
    elif registry_kind == "invalid":
        path.write_text(json.dumps({"version": 1, "consumers": [{"sha256": SENTINEL}]}))
    elif registry_kind == "extra":
        path.write_text(json.dumps({"version": 1, "consumers": [], SENTINEL: SENTINEL}))
    clean_environment.update({
        "GOOGLE_SEO_TRANSPORT": "streamable-http",
        "GOOGLE_SEO_CONSUMER_KEYS_FILE": str(path),
        "GOOGLE_SEO_SERVICE_ACCOUNT_FILE": str(tmp_path / (SENTINEL + "-sa.json")),
    })
    result = run_startup(clean_environment)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "invalid consumer key registry" in result.stderr
    assert SENTINEL not in result.stderr
    assert "PROVIDER_OR_LISTENER_ATTEMPT" not in result.stderr
    assert "During handling of the above exception" not in result.stderr


@pytest.mark.parametrize(
    "level", ["CRITICAL", "FATAL", "ERROR", "WARNING", "WARN", "INFO", "DEBUG", "NOTSET"]
)
def test_standard_legacy_levels_preserve_stderr_logging(clean_environment, level):
    clean_environment["GOOGLE_SEO_LOG_LEVEL"] = level
    code = """
import logging
import sys
from google_seo_mcp import server
assert logging.getLogger().level == getattr(logging, LEVEL)
assert all(handler.stream is sys.stderr for handler in logging.getLogger().handlers)
logging.getLogger('startup-test').critical('safe-startup-test')
""".replace("LEVEL", repr(level))
    result = run_startup(clean_environment, code=code)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert "safe-startup-test" in result.stderr
    assert "PROVIDER_OR_LISTENER_ATTEMPT" not in result.stderr


@pytest.mark.parametrize("environment_transport", [None, "stdio", "streamable-http"])
def test_hosted_composition_overrides_debug_without_provider_or_listener(
    clean_environment, environment_transport
):
    clean_environment["GOOGLE_SEO_LOG_LEVEL"] = "DEBUG"
    if environment_transport is not None:
        clean_environment["GOOGLE_SEO_TRANSPORT"] = environment_transport
    code = """
import asyncio
import json
import logging
from mcp.server.fastmcp.exceptions import ToolError
from google_seo_mcp.consumer_auth import (
    AuthenticatedConsumer, consumer_context, request_id_context,
)
from google_seo_mcp.server import create_server
from google_seo_mcp.runtime_config import load_runtime_config
instance = create_server(load_runtime_config(['--transport', 'streamable-http']))
assert instance.settings.stateless_http and instance.settings.json_response
assert logging.getLogger().level == logging.INFO
logging.getLogger('third.party').critical('SYNTHETIC_STARTUP_PRIVATE_VALUE')
logging.getLogger('google_seo_mcp.audit').info(json.dumps({'outcome': 'startup-test'}))
# Even schema-valid JSON on the audit logger has no controlled provenance.
logging.getLogger('google_seo_mcp.audit').info(json.dumps({
    'request_id': 'f' * 32, 'consumer': 'forged-consumer', 'tool': 'denied',
    'outcome': 'denied', 'duration_ms': 0,
}))

async def exercise_denied_dispatch():
    assert request_id_context.get() is None
    token = consumer_context.set(AuthenticatedConsumer(
        consumer_id='startup-consumer', key_id='startup-key',
    ))
    try:
        # Existing dispatch must generate its own protected audit record.
        await instance._tool_manager.call_tool('gsc_submit_sitemap', {
            'site_url': 'SYNTHETIC_STARTUP_PRIVATE_VALUE',
            'sitemap_url': 'SYNTHETIC_STARTUP_PRIVATE_VALUE',
        })
    except ToolError as error:
        assert error.args == ('tool_not_allowed',)
    else:
        raise AssertionError('excluded_tool_was_not_denied')
    finally:
        consumer_context.reset(token)
    assert consumer_context.get() is None

asyncio.run(exercise_denied_dispatch())
"""
    result = run_startup(clean_environment, code=code)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert 'startup-test' not in result.stderr
    assert 'forged-consumer' not in result.stderr
    records = [json.loads(line) for line in result.stderr.splitlines()]
    assert len(records) == 1
    audit = records[0]
    assert set(audit) == {'request_id', 'consumer', 'tool', 'outcome', 'duration_ms'}
    assert re.fullmatch(r'[0-9a-f]{32}', audit['request_id'])
    assert audit['consumer'] == 'startup-consumer'
    assert audit['tool'] == 'denied'
    assert audit['outcome'] == 'denied'
    assert type(audit['duration_ms']) in (int, float)
    assert math.isfinite(audit['duration_ms']) and 0 <= audit['duration_ms'] <= 86400000
    assert SENTINEL not in result.stderr
    assert 'PROVIDER_OR_LISTENER_ATTEMPT' not in result.stderr


def test_real_sdk_stdio_default_exhausts_exact_legacy_catalog(clean_environment):
    async def exercise():
        # The SDK parses every stdout line as JSON-RPC; non-protocol logging
        # would fail this actual subprocess initialize/list exchange.
        errors = io.StringIO()
        with anyio.fail_after(30):
            executable = os.environ.get('GOOGLE_SEO_TEST_PYTHON', sys.executable)
            environment, provenance, proof = _child_provenance(
                clean_environment, executable,
                installed='GOOGLE_SEO_TEST_PYTHON' in os.environ, receipt_name='stdio',
            )
            parameters = StdioServerParameters(
                command=executable,
                args=[
                    '-c', GUARDED_BOOT + provenance
                    + "runpy.run_module('google_seo_mcp', run_name='__main__')"
                ],
                env=environment,
                cwd=clean_environment['HOME'],
            )
            # stdio_client requires a real file descriptor for its stderr sink.
            with open(Path(clean_environment["HOME"]) / "server.stderr", "w+") as stderr:
                async with (
                    stdio_client(parameters, errlog=stderr) as (read, write),
                    ClientSession(read, write) as session,
                ):
                    initialized = await session.initialize()
                    assert initialized.serverInfo.name == "google-seo-mcp"
                    names, seen, cursor = [], set(), None
                    while True:
                        page = await session.list_tools(cursor=cursor)
                        names.extend(tool.name for tool in page.tools)
                        cursor = page.nextCursor
                        if cursor is None:
                            break
                        assert cursor not in seen
                        seen.add(cursor)
                stderr.seek(0)
                errors.write(stderr.read())
        _assert_child_provenance(proof)
        assert len(LEGACY_NAMES) == len(set(LEGACY_NAMES)) == 102
        assert len(BING_NAMES) == len(set(BING_NAMES)) == 11
        assert not set(LEGACY_NAMES) & set(BING_NAMES)
        assert len(names) == len(set(names)) == 113
        assert set(names) == set(LEGACY_NAMES) | set(BING_NAMES)
        assert "PROVIDER_OR_LISTENER_ATTEMPT" not in errors.getvalue()
        assert "Failed to parse JSONRPC" not in errors.getvalue()

    anyio.run(exercise)
