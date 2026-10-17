"""Real, offline SDK/socket checks of the hosted admission and lifecycle boundary.

GOOGLE_SEO_TEST_PYTHON selects a separately installed production wheel interpreter.
No parent credentials, PYTHONPATH, proxy configuration, or HOME enter children.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parents[1]
# Independent reviewed baseline and additive contract, never derived from discovery.
OLD35 = frozenset({
    "cross_gsc_to_ga4_journey", "cross_landing_page_full_diagnosis",
    "cross_multi_property_comparison", "cross_opportunity_matrix",
    "cross_seo_to_revenue_attribution", "cross_traffic_health_check",
    "ga4_anomalies", "ga4_channel_attribution", "ga4_cohort_retention", "ga4_content_decay",
    "ga4_conversion_funnel", "ga4_estimate_query_size", "ga4_event_volume_comparison",
    "ga4_get_property_details", "ga4_landing_page_health", "ga4_list_properties",
    "ga4_list_schema_categories", "ga4_query", "ga4_search_schema", "ga4_traffic_drops_by_channel",
    "gsc_alerts", "gsc_cannibalization", "gsc_content_decay", "gsc_ctr_opportunities",
    "gsc_inspect_url", "gsc_list_sitemaps", "gsc_list_sites", "gsc_quick_wins",
    "gsc_search_analytics", "gsc_site_snapshot", "gsc_traffic_drops",
    "serp_aio_monitor", "serp_check", "serp_competitor_intersect", "serp_paa_extractor",
})
BING11 = frozenset({
    "bing_list_sites", "bing_rank_traffic_stats", "bing_query_stats", "bing_page_stats",
    "bing_page_query_stats", "bing_query_page_stats", "bing_crawl_stats", "bing_crawl_issues",
    "bing_url_info", "bing_list_sitemaps", "bing_sitemap_details",
})
EXPECTED46 = OLD35 | BING11
PILOT = "https://kelleyconstructioninc.com/"
BING_PRIVATE = "SYNTHETIC_BING_KEY_NOT_ENROLLED+/=%"
PRIVATE = "SYNTHETIC_PRIVATE_ARGUMENT_AND_UPSTREAM_EXCEPTION"

# This launcher changes only test processes. The application/SDK implementation
# remains the installed one; no extra production routes or debug tools exist.
HARNESS = r'''
import builtins
from contextlib import asynccontextmanager
import json
from pathlib import Path
import socket
import sys
import time
import google.auth
from google.oauth2 import service_account
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from google_seo_mcp import server
from google_seo_mcp.consumer_auth import load_consumer_key_registry
from google_seo_mcp.http_app import create_http_app
from google_seo_mcp.runtime_config import load_runtime_config
import uvicorn
control = json.loads(sys.argv[1])
root = Path(control["directory"])
import hashlib
import google_seo_mcp
package = Path(google_seo_mcp.__file__).parent
(root / "provenance.json").write_text(json.dumps({
    "package": str(package),
    "hashes": {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in package.rglob("*")
               if p.is_file() and (p.suffix == ".py" or p.name == "production_tools.json")},
}))
original_run = StreamableHTTPSessionManager.run
@asynccontextmanager
async def observed(self):
    async with original_run(self):
        yield
    (root / "shutdown.json").write_text(json.dumps({
        "original_manager_exited": True,
        "task_group_cleared": self._task_group is None,
        "server_instances_empty": not self._server_instances,
    }))
StreamableHTTPSessionManager.run = observed
if control["slow"]:
    def slow():
        from google_seo_mcp.consumer_auth import consumer_context
        identity = consumer_context.get().consumer_id
        with (root / "entered").open("a") as output:
            output.write(identity + "\n")
        time.sleep(2)
        return {"consumer": identity}
    def upstream_error(site_url: str):
        raise RuntimeError("SYNTHETIC_PRIVATE_ARGUMENT_AND_UPSTREAM_EXCEPTION")
    server._LEGACY_TOOL_DEFINITIONS = [
        (slow if name == "gsc_list_sites" else
         upstream_error if name == "gsc_list_sitemaps" else fn, name)
        for fn, name in server._LEGACY_TOOL_DEFINITIONS
    ]
# Any accidental provider/DNS/fallback attempt leaves evidence and then fails.
def forbidden(*args, **kwargs):
    (root / "forbidden-attempt").write_text("attempted")
    raise AssertionError("PROVIDER_OR_FILE_ATTEMPT")
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden
socket.getaddrinfo = forbidden
google.auth.default = forbidden
service_account.Credentials.from_service_account_file = forbidden
config = load_runtime_config([])
instance = server.create_server(config)
app = create_http_app(config, load_consumer_key_registry(config.consumer_keys_file), instance)
if control["reflection"]:
    import httpx
    from urllib.parse import quote
    from google_seo_mcp.bing.client import BingReadClient
    from google_seo_mcp.bing.tools import configure_bing_tools
    def reflect(request):
        with (root / "synthetic-upstream").open("a") as output:
            output.write("one fake attempt\n")
        key = request.url.params["apikey"]
        mode = control["reflection"]
        if mode == "exception":
            raise RuntimeError(str(request.url))
        value = (quote(key, safe="") if mode == "encoded" else
                 "".join("\\u%04x" % ord(c) for c in key) if mode == "escaped" else key)
        return httpx.Response(200, json={"d": [], "unknown": {"nested": [{"value": value}]}})
    configure_bing_tools(BingReadClient(transport=httpx.MockTransport(reflect), max_retries=0))
if control["deny_bing_io"]:
    from google_seo_mcp.bing import auth as bing_auth, client as bing_client
    bing_auth._read = forbidden
    bing_auth.BingCredentialLoader.load = forbidden
    bing_client.BingReadClient.__init__ = forbidden
original_open, original_path_open = builtins.open, Path.open
def guarded_open(file, *args, **kwargs):
    if "SYNTHETIC_PRIVATE" in str(file):
        return forbidden()
    return original_open(file, *args, **kwargs)
def guarded_path_open(self, *args, **kwargs):
    if "SYNTHETIC_PRIVATE" in str(self):
        return forbidden()
    return original_path_open(self, *args, **kwargs)
builtins.open, Path.open = guarded_open, guarded_path_open
uvicorn.run(app, host=config.host, port=config.port, access_log=False,
            proxy_headers=False, log_config=None)
'''


def interpreter():
    selected = os.environ.get("GOOGLE_SEO_TEST_PYTHON", sys.executable)
    assert Path(selected).is_absolute() and Path(selected).is_file()
    return selected


class LiveServer:
    def __init__(self, directory, *, slow=False, entries=None, port=None,
                 google="pending", bing_key="pending", bing_policy="pending",
                 require_google=False, require_bing=False, deny_bing_io=False, reflection=None):
        self.directory = directory
        self.directory.mkdir(mode=0o700)
        home = directory / "empty-home"
        home.mkdir()
        self.keys = {name: secrets.token_urlsafe(32) for name in ("alpha", "beta", "revoked")}
        self.registry = directory / "consumers.json"
        self.entries = entries or [
            {"consumer_id": name, "key_id": name + "-key", "sha256": hashlib.sha256(
                key.encode("ascii")).hexdigest(), "enabled": name != "revoked"}
            for name, key in self.keys.items()
        ]
        self.write_registry()
        if port is None:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.environment = {
            "HOME": str(home), "TMPDIR": str(home), "LANG": "C.UTF-8",
            "PATH": f"{Path(interpreter()).parent}:/usr/local/bin:/usr/bin:/bin",
            "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "GOOGLE_SEO_TRANSPORT": "streamable-http", "GOOGLE_SEO_HOST": "0.0.0.0",
            "GOOGLE_SEO_PORT": str(port), "GOOGLE_SEO_CONSUMER_KEYS_FILE": str(self.registry),
            "GOOGLE_SEO_SERVICE_ACCOUNT_FILE": str(directory / "intentionally-missing.json"),
            "GOOGLE_SEO_REVISION": "b" * 40,
        }
        self.slow = slow
        self.deny_bing_io = deny_bing_io
        self.reflection = reflection
        self.process = None
        self.environment.update({
            "GOOGLE_SEO_BING_CREDENTIALS_FILE": str(directory / "synthetic-bing-key.json"),
            "GOOGLE_SEO_BING_SITES_FILE": str(directory / "synthetic-bing-policy.json"),
            "GOOGLE_SEO_REQUIRE_BING_CREDENTIALS": str(require_bing).lower(),
            "GOOGLE_SEO_REQUIRE_GOOGLE_CREDENTIALS": str(require_google).lower(),
        })
        documents = [
            (bing_key, "GOOGLE_SEO_BING_CREDENTIALS_FILE",
             {"version": 1, "api_key": BING_PRIVATE}),
            (bing_policy, "GOOGLE_SEO_BING_SITES_FILE", {"version": 1, "sites": [PILOT]}),
        ]
        if google == "available":
            # Ephemeral local signer; belongs to no Google identity or account.
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()).decode()
            google_document = {"type": "service_account", "client_email": "fixture@example.invalid",
                               "private_key": pem, "token_uri": "https://oauth2.googleapis.com/token"}
        else:
            google_document = {}
        documents.append((google, "GOOGLE_SEO_SERVICE_ACCOUNT_FILE", google_document))
        for state, variable, document in documents:
            assert state in ("pending", "invalid", "available")
            if state != "pending":
                path = Path(self.environment[variable])
                # Create with restrictive mode BEFORE any synthetic contents exist.
                with open(path, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as output:
                    output.write(json.dumps(document) if state == "available" else PRIVATE)

    def write_registry(self):
        with open(self.registry, "w", opener=lambda p, flags: os.open(p, flags, 0o600)) as output:
            output.write(json.dumps({"version": 1, "consumers": self.entries}))

    def start(self):
        self.stdout = (self.directory / "stdout").open("w")
        self.stderr = (self.directory / "stderr").open("w")
        self.process = subprocess.Popen(
            [interpreter(), "-c", HARNESS, json.dumps({
                "directory": str(self.directory), "slow": self.slow,
                "deny_bing_io": self.deny_bing_io, "reflection": self.reflection})],
            env=self.environment, cwd=self.directory, stdout=self.stdout, stderr=self.stderr,
        )
        deadline = time.monotonic() + 25
        with httpx.Client(trust_env=False, timeout=1) as client:
            while time.monotonic() < deadline:
                assert self.process.poll() is None, self.logs()
                try:
                    result = client.get(self.url + "/healthz")
                    if result.status_code == 200:
                        assert result.json() == {"status": "ok"}
                        package = ROOT / "src/google_seo_mcp"
                        expected = {
                            str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in package.rglob("*")
                            if p.is_file() and (
                                p.suffix == ".py" or p.name == "production_tools.json")
                        }
                        provenance = json.loads((self.directory / "provenance.json").read_text())
                        assert provenance["hashes"] == expected, (
                            "HTTP child is not the current candidate; build/install a fresh wheel "
                            "and set GOOGLE_SEO_TEST_PYTHON (no PYTHONPATH injection)",
                            provenance["package"],
                        )
                        return self
                except httpx.TransportError:
                    pass
                time.sleep(.025)
        raise AssertionError("test server did not become healthy")

    def logs(self):
        return (self.directory / "stderr").read_text()

    def stop(self):
        if self.process is None:
            return
        started = time.monotonic()
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
            pytest.fail("SIGTERM did not shut down promptly")
        self.stdout.close()
        self.stderr.close()
        assert time.monotonic() - started < 8
        # Uvicorn re-raises SIGTERM after original lifespan cleanup on Linux.
        assert self.process.returncode in (0, -signal.SIGTERM)
        assert json.loads((self.directory / "shutdown.json").read_text()) == {
            "original_manager_exited": True, "task_group_cleared": True,
            "server_instances_empty": True,
        }
        assert (self.directory / "stdout").read_text() == ""
        assert not (self.directory / "forbidden-attempt").exists()
        assert PRIVATE not in self.logs()
        assert "SYNTHETIC_BING_KEY" not in self.logs()
        assert all(key not in self.logs() for key in self.keys.values())
        for line in self.logs().splitlines():
            row = json.loads(line)
            assert set(row) <= {
                "request_id", "consumer", "tool", "outcome", "duration_ms", "status"
            }
            assert len(row["request_id"]) == 32

    def headers(self, name="alpha"):
        return {"Authorization": "Bearer " + self.keys[name], "X-Consumer": PRIVATE}


@pytest.fixture
def launch(tmp_path):
    servers = []

    def factory(**kwargs):
        server = LiveServer(tmp_path / f"server-{len(servers)}", **kwargs)
        servers.append(server)
        return server.start()

    yield factory
    for server in reversed(servers):
        server.stop()


async def sdk_catalog(server, identity="alpha", path="/mcp", calls=()):
    async with (
        httpx.AsyncClient(headers=server.headers(identity), trust_env=False) as http,
        streamable_http_client(server.url + path, http_client=http) as (read, write, _),
        ClientSession(read, write) as session,
    ):
        initialized = await session.initialize()
        assert initialized.serverInfo.name == "google-seo-mcp"
        cursor, names, seen = None, [], set()
        while True:
            page = await session.list_tools(cursor=cursor)
            names.extend(tool.name for tool in page.tools)
            for tool in page.tools:
                if tool.name in BING11:
                    assert tool.annotations.readOnlyHint is True
                    assert tool.annotations.destructiveHint is False
                    assert tool.annotations.openWorldHint is False
                    properties = tool.inputSchema.get("properties", {})
                    assert not set(properties) & {"api_key", "path", "endpoint", "client", "config"}
                    if tool.name == "bing_list_sites":
                        assert properties == {}
                    else:
                        assert properties["site_url"]["type"] == "string"
                        assert "site_url" in tool.inputSchema["required"]
                    if "limit" in properties:
                        assert properties["limit"]["type"] == "integer"
                        assert properties["limit"]["default"] == 100
            cursor = page.nextCursor
            if cursor is None:
                break
            assert cursor not in seen
            seen.add(cursor)
        assert len(OLD35) == 35 and len(BING11) == 11 and not OLD35 & BING11
        assert len(names) == len(set(names)) == 46
        assert set(names) == EXPECTED46
        results = []
        for name, arguments in calls:
            results.append(await session.call_tool(name, arguments))
        return results


def rpc(tool, arguments=None, request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments or {}}}


def rpc_headers(server, name="alpha"):
    return server.headers(name) | {"Accept": "application/json, text/event-stream",
                                   "Content-Type": "application/json"}


def test_sdk_exact_catalog_both_paths_two_validated_identities_and_pending_health(launch):
    server = launch()
    with httpx.Client(trust_env=False) as http:
        result = http.get(server.url + "/readyz")
        assert result.status_code == 200
        assert result.json() == {"status": "credential-pending", "transport_ready": True,
                                 "google_credentials_state": "pending",
                                 "bing_credentials_state": "pending", "revision": "b" * 40}
    for identity in ("alpha", "beta"):
        for path in ("/mcp", "/mcp/"):
            asyncio.run(sdk_catalog(server, identity, path))
    rows = [json.loads(line) for line in server.logs().splitlines()]
    for identity in ("alpha", "beta"):
        assert any(row["consumer"] == identity and row.get("status") == 200 for row in rows)


def test_every_method_alias_missing_malformed_unknown_revoked_and_duplicate_key_is_401(launch):
    server = launch()
    with httpx.Client(trust_env=False) as http:
        invalid = [[], [("Authorization", "Bearer")], [("Authorization", "Basic private")],
                   [("Authorization", "Bearer unknown-synthetic")],
                   list(server.headers("revoked").items()),
                   [("Authorization", "Bearer " + server.keys["alpha"])] * 2]
        for method in ("GET", "POST", "DELETE", "OPTIONS", "PATCH", "HEAD"):
            for path in ("/mcp", "/mcp/", "/sse", "/messages", "/unknown-alias"):
                for headers in invalid:
                    response = http.request(method, server.url + path, headers=headers)
                    assert response.status_code == 401, (method, path, response.status_code)
                    assert response.headers["www-authenticate"] == "Bearer"
                    if method != "HEAD":
                        assert response.json() == {"error": "unauthorized"}
        for path in ("/sse", "/messages", "/unknown-alias"):
            assert http.get(server.url + path, headers=server.headers()).status_code == 404
        # Liveness exception is exact path AND method.
        assert http.post(server.url + "/healthz").status_code == 401
        assert http.get(server.url + "/healthz/").status_code == 401
        for path in ("/mcp", "/mcp/"):
            for method in ("GET", "DELETE", "OPTIONS"):
                with http.stream(method, server.url + path, headers=rpc_headers(server)) as result:
                    # SDK1 supports an authenticated GET stream; close it after
                    # checking admission rather than waiting for unbounded data.
                    assert result.status_code in ((200, 405) if method == "GET" else (405,))
                    if result.status_code == 200:
                        assert result.headers["content-type"].startswith("text/event-stream")


def test_host_origin_duplicates_and_forwarded_host_spoofs_fail_closed(launch):
    server = launch()
    with httpx.Client(trust_env=False) as http:
        cases = [
            {"Host": "hostile.invalid"}, {"Origin": "https://hostile.invalid"},
            {"Origin": "null"}, {"Origin": "https://google-seo.mcp.propel.marketing.evil"},
            {"Host": "hostile.invalid", "X-Forwarded-Host": f"127.0.0.1:{server.port}"},
        ]
        for case in cases:
            assert http.post(
                server.url + "/mcp", headers=server.headers() | case
            ).status_code == 403
        duplicate = list(server.headers().items()) + [
            ("Origin", "https://google-seo.mcp.propel.marketing"),
            ("Origin", "https://google-seo.mcp.propel.marketing")]
        assert http.post(server.url + "/mcp", headers=duplicate).status_code == 403
        assert http.get(
            server.url + "/healthz", headers={"Host": "hostile.invalid"}
        ).status_code == 403
        # A loopback peer stays local even if it claims an external forwarded IP.
        assert http.get(server.url + "/readyz", headers={
            "X-Forwarded-For": "203.0.113.42"}).status_code == 200
    # Duplicate Host is rejected by the HTTP parser (400) or middleware (403).
    with socket.create_connection(("127.0.0.1", server.port), timeout=3) as sock:
        request = (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n"
                   f"Host: 127.0.0.1:{server.port}\r\nAuthorization: Bearer "
                   f"{server.keys['alpha']}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        sock.sendall(request.encode("ascii"))
        assert sock.recv(4096).split(b" ")[1] in (b"400", b"403")


def test_remote_actual_peer_cannot_spoof_local_readiness(launch):
    server = launch()
    addresses = {info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None,
                                                        socket.AF_INET)}
    remote = next((address for address in addresses if not address.startswith("127.")), None)
    assert remote is not None, "requires a local non-loopback interface for actual peer test"
    with httpx.Client(trust_env=False) as http:
        response = http.get(f"http://{remote}:{server.port}/readyz", headers={
            "Host": f"127.0.0.1:{server.port}", "X-Forwarded-For": "127.0.0.1",
            "Forwarded": 'for=127.0.0.1;host="localhost"'})
        assert response.status_code == 403
        assert response.json() == {"error": "local_only"}


def test_declared_and_chunked_body_above_four_mib_rejected_before_sdk(launch):
    server = launch()
    with httpx.Client(trust_env=False, timeout=10) as http:
        oversized = b"x" * (4 * 1024 * 1024 + 1)
        for content in (
            oversized, iter((oversized[:2 * 1024 * 1024], oversized[2 * 1024 * 1024:]))
        ):
            result = http.post(server.url + "/mcp", headers=server.headers(), content=content)
            assert result.status_code == 413
            assert result.json()["error"] in ("invalid_body_size", "body_too_large")
        # Declared length can be refused without receiving the body at all.
    with socket.create_connection(("127.0.0.1", server.port), timeout=3) as sock:
        sock.sendall((f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n"
                      f"Authorization: Bearer {server.keys['alpha']}\r\n"
                      "Content-Length: 4194305\r\nConnection: close\r\n\r\n").encode())
        assert sock.recv(4096).split(b" ")[1] == b"413"


def test_sixty_per_minute_rate_isolated_per_consumer(launch):
    server = launch()
    with httpx.Client(trust_env=False) as http:
        # Authenticated unknown routes consume edge admission without SDK work.
        responses = [http.get(server.url + "/unknown", headers=server.headers()) for _ in range(61)]
        assert [r.status_code for r in responses[:60]] == [404] * 60
        assert responses[60].status_code == 429
        assert responses[60].json() == {"error": "rate_limit"}
        assert int(responses[60].headers["retry-after"]) > 0
        assert http.get(server.url + "/unknown", headers=server.headers("beta")).status_code == 404
        assert http.get(server.url + "/healthz").status_code == 200


def test_two_sync_calls_offload_worker_keep_health_responsive_and_third_is_429(launch):
    server = launch(slow=True)

    async def exercise():
        async with httpx.AsyncClient(trust_env=False, timeout=10) as http:
            async def call(identity="alpha"):
                return await http.post(server.url + "/mcp", json=rpc("gsc_list_sites"),
                                       headers=rpc_headers(server, identity))
            first, second = asyncio.create_task(call()), asyncio.create_task(call())
            try:
                deadline = time.monotonic() + 5
                while True:
                    marker = server.directory / "entered"
                    if marker.exists() and len(marker.read_text().splitlines()) == 2:
                        break
                    assert time.monotonic() < deadline
                    await asyncio.sleep(.01)
                started = time.monotonic()
                health = await http.get(server.url + "/healthz")
                assert health.status_code == 200 and time.monotonic() - started < .75
                third = await call()
                assert third.status_code == 429 and third.json() == {"error": "concurrency_limit"}
                assert int(third.headers["retry-after"]) >= 1
                beta = asyncio.create_task(call("beta"))
                for result in await asyncio.gather(first, second, beta):
                    assert result.status_code == 200 and not result.json()["result"].get("isError")
                # Slots are released, and worker ContextVar is the actual consumer.
                assert (server.directory / "entered").read_text().splitlines() == [
                    "alpha", "alpha", "beta"
                ]
                result = await call()
                assert result.status_code == 200
            finally:
                await asyncio.gather(first, second, return_exceptions=True)
    asyncio.run(exercise())


def test_google_vendor_missing_and_fenced_direct_calls_never_network_or_open(launch):
    server = launch()
    fenced = ("gsc_submit_sitemap", "google_indexing_publish", "google_indexing_delete",
              "indexnow_submit", "indexnow_submit_sitemap", "indexnow_generate_key", "logs_parse",
              "history_list", "history_save_snapshot", "migration_wp_audit_site",
              "schema_extract_url", "aeo_llms_txt_check", "lighthouse_audit", "crawl_url",
              "get_capabilities", "reauthenticate", "reload_credentials", "gsc_list_sites_alias",
              "../gsc_list_sites", "GSC_LIST_SITES")
    results = asyncio.run(sdk_catalog(server, calls=[
        (name, {"path": "/" + PRIVATE, "url": "https://" + PRIVATE + ".invalid"})
        for name in fenced] + [("gsc_list_sites", {}), ("serp_check", {"keyword": "offline"})]))
    for result in results[:-2]:
        assert result.isError and "tool_not_allowed" in result.model_dump_json()
        assert PRIVATE not in result.model_dump_json()
    assert results[-2].isError and "credentials_missing" in results[-2].model_dump_json()
    vendor = json.loads(results[-1].content[0].text)
    assert vendor["data"]["error"] == "credentials_missing"
    assert not (server.directory / "forbidden-attempt").exists()
    assert not (server.directory / "forbidden-attempt").exists()
    rows = [json.loads(line) for line in server.logs().splitlines()]
    assert any(row["consumer"] == "alpha" and row["tool"] == "denied" for row in rows)


def test_upstream_exception_redacted_and_positive_identity_tool_audit(launch):
    server = launch(slow=True)
    results = asyncio.run(sdk_catalog(server, "beta", calls=[
        ("gsc_list_sitemaps", {"site_url": PRIVATE})]))
    assert results[0].isError and "provider_unavailable" in results[0].model_dump_json()
    assert PRIVATE not in results[0].model_dump_json()
    rows = [json.loads(line) for line in server.logs().splitlines()]
    assert any(row["consumer"] == "beta" and row["tool"] == "gsc_list_sitemaps"
               and row["outcome"] == "error" for row in rows)


def test_recreate_registry_revocation_new_acceptance_no_stale_identity(tmp_path):
    first = LiveServer(tmp_path / "first").start()
    try:
        asyncio.run(sdk_catalog(first))
    finally:
        first.stop()
    replacement = LiveServer(tmp_path / "replacement", port=first.port)
    replacement.keys["old"] = first.keys["alpha"]
    replacement.entries.append({"consumer_id": "alpha", "key_id": "retired-key",
                                "sha256": hashlib.sha256(first.keys["alpha"].encode()).hexdigest(),
                                "enabled": False})
    replacement.write_registry()
    replacement.start()
    try:
        with httpx.Client(trust_env=False) as http:
            assert http.post(replacement.url + "/mcp", headers={
                "Authorization": "Bearer " + first.keys["alpha"]}).status_code == 401
        asyncio.run(sdk_catalog(replacement, "beta"))
        rows = [json.loads(line) for line in replacement.logs().splitlines()]
        assert any(row["consumer"] is None and row.get("status") == 401 for row in rows)
        assert any(row["consumer"] == "beta" and row.get("status") == 200 for row in rows)
    finally:
        replacement.stop()


@pytest.mark.parametrize("required", [False, True])
@pytest.mark.parametrize("key_state", ["pending", "invalid", "available"])
@pytest.mark.parametrize("policy_state", ["pending", "invalid", "available"])
def test_pending_vs_required_readiness_missing_bing_does_not_break_google_readiness(
    launch, required, key_state, policy_state,
):
    server = launch(google="available", bing_key=key_state, bing_policy=policy_state,
                    require_google=True, require_bing=required)
    state = ("invalid" if "invalid" in (key_state, policy_state) else
             "pending" if "pending" in (key_state, policy_state) else "available")
    status = ("credential-pending" if required and state == "pending" else
              "credentials-invalid" if required and state == "invalid" else "transport-ready")
    with httpx.Client(trust_env=False) as http:
        for _ in range(2):
            response = http.get(server.url + "/readyz")
            assert response.status_code == (503 if required and state != "available" else 200)
            assert response.headers["cache-control"] == "no-store"
            assert response.json() == {
                "status": status, "transport_ready": True,
                "google_credentials_state": "available", "bing_credentials_state": state,
                "revision": "b" * 40,
            }
        health = http.get(server.url + "/healthz")
        assert health.status_code == 200 and health.json() == {"status": "ok"}
    assert not (server.directory / "forbidden-attempt").exists()


@pytest.mark.parametrize("google", ["pending", "invalid"])
@pytest.mark.parametrize("required", [False, True])
def test_bing_available_preserves_google_status_and_required_gate(launch, google, required):
    server = launch(google=google, bing_key="available", bing_policy="available",
                    require_google=required, require_bing=True)
    with httpx.Client(trust_env=False) as http:
        response = http.get(server.url + "/readyz")
        assert response.status_code == (503 if required else 200)
        assert response.json() == {
            "status": "credential-pending" if google == "pending" else "credentials-invalid",
            "transport_ready": True, "google_credentials_state": google,
            "bing_credentials_state": "available", "revision": "b" * 40,
        }
        assert http.get(server.url + "/healthz").status_code == 200


def bing_calls():
    # Independent exact argument inventory: no discovery-derived call arguments.
    return [
        ("bing_list_sites", {}),
        ("bing_rank_traffic_stats", {"site_url": PILOT}),
        ("bing_query_stats", {"site_url": PILOT}),
        ("bing_page_stats", {"site_url": PILOT}),
        ("bing_page_query_stats", {"site_url": PILOT, "page_url": PILOT + "page"}),
        ("bing_query_page_stats", {"site_url": PILOT, "query": "synthetic"}),
        ("bing_crawl_stats", {"site_url": PILOT}),
        ("bing_crawl_issues", {"site_url": PILOT}),
        ("bing_url_info", {"site_url": PILOT, "url": PILOT + "page"}),
        ("bing_list_sitemaps", {"site_url": PILOT}),
        ("bing_sitemap_details", {"site_url": PILOT, "sitemap_url": PILOT + "sitemap.xml"}),
    ]


def test_pending_bing_calls_no_network_real_sdk_all_eleven(launch):
    server = launch()
    calls = bing_calls()
    assert {name for name, _ in calls} == BING11
    results = asyncio.run(sdk_catalog(server, calls=calls))
    for result in results:
        assert not result.isError  # Transport success is NOT business success.
        data = json.loads(result.content[0].text)
        assert data["data"]["status"] == "unavailable"
        assert data["data"]["error"]["code"] == "provider_not_configured"
        assert data["data"]["records"] == []
        assert data["_meta"]["source"] == "bing_webmaster"
    assert not (server.directory / "forbidden-attempt").exists()


def test_bing_strict_schema_coercion_and_unknown_args_fail_before_io(launch):
    server = launch(deny_bing_io=True)
    calls = []
    for name, arguments in bing_calls():
        calls.append((name, arguments | {"endpoint": PRIVATE}))
        if name not in ("bing_list_sites", "bing_url_info"):
            for limit in (True, "1", 1.0):
                calls.append((name, arguments | {"limit": limit}))
    calls.extend([
        ("bing_query_stats", {"site_url": PILOT, "start_date": "2026-01-01"}),
        ("bing_query_stats", {"site_url": PILOT, "start_date": "2026-02-30",
                              "end_date": "2026-03-01"}),
        ("bing_query_page_stats", {"site_url": PILOT}),
        ("bing_query_page_stats", {"site_url": PILOT, "query": 1}),
        ("bing_page_query_stats", {"site_url": PILOT, "page_url": "https://other.invalid/"}),
        ("bing_url_info", {"site_url": PILOT, "url": "http://127.0.0.1/"}),
        ("bing_sitemap_details", {"site_url": PILOT, "sitemap_url": "domain:example.invalid"}),
    ])
    results = asyncio.run(sdk_catalog(server, calls=calls))
    for result in results:
        assert result.isError
        assert any(code in result.model_dump_json() for code in (
            "invalid_tool_arguments", "invalid_request"))
        assert PRIVATE not in result.model_dump_json()
    assert not (server.directory / "forbidden-attempt").exists()


@pytest.mark.parametrize("reflection", ["raw", "encoded", "escaped", "exception"])
def test_bing_failure_redaction_nested_payload(launch, reflection):
    from urllib.parse import quote

    server = launch(bing_key="available", bing_policy="available", reflection=reflection)
    results = asyncio.run(sdk_catalog(server, calls=[("bing_query_stats", {"site_url": PILOT})]))
    result = results[0]
    assert not result.isError
    data = json.loads(result.content[0].text)
    assert data["data"]["status"] == "provider_error"
    assert data["data"]["error"]["code"] == (
        "transport_error" if reflection == "exception" else "credential_reflection")
    serialized = result.model_dump_json() + server.logs()
    assert BING_PRIVATE not in serialized and quote(BING_PRIVATE, safe="") not in serialized
    assert "SYNTHETIC_BING_KEY" not in serialized
    assert "\\\\u0053\\\\u0059" not in serialized
    attempts = (server.directory / "synthetic-upstream").read_text().splitlines()
    assert attempts == ["one fake attempt"]
    assert not (server.directory / "forbidden-attempt").exists()


def test_all_bing_write_names_aliases_and_unknowns_denied_pre_sink(launch):
    server = launch(deny_bing_io=True)
    names = (
        "bing_submit_url", "bing_submit_url_batch", "bing_submit_content", "bing_submit_sitemap",
        "bing_submit_feed", "bing_remove_feed", "bing_add_site", "bing_remove_site",
        "bing_verify_site", "bing_fetch_url", "bing_save_crawl_settings", "bing_call_method",
        "bing_get_keyword", "bing_query_traffic_stats", "bing_list_sites_alias", "BING_LIST_SITES",
        "../bing_list_sites", "GetUserSites", "SubmitUrl", "FetchUrl", "configure_bing_tools",
    )
    results = asyncio.run(sdk_catalog(server, calls=[(name, {"path": PRIVATE}) for name in names]))
    for result in results:
        assert result.isError and "tool_not_allowed" in result.model_dump_json()
        assert PRIVATE not in result.model_dump_json()
    assert not (server.directory / "forbidden-attempt").exists()
