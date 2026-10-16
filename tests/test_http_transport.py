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
MANIFEST = json.loads((ROOT / "src/google_seo_mcp/production_tools.json").read_text())["tools"]
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
    def __init__(self, directory, *, slow=False, entries=None, port=None):
        self.directory = directory
        self.directory.mkdir()
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
        self.process = None

    def write_registry(self):
        self.registry.write_text(json.dumps({"version": 1, "consumers": self.entries}))

    def start(self):
        self.stdout = (self.directory / "stdout").open("w")
        self.stderr = (self.directory / "stderr").open("w")
        self.process = subprocess.Popen(
            [interpreter(), "-c", HARNESS, json.dumps({
                "directory": str(self.directory), "slow": self.slow})],
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
            cursor = page.nextCursor
            if cursor is None:
                break
            assert cursor not in seen
            seen.add(cursor)
        assert len(names) == len(set(names)) == len(MANIFEST)
        assert set(names) == set(MANIFEST)
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
                                 "google_credentials_state": "pending", "revision": "b" * 40}
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
