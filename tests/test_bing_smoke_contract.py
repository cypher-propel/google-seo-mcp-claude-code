"""SYNTHETIC HTTP peers only; real HTTPX + MCP SDK, never live credentials."""

import asyncio
import importlib.util
import json
import socket
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest

spec = importlib.util.spec_from_file_location(
    "bing_smoke", Path(__file__).parents[1] / "scripts" / "smoke_bing.py"
)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

OPERATIONS = dict(
    zip(
        (
            "bing_list_sites",
            "bing_rank_traffic_stats",
            "bing_query_stats",
            "bing_page_stats",
            "bing_crawl_stats",
            "bing_crawl_issues",
            "bing_list_sitemaps",
            "bing_page_query_stats",
            "bing_query_page_stats",
            "bing_url_info",
            "bing_sitemap_details",
        ),
        (
            "GetUserSites",
            "GetRankAndTrafficStats",
            "GetQueryStats",
            "GetPageStats",
            "GetCrawlStats",
            "GetCrawlIssues",
            "GetFeeds",
            "GetPageQueryStats",
            "GetQueryPageStats",
            "GetUrlInfo",
            "GetFeedDetails",
        ),
        strict=False,
    )
)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("SYNTHETIC test attempted network/credential access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)

    def safe_env(name, default=None):
        if name == "GOOGLE_SEO_SMOKE_KEY":
            return forbidden()
        return default

    monkeypatch.setattr(smoke.os.environ, "get", safe_env)


def options(*args):
    return smoke.parser().parse_args(
        [
            "--pilot",
            smoke.PILOT,
            "--synthetic",
            "--start-date",
            "2026-01-01",
            "--end-date",
            "2026-01-07",
            *args,
        ]
    )


class Peer:
    def __init__(self, verified=True, selectors=False, reflection=False):
        self.requests = []
        self.calls = []
        self.verified = verified
        self.selectors = selectors
        self.reflection = reflection
        self.base = smoke.synthetic_transport()

    def handle(self, request):
        self.requests.append(request)
        if request.method == "POST" and request.content:
            body = json.loads(request.content)
            if body.get("method") == "tools/call":
                name, args = body["params"]["name"], body["params"].get("arguments", {})
                self.calls.append((name, args))
                assert name in OPERATIONS  # no_submit_fetch_or_auto_enroll: every path.
                assert len(self.calls) <= 11
                assert len({n for n, _ in self.calls}) == len(self.calls)
                assert not args or args["site_url"] == smoke.PILOT
                rows = []
                if name == "bing_list_sites":
                    rows = [
                        {"kind": "site", "url": "https://other.example/", "is_verified": True},
                        {"kind": "site", "url": smoke.PILOT, "is_verified": self.verified},
                    ]
                data = {
                    "status": "ok" if rows else "empty",
                    "operation": OPERATIONS[name],
                    "site_url": None if name == "bing_list_sites" else smoke.PILOT,
                    "extracted_at": "2026-01-08T00:00:00Z",
                    "records": rows,
                    "source_rows": len(rows),
                    "returned_rows": len(rows),
                }
                result = {"data": data}
                if self.reflection:
                    result["_meta"] = {
                        "Authorization": "Bearer " + smoke.SYNTHETIC_TOKEN,
                        "unknown": quote(smoke.SYNTHETIC_TOKEN, safe=""),
                    }
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
                    },
                )
        return self.base.handle_request(request)


def run(peer, opts=None):
    return asyncio.run(smoke.run(opts or options(), transport=httpx.MockTransport(peer.handle)))


@pytest.mark.parametrize("case", ["partial", "denied", "malformed", "catalog_drift"])
def test_actual_outcomes_and_catalog_fail_closed(case):
    peer = Peer()

    def handle(request):
        response = peer.handle(request)
        if request.method != "POST" or not request.content:
            return response
        body = json.loads(request.content)
        if "id" not in body or response.status_code != 200:
            return response
        envelope = response.json()
        if case == "catalog_drift" and body["method"] == "tools/list":
            envelope["result"]["tools"].pop()
        elif body["method"] == "tools/call" and body["params"]["name"] == "bing_list_sites":
            data = json.loads(envelope["result"]["content"][0]["text"])["data"]
            if case == "partial":
                data.update(
                    status="partial",
                    dropped_rows=1,
                    source_rows=3,
                    warnings=["invalid_rows_dropped"],
                )
            elif case == "denied":
                data.update(
                    status="denied",
                    records=[],
                    source_rows=0,
                    returned_rows=0,
                    error={"code": "access_denied", "retryable": False},
                )
            elif case == "malformed":
                data["returned_rows"] = 999
            envelope["result"]["content"][0]["text"] = json.dumps({"data": data})
        return httpx.Response(200, json=envelope)

    result = asyncio.run(smoke.run(options(), transport=httpx.MockTransport(handle)))
    assert result["business_qualified"] is False
    if case == "partial":
        assert result["tools"][0]["outcome"] == "partial"
        assert result["tools"][0]["result"]["dropped_rows"] == 1
    else:
        assert result["status"] == "FAIL"
        assert len(peer.calls) <= 1


def test_explicit_pilot_not_first_discovered():
    peer = Peer()
    result = run(peer)
    assert result["status"] == "SYNTHETIC_ONLY"
    assert result["business_qualified"] is False
    assert len(peer.calls) == 7
    assert all(args["site_url"] == smoke.PILOT for _, args in peer.calls[1:])
    assert sum(t["outcome"].startswith("deferred") for t in result["tools"]) == 4


def test_unverified_pilot_aborts():
    peer = Peer(verified=False)
    result = run(peer)
    assert result["error"] == "explicit_pilot_not_verified"
    assert [n for n, _ in peer.calls] == ["bing_list_sites"]


def test_finite_call_budget():
    peer = Peer()
    result = run(
        peer,
        options(
            "--page-url",
            smoke.PILOT + "approved",
            "--query",
            "SYNTHETIC query",
            "--sitemap-url",
            smoke.PILOT + "approved.xml",
        ),
    )
    assert result["status"] == "SYNTHETIC_ONLY"
    assert result["bing_sdk_calls"] == len(peer.calls) == 11
    assert {n for n, _ in peer.calls} == set(OPERATIONS)
    assert all(
        t["upstream_attempts"] == "unobservable_from_hosted_protocol" for t in result["tools"]
    )


def test_raw_payload_sanitized_before_artifact(tmp_path, monkeypatch, capsys):
    # Exercise real output writer, nested reflection and typed payload removal.
    peer = Peer(reflection=True)
    monkeypatch.setattr(smoke, "synthetic_transport", lambda: httpx.MockTransport(peer.handle))
    path = tmp_path / "SYNTHETIC.json"
    assert (
        smoke.main(
            [
                "--pilot",
                smoke.PILOT,
                "--synthetic",
                "--start-date",
                "2026-01-01",
                "--end-date",
                "2026-01-07",
                "--output",
                str(path),
            ]
        )
        == 0
    )
    saved = path.read_text()
    assert smoke.SYNTHETIC_TOKEN not in saved + capsys.readouterr().out
    token = "SYNTHETIC+reflected/key"
    variants = [
        token,
        quote(token, safe=""),
        "".join(f"\\u{ord(c):04x}" for c in token),
        quote(quote(token, safe=""), safe=""),
        token.replace("/", "\\/"),
    ]
    safe = smoke.sanitize(
        {
            "nested": variants,
            "Authorization": "Bearer " + token,
            "url": "https://private.example/?apikey=SYNTHETIC",
        },
        token,
    )
    assert safe["nested"] == ["[REDACTED]"] * len(variants)
    assert "Authorization" not in safe
    assert "private.example" not in json.dumps(safe)


@pytest.mark.parametrize("kind", ["redirect", "exception"])
def test_hosted_redirect_cannot_forward_bearer_and_errors_redact_it(kind):
    peer = Peer()

    def handle(request):
        peer.requests.append(request)
        if request.headers.get("authorization"):
            if kind == "redirect":
                return httpx.Response(307, headers={"location": "https://evil.example/mcp"})
            raise httpx.ConnectError(
                "Bearer " + smoke.SYNTHETIC_TOKEN + " https://private.example/", request=request
            )
        return peer.base.handle_request(request)

    result = asyncio.run(smoke.run(options(), transport=httpx.MockTransport(handle)))
    assert result["status"] == "FAIL"
    assert not peer.calls
    assert all(r.url.host == "google-seo.mcp.propel.marketing" for r in peer.requests)
    assert smoke.SYNTHETIC_TOKEN not in json.dumps(result)
    assert "private.example" not in json.dumps(result)


def test_pending_zero_bing_calls(monkeypatch):
    # Only a SYNTHETIC token supplied by test process; no real env lookup.
    monkeypatch.setattr(smoke.os.environ, "get", lambda name, default="": smoke.SYNTHETIC_TOKEN)
    peer = Peer()
    opts = smoke.parser().parse_args(["--pilot", smoke.PILOT])
    # Production path uses normal HTTPX; replace ONLY HTTP transport constructor.
    real_client = httpx.AsyncClient

    def client(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        kwargs["transport"] = httpx.MockTransport(peer.handle)
        return real_client(**kwargs)

    monkeypatch.setattr(smoke.httpx, "AsyncClient", client)
    result = asyncio.run(smoke.run(opts))
    assert result["status"] == "PENDING_CATALOG_ONLY"
    assert result["catalog_count"] == 46
    assert result["bing_sdk_calls"] == 0 and peer.calls == []


def test_live_receipt_gate_precedes_credential_and_network():
    opts = smoke.parser().parse_args(
        ["--pilot", smoke.PILOT, "--live", "--start-date", "2026-01-01", "--end-date", "2026-01-07"]
    )
    result = asyncio.run(smoke.run(opts))
    assert result["error"] == "qualification_receipt_required"
    assert result["bing_sdk_calls"] == 0


def synthetic_qualification():
    """SYNTHETIC references, never an actual authorization receipt."""
    return {
        "version": 1,
        "evidence_class": "SYNTHETIC",
        "target": smoke.TARGET,
        "pilot": smoke.PILOT,
        "image_digest": "sha256:" + "1" * 64,
        "revision": "2" * 40,
        "image_qualification_record": "record_" + "3" * 16,
        "composition": {
            "tools_sha256": smoke.TOOLS_SHA256,
            "max_retries": 0,
            "review_evidence": "artifact_" + "4" * 16,
            "deployed_evidence": "record_" + "5" * 16,
        },
        "authorization": {
            "hold_record": "record_" + "6" * 16,
            "hold_at": "2026-01-01T00:00:00Z",
            "coordinator_key_enrolled_record": "record_" + "7" * 16,
            "key_enrolled_at": "2026-01-02T00:00:00Z",
        },
    }


def qualification_options(tmp_path, doc, *, live=False):
    path = tmp_path / "SYNTHETIC-qualification.json"
    path.write_text(json.dumps(doc))
    opts = options("--qualification-file", str(path))
    if live:
        opts.synthetic, opts.live = False, True
    return opts


@pytest.mark.parametrize(
    "case",
    [
        "synthetic_live",
        "unknown",
        "digest",
        "revision",
        "retry",
        "bool_retry",
        "module",
        "hold",
        "enrollment",
        "ordering",
        "future",
        "duplicate",
        "oversize",
        "nonfinite",
        "missing_composition",
        "target",
        "pilot",
        "secret",
        "nested_secret",
        "symlink",
    ],
)
def test_invalid_receipt_precredential_refusal(tmp_path, case):
    doc = synthetic_qualification()
    # Invented references stay in temp fixtures. Invalid live options MUST stop
    # before the trapped bearer lookup/HTTP construction; no live execution.
    if case != "synthetic_live":
        doc["evidence_class"] = "OPERATOR_READBACK"
    if case == "unknown":
        doc["extra"] = "opaque"
    elif case in ("digest", "revision"):
        doc["image_digest" if case == "digest" else "revision"] = "latest"
    elif case in ("retry", "bool_retry", "module"):
        doc["composition"]["tools_sha256" if case == "module" else "max_retries"] = (
            "0" * 64 if case == "module" else False if case == "bool_retry" else 1
        )
    elif case in ("hold", "enrollment"):
        doc["authorization"][
            "hold_record" if case == "hold" else "coordinator_key_enrolled_record"
        ] = "missing"
    elif case == "ordering":
        doc["authorization"]["key_enrolled_at"] = doc["authorization"]["hold_at"]
    elif case == "future":
        doc["authorization"]["key_enrolled_at"] = "9999-01-01T00:00:00Z"
    elif case == "missing_composition":
        del doc["composition"]
    elif case in ("target", "pilot"):
        doc[case] = "https://evil.example/"
    elif case == "secret":
        doc["api_key"] = smoke.SYNTHETIC_TOKEN
    elif case == "nested_secret":
        doc["composition"]["api_key"] = smoke.SYNTHETIC_TOKEN
    opts = qualification_options(tmp_path, doc, live=True)
    path = Path(opts.qualification_file)
    if case == "duplicate":
        path.write_text(path.read_text().replace('"version": 1', '"version": 1, "version": 1'))
    elif case == "oversize":
        path.write_text(" " * 8193)
    elif case == "nonfinite":
        path.write_text(path.read_text().replace('"version": 1', '"version": NaN'))
    elif case == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(path)
        opts.qualification_file = str(link)
    result = asyncio.run(smoke.run(opts))
    assert result["error"] == "invalid_qualification_receipt"
    assert result["bing_sdk_calls"] == 0
    assert smoke.SYNTHETIC_TOKEN not in json.dumps(result)


def test_qualified_synthetic_actual_sdk_transport_path(tmp_path):
    peer = Peer()
    doc = synthetic_qualification()
    opts = qualification_options(tmp_path, doc)
    opts.page_url, opts.query, opts.sitemap_url = (
        smoke.PILOT + "page",
        "SYNTHETIC",
        smoke.PILOT + "feed.xml",
    )

    def handle(request):
        if request.url.path == "/readyz":
            return httpx.Response(
                200,
                json={
                    "transport_ready": True,
                    "bing_credentials_state": "available",
                    "revision": doc["revision"],
                },
            )
        return peer.handle(request)

    result = asyncio.run(smoke.run(opts, transport=httpx.MockTransport(handle)))
    assert result["status"] == "SYNTHETIC_ONLY" and result["mode"] == "SYNTHETIC"
    assert result["read_smoke_complete"] is True
    assert result["business_qualified"] is False
    assert result["positive_business_observation"] is False
    assert result["bing_sdk_calls"] == len(peer.calls) == 11
    assert result["qualified_upstream_attempts_upper_bound"] == 11
    assert all(r.url.host == "google-seo.mcp.propel.marketing" for r in peer.requests)
    assert (
        result["trusted_operator_preflight"]["hold_record"] == doc["authorization"]["hold_record"]
    )
    assert (
        result["trusted_operator_preflight"]["enrollment_record"]
        == doc["authorization"]["coordinator_key_enrolled_record"]
    )
    assert "not_SDK_count" in result["attempt_bound_basis"]
    assert all(
        t["upstream_attempts"] == "unobservable_from_hosted_protocol" for t in result["tools"]
    )


def test_qualified_deployment_mismatch_before_discovery(tmp_path):
    peer = Peer()
    opts = qualification_options(tmp_path, synthetic_qualification())
    result = run(peer, opts)
    assert result["error"] == "qualified_deployment_readiness_mismatch"
    assert peer.calls == []


def test_live_rejects_fixture_transport_even_with_operator_shape(tmp_path):
    doc = synthetic_qualification()
    doc["evidence_class"] = "OPERATOR_READBACK"
    opts = qualification_options(tmp_path, doc, live=True)
    result = asyncio.run(smoke.run(opts, transport=smoke.synthetic_transport()))
    assert result["error"] == "fixture_transport_requires_synthetic"
    assert result["bing_sdk_calls"] == 0


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--page-url", smoke.PILOT + "%252e%252e/private"),
        ("--page-url", smoke.PILOT + "%ZZ"),
        ("--sitemap-url", smoke.PILOT + "\ud800"),
        ("--query", "\ud800"),
        ("--page-url", "http://127.0.0.1/private"),
        ("--page-url", smoke.PILOT + "%00"),
        ("--start-date", "20260101"),
    ],
)
def test_real_model_input_validation_precedes_bearer_network(flag, value):
    opts = options(flag, value)
    opts.synthetic = False
    result = asyncio.run(smoke.run(opts))
    assert result["status"] == "FAIL"
    assert result["error"] in (
        "invalid_selector",
        "invalid_query",
        "invalid_tool_request",
        "explicit_window_required",
    )
    assert result["bing_sdk_calls"] == 0


@pytest.mark.parametrize("depth", [7, 8, 9, 16, 64])
def test_sanitizer_decode_cap_fails_closed(depth):
    token = "SYNTHETIC+secret/key"
    value = token
    for _ in range(depth):
        value = quote(value, safe="")
    assert smoke.sanitize({"nested": [value]}, token)["nested"] == ["[REDACTED]"]


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/",
        "HTTPS://private.example/",
        "//private.example/",
        "file:///etc/shadow",
        smoke.PILOT + "%252e%252e/private",
        smoke.PILOT + "\ud800",
    ],
)
def test_sanitizer_rejects_invalid_private_urls(url):
    assert smoke.sanitize(url, "SYNTHETIC") == "[REDACTED_URL]"


@pytest.mark.parametrize("case", ["429", "503", "denied", "wrong_operation", "wrong_site"])
def test_business_faults_stop_without_retries(case):
    peer = Peer()

    def handle(request):
        response = peer.handle(request)
        if request.method != "POST" or not request.content:
            return response
        body = json.loads(request.content)
        if body.get("method") != "tools/call":
            return response
        if body["params"]["name"] != "bing_rank_traffic_stats":
            return response
        if case in ("429", "503"):
            return httpx.Response(int(case), headers={"retry-after": "0"})
        envelope = response.json()
        data = json.loads(envelope["result"]["content"][0]["text"])["data"]
        if case == "denied":
            data.update(status="denied", error={"code": "access_denied", "retryable": False})
        elif case == "wrong_operation":
            data["operation"] = "GetQueryStats"
        else:
            data["site_url"] = "https://other.example/"
        envelope["result"]["content"][0]["text"] = json.dumps({"data": data})
        return httpx.Response(200, json=envelope)

    result = asyncio.run(smoke.run(options(), transport=httpx.MockTransport(handle)))
    assert result["status"] == "FAIL"
    assert result["bing_sdk_calls"] == len(peer.calls) == 2
    assert result["business_qualified"] is False


def test_deep_reflection_typed_rows_sanitized_before_save(tmp_path, monkeypatch, capsys):
    peer = Peer()
    escaped = "".join(f"\\u{ord(c):04x}" for c in smoke.SYNTHETIC_TOKEN)
    for _ in range(9):
        escaped = quote(escaped, safe="")

    def handle(request):
        response = peer.handle(request)
        if request.url.path == "/readyz":
            data = response.json()
            data["revision"] = "SYNTHETIC-opaque-unknown-payload"
            data["unknown"] = {"payload": escaped}
            return httpx.Response(200, json=data)
        if request.method == "POST" and request.content:
            body = json.loads(request.content)
            if body.get("method") == "tools/call" and body["params"]["name"] == "bing_list_sites":
                envelope = response.json()
                data = json.loads(envelope["result"]["content"][0]["text"])["data"]
                data["records"][0]["url"] = escaped
                data["records"][0]["unknown"] = {"opaque": escaped}
                envelope["result"]["content"][0]["text"] = json.dumps({"data": data})
                return httpx.Response(200, json=envelope)
        return response

    monkeypatch.setattr(smoke, "synthetic_transport", lambda: httpx.MockTransport(handle))
    path = tmp_path / "SYNTHETIC-output.json"
    args = [
        "--pilot",
        smoke.PILOT,
        "--synthetic",
        "--start-date",
        "2026-01-01",
        "--end-date",
        "2026-01-07",
        "--output",
        str(path),
    ]
    assert smoke.main(args) == 0
    saved = path.read_text() + capsys.readouterr().out
    assert escaped not in saved and smoke.SYNTHETIC_TOKEN not in saved
    assert "opaque" not in saved and "unknown-payload" not in saved
    assert json.loads(path.read_text())["tools"][0]["result"]["records"][0]["url"] == "[REDACTED]"


def test_positive_fixture_observation_never_business_qualified():
    peer = Peer()

    def handle(request):
        response = peer.handle(request)
        if request.method == "POST" and request.content:
            body = json.loads(request.content)
            if (
                body.get("method") == "tools/call"
                and body["params"]["name"] == "bing_rank_traffic_stats"
            ):
                envelope = response.json()
                data = json.loads(envelope["result"]["content"][0]["text"])["data"]
                data.update(
                    status="ok",
                    source_rows=1,
                    returned_rows=1,
                    records=[
                        {
                            "kind": "traffic",
                            "clicks": 1,
                            "impressions": 10,
                            "ctr": 0.1,
                            "date": "/Date(1767225600000)/",
                            "date_utc": "2026-01-01T00:00:00Z",
                        }
                    ],
                )
                envelope["result"]["content"][0]["text"] = json.dumps({"data": data})
                return httpx.Response(200, json=envelope)
        return response

    result = asyncio.run(smoke.run(options(), transport=httpx.MockTransport(handle)))
    assert result["status"] == "SYNTHETIC_ONLY"
    assert result["positive_business_observation"] is True
    assert result["business_qualified"] is False
    assert result["read_smoke_complete"] is False


@pytest.mark.parametrize(
    "target",
    [
        "http://google-seo.mcp.propel.marketing/mcp",
        smoke.TARGET + "/",
        smoke.TARGET + "?key=x",
        "https://evil.example/mcp",
    ],
)
def test_target_validation_precedes_credential_use(target):
    opts = smoke.parser().parse_args(["--pilot", smoke.PILOT, "--url", target])
    result = asyncio.run(smoke.run(opts))
    assert result["error"] == "unapproved_target_or_pilot"


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--page-url", "https://other.example/"],
        ["--sitemap-url", smoke.PILOT + "#fragment"],
        ["--query", ""],
    ],
)
def test_no_submit_fetch_or_auto_enroll(args):
    peer = Peer()
    result = run(peer, options(*args))
    assert all(n in OPERATIONS for n, _ in peer.calls)
    assert result["business_qualified"] is False


REFLECTION_FAMILIES = (
    "raw",
    "percent",
    "html",
    "short_unicode",
    "hex",
    "long_unicode",
    "mixed",
    "nested",
    "double_backslash",
)


def reflected_bearer(token, family):
    if family == "raw":
        return token
    if family == "percent":
        return "".join(f"%{ord(c):02x}" for c in token)
    if family == "html":
        return "".join(f"&#{ord(c)};" for c in token)
    formats = ("\\x{:02x}", "\\u{:04x}", "\\U{:08x}")
    if family in ("hex", "short_unicode", "long_unicode"):
        fmt = formats[("hex", "short_unicode", "long_unicode").index(family)]
        return "".join(fmt.format(ord(c)) for c in token)
    mixed = "".join(formats[i % 3].format(ord(c)) for i, c in enumerate(token))
    if family == "mixed":
        return mixed
    if family == "double_backslash":
        return mixed.replace("\\", "\\\\")
    assert family == "nested"
    return quote(mixed.replace("\\", "&#92;", 1), safe="")


@pytest.mark.parametrize("family", REFLECTION_FAMILIES)
def test_recursive_reflection_invariant_keys_values_and_controls(family):
    token = "SYNTHETIC+bearer/key"
    reflected = reflected_bearer(token, family)
    value = {"outer": [{"query": reflected, reflected: "must_drop", "safe": "keep"}]}
    assert smoke.sanitize(value, token) == {"outer": [{"query": "[REDACTED]", "safe": "keep"}]}
    assert smoke.sanitize({"query": "ordinary query", "url": smoke.PILOT}, token) == {
        "query": "ordinary query",
        "url": smoke.PILOT,
    }


@pytest.mark.parametrize("family", REFLECTION_FAMILIES)
@pytest.mark.parametrize("source", ["query", "sitemap", "explicit_query"])
def test_real_writer_stdout_and_selector_reuse_reject_reflection(
    family, source, tmp_path, monkeypatch, capsys
):
    # Only the HTTP peer changes: real main/run/business/SDK/writer execute.
    peer = Peer()
    reflected = reflected_bearer(smoke.SYNTHETIC_TOKEN, family)
    supplied = smoke.PILOT + quote(reflected, safe="") if source == "sitemap" else reflected

    def handle(request):
        response = peer.handle(request)
        if request.method != "POST" or not request.content:
            return response
        body = json.loads(request.content)
        target = "bing_list_sitemaps" if source == "sitemap" else "bing_query_stats"
        if body.get("method") != "tools/call" or body["params"]["name"] != target:
            return response
        envelope = response.json()
        data = json.loads(envelope["result"]["content"][0]["text"])["data"]
        row = (
            {
                "kind": "feed",
                "url": supplied,
                "compressed": False,
                "file_size": 1,
                "last_crawled": "/Date(1767225600000)/",
                "last_crawled_utc": "2026-01-01T00:00:00Z",
                "status": "ok",
                "submitted": "/Date(1767225600000)/",
                "submitted_utc": "2026-01-01T00:00:00Z",
                "type": "Sitemap",
                "url_count": 1,
            }
            if source == "sitemap"
            else {
                "kind": "query",
                "query": reflected,
                "clicks": 1,
                "impressions": 2,
                "date": "/Date(1767225600000)/",
                "date_utc": "2026-01-01T00:00:00Z",
                "ctr": 0.5,
                "avg_click_position": 17,
                "avg_impression_position": 18,
            }
        )
        data.update(status="ok", source_rows=1, returned_rows=1, records=[row])
        envelope["result"]["content"][0]["text"] = json.dumps({"data": data})
        return httpx.Response(200, json=envelope)

    monkeypatch.setattr(smoke, "synthetic_transport", lambda: httpx.MockTransport(handle))
    path = tmp_path / "SYNTHETIC-reflection.json"
    opts = options("--output", str(path))
    argv = [
        "--pilot",
        opts.pilot,
        "--synthetic",
        "--start-date",
        opts.start_date,
        "--end-date",
        opts.end_date,
        "--output",
        str(path),
    ]
    if source == "explicit_query":
        argv += ["--query", reflected]
    code = smoke.main(argv)
    output = capsys.readouterr()
    saved = json.loads(path.read_text())
    printed = json.loads(output.out)
    assert saved == printed
    assert output.err == ""
    assert saved["business_qualified"] is False
    assert saved["mode"] == "SYNTHETIC"
    expected_tool = "bing_sitemap_details" if source == "sitemap" else "bing_query_page_stats"
    assert expected_tool not in {name for name, _ in peer.calls}
    for artifact in (saved, printed):
        text = json.dumps(artifact)
        for variant in (smoke.SYNTHETIC_TOKEN, reflected, supplied):
            assert json.dumps(variant)[1:-1] not in text
        entry = next(t for t in artifact["tools"] if t["tool"] == target_name(source))
        field = "url" if source == "sitemap" else "query"
        assert entry["result"]["records"][0][field] == "[REDACTED]"
    assert code == (1 if source == "explicit_query" else 0)
    assert len(peer.calls) == 7


def target_name(source):
    return "bing_list_sitemaps" if source == "sitemap" else "bing_query_stats"


@pytest.mark.parametrize("flag", ["--page-url", "--sitemap-url"])
@pytest.mark.parametrize("family", ["raw", "hex", "long_unicode", "nested"])
def test_explicit_url_reflection_never_dispatched_or_saved(
    flag, family, tmp_path, monkeypatch, capsys
):
    peer = Peer()
    reflected = reflected_bearer(smoke.SYNTHETIC_TOKEN, family)
    selector = smoke.PILOT + quote(reflected, safe="")
    monkeypatch.setattr(smoke, "synthetic_transport", lambda: httpx.MockTransport(peer.handle))
    path = tmp_path / "SYNTHETIC-explicit.json"
    assert (
        smoke.main(
            [
                "--pilot",
                smoke.PILOT,
                "--synthetic",
                "--start-date",
                "2026-01-01",
                "--end-date",
                "2026-01-07",
                flag,
                selector,
                "--output",
                str(path),
            ]
        )
        == 1
    )
    saved = json.loads(path.read_text())
    output = capsys.readouterr()
    assert json.loads(output.out) == saved and output.err == ""
    # URL contracts already refuse decoded backslashes before credential lookup;
    # raw approved-path reflection reaches the common pre-dispatch guard.
    assert saved["error"] == ("unsafe_tool_selector" if family == "raw" else "invalid_selector")
    assert saved["bing_sdk_calls"] == len(peer.calls) == (7 if family == "raw" else 0)
    assert all(selector not in args.values() for _, args in peer.calls)
    assert reflected not in path.read_text() + output.out


@pytest.mark.parametrize("field", ["query", "url"])
def test_discovered_safe_selector_after_reflection_remains_usable(field):
    peer = Peer()
    target = "bing_query_stats" if field == "query" else "bing_list_sitemaps"
    followup = "bing_query_page_stats" if field == "query" else "bing_sitemap_details"
    safe = "ordinary query" if field == "query" else smoke.PILOT + "safe.xml"
    reflected = reflected_bearer(smoke.SYNTHETIC_TOKEN, "hex")

    def handle(request):
        response = peer.handle(request)
        if request.method != "POST" or not request.content:
            return response
        body = json.loads(request.content)
        if body.get("method") != "tools/call" or body["params"]["name"] != target:
            return response
        from google_seo_mcp.bing.models import BingFeedRecord, BingQueryRecord

        if field == "query":
            row = BingQueryRecord(
                query=safe,
                clicks=1,
                impressions=2,
                date="/Date(1767225600000)/",
                date_utc=smoke.datetime(2026, 1, 1, tzinfo=smoke.UTC),
                ctr=0.5,
                avg_click_position=17,
                avg_impression_position=18,
            ).model_dump(mode="json")
        else:
            row = BingFeedRecord(
                url=safe,
                compressed=False,
                file_size=1,
                status="ok",
                type="Sitemap",
                url_count=1,
                last_crawled="/Date(1767225600000)/",
                last_crawled_utc=smoke.datetime(2026, 1, 1, tzinfo=smoke.UTC),
                submitted="/Date(1767225600000)/",
                submitted_utc=smoke.datetime(2026, 1, 1, tzinfo=smoke.UTC),
            ).model_dump(mode="json")
        unsafe = dict(
            row, **{field: reflected if field == "query" else smoke.PILOT + quote(reflected)}
        )
        envelope = response.json()
        data = json.loads(envelope["result"]["content"][0]["text"])["data"]
        data.update(status="ok", source_rows=2, returned_rows=2, records=[unsafe, row])
        envelope["result"]["content"][0]["text"] = json.dumps({"data": data})
        return httpx.Response(200, json=envelope)

    result = asyncio.run(smoke.run(options(), transport=httpx.MockTransport(handle)))
    assert result["status"] == "SYNTHETIC_ONLY"
    assert len(peer.calls) == result["bing_sdk_calls"] == 8
    args = next(args for name, args in peer.calls if name == followup)
    assert args["query" if field == "query" else "sitemap_url"] == safe


@pytest.mark.parametrize("value", ["\\Uffffffff", "A" * 65537])
def test_sanitizer_invalid_or_oversize_escapes_fail_closed(value):
    assert smoke.sanitize({"nested": [value]}, "SYNTHETIC") == {"nested": ["[REDACTED]"]}


def test_sanitizer_structure_depth_cap_fails_closed():
    value = reflected_bearer("SYNTHETIC", "long_unicode")
    for _ in range(40):
        value = [value]
    result = smoke.sanitize(value, "SYNTHETIC")
    for _ in range(33):
        assert isinstance(result, list)
        result = result[0]
    assert result == "[REDACTED]"
