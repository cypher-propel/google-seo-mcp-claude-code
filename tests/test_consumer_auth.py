"""Offline tests of the real outer ASGI admission and strict hash registry."""

import asyncio
import hashlib
import json
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from google_seo_mcp.consumer_auth import (
    MAX_BODY_BYTES,
    MAX_REGISTRY_BYTES,
    ConsumerKeyEdgeMiddleware,
    ConsumerKeyRegistry,
    consumer_context,
    load_consumer_key_registry,
    verify_consumer_key,
)
from google_seo_mcp.runtime_config import load_runtime_config


def entry(key="fixture-a", consumer="alpha", key_id="a", enabled=True):
    return {
        "consumer_id": consumer,
        "key_id": key_id,
        "sha256": hashlib.sha256(key.encode()).hexdigest(),
        "enabled": enabled,
    }


@pytest.fixture
def registry():
    return ConsumerKeyRegistry.model_validate(
        {
            "version": 1,
            "consumers": [
                entry(),
                entry("fixture-b", "beta", "b"),
                entry("revoked", "old", "c", False),
            ],
        }
    )


@pytest.mark.parametrize(
    "change",
    [
        {"version": True},
        {"version": "1"},
        {"version": 2},
        {"extra": "no"},
        {"consumers": []},
        {"consumers": [entry(enabled=False)]},
        {"consumers": [entry(), entry(key_id="a", key="different")]},
        {"consumers": [entry(), entry(key_id="b", enabled=False)]},
        {"consumers": [entry() | {"enabled": "true"}]},
        {"consumers": [entry() | {"consumer_id": "../escape"}]},
        {"consumers": [entry() | {"key_id": "é"}]},
        {"consumers": [entry() | {"sha256": "A" * 64}]},
        {"consumers": [entry() | {"sha256": "a" * 63}]},
        {"consumers": [entry() | {"sha256": "a" * 65}]},
        {"consumers": [entry() | {"sha256": "a" * 64 + "\n"}]},
        {"consumers": [entry() | {"unknown": True}]},
    ],
)
def test_registry_rejects_invalid_shapes(change):
    with pytest.raises(ValidationError):
        ConsumerKeyRegistry.model_validate({"version": 1, "consumers": [entry()]} | change)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"[]",
        b'{"version":1,"version":1,"consumers":[]}',
        json.dumps({"version": 1, "consumers": [entry()]})
        .replace('"enabled": true', '"enabled": true, "enabled": true')
        .encode(),
        b"x" * (MAX_REGISTRY_BYTES + 1),
    ],
)
def test_registry_file_rejection_is_sanitized(tmp_path, raw):
    registry_file = tmp_path / "private-sentinel.json"
    registry_file.write_bytes(raw)
    with pytest.raises(ValueError, match="^invalid consumer key registry$") as error:
        load_consumer_key_registry(registry_file)
    assert "private-sentinel" not in str(error.value)


def test_registry_load_and_missing(tmp_path):
    registry_file = tmp_path / "registry.json"
    registry_file.write_text(json.dumps({"version": 1, "consumers": [entry()]}))
    assert load_consumer_key_registry(registry_file).consumers[0].consumer_id == "alpha"
    with pytest.raises(ValueError, match="^invalid consumer key registry$"):
        load_consumer_key_registry(tmp_path / "absent")


def test_verifier_checks_all_enabled_digests_and_identifies(registry):
    import hmac

    with patch(
        "google_seo_mcp.consumer_auth.hmac.compare_digest", wraps=hmac.compare_digest
    ) as compare:
        assert verify_consumer_key("fixture-a", registry).model_dump() == {
            "consumer_id": "alpha",
            "key_id": "a",
        }
        assert compare.call_count == 2
    assert verify_consumer_key("fixture-b", registry).consumer_id == "beta"
    assert verify_consumer_key("revoked", registry) is None
    for token in ("", "unknown", "contains space", "é", "x" * 1025, "fixture-a\n"):
        assert verify_consumer_key(token, registry) is None
    assert "sha256" not in repr(registry)


def config():
    return load_runtime_config(
        [],
        {
            "GOOGLE_SEO_TRANSPORT": "streamable-http",
            "GOOGLE_SEO_ACCEPTED_HOSTS": "testserver,127.0.0.1:8000",
            "GOOGLE_SEO_ACCEPTED_ORIGINS": "https://approved.example",
        },
    )


def request_headers(key="fixture-a"):
    return [(b"host", b"testserver"), (b"authorization", f"Bearer {key}".encode())]


async def perform(
    app, *, path="/mcp", method="POST", headers=None, chunks=None, client=("127.0.0.1", 1234)
):
    messages = list(chunks or [{"type": "http.request", "body": b"", "more_body": False}])
    sent = []

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(
        {
            "type": "http",
            "path": path,
            "method": method,
            "headers": request_headers() if headers is None else headers,
            "client": client,
        },
        receive,
        send,
    )
    return sent


async def echo_identity(scope, receive, send):
    consumer = consumer_context.get()
    assert consumer == scope.get("authenticated_consumer")
    await receive()
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send(
        {
            "type": "http.response.body",
            "body": (consumer.consumer_id if consumer else "minimal").encode(),
        }
    )


def test_edge_auth_all_methods_aliases_and_exact_identities(registry):
    app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
    for path in ("/mcp", "/mcp/", "/unknown", "/sse", "/messages", "/healthz/"):
        for method in ("POST", "GET", "DELETE", "OPTIONS", "HEAD", "PUT"):
            sent = asyncio.run(
                perform(app, path=path, method=method, headers=[(b"host", b"testserver")])
            )
            assert sent[0]["status"] == 401
            assert (b"www-authenticate", b"Bearer") in sent[0]["headers"]
    for key, identity in (("fixture-a", b"alpha"), ("fixture-b", b"beta")):
        sent = asyncio.run(perform(app, headers=request_headers(key)))
        assert sent[0]["status"] == 200 and sent[-1]["body"] == identity
    assert consumer_context.get() is None


@pytest.mark.parametrize(
    "auth",
    [
        [],
        [b""],
        [b"Basic fixture-a"],
        [b"bearer fixture-a"],
        [b"Bearer "],
        [b"Bearer unknown"],
        [b"Bearer revoked"],
        [b"Bearer fixture-a", b"Bearer fixture-a"],
        [b"Bearer fixture-a "],
        [b"Bearer \xff"],
        [b"Bearer " + b"x" * 1025],
    ],
)
def test_invalid_auth_never_dispatches(registry, auth):
    async def forbidden(*args):
        pytest.fail("unauthorized request dispatched")

    headers = [(b"host", b"testserver")] + [(b"authorization", value) for value in auth]
    sent = asyncio.run(
        perform(ConsumerKeyEdgeMiddleware(forbidden, registry, config()), headers=headers)
    )
    assert sent[0]["status"] == 401


@pytest.mark.parametrize(
    "extra",
    [
        [(b"origin", b"https://evil.example")],
        [(b"origin", b"null")],
        [(b"origin", b"https://approved.example/")],
        [(b"origin", b"https://approved.example"), (b"origin", b"https://approved.example")],
        [(b"host", b"testserver")],
    ],
)
def test_untrusted_host_origin(registry, extra):
    app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
    assert asyncio.run(perform(app, headers=request_headers() + extra))[0]["status"] == 403


def test_exact_port_and_health_host_validation(registry):
    app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
    for host in (b"evil.example", b"testserver:80", b"testserver.", b"testserver@evil.example"):
        headers = [(b"host", host), (b"authorization", b"Bearer fixture-a")]
        assert asyncio.run(perform(app, headers=headers))[0]["status"] == 403
    assert (
        asyncio.run(
            perform(app, path="/healthz", method="GET", headers=[(b"host", b"testserver")])
        )[0]["status"]
        == 200
    )
    assert (
        asyncio.run(
            perform(app, path="/healthz", method="GET", headers=[(b"host", b"evil.example")])
        )[0]["status"]
        == 403
    )
    assert (
        asyncio.run(
            perform(app, headers=request_headers() + [(b"origin", b"https://approved.example")])
        )[0]["status"]
        == 200
    )


def test_readiness_only_actual_local_peer(registry):
    app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
    headers = [(b"host", b"testserver"), (b"x-forwarded-for", b"127.0.0.1")]
    assert (
        asyncio.run(
            perform(app, path="/readyz", method="GET", headers=headers, client=("192.0.2.1", 123))
        )[0]["status"]
        == 403
    )
    assert (
        asyncio.run(perform(app, path="/readyz", method="GET", headers=headers))[0]["status"] == 200
    )


@pytest.mark.parametrize("length", [b"4194305", b"-1", b"abc", b"999999999999", b"1"])
def test_declared_invalid_size_before_dispatch(registry, length):
    app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
    assert (
        asyncio.run(perform(app, headers=request_headers() + [(b"content-length", length)]))[0][
            "status"
        ]
        == 413
    )


def test_chunked_limit_and_duplicate_length(registry):
    app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
    chunks = [
        {"type": "http.request", "body": b"x" * MAX_BODY_BYTES, "more_body": True},
        {"type": "http.request", "body": b"x", "more_body": False},
    ]
    assert asyncio.run(perform(app, chunks=chunks))[0]["status"] == 413
    assert (
        asyncio.run(
            perform(
                app,
                headers=request_headers() + [(b"content-length", b"0"), (b"content-length", b"0")],
            )
        )[0]["status"]
        == 413
    )
    assert app._inflight["alpha"] == 0


def test_rate_rolling_window_and_separate_consumers(registry):
    app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
    with patch("google_seo_mcp.consumer_auth.time.monotonic", return_value=100):
        for _ in range(60):
            assert asyncio.run(perform(app))[0]["status"] == 200
        response = asyncio.run(perform(app))
        assert response[0]["status"] == 429
        assert (b"retry-after", b"60") in response[0]["headers"]
        assert asyncio.run(perform(app, headers=request_headers("fixture-b")))[0]["status"] == 200
    with patch("google_seo_mcp.consumer_auth.time.monotonic", return_value=161):
        assert asyncio.run(perform(app))[0]["status"] == 200


def test_concurrency_reserved_during_body_and_released(registry):
    async def exercise():
        app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
        release = asyncio.Event()
        entered = 0
        ready = asyncio.Event()

        async def slow_receive():
            nonlocal entered
            entered += 1
            if entered == 2:
                ready.set()
            await release.wait()
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            pass

        scope = {
            "type": "http",
            "path": "/mcp",
            "method": "POST",
            "headers": request_headers(),
            "client": ("127.0.0.1", 1),
        }
        first = asyncio.create_task(app(dict(scope), slow_receive, send))
        second = asyncio.create_task(app(dict(scope), slow_receive, send))
        await asyncio.wait_for(ready.wait(), 2)
        assert (await perform(app))[0]["status"] == 429
        assert (await perform(app, headers=request_headers("fixture-b")))[0]["status"] == 200
        release.set()
        await asyncio.gather(first, second)
        assert (await perform(app))[0]["status"] == 200
        assert app._inflight["alpha"] == 0

    asyncio.run(exercise())


def test_headers_bounded_and_exception_slot_cleanup(registry):
    app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
    assert (
        asyncio.run(perform(app, headers=request_headers() + [(b"large", b"x" * 17000)]))[0][
            "status"
        ]
        == 431
    )

    async def raises(*args):
        raise RuntimeError("fixture exception")

    app = ConsumerKeyEdgeMiddleware(raises, registry, config())
    with pytest.raises(RuntimeError, match="fixture exception"):
        asyncio.run(perform(app))
    assert app._inflight["alpha"] == 0 and consumer_context.get() is None


def test_rate_shared_by_rotated_keys_for_same_consumer():
    registry = ConsumerKeyRegistry.model_validate(
        {"version": 1, "consumers": [entry(), entry("rotation", "alpha", "rotation")]}
    )
    app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
    with patch("google_seo_mcp.consumer_auth.time.monotonic", return_value=100):
        for _ in range(30):
            assert asyncio.run(perform(app))[0]["status"] == 200
            assert (
                asyncio.run(perform(app, headers=request_headers("rotation")))[0]["status"] == 200
            )
        assert asyncio.run(perform(app))[0]["status"] == 429


def test_disconnect_and_size_rejections_release_consumer(registry):
    app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
    assert asyncio.run(perform(app, chunks=[{"type": "http.disconnect"}])) == []
    assert app._inflight["alpha"] == 0
    assert consumer_context.get() is None
    assert asyncio.run(perform(app))[0]["status"] == 200


def test_edge_audits_rejections_without_raw_values(registry, caplog):
    caplog.set_level("INFO", logger="google_seo_mcp.consumer_auth")
    app = ConsumerKeyEdgeMiddleware(echo_identity, registry, config())
    headers = request_headers("secret-sentinel") + [(b"x-consumer", b"untrusted-sentinel")]
    assert asyncio.run(perform(app, headers=headers))[0]["status"] == 401
    assert "secret-sentinel" not in caplog.text and "untrusted-sentinel" not in caplog.text
    record = json.loads(caplog.records[-1].message)
    assert record["consumer"] is None and record["outcome"] == "denied"
    assert len(record["request_id"]) == 32
    assert asyncio.run(perform(app))[0]["status"] == 200
    assert json.loads(caplog.records[-1].message)["consumer"] == "alpha"
