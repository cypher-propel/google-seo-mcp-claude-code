"""Hash-only consumer identity and the outer HTTP admission boundary."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import re
import time
import uuid
from collections import deque
from contextvars import ContextVar
from functools import lru_cache
from http import HTTPStatus
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from .runtime_config import ProductionRuntimeConfig

MAX_REGISTRY_BYTES = 1024 * 1024
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_TOKEN_BYTES = 1024
log = logging.getLogger(__name__)
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", strict=True)]

# An in-process capability, never accepted from JSON or a logger's name. Only
# controlled request/tool emitters use this; arbitrary Python code is trusted.
_HOSTED_AUDIT_MARKER = object()


@lru_cache(maxsize=1)
def _audit_tool_names() -> frozenset[str]:
    from .tool_policy import ProductionToolPolicy

    return ProductionToolPolicy().names


def _bounded_audit_payload(payload: dict) -> dict | None:
    """Select exact bounded scalar fields without formatting arbitrary objects."""
    if type(payload) is not dict or not {
        "request_id", "consumer", "tool", "outcome", "duration_ms"
    } <= payload.keys():
        return None
    request_id = payload.get("request_id")
    consumer = payload.get("consumer")
    tool = payload.get("tool")
    outcome = payload.get("outcome")
    duration = payload.get("duration_ms")
    status = payload.get("status")
    if (type(request_id) is not str
            or re.fullmatch(r"[0-9a-f]{32}", request_id) is None):
        return None
    if consumer is not None and (
        type(consumer) is not str
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", consumer) is None
    ):
        return None
    if tool is not None and (
        type(tool) is not str or (tool != "denied" and tool not in _audit_tool_names())
    ):
        return None
    if type(outcome) is not str or outcome not in ("success", "error", "denied"):
        return None
    if (type(duration) not in (int, float) or not 0 <= duration <= 86400000
            or (type(duration) is float and not math.isfinite(duration))):
        return None
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        return None
    safe = {
        "request_id": request_id, "consumer": consumer, "tool": tool,
        "outcome": outcome, "duration_ms": duration,
    }
    if "status" in payload:
        safe["status"] = status
    return safe


def emit_hosted_audit(logger: logging.Logger, audit_payload: dict) -> None:
    """Emit controlled audit provenance only after scalar schema validation."""
    safe = _bounded_audit_payload(audit_payload)
    if safe is not None:
        logger.info(
            json.dumps(safe, separators=(",", ":"), allow_nan=False),
            extra={"_hosted_audit_marker": _HOSTED_AUDIT_MARKER},
        )


def _hosted_audit_message(record: logging.LogRecord) -> str | None:
    """Reconstruct marked records; never call getMessage/str/repr on input."""
    if type(record) is not logging.LogRecord:
        return None
    fields = record.__dict__
    if fields.get("_hosted_audit_marker") is not _HOSTED_AUDIT_MARKER:
        return None
    name = fields.get("name")
    if type(name) is not str or name not in (
        "google_seo_mcp.audit", "google_seo_mcp.consumer_auth"
    ):
        return None
    message, args = fields.get("msg"), fields.get("args")
    if (type(message) is not str or len(message) > 2048
            or type(args) is not tuple or len(args) != 0
            or fields.get("exc_info") is not None
            or fields.get("stack_info") is not None):
        return None
    try:
        safe = _bounded_audit_payload(json.loads(message))
    except (ValueError, TypeError, RecursionError):
        return None
    return json.dumps(safe, separators=(",", ":"), allow_nan=False) if safe is not None else None


class ConsumerKeyEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    consumer_id: Identifier
    key_id: Identifier
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True, repr=False)
    enabled: StrictBool


class ConsumerKeyRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    version: Literal[1]
    consumers: tuple[ConsumerKeyEntry, ...] = Field(min_length=1, max_length=4096)

    @field_validator("version", mode="before")
    @classmethod
    def strict_version(cls, value):
        if type(value) is not int or value != 1:
            raise ValueError("invalid registry version")
        return value

    @model_validator(mode="after")
    def unique_entries(self) -> ConsumerKeyRegistry:
        if len({entry.key_id for entry in self.consumers}) != len(self.consumers):
            raise ValueError("duplicate key identifiers")
        if len({entry.sha256 for entry in self.consumers}) != len(self.consumers):
            raise ValueError("duplicate digests")
        if not any(entry.enabled for entry in self.consumers):
            raise ValueError("no active consumers")
        return self


class AuthenticatedConsumer(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    consumer_id: Identifier
    key_id: Identifier


consumer_context: ContextVar[AuthenticatedConsumer | None] = ContextVar(
    "authenticated_consumer", default=None
)
request_id_context: ContextVar[str | None] = ContextVar("request_id", default=None)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate registry field")
        result[key] = value
    return result


def load_consumer_key_registry(path: str | Path) -> ConsumerKeyRegistry:
    try:
        with Path(path).open("rb") as registry_file:
            raw = registry_file.read(MAX_REGISTRY_BYTES + 1)
        if len(raw) > MAX_REGISTRY_BYTES:
            raise ValueError("registry too large")
        return ConsumerKeyRegistry.model_validate(json.loads(raw, object_pairs_hook=_unique_object))
    except (OSError, ValueError, TypeError, RecursionError):
        raise ValueError("invalid consumer key registry") from None


def verify_consumer_key(token: str, registry: ConsumerKeyRegistry) -> AuthenticatedConsumer | None:
    if not isinstance(token, str) or not re.fullmatch(r"[\x21-\x7e]{1,1024}", token):
        return None
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    matched = None
    for entry in registry.consumers:
        if entry.enabled:
            equal = hmac.compare_digest(digest, entry.sha256)
            if equal:
                matched = AuthenticatedConsumer(consumer_id=entry.consumer_id, key_id=entry.key_id)
    return matched


class ConsumerKeyEdgeMiddleware:
    """Single-process admission; state is bounded by the validated registry."""

    def __init__(self, app, registry: ConsumerKeyRegistry, config: ProductionRuntimeConfig):
        self.app, self.registry, self.config = app, registry, config
        self._inflight = {entry.consumer_id: 0 for entry in registry.consumers if entry.enabled}
        self._requests = {name: deque(maxlen=60) for name in self._inflight}

    async def _reject(self, send, status: int, code: str, retry: int | None = None):
        headers = [(b"content-type", b"application/json"), (b"cache-control", b"no-store")]
        if status == 401:
            headers.append((b"www-authenticate", b"Bearer"))
        if retry is not None:
            headers.append((b"retry-after", str(retry).encode("ascii")))
        body = json.dumps({"error": code}).encode("ascii")
        headers.append((b"content-length", str(len(body)).encode("ascii")))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self._admit(scope, receive, send)
        request_id = uuid.uuid4().hex
        scope["request_id"] = request_id
        context_token = request_id_context.set(request_id)
        consumer_token = consumer_context.set(None)
        scope.pop("authenticated_consumer", None)
        started, status = time.monotonic(), None

        async def audited_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                # SDK Streamable HTTP uses HTTPStatus enums; convert this known
                # trusted enum before the audit schema's exact-integer check.
                if type(status) is HTTPStatus:
                    status = status.value
            await send(message)

        try:
            return await self._admit(scope, receive, audited_send)
        finally:
            consumer = scope.get("authenticated_consumer")
            emit_hosted_audit(
                log, {
                    "request_id": request_id,
                    "consumer": consumer.consumer_id if consumer else None,
                    "tool": None,
                    "outcome": "error"
                    if status is None or status >= 500
                    else ("denied" if status >= 400 else "success"),
                    "status": status,
                    "duration_ms": round((time.monotonic() - started) * 1000, 3),
                },
            )
            consumer_context.reset(consumer_token)
            request_id_context.reset(context_token)

    async def _admit(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        headers = scope.get("headers", [])
        # Bounded parsing happens before reading any body or invoking the SDK.
        if len(headers) > 100 or sum(len(k) + len(v) for k, v in headers) > MAX_HEADER_BYTES:
            return await self._reject(send, 431, "headers_too_large")
        values = {}
        for key, value in headers:
            values.setdefault(key.lower(), []).append(value)
        path, method = scope.get("path"), scope.get("method")
        liveness = path == "/healthz" and method == "GET"
        readiness = path == "/readyz"
        consumer = None
        if not liveness and not readiness:
            auth = values.get(b"authorization", [])
            if len(auth) != 1 or len(auth[0]) > MAX_TOKEN_BYTES + 7:
                return await self._reject(send, 401, "unauthorized")
            try:
                scheme, token = auth[0].decode("ascii").split(" ", 1)
            except (UnicodeDecodeError, ValueError):
                return await self._reject(send, 401, "unauthorized")
            if scheme != "Bearer":
                return await self._reject(send, 401, "unauthorized")
            consumer = verify_consumer_key(token, self.registry)
            if consumer is None:
                return await self._reject(send, 401, "unauthorized")
            # Attribute authenticated denials as well as dispatched requests.
            # The outer request finally restores context on every return path.
            consumer_context.set(consumer)
            scope["authenticated_consumer"] = consumer
        host, origin = values.get(b"host", []), values.get(b"origin", [])
        if len(host) != 1 or len(origin) > 1:
            return await self._reject(send, 403, "untrusted_request")
        try:
            trusted = host[0].decode("ascii").lower() in self.config.accepted_hosts
            trusted = trusted and (
                not origin or origin[0].decode("ascii") in self.config.accepted_origins
            )
        except UnicodeDecodeError:
            trusted = False
        if not trusted:
            return await self._reject(send, 403, "untrusted_request")
        if readiness:
            try:
                local = ipaddress.ip_address(scope["client"][0]).is_loopback
            except (ValueError, KeyError, TypeError, IndexError):
                local = False
            if not local:
                return await self._reject(send, 403, "local_only")
        if consumer is None:
            return await self.app(scope, receive, send)
        lengths = values.get(b"content-length", [])
        if (
            len(lengths) > 1
            or (
                lengths
                and (
                    not re.fullmatch(rb"[0-9]{1,10}", lengths[0])
                    or int(lengths[0]) > MAX_BODY_BYTES
                )
            )
            or (lengths and b"transfer-encoding" in values)
        ):
            return await self._reject(send, 413, "invalid_body_size")
        name, now = consumer.consumer_id, time.monotonic()
        requests = self._requests[name]
        while requests and requests[0] <= now - 60:
            requests.popleft()
        if self._inflight[name] >= 2:
            return await self._reject(send, 429, "concurrency_limit", 1)
        if len(requests) >= 60:
            return await self._reject(
                send, 429, "rate_limit", max(1, math.ceil(60 - now + requests[0]))
            )
        # No awaits between checking and reserving these process-local slots.
        requests.append(now)
        self._inflight[name] += 1
        try:
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                if message["type"] != "http.request":
                    return await self._reject(send, 400, "invalid_request")
                chunk = message.get("body", b"")
                if len(body) + len(chunk) > MAX_BODY_BYTES:
                    return await self._reject(send, 413, "body_too_large")
                body.extend(chunk)
                if not message.get("more_body", False):
                    break
            if lengths and len(body) != int(lengths[0]):
                return await self._reject(send, 413, "invalid_body_size")
            delivered = False

            async def buffered_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            return await self.app(scope, buffered_receive, send)
        finally:
            self._inflight[name] -= 1
