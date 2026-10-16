"""Hosted SDK transport composition; health probes never contact providers."""

from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version
from typing import Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import auth
from .consumer_auth import ConsumerKeyEdgeMiddleware, ConsumerKeyRegistry
from .runtime_config import ProductionRuntimeConfig
from .tool_policy import ProductionToolPolicy


class HealthStatus(BaseModel):
    """Transport readiness and offline credential availability, never API grants."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["not-ready", "credential-pending", "credentials-invalid", "transport-ready"]
    transport_ready: bool
    google_credentials_state: Literal["pending", "invalid", "available"]
    revision: str


def _release_revision() -> str:
    """Accept a build-supplied Git SHA; local installs use distribution version."""
    revision = os.environ.get("GOOGLE_SEO_REVISION", "unknown")
    if revision != "unknown":
        if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
            raise ValueError("invalid HTTP application configuration")
        return revision
    try:
        return version("google-seo-mcp")
    except PackageNotFoundError:
        return "unknown"


def create_http_app(
    config: ProductionRuntimeConfig, registry: ConsumerKeyRegistry, mcp: FastMCP
) -> ConsumerKeyEdgeMiddleware:
    """Wrap precisely the SDK HTTP handler with one owned session lifespan.

    Each process creates a new app/session manager. Both exact MCP paths use
    the same handler without a redirect or a mounted child lifespan.
    """
    if (
        not isinstance(config, ProductionRuntimeConfig)
        or config.transport != "streamable-http"
        or config.profile != "production"
        or not isinstance(registry, ConsumerKeyRegistry)
        or getattr(mcp, "runtime_config", None) != config
        or not mcp.settings.stateless_http
        or not mcp.settings.json_response
        or mcp.settings.streamable_http_path != "/mcp"
    ):
        raise ValueError("invalid HTTP application configuration")
    # Re-read the bundled policy and require the guarded registry before ever
    # opening a listener. Discovery checks do not invoke a business handler.
    policy = ProductionToolPolicy()
    if (
        getattr(mcp, "production_policy", None) is None
        or mcp.production_policy.names != policy.names
        or {tool.name for tool in mcp._tool_manager.list_tools()} != policy.names
    ):
        raise ValueError("invalid HTTP application configuration")
    sdk_app = mcp.streamable_http_app()
    sdk_routes = [route for route in sdk_app.routes if getattr(route, "path", None) == "/mcp"]
    if len(sdk_routes) != 1:
        raise ValueError("invalid HTTP application configuration")
    sdk_handler = sdk_routes[0].endpoint
    transport_ready = False
    revision = _release_revision()

    @asynccontextmanager
    async def lifespan(application: Starlette):
        nonlocal transport_ready
        # The SDK-created Starlette app is not mounted or separately started:
        # this is the only session_manager.run() call in the composition.
        async with mcp.session_manager.run():
            transport_ready = True
            try:
                yield
            finally:
                transport_ready = False

    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"}, headers={"Cache-Control": "no-store"})

    async def readyz(request: Request) -> JSONResponse:
        # This only validates the configured local file/schema. It never
        # constructs credentials, refreshes a token, or verifies Google access.
        state = auth.google_credentials_state()
        status = (
            "not-ready" if not transport_ready else
            "credential-pending" if state == "pending" else
            "credentials-invalid" if state == "invalid" else "transport-ready"
        )
        ready = transport_ready and (not config.require_google_credentials or state == "available")
        health = HealthStatus(
            status=status, transport_ready=transport_ready,
            google_credentials_state=state, revision=revision,
        )
        return JSONResponse(
            health.model_dump(), status_code=200 if ready else 503,
            headers={"Cache-Control": "no-store"},
        )

    application = Starlette(
        debug=False, lifespan=lifespan,
        routes=[
            Route("/healthz", healthz, methods=["GET"]),
            Route("/readyz", readyz, methods=["GET"]),
            Route("/mcp", sdk_handler),
            Route("/mcp/", sdk_handler),
        ],
    )
    application.router.redirect_slashes = False
    return ConsumerKeyEdgeMiddleware(application, registry, config)
