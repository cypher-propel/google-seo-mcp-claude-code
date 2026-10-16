#!/usr/bin/env python3
"""Credential-injected, discovery-only HTTP smoke. Never prints response data."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import re
from importlib.resources import files
from urllib.parse import urlsplit

PUBLIC_AUTHORITY = "google-seo.mcp.propel.marketing"
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10", "::1/128", "fc00::/7",
))


class SmokeFailure(Exception):
    """Deliberately contains no untrusted diagnostics."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise SmokeFailure()


def local_authority(authority: str) -> bool:
    parsed = urlsplit("//" + authority)
    if parsed.hostname == "localhost":
        return True
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        return False
    return any(address in network for network in PRIVATE_NETWORKS)


def validate_target(url: str, allowed_http_hosts: list[str]) -> tuple[str, bool]:
    """Public TLS has one exact authority; cleartext needs an explicit local IP."""
    if not url.isascii() or any(ord(char) <= 32 for char in url) or any(
        char in url for char in ("?", "#", "\\", "%")
    ):
        raise SmokeFailure()
    parsed = urlsplit(url)
    if (
        parsed.username is not None or parsed.password is not None
        or parsed.path not in ("/mcp", "/mcp/") or parsed.query or parsed.fragment
        or not parsed.hostname or parsed.port == 0
    ):
        raise SmokeFailure()
    if parsed.scheme == "https" and parsed.netloc == PUBLIC_AUTHORITY:
        return url, False
    if (
        parsed.scheme == "http" and parsed.netloc in allowed_http_hosts
        and local_authority(parsed.netloc)
    ):
        return url, True
    raise SmokeFailure()


async def smoke(options: argparse.Namespace) -> dict[str, str | int]:
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    url, local = validate_target(options.url, options.allow_http_host)
    if options.check_local_readiness and not local:
        raise SmokeFailure()
    token = os.environ.get("GOOGLE_SEO_SMOKE_KEY", "")
    if re.fullmatch(r"[\x21-\x7e]{1,1024}", token) is None:
        raise SmokeFailure()
    manifest = json.loads(files("google_seo_mcp").joinpath("production_tools.json").read_text())
    expected = manifest["tools"]
    if (
        manifest["version"] != 1 or len(expected) != 35
        or len(set(expected)) != len(expected)
    ):
        raise SmokeFailure()
    base = options.url.rsplit("/mcp", 1)[0]
    authority = urlsplit(url).netloc
    scheme = urlsplit(url).scheme

    async def check_request(request: httpx.Request) -> None:
        if (
            request.url.scheme != scheme or request.url.netloc.decode("ascii") != authority
            or request.url.path not in ("/mcp", "/mcp/", "/healthz", "/readyz")
            or request.url.query
        ):
            raise SmokeFailure()

    async def check_response(response: httpx.Response) -> None:
        # The SDK can handle redirects itself. Reject before it sees any 3xx,
        # including same-origin redirects; never rely only on follow_redirects.
        if 300 <= response.status_code < 400:
            raise SmokeFailure()

    common = dict(
        trust_env=False, verify=True, follow_redirects=False,
        timeout=httpx.Timeout(15),
        event_hooks={"request": [check_request], "response": [check_response]},
    )
    revision = "unavailable"
    async with httpx.AsyncClient(**common) as anonymous:
        denied = await anonymous.post(url, json={})
        if denied.status_code != 401 or denied.headers.get("www-authenticate") != "Bearer":
            raise SmokeFailure()
        health = await anonymous.get(base + "/healthz")
        if health.status_code != 200 or health.json() != {"status": "ok"}:
            raise SmokeFailure()
        if options.check_local_readiness:
            ready = await anonymous.get(base + "/readyz")
            data = ready.json()
            if (
                ready.status_code != 200 or data.get("transport_ready") is not True
                or data.get("status") not in (
                    "credential-pending", "credentials-invalid", "transport-ready"
                )
                or data.get("google_credentials_state") not in ("pending", "invalid", "available")
            ):
                raise SmokeFailure()
            revision = data.get("revision", "")
            if not isinstance(revision, str) or re.fullmatch(
                r"[a-f0-9]{40}|[0-9]+(?:\.[0-9]+){1,3}(?:[a-z0-9.+-]{0,24})?|unknown", revision
            ) is None:
                raise SmokeFailure()
            if options.expected_revision is not None and revision != options.expected_revision:
                raise SmokeFailure()
        elif options.expected_revision is not None:
            raise SmokeFailure()
    names: list[str] = []
    seen_cursors: set[str] = set()
    async with (
        httpx.AsyncClient(headers={"Authorization": "Bearer " + token}, **common) as http,
        streamable_http_client(url, http_client=http) as (read, write, _),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        cursor = None
        # Finite bound catches a malicious/nonterminating pagination response
        # while still exhausting every legitimate manifest page.
        for _ in range(len(expected) + 1):
            result = await session.list_tools(cursor=cursor)
            names.extend(tool.name for tool in result.tools)
            cursor = result.nextCursor
            if cursor is None:
                break
            if cursor in seen_cursors:
                raise SmokeFailure()
            seen_cursors.add(cursor)
        else:
            raise SmokeFailure()
    if len(names) != len(expected) or set(names) != set(expected):
        raise SmokeFailure()
    return {"status": "PASS", "catalog_count": len(names), "revision": revision}


def main(argv: list[str] | None = None) -> int:
    # SDK/HTTP errors can contain URLs/headers. This command exposes only the
    # fixed success fields or one generic failure status, never exception text.
    logging.disable(logging.CRITICAL)
    try:
        parser = SafeParser(description=__doc__)
        parser.add_argument("--url", default="https://" + PUBLIC_AUTHORITY + "/mcp")
        parser.add_argument(
            "--allow-http-host", action="append", default=[], metavar="EXACT_AUTHORITY"
        )
        parser.add_argument("--check-local-readiness", action="store_true")
        parser.add_argument("--expected-revision", metavar="REVIEWED_SHA")
        options = parser.parse_args(argv)
        if options.expected_revision is not None and re.fullmatch(
            r"[a-f0-9]{40}", options.expected_revision
        ) is None:
            raise SmokeFailure()
        result = asyncio.run(asyncio.wait_for(smoke(options), timeout=60))
    except (Exception, KeyboardInterrupt):
        print(json.dumps({"status": "FAIL"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
