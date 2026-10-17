"""SSRF guard + untrusted-content wrapper regression tests."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import pytest

from google_seo_mcp.security import (
    SSRFBlocked,
    assert_url_is_public,
    mark_third_party_strings,
    wrap_untrusted,
)


# ── SSRF guard ───────────────────────────────────────────────────────


@pytest.fixture
def synthetic_dns(monkeypatch):
    """SYNTHETIC terminal answers only: no DNS or live host-resolution claim."""
    answers = {
        "127.0.0.1": ("127.0.0.1",),
        "localhost": ("127.0.0.1", "::1"),
        "169.254.169.254": ("169.254.169.254",),
        "10.0.0.1": ("10.0.0.1",),
        "192.168.1.1": ("192.168.1.1",),
        "172.16.5.5": ("172.16.5.5",),
        "::1": ("::1",),
        "2130706433": ("127.0.0.1",),
        "www.google.com": ("8.8.8.8", "2001:4860:4860::8888"),
    }
    calls = []

    def getaddrinfo(host, port, *, type):
        calls.append((host, port, type))
        assert host in answers, f"Unexpected SYNTHETIC DNS lookup: {host!r}"
        assert port is None and type == socket.SOCK_STREAM
        return [
            (
                socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET,
                type,
                socket.IPPROTO_TCP,
                "",
                (ip, 0, 0, 0) if ipaddress.ip_address(ip).version == 6 else (ip, 0),
            )
            for ip in answers[host]
        ]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return answers, calls


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://172.16.5.5/",
        "http://[::1]/",
        "file:///etc/passwd",
        "ftp://example.com/",
    ],
)
def test_ssrf_guard_blocks(url, synthetic_dns):
    answers, calls = synthetic_dns
    with pytest.raises(SSRFBlocked):
        assert_url_is_public(url)
    host = urlparse(url).hostname
    if url.startswith(("file:", "ftp:")) or host == "metadata.google.internal":
        assert calls == []  # Scheme/cloud-hostname rejection must precede DNS.
    else:
        assert calls == [(host, None, socket.SOCK_STREAM)]

    if host == "127.0.0.1":
        # Additional SYNTHETIC answers exercise the existing reserved/private
        # predicates and rejection of a mixed public/non-public answer set.
        for ips in [("100::1",), ("192.0.2.1",), ("8.8.8.8", "10.0.0.1")]:
            answers[host] = ips
            calls.clear()
            with pytest.raises(SSRFBlocked):
                assert_url_is_public(url)
            assert calls == [(host, None, socket.SOCK_STREAM)]


def test_ssrf_guard_allows_public(synthetic_dns):
    answers, calls = synthetic_dns
    # SYNTHETIC public addresses, NOT a live www.google.com DNS assertion.
    assert all(ipaddress.ip_address(ip).is_global for ip in answers["www.google.com"])
    assert_url_is_public("https://www.google.com/")
    assert calls == [("www.google.com", None, socket.SOCK_STREAM)]


def test_ssrf_guard_blocks_decimal_ip_loopback(synthetic_dns):
    _, calls = synthetic_dns
    # SYNTHETIC canonical resolver answer: 2130706433 = 127.0.0.1 in decimal.
    with pytest.raises(SSRFBlocked):
        assert_url_is_public("http://2130706433/")
    assert calls == [("2130706433", None, socket.SOCK_STREAM)]


# ── Untrusted wrapper ───────────────────────────────────────────────


def test_wrap_untrusted_basic():
    out = wrap_untrusted("Hello")
    assert out.startswith("<untrusted-third-party-content>")
    assert out.endswith("</untrusted-third-party-content>")
    assert "Hello" in out


def test_wrap_untrusted_truncates_long():
    payload = "x" * 50_000
    out = wrap_untrusted(payload, max_bytes=1000)
    assert "[truncated]" in out
    assert len(out) < 2000


def test_wrap_untrusted_passes_non_strings():
    assert wrap_untrusted(None) is None
    assert wrap_untrusted(42) == 42
    assert wrap_untrusted(True) is True


def test_mark_third_party_strings_wraps_known_fields():
    sig = {
        "title": "Real title",
        "meta_description": "Some desc",
        "h1": ["First", "Second"],
        "og": {"title": "OG title"},
        "url": "https://example.com",  # not in untrusted set
        "html_size_bytes": 1234,        # not a string
    }
    out = mark_third_party_strings(sig)
    assert "<untrusted" in out["title"]
    assert "<untrusted" in out["meta_description"]
    assert all("<untrusted" in h for h in out["h1"])
    assert "<untrusted" in out["og"]["title"]
    # url and html_size_bytes pass through unchanged
    assert out["url"] == "https://example.com"
    assert out["html_size_bytes"] == 1234


# ── XXE / defusedxml regression ─────────────────────────────────────


def test_sitemap_diff_imports_use_defusedxml():
    """Static check: the sitemap_diff module must not import the unsafe ET."""
    import google_seo_mcp.migration.sitemap_diff as sd

    with open(sd.__file__) as source:
        src = source.read()
    assert "from defusedxml" in src
    assert "import xml.etree.ElementTree" not in src
