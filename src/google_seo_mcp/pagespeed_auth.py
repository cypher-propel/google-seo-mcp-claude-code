"""Lazy file-only hosted PageSpeed admission; legacy environment behavior is separate."""
from __future__ import annotations

import os
import stat

from . import auth
from .runtime_config import ProductionRuntimeConfig

_config: ProductionRuntimeConfig | None = None

PAGESPEED_TOOL_NAMES = frozenset({
    "lighthouse_audit", "lighthouse_core_web_vitals", "lighthouse_lcp_opportunities",
    "lighthouse_compare_mobile_desktop", "lighthouse_seo_score", "crux_current",
})


def configure_pagespeed_auth(config: ProductionRuntimeConfig) -> None:
    """Capture only the validated path; never read credentials at startup."""
    global _config
    _config = config


def load_hosted_key() -> str:
    """Read a bounded regular file without following a leaf symlink or blocking on a FIFO."""
    key = None
    descriptor = None
    try:
        if _config is not None and _config.profile == "production":
            descriptor = os.open(
                _config.pagespeed_api_key_file,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            )
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                raw = os.read(descriptor, 4097)
                if len(raw) <= 4096:
                    candidate = raw.decode("ascii").strip()
                    if candidate and all(33 <= ord(c) < 127 for c in candidate):
                        key = candidate
    except (OSError, UnicodeError):
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if key is None:
        raise RuntimeError("provider_not_configured")
    return key


def api_key(*, crux: bool = False) -> str | None:
    if auth.is_hosted_production():
        return load_hosted_key()
    if crux:
        return os.getenv("CRUX_API_KEY") or os.getenv("PAGESPEED_API_KEY")
    return os.getenv("PAGESPEED_API_KEY")
