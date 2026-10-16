"""Exact, bundled production admission policy; never admits a name by prefix."""

from __future__ import annotations

import json
from importlib.resources import files


class ToolPolicyError(ValueError):
    """Safe denial that contains no caller-controlled name or arguments."""


class ProductionToolPolicy:
    def __init__(self) -> None:
        try:
            resource = files("google_seo_mcp").joinpath("production_tools.json")
            manifest = json.loads(resource.read_text())
            if not isinstance(manifest, dict) or set(manifest) != {"version", "tools"}:
                raise ValueError
            names = manifest["tools"]
            if type(manifest["version"]) is not int or manifest["version"] != 1:
                raise ValueError
            if (not isinstance(names, list) or not names
                    or any(not isinstance(name, str) or not name.isascii()
                           or not name.replace("_", "").isalnum() for name in names)
                    or len(set(names)) != len(names)):
                raise ValueError
            self.names = frozenset(names)
        except (OSError, ValueError, TypeError, AttributeError):
            raise ToolPolicyError("invalid production tool manifest") from None

    def is_tool_allowed(self, name: str) -> bool:
        return isinstance(name, str) and name in self.names

    def enforce_tool_call(self, name: str, context=None) -> None:
        if not self.is_tool_allowed(name):
            raise ToolPolicyError("tool_not_allowed") from None


def is_tool_allowed(name: str, config) -> bool:
    return (
        getattr(config, "profile", None) != "production"
        or ProductionToolPolicy().is_tool_allowed(name)
    )


def enforce_tool_call(name: str, context=None) -> None:
    """Production-only helper; the context is attribution, never a policy override."""
    ProductionToolPolicy().enforce_tool_call(name, context)
