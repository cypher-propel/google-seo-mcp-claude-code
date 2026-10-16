"""Offline release-admission regressions; scanner/image outputs below are MOCK fixtures.

These tests never qualify an image or query an advisory/provider service. They
exercise the real helper boundaries while replacing only HTTP/subprocess terminals.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import datetime as dt
import importlib.util
import json
import logging
import re
import subprocess
import tomllib
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

# Import the SDK before patching HTTPX: it constructs HTTPX-dependent types.
from mcp import ClientSession  # noqa: F401
from mcp.client.streamable_http import streamable_http_client  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "src/google_seo_mcp/production_tools.json").read_text())
PUBLIC = "https://google-seo.mcp.propel.marketing/mcp"
MOCK_TOKEN = "synthetic-operator-test-not-a-consumer-secret"
SENTINEL = "MOCK_UPSTREAM_EXCEPTION_MUST_NOT_ESCAPE"
IMAGE_ID = "sha256:" + "a" * 64
REVISION = "b" * 40


def load_helper(name):
    spec = importlib.util.spec_from_file_location("operator_test_" + name, ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def smoke_module():
    return load_helper("smoke_http.py")


@pytest.fixture
def audit_module():
    return load_helper("audit_production.py")


@pytest.mark.parametrize("url", [
    "http://google-seo.mcp.propel.marketing/mcp", "https://example.org/mcp",
    "https://google-seo.mcp.propel.marketing:443/mcp", PUBLIC + "?token=x",
    PUBLIC + "#x", PUBLIC + "%2f", PUBLIC.replace("/mcp", "/sse"),
    PUBLIC.replace("https://", "https://user:password@"), PUBLIC + "\n",
    "http://169.254.169.254/mcp", "http://[fe80::1]/mcp", "http://8.8.8.8/mcp",
    "http://internal.example/mcp", "http://localhost:0/mcp", "http://[::ffff:127.0.0.1]/mcp",
])
def test_smoke_rejects_hostile_target_even_if_cleartext_opted_in(smoke_module, url):
    authority = url.split("/", 3)[2]
    with pytest.raises(smoke_module.SmokeFailure):
        smoke_module.validate_target(url, [authority])


@pytest.mark.parametrize("authority", [
    "localhost:3006", "127.0.0.1:3006", "10.2.3.4:3006", "172.16.2.3:3006",
    "192.168.2.3:3006", "100.64.2.3:3006", "[::1]:3006", "[fd00::1]:3006",
])
def test_smoke_requires_exact_explicit_local_authority(smoke_module, authority):
    target = "http://" + authority + "/mcp/"
    assert smoke_module.validate_target(target, [authority]) == (target, True)
    with pytest.raises(smoke_module.SmokeFailure):
        smoke_module.validate_target(target, [])
    with pytest.raises(smoke_module.SmokeFailure):
        smoke_module.validate_target(target, [authority + "0"])
    assert smoke_module.validate_target(PUBLIC, []) == (PUBLIC, False)


def install_mock_mcp(monkeypatch, pages, *, redirect=None, health=None, ready=None):
    """Real SDK conversation over HTTPX MockTransport, with observed wire requests."""
    observed, clients = [], []
    original_client = httpx.AsyncClient

    async def handler(request):
        body = json.loads(request.content) if request.content else None
        observed.append((request, body))
        if redirect is not None and request.url.path.startswith("/mcp"):
            return httpx.Response(redirect, headers={"location": "https://evil.example/mcp"})
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok"} if health is None else health)
        if request.url.path == "/readyz":
            return httpx.Response(200, json=ready)
        if "authorization" not in request.headers:
            return httpx.Response(401, headers={"www-authenticate": "Bearer"})
        assert request.headers["authorization"] == "Bearer " + MOCK_TOKEN
        method = body["method"]
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "initialize":
            result = {
                "protocolVersion": body["params"]["protocolVersion"],
                "serverInfo": {"name": "MOCK discovery fixture", "version": "1"},
                "capabilities": {"tools": {}},
            }
        elif method == "tools/list":
            cursor = body.get("params", {}).get("cursor")
            names, next_cursor = pages[cursor]
            result = {"tools": [
                {"name": name, "inputSchema": {"type": "object", "properties": {}}}
                for name in names
            ]}
            if next_cursor is not None:
                result["nextCursor"] = next_cursor
        else:
            pytest.fail("Smoke must never execute a business tool or another RPC method")
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    def client(**kwargs):
        clients.append(kwargs)
        return original_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    monkeypatch.setenv("GOOGLE_SEO_SMOKE_KEY", MOCK_TOKEN)
    return observed, clients


def smoke_options(**changes):
    values = dict(url=PUBLIC, allow_http_host=[], check_local_readiness=False,
                  expected_revision=None)
    return argparse.Namespace(**(values | changes))


def assert_discovery_only(observed):
    methods = [body["method"] for _, body in observed if body and "method" in body]
    assert set(methods) <= {"initialize", "notifications/initialized", "tools/list"}
    assert "initialize" in methods
    assert "tools/list" in methods


def assert_failure_leaves(error, expected_type):
    """SDK task groups may wrap failures; every leaf must remain the expected type."""
    if isinstance(error, BaseExceptionGroup):
        for nested in error.exceptions:
            assert_failure_leaves(nested, expected_type)
    else:
        assert isinstance(error, expected_type)


def test_smoke_real_sdk_exhausts_pages_without_business_calls(smoke_module, monkeypatch):
    names = MANIFEST["tools"]
    pages = {None: (names[:11], "page-2"), "page-2": (names[11:25], "page-3"),
             "page-3": (names[25:], None)}
    observed, clients = install_mock_mcp(monkeypatch, pages)
    result = asyncio.run(smoke_module.smoke(smoke_options()))
    assert result == {"status": "PASS", "catalog_count": 35, "revision": "unavailable"}
    assert_discovery_only(observed)
    assert [body.get("params", {}).get("cursor") for _, body in observed
            if body and body.get("method") == "tools/list"] == [None, "page-2", "page-3"]
    assert len(clients) == 2
    for options in clients:
        assert options["trust_env"] is False
        assert options["verify"] is True
        assert options["follow_redirects"] is False
        hooks = options["event_hooks"]["request"]
        for destination in ("https://evil.example/mcp", PUBLIC + "?leak=x",
                            PUBLIC.replace("https", "http"), PUBLIC.replace("/mcp", "/sse")):
            with pytest.raises(smoke_module.SmokeFailure):
                asyncio.run(hooks[0](httpx.Request("POST", destination)))


@pytest.mark.parametrize("catalog_case", ["duplicate", "missing", "unknown", "cycle", "endless"])
def test_smoke_real_sdk_refuses_bad_catalog(smoke_module, monkeypatch, catalog_case):
    names = list(MANIFEST["tools"])
    if catalog_case == "duplicate":
        names[-1] = names[0]
    elif catalog_case == "missing":
        names.pop()
    elif catalog_case == "unknown":
        names[-1] = "get_capabilities"
    if catalog_case == "cycle":
        pages = {None: ([], "again"), "again": ([], "again")}
    elif catalog_case == "endless":
        pages = {None: ([], "0")}
        pages.update({str(i): ([], str(i + 1)) for i in range(36)})
    else:
        pages = {None: (names, None)}
    observed, _ = install_mock_mcp(monkeypatch, pages)
    with pytest.raises((smoke_module.SmokeFailure, ExceptionGroup)) as caught:
        asyncio.run(smoke_module.smoke(smoke_options()))
    assert_failure_leaves(caught.value, smoke_module.SmokeFailure)
    assert_discovery_only(observed)
    assert len(observed) <= 40


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_smoke_never_follows_redirects(smoke_module, monkeypatch, status):
    observed, _ = install_mock_mcp(monkeypatch, {}, redirect=status)
    with pytest.raises(smoke_module.SmokeFailure):
        asyncio.run(smoke_module.smoke(smoke_options()))
    assert len(observed) == 1
    assert str(observed[0][0].url) == PUBLIC


@pytest.mark.parametrize("state", ["pending", "invalid", "available"])
def test_smoke_local_revision_checks_are_explicit(smoke_module, monkeypatch, state):
    ready = {"status": {"pending": "credential-pending", "invalid": "credentials-invalid",
                        "available": "transport-ready"}[state],
             "transport_ready": True, "google_credentials_state": state, "revision": REVISION}
    observed, _ = install_mock_mcp(monkeypatch, {None: (MANIFEST["tools"], None)}, ready=ready)
    options = smoke_options(url="http://127.0.0.1:3006/mcp/", allow_http_host=["127.0.0.1:3006"],
                            check_local_readiness=True, expected_revision=REVISION)
    assert asyncio.run(smoke_module.smoke(options))["revision"] == REVISION
    assert any(request.url.path == "/readyz" for request, _ in observed)
    options.expected_revision = "c" * 40
    with pytest.raises(smoke_module.SmokeFailure):
        asyncio.run(smoke_module.smoke(options))


@pytest.mark.parametrize("case", ["exception", "bad-argument", "bad-revision", "missing-key"])
def test_smoke_cli_failure_is_generic_and_redacted(smoke_module, monkeypatch, capsys, case):
    async def failure(options):
        raise RuntimeError(SENTINEL + MOCK_TOKEN)

    previous_logging = logging.root.manager.disable
    try:
        if case == "exception":
            monkeypatch.setattr(smoke_module, "smoke", failure)
            args = []
        elif case == "bad-argument":
            args = ["--consumer-key", MOCK_TOKEN]
        elif case == "bad-revision":
            args = ["--expected-revision", SENTINEL]
        else:
            monkeypatch.delenv("GOOGLE_SEO_SMOKE_KEY", raising=False)
            args = []
        assert smoke_module.main(args) == 1
        captured = capsys.readouterr()
        assert captured.out == '{"status": "FAIL"}\n'
        assert captured.err == ""
        assert SENTINEL not in captured.out and MOCK_TOKEN not in captured.out
    finally:
        logging.disable(previous_logging)


class MockAuditTerminals:
    """Synthetic installed inventory, SBOM and scanners; NO tools are executed."""

    def __init__(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        # Independently parse committed public pins; do not use the helper parser.
        pins = dict(re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)",
                               (ROOT / "requirements-production.lock").read_text(), re.M))
        self.expected = pins | {project["name"]: project["version"], "pip": "26.2.1"}
        self.thirdparty = {name: version for name, version in self.expected.items()
                           if name != project["name"]}
        self.probe = {
            "python": "3.11 MOCK qualification fixture", "prefix": "/mock/runtime",
            "base_prefix": "/mock/base", "application_file": "/mock/runtime/site/app.py",
            "manifest": copy.deepcopy(MANIFEST),
            "distributions": [{"name": name, "version": version, "direct_url": None,
                               "location": "/mock/runtime/site"}
                              for name, version in self.expected.items()],
        }
        self.inspect = {"installed": [{"metadata": {"name": name, "version": version}}
                                      for name, version in self.expected.items()]}
        self.freeze = "".join(f"{name}=={version}\n" for name, version in self.expected.items())
        self.audit = {"dependencies": [{"name": name, "version": version, "vulns": []}
                                       for name, version in self.thirdparty.items()], "fixes": []}
        self.identity = [IMAGE_ID, "10001:10001", "linux", "amd64", REVISION]
        self.spdx = {"spdxVersion": "SPDX-2.3", "packages": [
            {"name": "libc6", "externalRefs": [{"referenceType": "purl",
                                                "referenceLocator": "pkg:deb/debian/libc6@2"}]},
            {"name": "mcp", "externalRefs": [{"referenceType": "purl",
                                              "referenceLocator": "pkg:pypi/mcp@1.30.0"}]},
        ]}
        self.cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"name": "libc6", "purl": "pkg:deb/debian/libc6@2"},
            {"name": "mcp", "purl": "pkg:pypi/mcp@1.30.0"},
        ]}
        self.scan = {"SchemaVersion": 2, "ArtifactType": "container_image",
                     "Metadata": {"ImageID": IMAGE_ID}, "Results": [
                         {"Class": "os-pkgs", "Type": "debian", "Vulnerabilities": []},
                         {"Class": "lang-pkgs", "Type": "python-pkg", "Vulnerabilities": []},
                     ]}
        now = dt.datetime.now(dt.UTC)
        self.feed = {"Version": 2, "UpdatedAt": (now - dt.timedelta(hours=2)).isoformat(),
                     "DownloadedAt": (now - dt.timedelta(hours=1)).isoformat(),
                     "NextUpdate": (now + dt.timedelta(hours=4)).isoformat()}
        self.calls = []
        self.fail = None
        self.exit_codes = {}
        self.raw_overrides = {}
        self.tool_prefix = "/mock/audit"
        self.version_after = "0.99.0"

    def run(self, command, **kwargs):
        self.calls.append((command, kwargs))
        env = kwargs["env"]
        assert set(env) == {"HOME", "TMPDIR", "PATH", "LANG", "PYTHONUNBUFFERED",
                            "PYTHONDONTWRITEBYTECODE", "PIP_DISABLE_PIP_VERSION_CHECK",
                            "XDG_CACHE_HOME"}
        assert kwargs["cwd"] == Path(env["HOME"])
        assert kwargs["stdin"] == subprocess.DEVNULL and kwargs["check"] is False
        assert kwargs["timeout"] <= 900
        executable = Path(command[0]).name
        if "pip_audit" in command:
            name, value = "python-scan", self.audit
            requested = Path(command[command.index("--requirement") + 1]).read_text()
            assert dict(line.split("==") for line in requested.splitlines()) == self.thirdparty
            destination = Path(command[command.index("--output") + 1])
            destination.write_text(self.raw_overrides.get(name, json.dumps(value)))
            raw = "MOCK scanner completed"
        elif executable == "docker" and command[1] == "version":
            name, value = "docker-version", {"Client": {"Version": "28.0.0"},
                                             "Server": {"Version": "28.0.0"}}
            raw = json.dumps(value)
        elif executable == "docker" and command[1:3] == ["image", "inspect"]:
            name = "identity"
            raw = " ".join(json.dumps(value) for value in self.identity)
        elif executable == "syft" and command[1] == "version":
            name, raw = "syft-version", json.dumps({"application": "syft", "version": "1.99.0"})
        elif executable == "trivy" and command[1] == "version":
            after = any(Path(args[0]).name == "trivy" and args[1] == "image"
                        for args, _ in self.calls)
            name = "trivy-after" if after else "trivy-before"
            raw = json.dumps({"Version": self.version_after if after else "0.99.0",
                              "VulnerabilityDB": self.feed})
        elif executable == "syft" and command[1] == "scan":
            name, raw = "sbom", "MOCK SBOM generated"
            assert command[2] == "docker:" + IMAGE_ID
            for argument in command:
                if argument.startswith("spdx-json="):
                    Path(argument.split("=", 1)[1]).write_text(json.dumps(self.spdx))
                if argument.startswith("cyclonedx-json="):
                    Path(argument.split("=", 1)[1]).write_text(json.dumps(self.cdx))
        elif executable == "trivy" and command[1] == "image":
            name, raw = "image-scan", "MOCK image scan completed"
            assert command[-1] == IMAGE_ID and command[command.index("--image-src") + 1] == "docker"
            destination = Path(command[command.index("--output") + 1])
            destination.write_text(self.raw_overrides.get(name, json.dumps(self.scan)))
        elif "-c" in command:
            if "pip_audit" in command[-1]:
                name = "audit-version"
                raw = json.dumps({"prefix": self.tool_prefix, "python": "3.11 MOCK",
                                  "pip_audit": "2.10.1"})
            else:
                name, raw = "inventory", json.dumps(self.probe)
        elif command[-1] == "check":
            name, raw = "check", "MOCK no broken requirements"
        elif "inspect" in command:
            name, raw = "inspect", json.dumps(self.inspect)
        elif "freeze" in command:
            name, raw = "freeze", self.freeze
        else:
            pytest.fail("Unexpected subprocess terminal: " + repr(command))
        if name == self.fail:
            raise OSError(SENTINEL)
        raw = self.raw_overrides.get(name, raw)
        kwargs["stdout"].write(raw.encode())
        kwargs["stderr"].write(b"MOCK terminal diagnostic\n")
        return SimpleNamespace(returncode=self.exit_codes.get(name, 0))


@pytest.fixture
def audit_terminals(audit_module, monkeypatch):
    fixture = MockAuditTerminals()
    monkeypatch.setattr(audit_module.subprocess, "run", fixture.run)
    monkeypatch.setattr(audit_module.shutil, "which", lambda name, **kwargs: "/mock/bin/" + name)
    return fixture


def invoke_audit(audit_module, tmp_path, capsys, mode="runtime", extra=()):
    output = tmp_path / "MOCK-audit-evidence"
    args = [mode, "--audit-python", "/mock/audit/bin/python", "--output", str(output)]
    args += ["--runtime-python", "/mock/runtime/bin/python"] if mode == "runtime" else [
        "--image", IMAGE_ID]
    code = audit_module.main(args + list(extra))
    captured = capsys.readouterr()
    printed = json.loads(captured.out)
    assert printed == {"status": "clean" if code == 0 else "blocked", "artifacts": str(output)}
    assert captured.err == "" and SENTINEL not in captured.out
    summary = json.loads((output / "summary.json").read_text())
    assert summary["status"] == printed["status"]
    assert summary["image_deployment_or_transport_smoke"] == "not asserted"
    assert summary["started_at"] <= summary["finished_at"]
    for row in summary["commands"]:
        assert row["started_at"] <= row["finished_at"]
        assert (output / row["stdout"]).exists() and (output / row["stderr"]).exists()
    return code, summary, output


@pytest.mark.parametrize("mode", ["runtime", "image"])
def test_audit_coherent_mock_fixture_retains_evidence(
    audit_module, audit_terminals, tmp_path, capsys, mode
):
    code, summary, output = invoke_audit(audit_module, tmp_path, capsys, mode)
    assert code == 0
    assert summary["runtime_distributions"] == 76 and summary["manifest_tools"] == 35
    assert summary["twisted_chain"] == "absent"
    assert summary["python_audit"]["distributions"] == 75
    assert summary["python_audit"]["findings"] == 0  # MOCK fixture, not a real scan result.
    assert json.loads((output / "runtime-inventory.json").read_text()) == audit_terminals.expected
    records = list(output.glob("*.command.json"))
    assert len(records) == len(summary["commands"])
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in records)
    if mode == "image":
        assert summary["image"]["id"] == IMAGE_ID
        runs = [args for args, _ in audit_terminals.calls if args[1] == "run"]
        assert len(runs) == 4
        for command in runs:
            assert "--network=none" in command and "--read-only" in command
            assert "--cap-drop=ALL" in command and "--security-opt=no-new-privileges" in command
            assert "--pull=never" in command and "10001:10001" in command
            assert "--memory=512m" in command and "--cpus=1" in command
            assert "--pids-limit=128" in command and IMAGE_ID in command
            assert not any(arg in command for arg in ("--volume", "-v", "--privileged"))
        inspect = next(
            args for args, _ in audit_terminals.calls if args[1:3] == ["image", "inspect"]
        )
        assert "Config.Env" not in " ".join(inspect)


@pytest.mark.parametrize("case,reason", [
    ("version", "inventory_mismatch"), ("dev-package", "inventory_mismatch"),
    ("inspect-drift", "inventory_mismatch"), ("duplicate", "invalid_inventory"),
    ("editable", "editable_or_source_install"), ("source-directory", "editable_or_source_install"),
    ("freeze-editable", "editable_install"), ("application-path", "application_outside_runtime"),
    ("distribution-path", "distribution_outside_runtime"),
    ("global-prefix", "runtime_not_isolated"),
    ("audit-prefix", "audit_tooling_in_runtime"), ("manifest", "manifest_mismatch"),
])
def test_audit_runtime_drift_is_blocked(
    audit_module, audit_terminals, tmp_path, capsys, case, reason
):
    rows = audit_terminals.probe["distributions"]
    if case == "version":
        rows[0]["version"] = "999"
    elif case == "dev-package":
        rows.append({"name": "pytest", "version": "99"})
    elif case == "inspect-drift":
        audit_terminals.inspect["installed"].pop()
    elif case == "duplicate":
        rows.append(copy.deepcopy(rows[0]))
    elif case == "editable":
        rows[0]["direct_url"] = {"dir_info": {"editable": True}}
    elif case == "source-directory":
        rows[0]["direct_url"] = {"dir_info": {}}
    elif case == "freeze-editable":
        audit_terminals.freeze += "-e /mock/source\n"
    elif case == "application-path":
        audit_terminals.probe["application_file"] = "/mock/source/app.py"
    elif case == "distribution-path":
        rows[0]["location"] = "/mock/global/site"
    elif case == "global-prefix":
        audit_terminals.probe["base_prefix"] = audit_terminals.probe["prefix"]
    elif case == "audit-prefix":
        audit_terminals.tool_prefix = audit_terminals.probe["prefix"]
    elif case == "manifest":
        audit_terminals.probe["manifest"]["tools"].pop()
    code, summary, _ = invoke_audit(audit_module, tmp_path, capsys)
    assert code == 1 and summary["reason"] == reason
    assert not any("pip_audit" in args for args, _ in audit_terminals.calls)


@pytest.mark.parametrize("lock", [
    "mcp>=1\n", "-r other.txt\n", "--index-url https://evil.example\n",
    "mcp @ https://evil.example/mcp.whl\n", "mcp==1 --hash=sha256:bad\n",
    "", "# no dependencies\n", "mcp==1 \\\n", "pytest==1 --hash=sha256:" + "0" * 64,
    ("mcp==1 --hash=sha256:" + "0" * 64 + "\n") * 2,
])
def test_audit_invalid_lock_blocks_before_any_tool(
    audit_module, audit_terminals, tmp_path, capsys, lock
):
    path = tmp_path / "invalid.lock"
    path.write_text(lock)
    code, summary, _ = invoke_audit(audit_module, tmp_path, capsys, extra=["--lock", str(path)])
    assert code == 1 and summary["reason"] == "invalid_lock"
    assert audit_terminals.calls == []


@pytest.mark.parametrize("case,reason", [
    ("unavailable", "runtime-pip-audit_failed"), ("nonzero", "python_scanner_nonzero"),
    ("error-exit", "runtime-pip-audit_failed"), ("malformed", "invalid_json"),
    ("missing", "scanner_inventory_mismatch"), ("unknown", "scanner_inventory_mismatch"),
    ("version", "scanner_inventory_mismatch"), ("skip", "scanner_skipped_dependency"),
    ("missing-vulns", "scanner_skipped_dependency"),
    ("findings", "python_vulnerability_findings"),
    ("unknown-schema", "invalid_or_unavailable_evidence"),
])
def test_audit_python_scanner_errors_never_clean(
    audit_module, audit_terminals, tmp_path, capsys, case, reason
):
    dependencies = audit_terminals.audit["dependencies"]
    if case == "unavailable":
        audit_terminals.fail = "python-scan"
    elif case == "nonzero":
        audit_terminals.exit_codes["python-scan"] = 1
    elif case == "error-exit":
        audit_terminals.exit_codes["python-scan"] = 2
    elif case == "malformed":
        audit_terminals.raw_overrides["python-scan"] = SENTINEL
    elif case == "missing":
        dependencies.pop()
    elif case == "unknown":
        dependencies.append({"name": "unexpected", "version": "1", "vulns": []})
    elif case == "version":
        dependencies[0]["version"] = "999"
    elif case == "skip":
        dependencies[0]["skip_reason"] = SENTINEL
    elif case == "missing-vulns":
        del dependencies[0]["vulns"]
    elif case == "findings":
        dependencies[0]["vulns"] = [{"id": "MOCK-CVE-fixture"}]
    elif case == "unknown-schema":
        audit_terminals.audit = {"not_a_report": True}
    code, summary, _ = invoke_audit(audit_module, tmp_path, capsys)
    assert code == 1 and summary["reason"] == reason


@pytest.mark.parametrize("image", ["latest", "repo:latest", "sha256:bad", "sha256:" + "A" * 64,
                                   "repo@sha512:" + "a" * 64, IMAGE_ID + ";bad"])
def test_audit_requires_immutable_image(audit_module, audit_terminals, tmp_path, capsys, image):
    code, summary, _ = invoke_audit(audit_module, tmp_path, capsys, "image", ["--image", image])
    assert code == 1 and summary["reason"] == "immutable_image_required"
    assert len(audit_terminals.calls) == 2  # Only isolated audit-tool identity/freeze.


@pytest.mark.parametrize("missing", ["docker", "syft", "trivy"])
def test_audit_missing_image_tool_is_blocked(
    audit_module, audit_terminals, monkeypatch, tmp_path, capsys, missing
):
    monkeypatch.setattr(audit_module.shutil, "which",
                        lambda name, **kwargs: None if name == missing else "/mock/bin/" + name)
    code, summary, _ = invoke_audit(audit_module, tmp_path, capsys, "image")
    assert code == 1 and summary["reason"] == missing + "_unavailable"
    assert len(audit_terminals.calls) == 2


@pytest.mark.parametrize("case,reason", [
    ("identity-user", "unqualified_image_identity"),
    ("identity-revision", "unqualified_image_identity"),
    ("tool-version", "unknown_tool_version"), ("sbom-schema", "unknown_image_sbom_schema"),
    ("sbom-empty", "empty_image_sbom"), ("sbom-python-missing", "incomplete_image_sbom"),
    ("sbom-twisted", "forbidden_package_in_image"),
    ("sbom-hidden-purl", "forbidden_package_in_image"), ("sbom-build", "build_tool_in_image"),
    ("scanner-unavailable", "image-vulnerability-scan_failed"),
    ("scanner-nonzero", "image_scanner_nonzero"),
    ("scanner-error", "image-vulnerability-scan_failed"),
    ("scanner-malformed", "invalid_json"), ("scanner-schema", "unknown_image_scan_schema"),
    ("scanner-identity", "image_scan_identity_mismatch"),
    ("scanner-partial", "incomplete_image_scan"), ("scanner-type", "unknown_image_scan_coverage"),
    ("scanner-vulns-shape", "invalid_image_scan_findings"),
    ("scanner-findings", "image_vulnerability_findings"),
    ("scanner-changed", "scanner_version_changed"),
    ("feed-missing", "missing_scanner_feed_metadata"), ("feed-expired", "stale_scanner_feed"),
    ("feed-future", "stale_scanner_feed"), ("feed-malformed", "invalid_or_unavailable_evidence"),
])
def test_audit_image_mock_failures_never_clean(
    audit_module, audit_terminals, tmp_path, capsys, case, reason
):
    mock = audit_terminals
    if case == "identity-user":
        mock.identity[1] = "0:0"
    elif case == "identity-revision":
        mock.identity[4] = "unknown"
    elif case == "tool-version":
        mock.raw_overrides["syft-version"] = json.dumps(
            {"application": "syft", "version": "unknown"}
        )
    elif case == "sbom-schema":
        mock.spdx["spdxVersion"] = "SPDX-UNKNOWN"
    elif case == "sbom-empty":
        mock.cdx["components"] = []
    elif case == "sbom-python-missing":
        mock.cdx["components"].pop()
    elif case == "sbom-twisted":
        mock.cdx["components"].append({"name": "python3-twisted"})
    elif case == "sbom-hidden-purl":
        mock.cdx["components"].append({"name": "innocent-label", "purl": "pkg:pypi/Twisted@26"})
    elif case == "sbom-build":
        mock.cdx["components"].append({"name": "compiler", "purl": "pkg:deb/debian/gcc-12@12"})
    elif case == "scanner-unavailable":
        mock.fail = "image-scan"
    elif case == "scanner-nonzero":
        mock.exit_codes["image-scan"] = 1
    elif case == "scanner-error":
        mock.exit_codes["image-scan"] = 2
    elif case == "scanner-malformed":
        mock.raw_overrides["image-scan"] = SENTINEL
    elif case == "scanner-schema":
        mock.scan["SchemaVersion"] = 99
    elif case == "scanner-identity":
        mock.scan["Metadata"]["ImageID"] = "sha256:" + "f" * 64
    elif case == "scanner-partial":
        mock.scan["Results"].pop()
    elif case == "scanner-type":
        mock.scan["Results"][1]["Type"] = "unknown"
    elif case == "scanner-vulns-shape":
        mock.scan["Results"][0]["Vulnerabilities"] = {}
    elif case == "scanner-findings":
        mock.scan["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "MOCK-CVE-fixture"}]
    elif case == "scanner-changed":
        mock.version_after = "0.99.1"
    elif case == "feed-missing":
        del mock.feed["DownloadedAt"]
    elif case == "feed-expired":
        mock.feed["NextUpdate"] = (dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)).isoformat()
    elif case == "feed-future":
        mock.feed["UpdatedAt"] = (dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)).isoformat()
    elif case == "feed-malformed":
        mock.feed["NextUpdate"] = SENTINEL
    code, summary, _ = invoke_audit(audit_module, tmp_path, capsys, "image")
    assert code == 1 and summary["reason"] == reason
    assert not any(args[1] == "run" for args, _ in mock.calls)


def test_audit_refuses_existing_evidence_without_mutation(audit_module, tmp_path, capsys):
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "summary.json"
    marker.write_bytes(b"previous immutable evidence")
    assert audit_module.main(["runtime", "--runtime-python", "/not-executed",
                              "--audit-python", "/not-executed", "--output", str(output)]) == 1
    assert marker.read_bytes() == b"previous immutable evidence"
    assert sorted(path.name for path in output.iterdir()) == ["summary.json"]
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
