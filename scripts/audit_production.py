#!/usr/bin/env python3
"""Fail-closed installed-runtime/image audit. Evidence is private; no tool installs.

A clean runtime result is not an image or deployment acceptance. Advisory scans
cover third-party distributions; the owned application is reviewed/tested source.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_PIP = "26.2.1"  # Separately pinned/hash-checked in Dockerfile.
# Independent hosted admission: frozen historical 35 plus the approved eleven Bing reads.
EXPECTED_TOOLS = frozenset({
    "cross_gsc_to_ga4_journey", "cross_landing_page_full_diagnosis",
    "cross_multi_property_comparison", "cross_opportunity_matrix",
    "cross_seo_to_revenue_attribution", "cross_traffic_health_check",
    "ga4_anomalies", "ga4_channel_attribution", "ga4_cohort_retention",
    "ga4_content_decay", "ga4_conversion_funnel", "ga4_estimate_query_size",
    "ga4_event_volume_comparison", "ga4_get_property_details", "ga4_landing_page_health",
    "ga4_list_properties", "ga4_list_schema_categories", "ga4_query", "ga4_search_schema",
    "ga4_traffic_drops_by_channel", "gsc_alerts", "gsc_cannibalization", "gsc_content_decay",
    "gsc_ctr_opportunities", "gsc_inspect_url", "gsc_list_sitemaps", "gsc_list_sites",
    "gsc_quick_wins", "gsc_search_analytics", "gsc_site_snapshot", "gsc_traffic_drops",
    "serp_aio_monitor", "serp_check", "serp_competitor_intersect", "serp_paa_extractor",
    "bing_list_sites", "bing_rank_traffic_stats", "bing_query_stats", "bing_page_stats",
    "bing_page_query_stats", "bing_query_page_stats", "bing_crawl_stats", "bing_crawl_issues",
    "bing_url_info", "bing_list_sitemaps", "bing_sitemap_details",
})
FORBIDDEN = {
    "advertools",
    "scrapy",
    "twisted",
    "playwright",
    "scipy",
    "statsmodels",
    "setuptools",
    "wheel",
    "packaging",
    "build",
    "pip-tools",
    "pip-audit",
    "pytest",
    "pytest-mock",
    "ruff",
    "fastmcp",
}
PROBE = r"""
import importlib.metadata as m, importlib.resources as r, json, sys
from pathlib import Path
import google_seo_mcp
rows=[]
for d in m.distributions():
    direct=d.read_text('direct_url.json')
    rows.append({'name':d.metadata['Name'],'version':d.version,
                 'direct_url':json.loads(direct) if direct else None,
                 'location':str(d.locate_file(''))})
print(json.dumps({'python':sys.version,'prefix':sys.prefix,'base_prefix':sys.base_prefix,
 'application_file':google_seo_mcp.__file__,'distributions':rows,
 'manifest':json.loads(r.files('google_seo_mcp').joinpath('production_tools.json').read_text())}))
"""
TOOL_PROBE = (
    "import sys,importlib.metadata as m,json; "
    "print(json.dumps({'prefix':sys.prefix,'python':sys.version,"
    "'pip_audit':m.version('pip-audit')}))"
)


class AuditBlocked(Exception):
    """Only fixed diagnostic codes escape to summary/stdout."""


def utc() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


class Evidence:
    def __init__(self, directory: Path):
        # Refuse even an empty existing directory: previous evidence is immutable.
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.directory = directory.resolve()
        self.home = self.directory / "empty-home"
        self.home.mkdir(mode=0o700)
        self.commands: list[dict] = []
        self.env = {
            "HOME": str(self.home),
            "TMPDIR": str(self.home),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "XDG_CACHE_HOME": str(self.home / "cache"),
        }

    def run(self, name: str, command: list[str], *, allowed=(0,), timeout=900) -> str:
        row = {"name": name, "command": command, "started_at": utc()}
        prefix = self.directory / f"{len(self.commands) + 1:02d}-{name}"
        output, error = prefix.with_suffix(".stdout"), prefix.with_suffix(".stderr")
        self.commands.append(row)
        try:
            with output.open("xb") as stdout, error.open("xb") as stderr:
                output.chmod(0o600)
                error.chmod(0o600)
                completed = subprocess.run(
                    command,
                    cwd=self.home,
                    env=self.env,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=timeout,
                    check=False,
                )
            row["exit_code"] = completed.returncode
        except (OSError, subprocess.TimeoutExpired):
            row["exit_code"] = None
            row["failure"] = "unavailable_or_timeout"
        finally:
            row["finished_at"] = utc()
            row["stdout"] = output.name
            row["stderr"] = error.name
            write_json(prefix.with_suffix(".command.json"), row)
        if row["exit_code"] not in allowed:
            raise AuditBlocked(f"{name}_failed")
        return output.read_text()


def parse_json(raw: str) -> object:
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        raise AuditBlocked("invalid_json") from None


def locked_versions(path: Path) -> dict[str, str]:
    # Accept only the committed exact-pin/hash grammar, never pip directives,
    # URLs, editables, markers, includes or an implicitly resolved dependency.
    result: dict[str, str] = {}
    logical = ""
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        logical += " " + line.removesuffix("\\").strip()
        if line.endswith("\\"):
            continue
        match = re.fullmatch(
            r"\s*([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)"
            r"((?:\s+--hash=sha256:[a-f0-9]{64})+)\s*",
            logical,
        )
        if not match or canonical(match[1]) in result:
            raise AuditBlocked("invalid_lock")
        result[canonical(match[1])] = match[2]
        logical = ""
    if logical or not result or FORBIDDEN.intersection(result):
        raise AuditBlocked("invalid_lock")
    return result


def versions(rows: list[dict]) -> dict[str, str]:
    result = {}
    for row in rows:
        name, version = canonical(row["name"]), row["version"]
        if name in result or not isinstance(version, str) or not version:
            raise AuditBlocked("invalid_inventory")
        result[name] = version
    return result


def validate_inventory(probe: dict, inspect: dict, freeze: str, lock: dict) -> dict:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    application = canonical(project["name"])
    expected = {**lock, application: project["version"], "pip": BOOTSTRAP_PIP}
    actual = versions(probe["distributions"])
    inspected = versions(
        [
            {"name": row["metadata"]["name"], "version": row["metadata"]["version"]}
            for row in inspect["installed"]
        ]
    )
    if actual != expected or inspected != actual or FORBIDDEN.intersection(actual):
        raise AuditBlocked("inventory_mismatch")
    if probe["prefix"] == probe["base_prefix"]:
        raise AuditBlocked("runtime_not_isolated")
    prefix = Path(probe["prefix"])
    if not Path(probe["application_file"]).is_relative_to(prefix):
        raise AuditBlocked("application_outside_runtime")
    for row in probe["distributions"]:
        if not Path(row["location"]).is_relative_to(prefix):
            raise AuditBlocked("distribution_outside_runtime")
        direct = row.get("direct_url")
        if direct and (direct.get("dir_info", {}).get("editable") or "dir_info" in direct):
            raise AuditBlocked("editable_or_source_install")
    # freeze can represent a noneditable wheel as `name @ file:///...whl#...`.
    if "-e " in freeze or "__editable__" in freeze:
        raise AuditBlocked("editable_install")
    manifest = parse_json((ROOT / "src/google_seo_mcp/production_tools.json").read_text())
    if (
        probe["manifest"] != manifest or manifest["version"] != 1
        or set(manifest["tools"]) != EXPECTED_TOOLS
        or len(set(manifest["tools"])) != len(manifest["tools"])
    ):
        raise AuditBlocked("manifest_mismatch")
    return actual


def audit_python(evidence: Evidence, python: str, inventory: dict, label: str) -> dict:
    requirements = evidence.directory / f"{label}-requirements.txt"
    requirements.write_text(
        "".join(f"{name}=={version}\n" for name, version in sorted(inventory.items()))
    )
    requirements.chmod(0o600)
    destination = evidence.directory / f"{label}-pip-audit.json"
    started = utc()
    evidence.run(
        label + "-pip-audit",
        [
            python,
            "-I",
            "-m",
            "pip_audit",
            "--requirement",
            str(requirements),
            "--no-deps",
            "--disable-pip",
            "--vulnerability-service",
            "pypi",
            "--progress-spinner",
            "off",
            "--format",
            "json",
            "--output",
            str(destination),
        ],
        allowed=(0, 1),
    )
    report = parse_json(destination.read_text())
    dependencies = report["dependencies"]
    returned = versions(dependencies)
    if returned != inventory or report.get("fixes") not in ([], None):
        raise AuditBlocked("scanner_inventory_mismatch")
    finding_count = 0
    for row in dependencies:
        if "skip_reason" in row or not isinstance(row.get("vulns"), list):
            raise AuditBlocked("scanner_skipped_dependency")
        finding_count += len(row["vulns"])
    metadata = {
        "source": "PyPI vulnerability API",
        "queried_at": started,
        "completed_at": utc(),
        "published_feed_timestamp": None,
        "feed_timestamp_note": "PyPI API does not publish a global feed timestamp",
        "distributions": len(returned),
        "findings": finding_count,
    }
    write_json(evidence.directory / f"{label}-feed.json", metadata)
    if finding_count:
        raise AuditBlocked("python_vulnerability_findings")
    # pip-audit can return nonzero with an otherwise parseable partial report.
    if evidence.commands[-1]["exit_code"] != 0:
        raise AuditBlocked("python_scanner_nonzero")
    return metadata


def runtime_commands(evidence: Evidence, prefix: list[str]) -> tuple[dict, dict, str]:
    evidence.run("runtime-pip-check", prefix + ["-I", "-m", "pip", "check"])
    freeze = evidence.run("runtime-pip-freeze", prefix + ["-I", "-m", "pip", "freeze", "--all"])
    inspect = parse_json(
        evidence.run("runtime-pip-inspect", prefix + ["-I", "-m", "pip", "inspect", "--local"])
    )
    probe = parse_json(evidence.run("runtime-inventory", prefix + ["-I", "-c", PROBE]))
    return probe, inspect, freeze


def required_tool(name: str) -> str:
    found = shutil.which(name, path="/usr/local/bin:/usr/bin:/bin")
    if not found:
        raise AuditBlocked(f"{name}_unavailable")
    return found


def explicit_tool_path(name: str, path: str | Path) -> str:
    """Resolve an explicit executable before Evidence.run changes child cwd."""
    try:
        resolved = Path(path).resolve(strict=True)
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return str(resolved)
    except (OSError, RuntimeError, ValueError):
        pass
    raise AuditBlocked(f"{name}_unavailable")


def image_commands(
    evidence: Evidence, image: str, tool_paths: dict[str, str | Path] | None = None
) -> tuple[list[str], dict]:
    if not re.fullmatch(
        r"(?:sha256:[a-f0-9]{64}|[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64})", image
    ):
        raise AuditBlocked("immutable_image_required")
    tool_paths = tool_paths if tool_paths is not None else {}
    docker, syft, trivy = (
        explicit_tool_path(name, tool_paths[name]) if name in tool_paths else required_tool(name)
        for name in ("docker", "syft", "trivy")
    )
    docker_version = parse_json(
        evidence.run("docker-version", [docker, "version", "--format", "{{json .}}"])
    )
    syft_version = parse_json(evidence.run("syft-version", [syft, "version", "-o", "json"]))
    trivy_version = parse_json(
        evidence.run("trivy-version-before", [trivy, "version", "--format", "json"])
    )
    for version in (
        docker_version.get("Client", {}).get("Version"),
        docker_version.get("Server", {}).get("Version"),
        syft_version.get("version"),
        trivy_version.get("Version"),
    ):
        if not isinstance(version, str) or not re.fullmatch(
            r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version
        ):
            raise AuditBlocked("unknown_tool_version")
    if syft_version.get("application") != "syft":
        raise AuditBlocked("unknown_sbom_tool")
    projection = (
        "{{json .Id}} {{json .Config.User}} {{json .Os}} {{json .Architecture}} "
        '{{json (index .Config.Labels "org.opencontainers.image.revision")}}'
    )
    raw = evidence.run(
        "image-identity", [docker, "image", "inspect", "--format", projection, image]
    )
    # Whitespace-safe JSON values, never Config.Env or complete inspect.
    decoder, cursor, values = json.JSONDecoder(), 0, []
    while cursor < len(raw.strip()):
        value, end = decoder.raw_decode(raw[cursor:].lstrip())
        cursor = len(raw) - len(raw[cursor:].lstrip()) + end
        values.append(value)
    if len(values) != 5 or not re.fullmatch(r"sha256:[a-f0-9]{64}", values[0]):
        raise AuditBlocked("invalid_image_identity")
    if values[1:4] != ["10001:10001", "linux", "amd64"] or not re.fullmatch(
        r"[a-f0-9]{40}", values[4] or ""
    ):
        raise AuditBlocked("unqualified_image_identity")
    identity = dict(zip(("id", "user", "os", "architecture", "revision"), values, strict=True))
    write_json(evidence.directory / "image-identity.json", identity)
    # All following operations address the projected local content ID, never a
    # tag re-resolved by a scanner. No credentials, host socket or HOME are mounted.
    image_id = values[0]
    evidence.run(
        "image-sbom",
        [
            syft,
            "scan",
            "docker:" + image_id,
            "-o",
            "spdx-json=" + str(evidence.directory / "image.spdx.json"),
            "-o",
            "cyclonedx-json=" + str(evidence.directory / "image.cdx.json"),
        ],
    )
    spdx = parse_json((evidence.directory / "image.spdx.json").read_text())
    cdx = parse_json((evidence.directory / "image.cdx.json").read_text())
    if spdx.get("spdxVersion") not in ("SPDX-2.2", "SPDX-2.3") or (
        cdx.get("bomFormat") != "CycloneDX"
        or cdx.get("specVersion") not in ("1.4", "1.5", "1.6", "1.7")
    ):
        raise AuditBlocked("unknown_image_sbom_schema")
    if not spdx.get("packages") or not cdx.get("components"):
        raise AuditBlocked("empty_image_sbom")
    for row in spdx["packages"] + cdx["components"]:
        package = canonical(row.get("name", ""))
        if package in FORBIDDEN or package.removeprefix("python3-") in FORBIDDEN:
            raise AuditBlocked("forbidden_package_in_image")
    spdx_purls = {
        ref.get("referenceLocator", "")
        for package in spdx["packages"]
        for ref in package.get("externalRefs", [])
        if ref.get("referenceType") == "purl"
    }
    cdx_purls = {component.get("purl", "") for component in cdx["components"]}
    for purls in (spdx_purls, cdx_purls):
        if not all(
            any(purl.startswith(kind) for purl in purls) for kind in ("pkg:deb/", "pkg:pypi/")
        ):
            raise AuditBlocked("incomplete_image_sbom")
        for purl in purls:
            package = canonical(unquote(purl.split("@", 1)[0].rsplit("/", 1)[-1]))
            if purl.startswith("pkg:pypi/") and package in FORBIDDEN:
                raise AuditBlocked("forbidden_package_in_image")
            if purl.startswith("pkg:deb/") and re.fullmatch(
                r"(?:gcc|g\+\+|cpp)(?:-\d+)?|make|build-essential|.+-dev",
                package,
            ):
                raise AuditBlocked("build_tool_in_image")
    scan = evidence.directory / "image-trivy.json"
    evidence.run(
        "image-vulnerability-scan",
        [
            trivy,
            "image",
            "--image-src",
            "docker",
            "--scanners",
            "vuln",
            "--severity",
            "HIGH,CRITICAL",
            "--exit-code",
            "1",
            "--format",
            "json",
            "--output",
            str(scan),
            image_id,
        ],
        allowed=(0, 1),
    )
    report = parse_json(scan.read_text())
    results = report.get("Results")
    if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image":
        raise AuditBlocked("unknown_image_scan_schema")
    if report.get("Metadata", {}).get("ImageID") != image_id:
        raise AuditBlocked("image_scan_identity_mismatch")
    if (
        not isinstance(results, list)
        or not results
        or not any(row.get("Class") == "os-pkgs" for row in results)
        or not any(row.get("Class") == "lang-pkgs" for row in results)
    ):
        raise AuditBlocked("incomplete_image_scan")
    if not any(row.get("Type") == "debian" for row in results) or not any(
        row.get("Type") == "python-pkg" for row in results
    ):
        raise AuditBlocked("unknown_image_scan_coverage")
    if any(
        row.get("Vulnerabilities") is not None and not isinstance(row["Vulnerabilities"], list)
        for row in results
    ):
        raise AuditBlocked("invalid_image_scan_findings")
    if any(row.get("Vulnerabilities") for row in results):
        raise AuditBlocked("image_vulnerability_findings")
    if evidence.commands[-1]["exit_code"] != 0:
        raise AuditBlocked("image_scanner_nonzero")
    version = parse_json(
        evidence.run("trivy-version-after", [trivy, "version", "--format", "json"])
    )
    if version.get("Version") != trivy_version.get("Version"):
        raise AuditBlocked("scanner_version_changed")
    database = version.get("VulnerabilityDB")
    if (
        not isinstance(database, dict)
        or database.get("Version") != 2
        or not database.get("UpdatedAt")
        or not database.get("DownloadedAt")
        or not database.get("NextUpdate")
    ):
        raise AuditBlocked("missing_scanner_feed_metadata")
    expiry = dt.datetime.fromisoformat(database["NextUpdate"].replace("Z", "+00:00"))
    updated = dt.datetime.fromisoformat(database["UpdatedAt"].replace("Z", "+00:00"))
    downloaded = dt.datetime.fromisoformat(database["DownloadedAt"].replace("Z", "+00:00"))
    now = dt.datetime.now(dt.UTC)
    if updated > now or downloaded > now or updated >= expiry or expiry <= now:
        raise AuditBlocked("stale_scanner_feed")
    write_json(evidence.directory / "image-feed.json", database)
    prefix = [
        docker,
        "run",
        "--rm",
        "--pull=never",
        "--read-only",
        "--network=none",
        "--user",
        "10001:10001",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory=512m",
        "--memory-swap=512m",
        "--cpus=1",
        "--pids-limit=128",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=64m",
        "--entrypoint",
        "/opt/venv/bin/python",
        image_id,
    ]
    return prefix, identity


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for mode in ("runtime", "image"):
        subparser = subparsers.add_parser(mode, allow_abbrev=mode != "image")
        subparser.add_argument(
            "--runtime-python" if mode == "runtime" else "--image", required=True
        )
        subparser.add_argument("--audit-python", required=True)
        subparser.add_argument("--output", required=True, type=Path)
        subparser.add_argument("--lock", type=Path, default=ROOT / "requirements-production.lock")
        if mode == "image":
            for name in ("docker", "syft", "trivy"):
                subparser.add_argument(f"--{name}-path", type=Path)
    args = parser.parse_args(argv)
    evidence = None
    summary = {
        "status": "blocked",
        "mode": args.mode,
        "started_at": utc(),
        "image_deployment_or_transport_smoke": "not asserted",
    }
    try:
        evidence = Evidence(args.output)
        lock = locked_versions(args.lock)
        summary["lock_sha256"] = hashlib.sha256(args.lock.read_bytes()).hexdigest()
        audit_python_path = os.path.abspath(args.audit_python)
        tooling = parse_json(
            evidence.run("audit-tool-version", [audit_python_path, "-I", "-c", TOOL_PROBE])
        )
        evidence.run("audit-tool-freeze", [audit_python_path, "-I", "-m", "pip", "freeze", "--all"])
        summary["audit_tool"] = tooling
        if args.mode == "image":
            tool_paths = {
                name: path
                for name in ("docker", "syft", "trivy")
                if (path := getattr(args, f"{name}_path")) is not None
            }
            prefix, summary["image"] = image_commands(evidence, args.image, tool_paths)
        else:
            prefix = [os.path.abspath(args.runtime_python)]
        probe, inspect, freeze = runtime_commands(evidence, prefix)
        if probe["prefix"] == tooling["prefix"]:
            raise AuditBlocked("audit_tooling_in_runtime")
        inventory = validate_inventory(probe, inspect, freeze, lock)
        write_json(evidence.directory / "runtime-inventory.json", inventory)
        summary["runtime_python"] = probe["python"]
        summary["runtime_distributions"] = len(inventory)
        summary["manifest_tools"] = len(probe["manifest"]["tools"])
        summary["twisted_chain"] = "absent"
        thirdparty = {
            name: version for name, version in inventory.items() if name != "google-seo-mcp"
        }
        summary["owned_application"] = {
            "name": "google-seo-mcp",
            "version": inventory["google-seo-mcp"],
            "advisory_coverage": "owned source reviewed/tested separately; not a PyPI dependency",
        }
        summary["python_audit"] = audit_python(evidence, audit_python_path, thirdparty, "runtime")
        summary["status"] = "clean"
    except AuditBlocked as exc:
        summary["reason"] = str(exc)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        summary["reason"] = "invalid_or_unavailable_evidence"
    finally:
        summary["finished_at"] = utc()
        if evidence:
            summary["commands"] = evidence.commands
            write_json(evidence.directory / "summary.json", summary)
    print(json.dumps({"status": summary["status"], "artifacts": str(args.output)}))
    return 0 if summary["status"] == "clean" else 1


if __name__ == "__main__":
    sys.exit(main())
