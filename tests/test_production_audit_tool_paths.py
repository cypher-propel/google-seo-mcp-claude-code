"""Portable executable-path regressions using controlled MOCK scanner terminals.

No image engine, advisory service, provider, or actual scanner is invoked here.
The fixture executables independently record their received argv and environment.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import shutil
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:" + "a" * 64
REVISION = "b" * 40
TOOLS = ("docker", "syft", "trivy")


@pytest.fixture
def audit():
    spec = importlib.util.spec_from_file_location(
        "audit_path_tests", ROOT / "scripts/audit_production.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def mock_tools(tmp_path):
    """Execute only these Python fixtures, never an installed engine/scanner."""
    observed = tmp_path / "MOCK-observed.jsonl"
    now = dt.datetime.now(dt.UTC)
    feed = {
        "Version": 2,
        "UpdatedAt": (now - dt.timedelta(hours=2)).isoformat(),
        "DownloadedAt": (now - dt.timedelta(hours=1)).isoformat(),
        "NextUpdate": (now + dt.timedelta(hours=4)).isoformat(),
    }
    paths = {}
    for tool in TOOLS:
        # Spaces and shell metacharacters must remain literal filename bytes.
        path = tmp_path / f"MOCK {tool}; literal $tool"
        path.write_text(
            f"#!{sys.executable}\n"
            f"tool = {tool!r}\nobserved = {str(observed)!r}\n"
            f"image = {IMAGE!r}\nrevision = {REVISION!r}\nfeed = {feed!r}\n"
            + textwrap.dedent(r"""
                import json, os, sys
                from pathlib import Path
                with Path(observed).open('a') as output:
                    output.write(json.dumps({
                        'tool': tool, 'argv': sys.argv, 'env': dict(os.environ),
                        'cwd': os.getcwd(), 'home_files': list(os.listdir(os.environ['HOME']))
                    }) + '\n')
                args = sys.argv[1:]
                if tool == 'docker':
                    if args[0] == 'version':
                        print(json.dumps({'Client': {'Version': '28.0.0'},
                                          'Server': {'Version': '28.0.0'}}))
                    else:
                        identity = [image, '10001:10001', 'linux', 'amd64', revision]
                        print(' '.join(json.dumps(x) for x in identity))
                elif tool == 'syft':
                    if args[0] == 'version':
                        print(json.dumps({'application': 'syft', 'version': '1.54.1'}))
                    else:
                        packages = [('libc6', 'pkg:deb/debian/libc6@2'),
                                    ('mcp', 'pkg:pypi/mcp@1.30.0')]
                        for arg in args:
                            if arg.startswith('spdx-json='):
                                value = {'spdxVersion': 'SPDX-2.3', 'packages': [
                                    {'name': name, 'externalRefs': [
                                        {'referenceType': 'purl', 'referenceLocator': purl}]}
                                    for name, purl in packages]}
                                Path(arg.split('=', 1)[1]).write_text(json.dumps(value))
                            elif arg.startswith('cyclonedx-json='):
                                value = {'bomFormat': 'CycloneDX', 'specVersion': '1.6',
                                         'components': [{'name': name, 'purl': purl}
                                                        for name, purl in packages]}
                                Path(arg.split('=', 1)[1]).write_text(json.dumps(value))
                else:
                    if args[0] == 'version':
                        print(json.dumps({'Version': '0.76.0', 'VulnerabilityDB': feed}))
                    else:
                        value = {'SchemaVersion': 2, 'ArtifactType': 'container_image',
                                 'Metadata': {'ImageID': image}, 'Results': [
                                     {'Class': 'os-pkgs', 'Type': 'debian',
                                      'Vulnerabilities': []},
                                     {'Class': 'lang-pkgs', 'Type': 'python-pkg',
                                      'Vulnerabilities': []}]}
                        Path(args[args.index('--output') + 1]).write_text(json.dumps(value))
                """)
        )
        path.chmod(0o700)
        paths[tool] = path
    return paths, observed


@pytest.mark.parametrize("path_kind", ["absolute", "relative", "symlink"])
def test_explicit_paths_reach_real_mock_terminals_with_exact_provenance(
    audit, mock_tools, tmp_path, monkeypatch, path_kind
):
    paths, observed = mock_tools
    monkeypatch.chdir(tmp_path)
    supplied = dict(paths)
    if path_kind == "relative":
        supplied = {name: path.name for name, path in paths.items()}
    elif path_kind == "symlink":
        supplied = {}
        for name, target in paths.items():
            link = tmp_path / (name + "-link")
            link.symlink_to(target)
            supplied[name] = link
    for name in (
        "GOOGLE_APPLICATION_CREDENTIALS",
        "DOCKER_CONFIG",
        "AWS_SECRET_ACCESS_KEY",
        "TRIVY_TOKEN",
        "SYFT_CONFIG",
        "HTTPS_PROXY",
        "PYTHONPATH",
    ):
        monkeypatch.setenv(name, "MOCK-must-not-be-inherited")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(
        audit, "required_tool", lambda name: pytest.fail("Unexpected default lookup")
    )
    evidence = audit.Evidence(tmp_path / "evidence")
    prefix, identity = audit.image_commands(evidence, IMAGE, supplied)
    rows = [json.loads(line) for line in observed.read_text().splitlines()]
    assert len(rows) == 7
    assert prefix[0] == str(paths["docker"]) and prefix[-1] == IMAGE
    assert identity == {
        "id": IMAGE,
        "user": "10001:10001",
        "os": "linux",
        "architecture": "amd64",
        "revision": REVISION,
    }
    assert [row["argv"] for row in rows] == [row["command"] for row in evidence.commands]
    assert rows[0]["argv"] == [str(paths["docker"]), "version", "--format", "{{json .}}"]
    assert rows[1]["argv"] == [str(paths["syft"]), "version", "-o", "json"]
    assert rows[2]["argv"] == [str(paths["trivy"]), "version", "--format", "json"]
    for index, row in enumerate(rows, 1):
        assert row["argv"][0] == str(paths[row["tool"]])
        assert row["env"] == evidence.env
        assert row["env"]["PATH"] == "/usr/local/bin:/usr/bin:/bin"
        assert row["cwd"] == str(evidence.home) and row["home_files"] == []
        saved = json.loads(next(evidence.directory.glob(f"{index:02d}-*.command.json")).read_text())
        assert saved["command"] == row["argv"] and saved["exit_code"] == 0


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "directory",
        "nonexecutable",
        "broken-link",
        "link-loop",
        "nul",
        "shell-string",
        "fifo",
    ],
)
def test_invalid_explicit_path_blocks_before_any_image_child(
    audit, mock_tools, tmp_path, tool, case
):
    paths, observed = mock_tools
    bad = tmp_path / "bad-path"
    if case == "directory":
        bad.mkdir()
    elif case == "nonexecutable":
        bad.write_text("MOCK not executable")
        bad.chmod(0o600)
    elif case == "broken-link":
        bad.symlink_to(tmp_path / "missing-target")
    elif case == "link-loop":
        bad.symlink_to(bad)
    elif case == "nul":
        bad = "invalid\x00path"
    elif case == "shell-string":
        bad = str(paths[tool]) + " --version"
    elif case == "fifo":
        os.mkfifo(bad, 0o700)
    evidence = audit.Evidence(tmp_path / "evidence")
    with pytest.raises(audit.AuditBlocked, match=f"^{tool}_unavailable$"):
        audit.image_commands(evidence, IMAGE, paths | {tool: bad})
    assert evidence.commands == [] and not observed.exists()


@pytest.mark.parametrize("provided", [None, (), ("syft",), TOOLS])
def test_only_unsupplied_tools_use_single_argument_default_lookup(
    audit, mock_tools, tmp_path, monkeypatch, provided
):
    paths, observed = mock_tools
    looked_up = []

    def default(name):
        looked_up.append(name)
        return str(paths[name])

    monkeypatch.setattr(audit, "required_tool", default)
    evidence = audit.Evidence(tmp_path / "evidence")
    if provided is None:
        prefix, _ = audit.image_commands(evidence, IMAGE)
    else:
        prefix, _ = audit.image_commands(evidence, IMAGE, {name: paths[name] for name in provided})
    assert looked_up == [name for name in TOOLS if name not in (provided or ())]
    assert prefix[0] == str(paths["docker"])
    assert len(observed.read_text().splitlines()) == 7


@pytest.mark.parametrize("tool", TOOLS)
def test_default_lookup_ignores_ambient_path_and_cwd(audit, tmp_path, monkeypatch, tool):
    candidate = tmp_path / tool
    candidate.write_text("#!/bin/sh\nexit 99\n")
    candidate.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path))
    real_which = shutil.which
    observed = []

    def lookup(name, *, path):
        observed.append((name, path))
        # Do not inspect or execute actual installed engines/scanners.
        assert real_which(name, path=str(tmp_path)) == str(candidate)
        return None

    monkeypatch.setattr(audit.shutil, "which", lookup)
    with pytest.raises(audit.AuditBlocked, match=f"^{tool}_unavailable$"):
        audit.required_tool(tool)
    assert observed == [(tool, "/usr/local/bin:/usr/bin:/bin")]


@pytest.mark.parametrize("provided", [(), ("docker", "syft", "trivy"), ("syft",)])
def test_image_cli_passes_only_explicit_paths(audit, tmp_path, monkeypatch, capsys, provided):
    seen = []

    def run(evidence, name, command):
        assert name in ("audit-tool-version", "audit-tool-freeze")
        return json.dumps({"prefix": "/MOCK/audit"}) if name == "audit-tool-version" else ""

    def image(evidence, image_ref, tool_paths=None):
        seen.append((image_ref, tool_paths))
        raise audit.AuditBlocked("MOCK_cli_handoff")

    monkeypatch.setattr(audit.Evidence, "run", run)
    monkeypatch.setattr(audit, "image_commands", image)
    output = tmp_path / "evidence"
    args = [
        "image",
        "--image",
        IMAGE,
        "--audit-python",
        "/MOCK/audit/python",
        "--output",
        str(output),
    ]
    for name in provided:
        args.extend([f"--{name}-path", f"relative {name}"])
    assert audit.main(args) == 1
    assert seen == [(IMAGE, {name: Path(f"relative {name}") for name in provided})]
    assert json.loads((output / "summary.json").read_text())["reason"] == "MOCK_cli_handoff"
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


@pytest.mark.parametrize("missing", TOOLS)
def test_image_cli_invalid_path_retains_stable_blocked_summary(
    audit, mock_tools, tmp_path, monkeypatch, capsys, missing
):
    paths, observed = mock_tools

    def audit_tool_only(evidence, name, command):
        assert name in ("audit-tool-version", "audit-tool-freeze")
        return json.dumps({"prefix": "/MOCK/audit"}) if name == "audit-tool-version" else ""

    monkeypatch.setattr(audit.Evidence, "run", audit_tool_only)
    output = tmp_path / "evidence"
    args = [
        "image",
        "--image",
        IMAGE,
        "--audit-python",
        "/MOCK/audit/python",
        "--output",
        str(output),
    ]
    for name in TOOLS:
        args.extend(
            [f"--{name}-path", str(tmp_path / "missing" if name == missing else paths[name])]
        )
    assert audit.main(args) == 1
    summary = json.loads((output / "summary.json").read_text())
    assert summary["status"] == "blocked" and summary["reason"] == f"{missing}_unavailable"
    assert summary["commands"] == [] and not observed.exists()
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


@pytest.mark.parametrize(
    "option", ["--docker-path", "--syft-path", "--trivy-path", "--syft-pat", "--trivy-pth"]
)
@pytest.mark.parametrize("mode", ["runtime", "image"])
def test_unknown_or_runtime_path_flags_fail_before_evidence(
    audit, tmp_path, monkeypatch, capsys, option, mode
):
    if mode == "image" and option in {f"--{name}-path" for name in TOOLS}:
        # A recognized image option with no value is also an argument failure.
        extra = [option]
    else:
        extra = [option, "/MOCK/tool"]
    monkeypatch.setattr(
        audit, "Evidence", lambda directory: pytest.fail("Evidence created on bad CLI")
    )
    selector = (
        ["--runtime-python", "/MOCK/runtime/python"] if mode == "runtime" else ["--image", IMAGE]
    )
    with pytest.raises(SystemExit) as failure:
        audit.main(
            [
                mode,
                *selector,
                "--audit-python",
                "/MOCK/audit/python",
                "--output",
                str(tmp_path / "evidence"),
                *extra,
            ]
        )
    assert failure.value.code == 2
    assert capsys.readouterr().out == ""
