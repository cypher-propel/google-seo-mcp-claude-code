"""Portable source contracts and explicit noneditable production-wheel checks."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = {
    "advertools", "scrapy", "twisted", "playwright", "statsmodels", "scipy", "pytest",
    "pytest-mock", "ruff", "pip-audit", "pip-tools", "build", "setuptools", "wheel", "packaging",
}


def locked_versions():
    text = (ROOT / "requirements-production.lock").read_text()
    records = re.sub(r"\\\n\s*", " ", text).splitlines()
    result = {}
    for line in records:
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s]+)(?: +--hash=sha256:[0-9a-f]{64})+", line)
        assert match is not None, "every dependency must be exact and hash locked"
        name, version = match.groups()
        name = name.lower().replace("_", "-")
        assert name not in result
        result[name] = version
    assert result
    return result


def child_environment(tmp_path, executable):
    home = tmp_path / "empty-home"
    home.mkdir()
    return {"HOME": str(home), "TMPDIR": str(home), "LANG": "C.UTF-8",
            "PATH": f"{Path(executable).parent}:/usr/local/bin:/usr/bin:/bin",
            "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1"}


def test_source_crawl_optional_sdk_floor_manifest_package_data_and_exact_lock():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dependencies = project["project"]["dependencies"]
    assert "mcp>=1.30.0,<2" in dependencies
    assert not any("advertools" in item.lower() for item in dependencies)
    assert any(
        item.startswith("advertools")
        for item in project["project"]["optional-dependencies"]["crawl"]
    )
    assert "production_tools.json" in (
        project["tool"]["setuptools"]["package-data"]["google_seo_mcp"]
    )
    locked = locked_versions()
    assert locked["mcp"] == "1.30.0"
    assert not set(locked) & FORBIDDEN
    assert "google-seo-mcp[crawl]" in (ROOT / "src/google_seo_mcp/_dep_check.py").read_text()


def test_no_crawler_import_needed_for_default_server_composition(tmp_path):
    # A real process importing the source package must not need crawling extras.
    code = '''
import importlib.abc
import sys
class NoCrawler(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'advertools', 'scrapy', 'twisted', 'playwright'}:
            raise AssertionError('crawler eagerly imported')
sys.meta_path.insert(0, NoCrawler())
from google_seo_mcp.server import create_server
from google_seo_mcp.runtime_config import load_runtime_config
instance = create_server(load_runtime_config([]))
assert len(instance._tool_manager.list_tools()) == 102
'''
    result = subprocess.run([sys.executable, "-c", code],
                            env=child_environment(tmp_path, sys.executable),
                            cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_container_source_security_contract_without_claiming_image_execution():
    docker = (ROOT / "Dockerfile").read_text()
    images = re.findall(r"^FROM (\S+)", docker, re.MULTILINE)
    assert len(images) == 2 and len(set(images)) == 1
    assert re.fullmatch(r"python:3\.11-slim-bookworm@sha256:[0-9a-f]{64}", images[0])
    for required in ("--require-hashes", "--no-deps", "USER 10001:10001", "STOPSIGNAL SIGTERM",
                     "production_tools.json", "--without-pip", "pip check"):
        assert required in docker
    assert "COPY --from=wheel-builder /opt/venv /opt/venv" in docker
    assert not re.search(r"pip install .*\[(?:dev|crawl|ssr|stats)\]", docker)
    compose = (ROOT / "docker-compose.yml").read_text()
    for required in ("3006:8000", "read_only: true", "cap_drop: [ALL]", "no-new-privileges:true",
                     "512m", "cpus: 1.0", "pids_limit: 128", "restart: unless-stopped",
                     "max-size: 10m", 'max-file: "3"', "create_host_path: false", "/run/secrets"):
        assert required in compose
    assert "docker.sock" not in compose
    ignored = (ROOT / ".dockerignore").read_text().splitlines()
    assert "**" in ignored  # deny everything except explicitly admitted build inputs
    for private in (".git", ".agents", ".venv", ".env"):
        assert "**/" + private in ignored


def test_explicit_production_wheel_runtime_exact_lock_manifest_no_crawl_dev_or_audit(tmp_path):
    executable = os.environ.get("GOOGLE_SEO_TEST_PYTHON")
    if not executable:
        pytest.skip(
            "production-wheel qualification requires explicit GOOGLE_SEO_TEST_PYTHON; "
            "source tests ran"
        )
    assert Path(executable).is_absolute() and Path(executable).is_file()
    expected = locked_versions()
    # The only additional runtime tooling is the Dockerfile's pinned pip.
    docker = (ROOT / "Dockerfile").read_text()
    pip_pin = re.search(r"'pip==([^\s]+) --hash=sha256:", docker)
    assert pip_pin
    code = r'''
from importlib import metadata, resources, util
import json
from pathlib import Path
import sys
import google_seo_mcp
from google_seo_mcp.server import create_server
from google_seo_mcp.runtime_config import load_runtime_config
from google_seo_mcp.migration.wp_audit import crawl_site_advertools
from google_seo_mcp._dep_check import probe_optional_deps
expected, forbidden, pip_version, source = json.loads(sys.argv[1])
normal = lambda n: n.lower().replace('_', '-')
actual = {normal(d.metadata['Name']): d.version for d in metadata.distributions()}
assert not set(actual) & set(forbidden), sorted(set(actual) & set(forbidden))
assert set(actual) == set(expected) | {'google-seo-mcp', 'pip'}, sorted(
    set(actual) ^ (set(expected) | {'google-seo-mcp', 'pip'}))
assert all(actual[name] == version for name, version in expected.items())
assert actual['pip'] == pip_version
assert Path(source) not in Path(google_seo_mcp.__file__).resolve().parents
package = metadata.distribution('google-seo-mcp')
assert 'google_seo_mcp/production_tools.json' in {str(file) for file in package.files}
direct = package.read_text('direct_url.json')
assert not direct or not json.loads(direct).get('dir_info', {}).get('editable', False)
manifest = json.loads(
    resources.files('google_seo_mcp').joinpath('production_tools.json').read_text())
assert manifest['version'] == 1 and len(manifest['tools']) == len(set(manifest['tools'])) == 35
assert util.find_spec('advertools') is None and util.find_spec('twisted') is None
assert 'advertools' not in sys.modules
report = probe_optional_deps()
assert any('[crawl]' in item['install_cmd'] for item in report['unavailable'])
# Missing optional crawler fails before creating a temp file or touching network.
try:
    crawl_site_advertools('https://offline.invalid')
except ModuleNotFoundError as error:
    assert error.name == 'advertools'
else:
    raise AssertionError('crawler unexpectedly available')
assert len(create_server(load_runtime_config([]))._tool_manager.list_tools()) == 102
print(json.dumps({'runtime_packages': len(actual), 'manifest_tools': len(manifest['tools']),
                  'noneditable': True, 'twisted': 'absent'}))
'''
    environment = child_environment(tmp_path, executable)
    result = subprocess.run([executable, "-c", code, json.dumps([
        expected, sorted(FORBIDDEN), pip_pin.group(1), str(ROOT / "src")])], env=environment,
        cwd=tmp_path, capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["noneditable"] and summary["twisted"] == "absent"
    check = subprocess.run([executable, "-m", "pip", "check"], env=environment, cwd=tmp_path,
                           capture_output=True, text=True, timeout=40)
    assert check.returncode == 0, check.stdout + check.stderr
