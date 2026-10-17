"""Source and executable contracts for global cleanup, without building an image."""

import ast
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_PACKAGES = {"pip", "setuptools", "wheel", "packaging"}


def runtime_cleanup_guard():
    """Extract the real global guard, checking its stage and shell ordering."""
    docker = (ROOT / "Dockerfile").read_text()
    logical_lines = re.sub(r"\\\n\s*", " ", docker).splitlines()
    stages = []
    for line in logical_lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        instruction, _, argument = line.strip().partition(" ")
        if instruction.upper() == "FROM":
            stages.append((shlex.split(argument)[-1], []))
        else:
            assert stages, "Docker instructions must belong to a stage"
            stages[-1][1].append((instruction.upper(), argument))
    runtime = [instructions for name, instructions in stages if name == "runtime"]
    assert len(runtime) == 1 and stages[-1][0] == "runtime", "check the final runtime stage"
    instructions = runtime[0]
    cleanups = []
    for index, (instruction, argument) in enumerate(instructions):
        if instruction != "RUN":
            continue
        # Keep shell argv intact while recognizing success-only command chaining.
        lexer = shlex.shlex(argument, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        tokens = list(lexer)
        commands = [[]]
        for token in tokens:
            if token == "&&":
                commands.append([])
            else:
                commands[-1].append(token)
        for command_index, command in enumerate(commands):
            if command[:4] == ["python", "-m", "pip", "uninstall"]:
                cleanups.append((index, commands, command_index))
    assert len(cleanups) == 1, "runtime must uninstall global bootstrap distributions"
    index, commands, command_index = cleanups[0]
    uninstall = commands[command_index]
    assert uninstall[4] == "--yes"
    assert set(uninstall[5:]) == BOOTSTRAP_PACKAGES, "remove all four global packages"
    assert len(uninstall[5:]) == len(BOOTSTRAP_PACKAGES)
    assert all(not (set(token) <= set(";&|"))
               for command in commands for token in command), "use only success-only chaining"
    assert command_index + 2 < len(commands), "chain removal and guard immediately after uninstall"
    removal = commands[command_index + 1]
    assert len(removal) == 3 and removal[:2] == ["python", "-c"], (
        "remove ensurepip with global Python"
    )
    expected_removal = ast.parse(
        'from pathlib import Path; import shutil,sysconfig; '
        'shutil.rmtree(Path(sysconfig.get_path("stdlib"))/"ensurepip")'
    )
    assert ast.dump(ast.parse(removal[2])) == ast.dump(expected_removal), (
        "require exactly the accepted stdlib ensurepip removal"
    )
    guard = commands[command_index + 2]
    assert len(guard) == 3 and guard[:2] == ["python", "-c"], "use global Python"
    tree = ast.parse(guard[2])
    assert any(isinstance(node, ast.ImportFrom) and node.module == "importlib.metadata"
               for node in ast.walk(tree)), "use stdlib metadata"
    assert any(isinstance(node, ast.Assert) for node in ast.walk(tree)), "require an assertion"
    before_guard = "\n".join(argument for _, argument in instructions[:index])
    before_guard += "\n" + "\n".join(" ".join(command)
                                        for command in commands[:command_index + 2])
    assert "/opt/venv" not in before_guard, "cleanup must precede venv selection or COPY"
    assert "PYTHONOPTIMIZE" not in before_guard, "the assertion must remain enabled"
    after_guard = instructions[index + 1:]
    copies = [i for i, (op, arg) in enumerate(after_guard)
              if op == "COPY" and "/opt/venv" in arg]
    paths = [i for i, (op, arg) in enumerate(after_guard)
             if op == "ENV" and "PATH=/opt/venv/bin:" in arg]
    assert copies and paths and copies[0] < paths[0], "guard, then venv COPY, then PATH"
    return guard[2]


def test_runtime_global_cleanup_precedes_application_venv():
    runtime_cleanup_guard()


@pytest.mark.parametrize(
    "names",
    [(), ("pip",), ("setuptools",), ("wheel",), ("packaging",),
     ("unexpected-global",), ("packaging", "unexpected-global"), (None,)],
    ids=["empty", "pip", "setuptools", "wheel", "packaging", "unexpected", "mixed",
         "missing-name"],
)
def test_extracted_global_guard_requires_no_distributions(tmp_path, names):
    guard = runtime_cleanup_guard()
    metadata_path = tmp_path / "metadata"
    metadata_path.mkdir()
    for index, name in enumerate(names):
        distribution = metadata_path / f"controlled_{index}-1.0.dist-info"
        distribution.mkdir()
        metadata = "Metadata-Version: 2.1\nVersion: 1.0\n"
        if name is not None:
            metadata += f"Name: {name}\n"
        (distribution / "METADATA").write_text(metadata)
    home = tmp_path / "empty-home"
    home.mkdir()
    environment = {
        "HOME": str(home), "TMPDIR": str(home), "LANG": "C.UTF-8",
        "PATH": f"{Path(sys.executable).parent}:/usr/local/bin:/usr/bin:/bin",
        "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    }
    # Redirect only discovery's search root. Real stdlib distribution metadata is
    # used, and the extracted production assertion executes unchanged.
    harness = """
import importlib.metadata as metadata
import sys
discover = metadata.distributions
metadata.distributions = lambda: discover(path=[sys.argv[2]])
exec(compile(sys.argv[1], '<Dockerfile global cleanup>', 'exec'))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", harness, guard, str(metadata_path)],
        env=environment, cwd=tmp_path, capture_output=True, text=True, timeout=10,
    )
    assert result.stdout == ""
    if not names:
        assert result.returncode == 0, result.stderr
        assert result.stderr == ""
    else:
        assert result.returncode != 0, "global distribution unexpectedly accepted"
        assert "AssertionError" in result.stderr, result.stderr
        for name in names:
            assert repr(name) in result.stderr, result.stderr
