"""Repository-independent pytest source discovery and real collection."""

from __future__ import annotations

import ast
import configparser
import fnmatch
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

from .model import Candidate, CollectedNode, CollectionResult
from .util import as_text, is_transient_path, normalize_repo_path, split_patterns

DEFAULT_FILE_PATTERNS = ("test_*.py", "*_test.py")
DEFAULT_FUNCTION_PATTERNS = ("test_*",)
DEFAULT_CLASS_PATTERNS = ("Test*",)


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _read_ini(path: Path, section: str) -> dict[str, str]:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, configparser.Error):
        return {}
    if not parser.has_section(section):
        return {}
    return {key.lower(): value for key, value in parser.items(section)}


def pytest_config(root: Path) -> tuple[dict[str, Any], str | None]:
    """Read the first pytest configuration file pytest would normally honor."""

    ini = root / "pytest.ini"
    if ini.exists():
        return _read_ini(ini, "pytest"), ini.as_posix()

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        data = _read_toml(pyproject)
        options = data.get("tool", {}).get("pytest", {}).get("ini_options", {})
        if isinstance(options, dict):
            return options, pyproject.as_posix()

    tox_ini = root / "tox.ini"
    if tox_ini.exists():
        values = _read_ini(tox_ini, "pytest")
        if values:
            return values, tox_ini.as_posix()

    setup_cfg = root / "setup.cfg"
    if setup_cfg.exists():
        values = _read_ini(setup_cfg, "tool:pytest")
        if values:
            return values, setup_cfg.as_posix()
    return {}, None


def _matches(name: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _test_symbols(
    tree: ast.Module, function_patterns: tuple[str, ...], class_patterns: tuple[str, ...]
) -> list[str]:
    symbols: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _matches(
            node.name, function_patterns
        ):
            symbols.append(node.name)
        elif isinstance(node, ast.ClassDef) and _matches(node.name, class_patterns):
            methods = [
                child.name
                for child in node.body
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
                and _matches(child.name, function_patterns)
            ]
            if methods:
                symbols.extend(f"{node.name}.{method}" for method in methods)
    return symbols


def discover_candidates(root: Path) -> tuple[Candidate, ...]:
    options, _ = pytest_config(root)
    file_patterns = split_patterns(options.get("python_files"), DEFAULT_FILE_PATTERNS)
    function_patterns = split_patterns(options.get("python_functions"), DEFAULT_FUNCTION_PATTERNS)
    class_patterns = split_patterns(options.get("python_classes"), DEFAULT_CLASS_PATTERNS)
    candidates: list[Candidate] = []
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        relative_dir = Path(directory).relative_to(root)
        dirnames[:] = [
            name
            for name in dirnames
            if not is_transient_path(relative_dir / name) and name.lower() != ".git"
        ]
        for filename in filenames:
            if not _matches(filename, file_patterns) or not filename.endswith(".py"):
                continue
            path = Path(directory) / filename
            relative = normalize_repo_path(root, path)
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError, UnicodeError) as exc:
                candidates.append(
                    Candidate(
                        relative, "low", (), f"filename matched but AST inspection failed: {exc}"
                    )
                )
                continue
            symbols = tuple(_test_symbols(tree, function_patterns, class_patterns))
            if symbols:
                candidates.append(
                    Candidate(relative, "high", symbols, "pytest-style symbols found")
                )
            else:
                candidates.append(
                    Candidate(
                        relative, "low", (), "filename matched without a recognizable pytest symbol"
                    )
                )
    return tuple(sorted(candidates, key=lambda item: item.path))


_NODE_MARKER = "::"


def _parse_nodes(root: Path, stdout: str, stderr: str) -> tuple[CollectedNode, ...]:
    nodes: dict[str, CollectedNode] = {}
    for raw_line in (stdout + "\n" + stderr).splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", raw_line).strip()
        marker = line.find(_NODE_MARKER)
        if marker < 1 or ".py" not in line[:marker]:
            continue
        prefix = line[:marker].strip().split()[-1]
        if prefix.startswith("E") and len(prefix) < 3:
            continue
        nodeid = line.split()[0] if line.split() else ""
        if _NODE_MARKER not in nodeid:
            nodeid = prefix + line[marker:]
        path = normalize_repo_path(root, prefix)
        if path and path != ".":
            nodes.setdefault(nodeid, CollectedNode(nodeid, path))
    return tuple(sorted(nodes.values(), key=lambda item: item.nodeid))


def _looks_environment_invalid(output: str) -> bool:
    lowered = output.lower()
    return any(
        marker in lowered
        for marker in (
            "modulenotfounderror",
            "importerror",
            "no module named",
            "plugin ",
            "syntaxerror",
            "conftest.py",
        )
    )


def collect_pytest(root: Path, timeout: float = 60.0) -> CollectionResult:
    """Run the actual pytest collector; never replace it with AST emulation."""

    environment = os.environ.copy()
    src = root / "src"
    if src.is_dir():
        old = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = str(src) + (os.pathsep + old if old else "")
    args = [sys.executable, "-m", "pytest", "--collect-only", "-q"]
    try:
        completed = subprocess.run(
            args,
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = as_text(exc.stdout)
        stderr = as_text(exc.stderr)
        nodes = _parse_nodes(root, stdout, stderr)
        return CollectionResult(
            complete=False,
            environment_valid=False,
            nodes=nodes,
            paths=tuple(sorted({node.path for node in nodes})),
            stdout=stdout,
            stderr=stderr,
            error=f"pytest collection timed out after {timeout:g}s",
            timed_out=True,
        )
    except OSError as exc:
        return CollectionResult(False, False, error=f"could not start pytest: {exc}")

    stdout = completed.stdout
    stderr = completed.stderr
    nodes = _parse_nodes(root, stdout, stderr)
    combined = stdout + "\n" + stderr
    no_tests = "no tests collected" in combined.lower() or "collected 0 items" in combined.lower()
    complete = completed.returncode == 0 or (completed.returncode == 5 and no_tests)
    environment_valid = complete or not _looks_environment_invalid(combined)
    error = None if complete else f"pytest collection exited with code {completed.returncode}"
    return CollectionResult(
        complete=complete,
        environment_valid=environment_valid,
        nodes=nodes,
        paths=tuple(sorted({node.path for node in nodes})),
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        error=error,
    )


def scan_pytest(
    root: Path, timeout: float = 60.0
) -> tuple[tuple[Candidate, ...], CollectionResult]:
    return discover_candidates(root), collect_pytest(root, timeout)
