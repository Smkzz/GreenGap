"""Repository-independent pytest source discovery and real collection."""

from __future__ import annotations

import ast
import configparser
import contextlib
import fnmatch
import importlib.metadata
import os
import re
import subprocess
import sys
import threading
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Any

from .model import Candidate, CollectedNode, CollectionResult
from .util import (
    MAX_COLLECTION_OUTPUT_BYTES,
    MAX_COLLECTION_SECONDS,
    MAX_CONFIG_BYTES,
    PathSafetyError,
    as_text,
    is_transient_path,
    normalize_repo_path,
    read_limited_text,
    split_patterns,
)

DEFAULT_FILE_PATTERNS = ("test_*.py", "*_test.py")
DEFAULT_FUNCTION_PATTERNS = ("test_*",)
DEFAULT_CLASS_PATTERNS = ("Test*",)


def _git_candidate_paths(root: Path) -> tuple[Path, ...] | None:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    raw = result.stdout.decode("utf-8", errors="surrogateescape")
    return tuple(
        root / Path(item)
        for item in raw.split("\0")
        if item and not is_transient_path(item)
    )


def _filesystem_candidate_paths(root: Path) -> Iterator[Path]:
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        relative_dir = Path(directory).relative_to(root)
        dirnames[:] = [
            name
            for name in dirnames
            if name.lower() != ".git" and not is_transient_path(relative_dir / name)
        ]
        for filename in filenames:
            relative = relative_dir / filename
            if not is_transient_path(relative):
                yield Path(directory) / filename


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(read_limited_text(path, MAX_CONFIG_BYTES))
    except (OSError, ValueError, UnicodeError, tomllib.TOMLDecodeError):
        return {}


def _read_ini(path: Path, section: str) -> dict[str, str]:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(read_limited_text(path, MAX_CONFIG_BYTES))
    except (OSError, ValueError, UnicodeError, configparser.Error):
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
    git_paths = _git_candidate_paths(root)
    paths = _filesystem_candidate_paths(root) if git_paths is None else iter(git_paths)
    for path in paths:
        filename = path.name
        if not _matches(filename, file_patterns) or not filename.endswith(".py"):
            continue
        try:
            relative = normalize_repo_path(root, path)
        except PathSafetyError as exc:
            candidates.append(
                Candidate(
                    path.as_posix(),
                    "low",
                    (),
                    f"candidate path is unsafe and was not inspected: {exc}",
                )
            )
            continue
        if path.is_symlink():
            candidates.append(
                Candidate(
                    relative,
                    "low",
                    (),
                    "symlink test candidate is not inspected by default",
                )
            )
            continue
        try:
            tree = ast.parse(read_limited_text(path, MAX_CONFIG_BYTES), filename=relative)
        except (OSError, ValueError, SyntaxError, UnicodeError) as exc:
            candidates.append(
                Candidate(
                    relative, "low", (), f"filename matched but AST inspection failed: {exc}"
                )
            )
            continue
        symbols = tuple(_test_symbols(tree, function_patterns, class_patterns))
        if symbols:
            candidates.append(Candidate(relative, "high", symbols, "pytest-style symbols found"))
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
        try:
            path = normalize_repo_path(root, prefix)
        except PathSafetyError:
            continue
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


def _explicit_project_plugin_args(root: Path) -> tuple[str, ...]:
    """Load only marker plugins declared by the repository and used by its source."""

    manifest_text: list[str] = []
    for name in (
        "pyproject.toml",
        "pytest.ini",
        "tox.ini",
        "setup.cfg",
        "setup.py",
        "requirements.txt",
        "requirements-dev.txt",
        "test-requirements.txt",
    ):
        path = root / name
        if path.is_file():
            try:
                manifest_text.append(read_limited_text(path, MAX_CONFIG_BYTES))
            except (OSError, ValueError, UnicodeError):
                return ()
    normalized_manifests = re.sub(r"[-_.]+", "-", "\n".join(manifest_text).lower())
    marker_names: set[str] = set()
    try:
        candidate_paths = _git_candidate_paths(root)
        if candidate_paths is None:
            candidate_paths = tuple(_filesystem_candidate_paths(root))
        for path in candidate_paths:
            if path.suffix.lower() != ".py":
                continue
            text = read_limited_text(path, MAX_CONFIG_BYTES)
            marker_names.update(re.findall(r"pytest\.mark\.([A-Za-z_][A-Za-z0-9_]*)", text))
    except (OSError, ValueError, UnicodeError, PathSafetyError):
        return ()
    if not marker_names:
        return ()
    try:
        entry_points = importlib.metadata.entry_points(group="pytest11")
    except (TypeError, ValueError, RuntimeError):
        return ()
    modules: set[str] = set()
    for entry_point in entry_points:
        distribution = getattr(entry_point, "dist", None)
        distribution_name = getattr(distribution, "name", "")
        normalized_name = re.sub(r"[-_.]+", "-", str(distribution_name).lower())
        if not normalized_name or normalized_name not in normalized_manifests:
            continue
        entry_name = str(entry_point.name).lower()
        if entry_name not in {name.lower() for name in marker_names}:
            continue
        module = str(entry_point.value).split(":", 1)[0]
        if module:
            modules.add(module)
    args: list[str] = []
    for module in sorted(modules):
        args.extend(("-p", module))
    return tuple(args)


@dataclass(frozen=True)
class _BoundedProcessResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    output_limited: bool = False


def _drain_pipe(
    pipe: Any, target: bytearray, limit: int, overflow: threading.Event
) -> None:
    try:
        while True:
            chunk = pipe.read(64 * 1024)
            if not chunk:
                break
            remaining = limit - len(target)
            if remaining > 0:
                target.extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow.set()
    finally:
        pipe.close()


def _run_pytest_bounded(
    args: list[str], root: Path, environment: dict[str, str], timeout: float
) -> _BoundedProcessResult:
    """Collect pytest output without allowing a noisy repository to fill memory."""

    process = subprocess.Popen(
        args,
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    overflow = threading.Event()
    readers = (
        threading.Thread(
            target=_drain_pipe,
            args=(process.stdout, stdout_buffer, MAX_COLLECTION_OUTPUT_BYTES, overflow),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_pipe,
            args=(process.stderr, stderr_buffer, MAX_COLLECTION_OUTPUT_BYTES, overflow),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()

    deadline = monotonic() + min(max(timeout, 0.01), MAX_COLLECTION_SECONDS)
    timed_out = False
    while process.poll() is None:
        if overflow.is_set():
            break
        remaining = deadline - monotonic()
        if remaining <= 0:
            timed_out = True
            break
        overflow.wait(min(0.05, remaining))

    if process.poll() is None:
        with contextlib.suppress(OSError):
            process.terminate()
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                process.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=1.0)
    for reader in readers:
        reader.join(timeout=2.0)
    return _BoundedProcessResult(
        process.returncode,
        as_text(bytes(stdout_buffer)),
        as_text(bytes(stderr_buffer)),
        timed_out=timed_out,
        output_limited=overflow.is_set(),
    )


def collect_pytest(root: Path, timeout: float = 60.0) -> CollectionResult:
    """Run the actual pytest collector; never replace it with AST emulation."""

    environment = os.environ.copy()
    ambient = tuple(
        name
        for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTEST_DISABLE_PLUGIN_AUTOLOAD")
        if environment.get(name)
    )
    if ambient:
        return CollectionResult(
            complete=False,
            environment_valid=False,
            error="ambient pytest selection/plugin environment is set: " + ", ".join(ambient),
        )
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    src = root / "src"
    if src.is_dir():
        # Do not let an analyst's ambient import path change collection.  The
        # repository source directory is the only extra import root GreenGap
        # intentionally supplies.
        environment["PYTHONPATH"] = str(src)
    else:
        environment.pop("PYTHONPATH", None)
    args = [
        sys.executable,
        "-m",
        "pytest",
        *_explicit_project_plugin_args(root),
        "--collect-only",
        "-q",
    ]
    try:
        completed = _run_pytest_bounded(args, root, environment, timeout)
    except OSError as exc:
        return CollectionResult(
            complete=False,
            environment_valid=False,
            error=f"could not start pytest: {exc}",
        )

    stdout = completed.stdout
    stderr = completed.stderr
    if completed.output_limited:
        return CollectionResult(
            complete=False,
            environment_valid=False,
            stdout=stdout[:MAX_COLLECTION_OUTPUT_BYTES],
            stderr=stderr[:MAX_COLLECTION_OUTPUT_BYTES],
            returncode=completed.returncode,
            error=f"pytest collection output exceeds limit of {MAX_COLLECTION_OUTPUT_BYTES} bytes",
        )
    if completed.timed_out:
        nodes = _parse_nodes(root, stdout, stderr)
        return CollectionResult(
            complete=False,
            environment_valid=False,
            nodes=nodes,
            paths=tuple(sorted({node.path for node in nodes})),
            stdout=stdout,
            stderr=stderr,
            error=f"pytest collection timed out after {min(max(timeout, 0.01), MAX_COLLECTION_SECONDS):g}s",
            timed_out=True,
        )
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
