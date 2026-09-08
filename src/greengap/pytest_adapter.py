"""Repository-independent pytest source discovery and real collection."""

from __future__ import annotations

import ast
import configparser
import contextlib
import fnmatch
import importlib.metadata
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import tomllib
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from time import monotonic
from typing import Any

from .environment import collection_environment
from .model import Candidate, CollectedNode, CollectionResult
from .util import (
    MAX_COLLECTION_OUTPUT_BYTES,
    MAX_COLLECTION_SECONDS,
    MAX_CONFIG_BYTES,
    PathInventoryLimitError,
    PathSafetyError,
    as_text,
    bounded_filesystem_paths,
    bounded_git_paths,
    normalize_repo_path,
    process_group_options,
    read_limited_text,
    split_patterns,
)

DEFAULT_FILE_PATTERNS = ("test_*.py", "*_test.py")
DEFAULT_FUNCTION_PATTERNS = ("test_*",)
DEFAULT_CLASS_PATTERNS = ("Test*",)
_DISCOVERY_PARALLEL_MIN_FILES = 256
_DISCOVERY_MAX_WORKERS = 4


def _git_candidate_paths(root: Path) -> tuple[Path, ...] | None:
    result = bounded_git_paths(root, 10.0)
    if result is None:
        return None
    paths, error = result
    if error is not None:
        raise PathInventoryLimitError(error)
    return tuple(root / Path(item) for item in paths)


def _filesystem_candidate_paths(root: Path) -> Iterator[Path]:
    paths, error = bounded_filesystem_paths(root)
    if error is not None:
        raise PathInventoryLimitError(error)
    yield from (root / Path(relative) for relative in paths)


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

    for pytest_toml in (root / "pytest.toml", root / ".pytest.toml"):
        if pytest_toml.exists():
            data = _read_toml(pytest_toml)
            options = data.get("pytest", {})
            return (options if isinstance(options, dict) else {}), pytest_toml.as_posix()

    for ini in (root / "pytest.ini", root / ".pytest.ini"):
        if ini.exists():
            return _read_ini(ini, "pytest"), ini.as_posix()

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        data = _read_toml(pyproject)
        tool = data.get("tool", {})
        pytest_options = tool.get("pytest") if isinstance(tool, dict) and "pytest" in tool else None
        if isinstance(pytest_options, dict):
            native_options = pytest_options.get("ini_options", pytest_options)
            if isinstance(native_options, dict):
                return native_options, pyproject.as_posix()

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


def _inspect_candidate(
    root: Path,
    path: Path,
    function_patterns: tuple[str, ...],
    class_patterns: tuple[str, ...],
) -> Candidate:
    try:
        relative = normalize_repo_path(root, path)
    except PathSafetyError as exc:
        return Candidate(
            path.as_posix(),
            "low",
            (),
            f"candidate path is unsafe and was not inspected: {exc}",
        )
    if path.is_symlink():
        return Candidate(
            relative,
            "low",
            (),
            "symlink test candidate is not inspected by default",
        )
    try:
        tree = ast.parse(read_limited_text(path, MAX_CONFIG_BYTES), filename=relative)
    except (OSError, ValueError, SyntaxError, UnicodeError) as exc:
        return Candidate(
            relative, "low", (), f"filename matched but AST inspection failed: {exc}"
        )
    symbols = tuple(_test_symbols(tree, function_patterns, class_patterns))
    if symbols:
        return Candidate(relative, "high", symbols, "pytest-style symbols found")
    return Candidate(
        relative, "low", (), "filename matched without a recognizable pytest symbol"
    )


def discover_candidates(root: Path) -> tuple[Candidate, ...]:
    options, _ = pytest_config(root)
    file_patterns = split_patterns(options.get("python_files"), DEFAULT_FILE_PATTERNS)
    function_patterns = split_patterns(options.get("python_functions"), DEFAULT_FUNCTION_PATTERNS)
    class_patterns = split_patterns(options.get("python_classes"), DEFAULT_CLASS_PATTERNS)
    git_paths = _git_candidate_paths(root)
    paths = _filesystem_candidate_paths(root) if git_paths is None else iter(git_paths)
    candidate_paths = tuple(
        path
        for path in paths
        if _matches(path.name, file_patterns) and path.name.endswith(".py")
    )
    if len(candidate_paths) >= _DISCOVERY_PARALLEL_MIN_FILES:
        workers = min(_DISCOVERY_MAX_WORKERS, len(candidate_paths))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            candidates = tuple(
                executor.map(
                    _inspect_candidate,
                    (root,) * len(candidate_paths),
                    candidate_paths,
                    (function_patterns,) * len(candidate_paths),
                    (class_patterns,) * len(candidate_paths),
                )
            )
    else:
        candidates = tuple(
            _inspect_candidate(root, path, function_patterns, class_patterns)
            for path in candidate_paths
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


def _parse_collection_witness(
    root: Path, path: Path
) -> tuple[tuple[CollectedNode, ...] | None, str | None]:
    try:
        payload = json.loads(read_limited_text(path, MAX_CONFIG_BYTES))
    except (OSError, ValueError, UnicodeError, RecursionError, MemoryError):
        return None, "pytest collection witness was missing or malformed"
    if not isinstance(payload, dict) or payload.get("version") != 1:
        return None, "pytest collection witness version is unsupported"
    records = payload.get("nodes")
    if not isinstance(records, list):
        return None, "pytest collection witness nodes are not a list"
    nodes: dict[str, CollectedNode] = {}
    for record in records:
        if not isinstance(record, dict):
            return None, "pytest collection witness contains an invalid node"
        nodeid = record.get("nodeid")
        raw_path = record.get("path")
        if not isinstance(nodeid, str) or not isinstance(raw_path, str) or "::" not in nodeid:
            return None, "pytest collection witness contains an unverifiable node"
        node_path = nodeid.split("::", 1)[0]
        try:
            relative = normalize_repo_path(root, raw_path)
            node_relative = normalize_repo_path(root, node_path)
        except PathSafetyError:
            return None, "pytest collection witness contains a path outside the checkout"
        if relative != node_relative:
            return None, "pytest collection witness node path does not match its file path"
        candidate = root / Path(relative)
        try:
            if candidate.is_symlink() or not candidate.is_file():
                return None, "pytest collection witness references a non-regular file"
        except OSError:
            return None, "pytest collection witness file could not be verified"
        existing = nodes.get(nodeid)
        if existing is not None and existing.path != relative:
            return None, "pytest collection witness contains conflicting node paths"
        nodes[nodeid] = CollectedNode(nodeid, relative)
    return tuple(sorted(nodes.values(), key=lambda item: item.nodeid)), None


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


def _normalize_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.strip().lower()).strip("-")


def _requirement_distribution_name(value: str) -> str | None:
    text = value.strip()
    if not text or text.startswith("#"):
        return None
    egg = re.search(r"#egg=([A-Za-z0-9][A-Za-z0-9_.-]*)", text, re.IGNORECASE)
    if egg is not None:
        return _normalize_distribution_name(egg.group(1))
    if text.startswith(("-r", "--requirement", "-c", "--constraint")):
        return None
    if text.startswith(("-e ", "--editable ")):
        text = text.split(None, 1)[1]
        egg = re.search(r"#egg=([A-Za-z0-9][A-Za-z0-9_.-]*)", text, re.IGNORECASE)
        return _normalize_distribution_name(egg.group(1)) if egg is not None else None
    match = re.match(r"([A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?)", text)
    return _normalize_distribution_name(match.group(1)) if match else None


def _declared_project_distributions(root: Path) -> frozenset[str]:
    """Extract dependency names without treating arbitrary manifest text as code."""

    distributions: set[str] = set()

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        data = _read_toml(pyproject)
        project = data.get("project", {})
        if isinstance(project, dict):
            dependencies = project.get("dependencies", [])
            if isinstance(dependencies, list):
                for dependency in dependencies:
                    if isinstance(dependency, str):
                        name = _requirement_distribution_name(dependency)
                        if name:
                            distributions.add(name)
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for values in optional.values():
                    if isinstance(values, list):
                        for dependency in values:
                            if isinstance(dependency, str):
                                name = _requirement_distribution_name(dependency)
                                if name:
                                    distributions.add(name)
        tool = data.get("tool", {})
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        poetry_dependencies = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
        if isinstance(poetry_dependencies, dict):
            for dependency in poetry_dependencies:
                if dependency.lower() != "python":
                    name = _normalize_distribution_name(str(dependency))
                    if name:
                        distributions.add(name)

    for filename in ("requirements.txt", "requirements-dev.txt", "test-requirements.txt"):
        path = root / filename
        if not path.is_file():
            continue
        try:
            lines = read_limited_text(path, MAX_CONFIG_BYTES).splitlines()
        except (OSError, ValueError, UnicodeError):
            return frozenset()
        for line in lines:
            name = _requirement_distribution_name(line)
            if name:
                distributions.add(name)

    setup_cfg = root / "setup.cfg"
    if setup_cfg.is_file():
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(read_limited_text(setup_cfg, MAX_CONFIG_BYTES))
        except (OSError, ValueError, UnicodeError, configparser.Error):
            return frozenset()
        for section in ("options", "options.extras_require"):
            if parser.has_option(section, "install_requires"):
                values = parser.get(section, "install_requires").splitlines()
                for value in values:
                    name = _requirement_distribution_name(value)
                    if name:
                        distributions.add(name)
            if parser.has_section(section) and section == "options.extras_require":
                for _, value in parser.items(section):
                    name = _requirement_distribution_name(value)
                    if name:
                        distributions.add(name)

    return frozenset(distributions)


def _explicit_project_plugin_args(root: Path) -> tuple[str, ...]:
    """Load only marker plugins declared by the repository and used by its source."""

    declared_distributions = _declared_project_distributions(root)
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
        entry_points = tuple(importlib.metadata.entry_points(group="pytest11"))
    except (TypeError, ValueError, RuntimeError):
        return ()
    modules: set[str] = set()
    for entry_point in entry_points:
        distribution = getattr(entry_point, "dist", None)
        distribution_name = getattr(distribution, "name", "")
        normalized_name = re.sub(r"[-_.]+", "-", str(distribution_name).lower())
        if not normalized_name or normalized_name not in declared_distributions:
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


def _unbound_pytest_plugins(root: Path) -> tuple[str, ...] | None:
    """Return installed pytest plugins that collection does not explicitly bind."""

    try:
        entry_points = tuple(importlib.metadata.entry_points(group="pytest11"))
    except (TypeError, ValueError, RuntimeError):
        return None
    explicit = _explicit_project_plugin_args(root)
    explicit_modules = {
        explicit[index + 1]
        for index, token in enumerate(explicit[:-1])
        if token == "-p"
    }
    unbound = {
        str(entry_point.value).split(":", 1)[0]
        for entry_point in entry_points
        if str(entry_point.value).split(":", 1)[0] not in explicit_modules
    }
    return tuple(sorted(module for module in unbound if module))


@dataclass(frozen=True)
class _BoundedProcessResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    output_limited: bool = False


def _process_group_options() -> dict[str, Any]:
    """Start collection in an isolated process group/session."""

    return process_group_options()


def _create_windows_job(process: subprocess.Popen[Any]) -> Any | None:
    """Put a collection process in a kill-on-close Windows Job Object."""

    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class _IoCounters(ctypes.Structure):
            _fields_ = [("value", ctypes.c_ulonglong)] * 6

        class _BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("per_process_user_time_limit", ctypes.c_longlong),
                ("per_job_user_time_limit", ctypes.c_longlong),
                ("limit_flags", wintypes.DWORD),
                ("minimum_working_set_size", ctypes.c_size_t),
                ("maximum_working_set_size", ctypes.c_size_t),
                ("active_process_limit", wintypes.DWORD),
                ("affinity", ctypes.c_size_t),
                ("priority_class", wintypes.DWORD),
                ("scheduling_class", wintypes.DWORD),
            ]

        class _ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("basic_limit_information", _BasicLimitInformation),
                ("io_info", _IoCounters),
                ("process_memory_limit", ctypes.c_size_t),
                ("job_memory_limit", ctypes.c_size_t),
                ("peak_process_memory_used", ctypes.c_size_t),
                ("peak_job_memory_used", ctypes.c_size_t),
            ]

        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            return None
        kernel32 = win_dll("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            wintypes.INT,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        information = _ExtendedLimitInformation()
        information.basic_limit_information.limit_flags = 0x2000
        configured = kernel32.SetInformationJobObject(
            job,
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        )
        if not configured:
            kernel32.CloseHandle(job)
            return None
        process_handle = kernel32.OpenProcess(0x0001 | 0x0100, False, process.pid)
        if not process_handle:
            kernel32.CloseHandle(job)
            return None
        assigned = kernel32.AssignProcessToJobObject(job, process_handle)
        kernel32.CloseHandle(process_handle)
        if not assigned:
            kernel32.CloseHandle(job)
            return None
        return (kernel32, job)
    except (AttributeError, OSError, TypeError):
        return None


def _close_windows_job(job: Any | None) -> None:
    if job is None:
        return
    kernel32, handle = job
    with contextlib.suppress(OSError):
        kernel32.CloseHandle(handle)


def _terminate_process_tree(process: subprocess.Popen[Any]) -> None:
    """Terminate a bounded collection process and every descendant it owns."""

    if os.name == "nt":
        if process.poll() is not None:
            return
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                check=False,
                timeout=5,
            )
    else:
        killpg = getattr(os, "killpg", None)
        sigterm = getattr(signal, "SIGTERM", 15)
        sigkill = getattr(signal, "SIGKILL", 9)
        if callable(killpg):
            try:
                killpg(process.pid, sigterm)
            except (OSError, ProcessLookupError):
                with contextlib.suppress(OSError):
                    process.terminate()
        else:
            with contextlib.suppress(OSError):
                process.terminate()
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            if callable(killpg):
                try:
                    killpg(process.pid, sigkill)
                except (OSError, ProcessLookupError):
                    with contextlib.suppress(OSError):
                        process.kill()
            else:
                with contextlib.suppress(OSError):
                    process.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=2.0)


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
        **_process_group_options(),
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
    windows_job = _create_windows_job(process)

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

    if process.poll() is None or os.name != "nt":
        _terminate_process_tree(process)
    for reader in readers:
        reader.join(timeout=2.0)
    _close_windows_job(windows_job)
    return _BoundedProcessResult(
        process.returncode,
        as_text(bytes(stdout_buffer)),
        as_text(bytes(stderr_buffer)),
        timed_out=timed_out,
        output_limited=overflow.is_set(),
    )


def collection_disabled(reason: str = "pytest collection is disabled") -> CollectionResult:
    """Represent the safe, non-executing inspection mode."""

    return CollectionResult(
        complete=False,
        # The analyzer itself is healthy; only the evidence-producing step was
        # deliberately withheld.  This keeps the result UNKNOWN without
        # misclassifying a user's explicit safety choice as an environment bug.
        environment_valid=True,
        error=reason,
    )


def collect_pytest(
    root: Path,
    timeout: float = 60.0,
    python_executable: str | None = None,
) -> CollectionResult:
    """Run the selected project's pytest collector; never emulate collection."""

    selected_python = python_executable or sys.executable
    if not selected_python.strip():
        return CollectionResult(
            complete=False,
            environment_valid=False,
            error="the selected Python interpreter is empty",
        )

    environment = collection_environment()
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
    unbound_plugins = _unbound_pytest_plugins(root)
    if unbound_plugins is None:
        return CollectionResult(
            complete=False,
            environment_valid=False,
            error="installed pytest plugin entry points could not be inspected safely",
        )
    if unbound_plugins:
        return CollectionResult(
            complete=False,
            environment_valid=False,
            error=(
                "pytest collection environment contains unbound pytest11 plugins: "
                + ", ".join(unbound_plugins)
            ),
        )
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["NO_COLOR"] = "1"
    environment["PY_COLORS"] = "0"
    src = root / "src"
    analyzer_src = Path(__file__).resolve().parents[1]
    if src.is_dir():
        # Do not let an analyst's ambient import path change collection.  The
        # repository source directory is the only extra import root GreenGap
        # intentionally supplies.
        environment["PYTHONPATH"] = os.pathsep.join((str(analyzer_src), str(src)))
    else:
        environment["PYTHONPATH"] = str(analyzer_src)
    with tempfile.TemporaryDirectory(prefix="greengap-pytest-cache-") as cache_dir:
        for name in ("TEMP", "TMP", "TMPDIR"):
            environment[name] = cache_dir
        collection_file = Path(cache_dir) / "collection-witness.json"
        environment["GREENGAP_COLLECTION_FILE"] = str(collection_file)
        args = [
            selected_python,
            "-m",
            "pytest",
            "-p",
            "greengap._collection_plugin",
            *_explicit_project_plugin_args(root),
            # GreenGap's ``root`` is the checkout boundary.  Without this,
            # pytest can walk above a nested checkout and adopt an analyst
            # host's pytest configuration, making discovery diverge from the
            # GitHub Actions workspace we are modeling.
            "--rootdir",
            str(root),
            "--collect-only",
            "-q",
            "-o",
            f"cache_dir={cache_dir}",
        ]
        try:
            completed = _run_pytest_bounded(args, root, environment, timeout)
        except OSError as exc:
            return CollectionResult(
                complete=False,
                environment_valid=False,
                error=f"could not start pytest: {exc}",
            )
        witness_nodes, witness_error = _parse_collection_witness(root, collection_file)

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
    if witness_nodes is None:
        return CollectionResult(
            complete=False,
            environment_valid=False,
            stdout=stdout,
            stderr=stderr,
            returncode=completed.returncode,
            error=witness_error,
        )
    nodes = witness_nodes
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
    root: Path,
    timeout: float = 60.0,
    *,
    python_executable: str | None = None,
    collect: bool = True,
) -> tuple[tuple[Candidate, ...], CollectionResult]:
    collection = (
        collect_pytest(root, timeout, python_executable)
        if collect
        else collection_disabled(
            "pytest collection is disabled; pass --trust-collection only for a trusted checkout"
        )
    )
    try:
        candidates = discover_candidates(root)
    except PathInventoryLimitError as exc:
        collection = replace(collection, complete=False, error=str(exc))
        candidates = ()
    return candidates, collection
