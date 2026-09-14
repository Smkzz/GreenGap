"""Deterministic workspace-byte binding for every analysis."""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .model import WorkspaceSnapshot
from .util import (
    MAX_PATH_INVENTORY_BYTES,
    MAX_PATH_INVENTORY_ITEMS,
    MAX_WORKSPACE_FILE_BYTES,
    MAX_WORKSPACE_FILES,
    MAX_WORKSPACE_TOTAL_BYTES,
    PathReadContext,
    bounded_command_output,
    bounded_filesystem_paths,
    bounded_git_paths,
    is_transient_path,
    read_limited_bytes,
)

_SNAPSHOT_PARALLEL_MIN_FILES = 256
_SNAPSHOT_MAX_WORKERS = 8


def _git_paths(
    root: Path, timeout: float
) -> tuple[tuple[str, ...], str, str | None] | None:
    result = bounded_git_paths(root, timeout)
    if result is None:
        return None
    paths, error = result
    return paths, "git", error


def _walk_paths(root: Path) -> tuple[tuple[str, ...], str | None]:
    return bounded_filesystem_paths(root)


def _read_snapshot_entry(
    path: Path,
    relative: str,
    parent_context: PathReadContext | None = None,
) -> tuple[bytes, str | None]:
    try:
        return (
            read_limited_bytes(
                path,
                MAX_WORKSPACE_FILE_BYTES,
                parent_context=parent_context,
            ),
            None,
        )
    except ValueError as exc:
        return b"<UNREADABLE>", f"{relative}: {exc}"


def _hash_snapshot_paths(
    root: Path,
    paths: tuple[str, ...],
    *,
    method: str,
    inventory_error: str | None,
    read_context: PathReadContext | None,
) -> WorkspaceSnapshot:
    """Hash one already-selected path surface with the normal read bounds."""

    digest = hashlib.sha256()
    errors: list[str] = [inventory_error] if inventory_error is not None else []
    if len(paths) > MAX_WORKSPACE_FILES:
        errors.append(
            f"workspace contains {len(paths)} files; limit is {MAX_WORKSPACE_FILES}"
        )
    total_bytes = 0

    def consume(relative: str, data: bytes, error: str | None) -> bool:
        nonlocal total_bytes
        if error is not None:
            errors.append(error)
        total_bytes += len(data)
        if total_bytes > MAX_WORKSPACE_TOTAL_BYTES:
            errors.append(
                f"workspace bytes exceed limit of {MAX_WORKSPACE_TOTAL_BYTES}"
            )
            return False
        encoded_path = relative.replace("\\", "/").encode("utf-8", errors="surrogateescape")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        return True

    selected_paths = paths[:MAX_WORKSPACE_FILES]
    selected_files = tuple(root / Path(relative) for relative in selected_paths)
    context = read_context or PathReadContext(root)
    context_error = context.prepare(selected_files)
    batch_context: PathReadContext | None = context
    if context_error is not None:
        errors.append(context_error)
        batch_context = None
    if batch_context is None and len(selected_paths) >= _SNAPSHOT_PARALLEL_MIN_FILES:
        workers = min(_SNAPSHOT_MAX_WORKERS, len(selected_paths))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            index = 0
            while index < len(selected_paths):
                batch = selected_paths[index : index + workers]
                # Never schedule a batch whose worst-case bytes could cross
                # the total-read limit; finish the tail sequentially.
                if total_bytes > MAX_WORKSPACE_TOTAL_BYTES - (workers * MAX_WORKSPACE_FILE_BYTES):
                    for relative, path in zip(
                        selected_paths[index:], selected_files[index:], strict=True
                    ):
                        data, error = _read_snapshot_entry(path, relative, batch_context)
                        if not consume(relative, data, error):
                            break
                    break
                for relative, (data, error) in zip(
                    batch,
                    executor.map(
                        _read_snapshot_entry,
                        selected_files[index : index + len(batch)],
                        batch,
                        (batch_context,) * len(batch),
                    ),
                    strict=True,
                ):
                    if not consume(relative, data, error):
                        index = len(selected_paths)
                        break
                else:
                    index += len(batch)
    else:
        for relative, path in zip(selected_paths, selected_files, strict=True):
            data, error = _read_snapshot_entry(path, relative, batch_context)
            if not consume(relative, data, error):
                break
    if batch_context is not None:
        context_error = batch_context.verify()
        if context_error is not None:
            errors.append(context_error)
    return WorkspaceSnapshot(digest.hexdigest(), paths, method, tuple(errors))


def _bounded_git_list(
    root: Path,
    timeout: float,
    options: tuple[str, ...],
) -> tuple[tuple[str, ...], str | None] | None:
    """Read one bounded Git path list, preserving inventory-limit errors."""

    result = bounded_command_output(
        ["git", "ls-files", *options, "-z"],
        cwd=root,
        timeout=timeout,
        max_bytes=MAX_PATH_INVENTORY_BYTES,
    )
    if result is None:
        return None
    raw, output_limited, timed_out, returncode = result
    if timed_out or returncode != 0:
        return None
    paths: list[str] = []
    for index, item in enumerate(raw.split(b"\0")):
        if not item:
            continue
        if index >= MAX_PATH_INVENTORY_ITEMS:
            return tuple(paths), f"source path inventory exceeds limit of {MAX_PATH_INVENTORY_ITEMS} files"
        paths.append(os.fsdecode(item))
    if output_limited or (raw and not raw.endswith(b"\0")):
        return tuple(paths), f"source path inventory exceeds byte limit of {MAX_PATH_INVENTORY_BYTES}"
    return tuple(paths), None


_SOURCE_UNTRACKED_SUFFIXES = frozenset(
    {
        ".bat",
        ".cfg",
        ".cmd",
        ".ini",
        ".mk",
        ".ps1",
        ".py",
        ".pyi",
        ".pyx",
        ".pxd",
        ".sh",
        ".toml",
        ".txt",
        ".yaml",
        ".yml",
    }
)
_SOURCE_CONFIG_BASENAMES = frozenset(
    {
        "makefile",
        "noxfile.py",
        "pyproject.toml",
        "pytest.ini",
        "setup.cfg",
        "setup.py",
        "taskfile.yml",
        "tox.ini",
    }
)
_SOURCE_CONFIG_PREFIXES = (
    ".azure/",
    ".buildkite/",
    ".circleci/",
    ".github/",
    ".gitlab/",
    "ci/",
    "spec/",
    "test/",
    "tests/",
    "testing/",
)


def _is_source_input(relative: str, *, tracked: bool) -> bool:
    """Select source/config inputs without absorbing common test outputs."""

    normalized = relative.replace("\\", "/").lstrip("./").casefold()
    if not normalized or is_transient_path(normalized):
        return False
    if tracked:
        # A tracked file is authoritative unless it is under a known transient
        # directory. This deliberately protects tracked tests and config even
        # when their extension is unusual.
        return True
    basename = normalized.rsplit("/", 1)[-1]
    if basename in _SOURCE_CONFIG_BASENAMES:
        return True
    if any(normalized.startswith(prefix) for prefix in _SOURCE_CONFIG_PREFIXES):
        return True
    return Path(normalized).suffix.casefold() in _SOURCE_UNTRACKED_SUFFIXES


def source_snapshot(
    root: Path,
    timeout: float = 10.0,
    *,
    read_context: PathReadContext | None = None,
) -> WorkspaceSnapshot:
    """Hash the source/configuration identity independently of runtime output.

    Tracked repository inputs are authoritative. Non-ignored untracked files
    are included only when they look like source, tests, or test/CI
    configuration; common generated reports such as ``coverage.xml`` and
    ``uv.lock`` are therefore runtime state, not source identity. If Git is
    unavailable, the bounded filesystem walk remains conservative and hashes
    every non-transient path it can inspect.
    """

    root = root.resolve()
    tracked = _bounded_git_list(root, timeout, ("--cached",))
    untracked = _bounded_git_list(root, timeout, ("--others", "--exclude-standard"))
    if tracked is not None and untracked is not None:
        tracked_paths, tracked_error = tracked
        untracked_paths, untracked_error = untracked
        paths = tuple(
            sorted(
                {
                    path
                    for path in tracked_paths
                    if _is_source_input(path, tracked=True)
                }
                | {
                    path
                    for path in untracked_paths
                    if _is_source_input(path, tracked=False)
                }
            )
        )
        errors = "; ".join(error for error in (tracked_error, untracked_error) if error)
        return _hash_snapshot_paths(
            root,
            paths,
            method="git-source",
            inventory_error=errors or None,
            read_context=read_context,
        )

    paths, error = _walk_paths(root)
    source_paths = tuple(
        path for path in paths if _is_source_input(path, tracked=False)
    )
    fallback_errors = [error] if error else []
    for result in (tracked, untracked):
        if result is not None and result[1] is not None:
            fallback_errors.append(result[1])
    return _hash_snapshot_paths(
        root,
        source_paths,
        method="filesystem-source",
        inventory_error="; ".join(fallback_errors) or None,
        read_context=read_context,
    )


def workspace_snapshot(
    root: Path,
    timeout: float = 10.0,
    *,
    read_context: PathReadContext | None = None,
) -> WorkspaceSnapshot:
    """Hash relevant tracked and non-ignored bytes, including dirty files."""

    root = root.resolve()
    selected = _git_paths(root, timeout)
    if selected is None:
        paths, inventory_error = _walk_paths(root)
        method = "filesystem"
    else:
        paths, method, inventory_error = selected

    return _hash_snapshot_paths(
        root,
        paths,
        method=method,
        inventory_error=inventory_error,
        read_context=read_context,
    )
