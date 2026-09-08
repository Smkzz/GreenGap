"""Deterministic workspace-byte binding for every analysis."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .model import WorkspaceSnapshot
from .util import (
    MAX_WORKSPACE_FILE_BYTES,
    MAX_WORKSPACE_FILES,
    MAX_WORKSPACE_TOTAL_BYTES,
    bounded_filesystem_paths,
    bounded_git_paths,
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


def _read_snapshot_entry(root: Path, relative: str) -> tuple[bytes, str | None]:
    path = root / Path(relative)
    try:
        return read_limited_bytes(path, MAX_WORKSPACE_FILE_BYTES), None
    except ValueError as exc:
        return b"<UNREADABLE>", f"{relative}: {exc}"


def workspace_snapshot(root: Path, timeout: float = 10.0) -> WorkspaceSnapshot:
    """Hash relevant tracked and non-ignored bytes, including dirty files."""

    root = root.resolve()
    selected = _git_paths(root, timeout)
    if selected is None:
        paths, inventory_error = _walk_paths(root)
        method = "filesystem"
    else:
        paths, method, inventory_error = selected

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
    if len(selected_paths) >= _SNAPSHOT_PARALLEL_MIN_FILES:
        workers = min(_SNAPSHOT_MAX_WORKERS, len(selected_paths))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            index = 0
            while index < len(selected_paths):
                batch = selected_paths[index : index + workers]
                # Never schedule a batch whose worst-case bytes could cross
                # the total-read limit; finish the tail sequentially.
                if total_bytes > MAX_WORKSPACE_TOTAL_BYTES - (workers * MAX_WORKSPACE_FILE_BYTES):
                    for relative in selected_paths[index:]:
                        data, error = _read_snapshot_entry(root, relative)
                        if not consume(relative, data, error):
                            break
                    break
                for relative, (data, error) in zip(
                    batch,
                    executor.map(
                        _read_snapshot_entry,
                        (root,) * len(batch),
                        batch,
                    ),
                    strict=True,
                ):
                    if not consume(relative, data, error):
                        index = len(selected_paths)
                        break
                else:
                    index += len(batch)
    else:
        for relative in selected_paths:
            data, error = _read_snapshot_entry(root, relative)
            if not consume(relative, data, error):
                break
    return WorkspaceSnapshot(digest.hexdigest(), paths, method, tuple(errors))
