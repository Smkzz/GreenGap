"""Deterministic workspace-byte binding for every analysis."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

from .model import WorkspaceSnapshot
from .util import (
    MAX_WORKSPACE_FILE_BYTES,
    MAX_WORKSPACE_FILES,
    MAX_WORKSPACE_TOTAL_BYTES,
    is_transient_path,
    read_limited_bytes,
)


def _git_paths(root: Path, timeout: float) -> tuple[tuple[str, ...], str] | None:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    raw = result.stdout.decode("utf-8", errors="surrogateescape")
    paths = tuple(
        sorted({item for item in raw.split("\0") if item and not is_transient_path(item)})
    )
    return paths, "git"


def _walk_paths(root: Path) -> tuple[str, ...]:
    paths: list[str] = []
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        relative_dir = Path(directory).relative_to(root)
        dirnames[:] = [
            name
            for name in dirnames
            if not is_transient_path(relative_dir / name) and name.lower() not in {".git"}
        ]
        for filename in filenames:
            relative = (relative_dir / filename).as_posix()
            if not is_transient_path(relative):
                paths.append(relative)
    return tuple(sorted(set(paths)))


def workspace_snapshot(root: Path, timeout: float = 10.0) -> WorkspaceSnapshot:
    """Hash relevant tracked and non-ignored bytes, including dirty files."""

    root = root.resolve()
    selected = _git_paths(root, timeout)
    if selected is None:
        paths, method = _walk_paths(root), "filesystem"
    else:
        paths, method = selected

    digest = hashlib.sha256()
    errors: list[str] = []
    if len(paths) > MAX_WORKSPACE_FILES:
        errors.append(
            f"workspace contains {len(paths)} files; limit is {MAX_WORKSPACE_FILES}"
        )
    total_bytes = 0
    for relative in paths[:MAX_WORKSPACE_FILES]:
        path = root / Path(relative)
        try:
            data = read_limited_bytes(path, MAX_WORKSPACE_FILE_BYTES)
            total_bytes += len(data)
            if total_bytes > MAX_WORKSPACE_TOTAL_BYTES:
                errors.append(
                    f"workspace bytes exceed limit of {MAX_WORKSPACE_TOTAL_BYTES}"
                )
                break
        except ValueError as exc:
            errors.append(f"{relative}: {exc}")
            data = b"<UNREADABLE>"
        encoded_path = relative.replace("\\", "/").encode("utf-8", errors="surrogateescape")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return WorkspaceSnapshot(digest.hexdigest(), paths, method, tuple(errors))
