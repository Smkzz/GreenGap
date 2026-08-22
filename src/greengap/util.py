"""Shared path, subprocess, and deterministic serialization helpers."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

MAX_CONFIG_BYTES = 1 * 1024 * 1024
MAX_JUNIT_BYTES = 8 * 1024 * 1024
MAX_JUNIT_CASES = 100_000
MAX_MATRIX_ROWS = 256
MAX_WORKFLOW_FILES = 1_024
MAX_WORKSPACE_FILES = 100_000
MAX_WORKSPACE_FILE_BYTES = 8 * 1024 * 1024
MAX_WORKSPACE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_COLLECTION_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_COLLECTION_SECONDS = 300.0


class PathSafetyError(ValueError):
    """A path is outside the repository or crosses a symlink boundary."""


def as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def relpath(root: Path, path: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        relative = path
    value = relative.as_posix()
    return value[2:] if value.startswith("./") else value


def safe_resolve(root: Path, value: str | Path, base: Path | None = None) -> Path:
    """Resolve a repository path without crossing symlinks or the root boundary."""

    root_absolute = Path(os.path.abspath(root))
    root_real = root_absolute.resolve(strict=False)
    raw = Path(value)
    if not raw.is_absolute():
        raw = (base or root_absolute) / raw
    lexical = Path(os.path.abspath(raw))
    try:
        relative = lexical.relative_to(root_absolute)
    except ValueError as exc:
        raise PathSafetyError(f"path escapes repository root: {value}") from exc

    current = root_absolute
    for part in relative.parts:
        current /= part
        try:
            if current.is_symlink():
                raise PathSafetyError(f"path crosses symlink: {current}")
        except OSError as exc:
            raise PathSafetyError(f"could not inspect path: {current}: {exc}") from exc

    resolved = lexical.resolve(strict=False)
    try:
        resolved.relative_to(root_real)
    except ValueError as exc:
        raise PathSafetyError(f"resolved path escapes repository root: {value}") from exc
    return resolved


def normalize_repo_path(root: Path, value: str | Path, base: Path | None = None) -> str:
    return relpath(root, safe_resolve(root, value, base))


def read_limited_bytes(path: Path, limit: int) -> bytes:
    """Read regular-file bytes or stable symlink metadata without following links."""

    for parent in path.parents:
        try:
            if stat.S_ISLNK(parent.lstat().st_mode):
                raise ValueError(f"path crosses symlink: {parent}")
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ValueError(f"could not inspect {parent}: {exc}") from exc
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError(f"could not inspect {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        try:
            target = os.readlink(path)
        except OSError as exc:
            raise ValueError(f"could not read symlink {path}: {exc}") from exc
        encoded = os.fsencode(target)
        if len(encoded) + len(b"SYMLINK\0") > limit:
            raise ValueError(f"symlink target exceeds size limit: {path}")
        return b"SYMLINK\0" + encoded
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"unsupported non-regular file: {path}")
    if info.st_size > limit:
        raise ValueError(f"file exceeds size limit: {path}")
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise ValueError(f"could not read {path}: {exc}") from exc
    if len(data) > limit:
        raise ValueError(f"file exceeds size limit: {path}")
    return data


def read_limited_text(path: Path, limit: int) -> str:
    return read_limited_bytes(path, limit).decode("utf-8", errors="strict")


def is_transient_path(path: str | Path) -> bool:
    transient = {
        ".git",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "node_modules",
        "build",
        "dist",
        ".eggs",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".cache",
        "htmlcov",
        "coverage",
        "reports/raw",
        "qualification/clones",
        "qualification/envs",
    }
    parts = Path(str(path).replace("\\", "/")).parts
    lowered = {part.lower() for part in parts}
    if lowered & transient:
        return True
    normalized = "/".join(part.lower() for part in parts)
    if normalized.startswith("qualification/stage0f"):
        return True
    return any(normalized == item or normalized.startswith(item + "/") for item in transient)


def run_command(
    args: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def json_dump(value: Any) -> str:
    # Escaping non-ASCII characters keeps JSON output usable on legacy Windows
    # consoles whose active code page cannot encode arbitrary repository paths.
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def split_patterns(value: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    if isinstance(value, str):
        parts = tuple(part for part in re.split(r"[\s,]+", value.strip()) if part)
        return parts or default
    if isinstance(value, list | tuple):
        parts = tuple(str(part) for part in value if str(part))
        return parts or default
    return default
