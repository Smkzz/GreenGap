"""Shared path, subprocess, and deterministic serialization helpers."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any


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


def normalize_repo_path(root: Path, value: str | Path, base: Path | None = None) -> str:
    raw = Path(value)
    if not raw.is_absolute():
        raw = (base or root) / raw
    return relpath(root, raw)


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
    }
    parts = Path(str(path).replace("\\", "/")).parts
    lowered = {part.lower() for part in parts}
    if lowered & transient:
        return True
    normalized = "/".join(part.lower() for part in parts)
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
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


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
