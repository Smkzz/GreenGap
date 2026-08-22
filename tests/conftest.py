from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path


def write_files(root: Path, files: Mapping[str, str]) -> None:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
