#!/usr/bin/env python3
"""Create deterministic provenance metadata for one exact release build."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_manifest(dist: Path, output: Path, tag: str, commit: str, tree: str) -> None:
    artifacts = sorted(path for path in dist.iterdir() if path.is_file())
    if not artifacts:
        raise ValueError(f"no release artifacts found in {dist}")
    payload = {
        "schemaVersion": 1,
        "tag": tag,
        "commit": commit,
        "tree": tree,
        "artifacts": [
            {"name": path.name, "size": path.stat().st_size, "sha256": _digest(path)}
            for path in artifacts
        ],
    }
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    args = parser.parse_args()
    create_manifest(args.dist, args.output, args.tag, args.commit, args.tree)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
