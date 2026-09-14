"""Analyzer-owned pytest collection witness channel."""

from __future__ import annotations

import json
import os
from pathlib import Path


def pytest_collection_finish(session: object) -> None:
    """Write collected node metadata outside pytest's human output stream."""

    output_name = os.environ.get("GREENGAP_COLLECTION_FILE")
    if not output_name:
        return
    items = getattr(session, "items", ())
    nodes: list[dict[str, str]] = []
    for item in items:
        nodeid = str(getattr(item, "nodeid", ""))
        item_path = getattr(item, "path", None)
        if not nodeid or item_path is None:
            continue
        nodes.append({"nodeid": nodeid, "path": str(item_path)})
    payload = {"version": 1, "nodes": nodes}
    Path(output_name).write_text(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
        encoding="utf-8",
    )
