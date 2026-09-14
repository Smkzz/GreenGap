"""Evidence-only JUnit parsing groundwork for the uncertified witness mode."""

from __future__ import annotations

import math
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .model import FindingState
from .util import MAX_CONFIG_BYTES, MAX_JUNIT_BYTES, MAX_JUNIT_CASES, read_limited_bytes

MAX_JUNIT_NODES = 250_000
MAX_JUNIT_DEPTH = 128
_XML_DECLARATION_ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")



@dataclass(frozen=True)
class JUnitCase:
    classname: str
    name: str
    state: FindingState
    time: float | None = None
    message: str = ""
    file: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "classname": self.classname,
            "name": self.name,
            "state": self.state.value,
            "time": self.time,
            "message": self.message,
            "file": self.file,
        }


def _float_or_none(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) else None


def _reject_entity_declarations(data: bytes) -> None:
    """Reject DTD/entity declarations before stdlib XML parsing can expand them."""

    lowered = data.lower()
    for declaration in ("<!doctype", "<!entity"):
        if any(declaration.encode(encoding) in lowered for encoding in _XML_DECLARATION_ENCODINGS):
            raise ValueError("JUnit XML DTD and entity declarations are not supported")


def parse_junit(path: Path) -> tuple[JUnitCase, ...]:
    """Parse common JUnit dialects without asserting cross-runner identity."""

    data = read_limited_bytes(path, MAX_JUNIT_BYTES)
    _reject_entity_declarations(data)
    parser: Any = ET.XMLPullParser(events=("start", "end"))
    cases: list[JUnitCase] = []
    case_markers: list[dict[str, str]] = []
    depth = 0
    node_count = 0
    try:
        for offset in range(0, len(data), MAX_CONFIG_BYTES):
            parser.feed(data[offset : offset + MAX_CONFIG_BYTES])
            events = cast(Iterator[tuple[str, Any]], parser.read_events())
            for event, element in events:
                if event == "start":
                    node_count += 1
                    if node_count > MAX_JUNIT_NODES:
                        raise ValueError(f"JUnit XML node count exceeds limit of {MAX_JUNIT_NODES}")
                    depth += 1
                    if depth > MAX_JUNIT_DEPTH:
                        raise ValueError(f"JUnit XML nesting exceeds limit of {MAX_JUNIT_DEPTH}")
                    if element.tag == "testcase":
                        case_markers.append({})
                    continue

                if element.tag in {"skipped", "failure", "error"} and case_markers:
                    marker_text = "".join(element.itertext())
                    case_markers[-1][element.tag] = element.get("message", "") or marker_text
                if element.tag == "testcase":
                    if len(cases) >= MAX_JUNIT_CASES:
                        raise ValueError(
                            f"JUnit testcase count exceeds size limit of {MAX_JUNIT_CASES}"
                        )
                    markers = case_markers.pop()
                    if "skipped" in markers:
                        state = FindingState.SKIPPED
                        message = markers["skipped"]
                    elif "failure" in markers or "error" in markers:
                        state = FindingState.EXECUTED_FAIL
                        message = markers.get("failure", markers.get("error", ""))
                    else:
                        state = FindingState.EXECUTED_PASS
                        message = ""
                    cases.append(
                        JUnitCase(
                            classname=element.get("classname", ""),
                            name=element.get("name", ""),
                            state=state,
                            time=_float_or_none(element.get("time")),
                            message=message,
                            file=element.get("file"),
                        )
                    )
                    element.clear()
                elif not case_markers:
                    element.clear()
                depth -= 1
        parser.close()
    except ET.ParseError as exc:
        raise ValueError(f"could not parse JUnit XML: {exc}") from exc
    return tuple(cases)
