"""Evidence-only JUnit parsing groundwork for the uncertified witness mode."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import FindingState


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
        return float(value)
    except ValueError:
        return None


def parse_junit(path: Path) -> tuple[JUnitCase, ...]:
    """Parse common JUnit dialects without asserting cross-runner identity."""

    tree = ET.parse(path)
    cases: list[JUnitCase] = []
    for testcase in tree.iter("testcase"):
        skipped = testcase.find("skipped")
        failure = testcase.find("failure")
        error = testcase.find("error")
        marker: ET.Element[str] | None
        if skipped is not None:
            state = FindingState.SKIPPED
            marker = skipped
        elif failure is not None or error is not None:
            state = FindingState.EXECUTED_FAIL
            marker = failure if failure is not None else error
        else:
            state = FindingState.EXECUTED_PASS
            marker = None
        message = ""
        if marker is not None:
            message = marker.get("message", "") or (marker.text or "")
        cases.append(
            JUnitCase(
                classname=testcase.get("classname", ""),
                name=testcase.get("name", ""),
                state=state,
                time=_float_or_none(testcase.get("time")),
                message=message,
                file=testcase.get("file"),
            )
        )
    return tuple(cases)
