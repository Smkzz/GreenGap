"""Measure repeatable local GreenGap overhead without changing a checkout."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import statistics
import sys
import time
import tracemalloc
from ctypes import wintypes
from pathlib import Path
from typing import Any, Literal

from greengap.cli import run_plan
from greengap.report import public_report


def _percentile(values: list[float], percentile: float) -> float:
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = min(len(ordered) - 1, round((len(ordered) - 1) * percentile))
    return ordered[index]


def _process_rss_bytes() -> int | None:
    """Return the current process peak RSS using only platform primitives."""

    if os.name == "nt":
        try:
            win_dll = ctypes.windll

            class ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("page_fault_count", wintypes.DWORD),
                    ("peak_working_set_size", ctypes.c_size_t),
                    ("working_set_size", ctypes.c_size_t),
                    ("quota_peak_paged_pool_usage", ctypes.c_size_t),
                    ("quota_paged_pool_usage", ctypes.c_size_t),
                    ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
                    ("quota_non_paged_pool_usage", ctypes.c_size_t),
                    ("pagefile_usage", ctypes.c_size_t),
                    ("peak_pagefile_usage", ctypes.c_size_t),
                ]

            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            get_current_process = win_dll.kernel32.GetCurrentProcess
            get_current_process.restype = wintypes.HANDLE
            get_process_memory_info = win_dll.psapi.GetProcessMemoryInfo
            get_process_memory_info.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(ProcessMemoryCounters),
                wintypes.DWORD,
            ]
            get_process_memory_info.restype = wintypes.BOOL
            ok = get_process_memory_info(
                get_current_process(),
                ctypes.byref(counters),
                counters.cb,
            )
            return int(counters.peak_working_set_size) if ok else None
        except (AttributeError, OSError, TypeError):
            return None

    try:
        import resource

        getrusage = getattr(resource, "getrusage", None)
        rusage_self = getattr(resource, "RUSAGE_SELF", None)
        if getrusage is None or rusage_self is None:
            return None
        raw = int(getrusage(rusage_self).ru_maxrss)
    except (ImportError, OSError, ValueError):
        return None
    return raw if sys.platform == "darwin" else raw * 1024


def _directory_size_bytes(root: Path) -> int | None:
    """Measure regular-file bytes without following symlinks or entering .git."""

    total = 0
    try:
        for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            dirnames[:] = [name for name in dirnames if name.lower() != ".git"]
            for filename in filenames:
                path = Path(directory) / filename
                if path.is_symlink():
                    continue
                total += path.stat().st_size
    except OSError:
        return None
    return total


def _fixture_definition(size: Literal["small", "medium", "large"]) -> dict[str, int | str]:
    definitions: dict[str, dict[str, int | str]] = {
        "small": {"test_files": 10, "workflow_files": 1, "workflow_shapes": 1},
        "medium": {"test_files": 1_000, "workflow_files": 4, "workflow_shapes": 4},
        "large": {"test_files": 10_000, "workflow_files": 4, "workflow_shapes": 4},
    }
    return {"name": size, **definitions[size]}


def create_fixture(root: Path, size: Literal["small", "medium", "large"]) -> dict[str, int | str]:
    """Create a deterministic, non-executing performance fixture in an empty root."""

    root = root.resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError(f"fixture root must be empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    definition = _fixture_definition(size)
    tests = root / "tests"
    workflows = root / ".github" / "workflows"
    tests.mkdir(parents=True, exist_ok=True)
    workflows.mkdir(parents=True, exist_ok=True)
    test_count = int(definition["test_files"])
    workflow_count = int(definition["workflow_files"])
    for index in range(test_count):
        (tests / f"test_{index:05d}.py").write_text(
            "def test_synthetic_case():\n    assert True\n",
            encoding="utf-8",
        )
    for index in range(workflow_count):
        selected = index % max(1, test_count)
        (workflows / f"ci-{index}.yml").write_text(
            "\n".join(
                (
                    f"name: synthetic-{index}",
                    "on: [push]",
                    "jobs:",
                    "  test:",
                    "    runs-on: ubuntu-latest",
                    "    steps:",
                    "      - uses: actions/checkout@v4",
                    f"      - run: pytest tests/test_{selected:05d}.py",
                    "",
                )
            ),
            encoding="utf-8",
        )
    return definition


def measure(
    root: Path,
    runs: int,
    timeout: float,
    collect: bool,
    *,
    fixture: str | None = None,
    warmup: int = 0,
    fixture_definition: dict[str, int | str] | None = None,
) -> dict[str, Any]:
    durations: list[float] = []
    peaks: list[int] = []
    rss_values: list[int] = []
    disk_deltas: list[int] = []
    outcomes: list[str] = []
    report_bytes = 0
    for _ in range(warmup):
        run_plan(root, timeout=timeout, collect=collect)
    for _ in range(runs):
        disk_before = _directory_size_bytes(root)
        tracemalloc.start()
        started = time.perf_counter()
        report = run_plan(root, timeout=timeout, collect=collect)
        durations.append(time.perf_counter() - started)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
        rss = _process_rss_bytes()
        if rss is not None:
            rss_values.append(rss)
        disk_after = _directory_size_bytes(root)
        if disk_before is not None and disk_after is not None:
            disk_deltas.append(disk_after - disk_before)
        public = public_report(report, root=root, collection_enabled=collect)
        report_bytes = len(json.dumps(public, sort_keys=True, ensure_ascii=True).encode("utf-8"))
        outcomes.append(str(public.get("outcome", "INCOMPLETE")))
    return {
        "fixture": fixture or root.name,
        "fixture_definition": fixture_definition,
        "machine": {
            "os": platform.system(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
        },
        "runs": runs,
        "warmup_runs": warmup,
        "collection_enabled": collect,
        "wall_seconds": durations,
        "p50_wall_seconds": statistics.median(durations),
        "p95_wall_seconds": _percentile(durations, 0.95),
        "peak_python_allocated_bytes": max(peaks),
        "report_json_bytes": report_bytes,
        "outcomes": outcomes,
        "process_rss_bytes": max(rss_values) if rss_values else None,
        "process_rss_bytes_per_run": rss_values,
        "disk_delta_bytes": max(disk_deltas) if disk_deltas else None,
        "disk_delta_bytes_per_run": disk_deltas,
        "measurement_scope": {
            "process_rss": "GreenGap parent process peak RSS; child collection processes are not included",
            "disk_delta": "regular-file byte delta under the fixture root, excluding .git and symlinks",
        },
        "note": (
            "Process RSS uses the platform process API and disk delta covers only regular files under the fixture root."
            if rss_values and disk_deltas
            else "One or more platform measurements were unavailable and remain UNKNOWN."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--trust-collection", action="store_true")
    parser.add_argument("--warmup", type=int, default=0)
    parser.add_argument("--fixture-size", choices=("small", "medium", "large"))
    parser.add_argument(
        "--fixture-root",
        type=Path,
        help="empty disposable root to populate when --fixture-size is provided",
    )
    parser.add_argument("--fixture-name", help="label for an existing fixture root")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.runs < 1 or args.timeout <= 0 or args.warmup < 0:
        parser.error("--runs and --timeout must be positive; --warmup cannot be negative")
    fixture_definition = None
    root = args.root.resolve()
    if args.fixture_size:
        if args.fixture_root is None:
            parser.error("--fixture-root is required with --fixture-size")
        root = args.fixture_root.resolve()
        fixture_definition = create_fixture(root, args.fixture_size)
    elif args.fixture_root is not None:
        parser.error("--fixture-root requires --fixture-size")
    payload = measure(
        root,
        args.runs,
        args.timeout,
        args.trust_collection,
        fixture=args.fixture_name or (args.fixture_size or root.name),
        warmup=args.warmup,
        fixture_definition=fixture_definition,
    )
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
