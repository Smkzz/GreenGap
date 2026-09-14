"""Compare production timing with the legacy instrumented performance method."""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Literal

from measure_performance import (
    _directory_size_bytes,
    _fixture_definition,
    _percentile,
    _process_rss_bytes,
    create_fixture,
    measure,
)

from greengap.cli import run_plan
from greengap.report import public_report

FixtureSize = Literal["small", "medium", "large"]
Mode = Literal["production", "instrumented", "harness"]


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "wall_seconds": values,
        "p50_wall_seconds": statistics.median(values),
        "p95_wall_seconds": _percentile(values, 0.95),
    }


def _measure_production(
    root: Path,
    runs: int,
    timeout: float,
    collect: bool,
    warmup: int,
    fixture_definition: dict[str, int | str],
) -> dict[str, Any]:
    """Measure only the uninstrumented production analysis call."""

    for _ in range(warmup):
        run_plan(root, timeout=timeout, collect=collect)

    durations: list[float] = []
    report_durations: list[float] = []
    rss_values: list[int] = []
    disk_deltas: list[int] = []
    outcomes: list[str] = []
    report_bytes = 0
    for _ in range(runs):
        disk_before = _directory_size_bytes(root)
        started = time.perf_counter()
        report = run_plan(root, timeout=timeout, collect=collect)
        durations.append(time.perf_counter() - started)

        report_started = time.perf_counter()
        public = public_report(report, root=root, collection_enabled=collect)
        report_bytes = len(
            json.dumps(public, sort_keys=True, ensure_ascii=True).encode("utf-8")
        )
        report_durations.append(time.perf_counter() - report_started)

        rss = _process_rss_bytes()
        if rss is not None:
            rss_values.append(rss)
        disk_after = _directory_size_bytes(root)
        if disk_before is not None and disk_after is not None:
            disk_deltas.append(disk_after - disk_before)
        outcomes.append(str(public.get("outcome", "INCOMPLETE")))

    return {
        "mode": "production_uninstrumented",
        "instrumentation": ["none"],
        "fixture_definition": fixture_definition,
        "runs": runs,
        "warmup_runs": warmup,
        "collection_enabled": collect,
        **_summary(durations),
        "report_serialization_wall_seconds": report_durations,
        "report_serialization_p50_seconds": statistics.median(report_durations),
        "report_serialization_p95_seconds": _percentile(report_durations, 0.95),
        "peak_process_rss_bytes": max(rss_values) if rss_values else None,
        "process_rss_bytes_per_run": rss_values,
        "report_json_bytes": report_bytes,
        "disk_delta_bytes": max(disk_deltas) if disk_deltas else None,
        "disk_delta_bytes_per_run": disk_deltas,
        "outcomes": outcomes,
        "measurement_scope": {
            "timed_wall": "run_plan only; no tracemalloc, profiler, debugger, or coverage instrumentation",
            "report_serialization": "public_report and JSON serialization measured after run_plan",
            "process_rss": "GreenGap parent process peak RSS from the platform API",
            "disk_delta": "regular-file byte delta under the fixture root, excluding .git and symlinks",
        },
    }


def _measure_harness(
    root: Path,
    runs: int,
    timeout: float,
    collect: bool,
    warmup: int,
    fixture_definition: dict[str, int | str],
) -> dict[str, Any]:
    """Measure report and disk/RSS instrumentation without analysis timing."""

    report = run_plan(root, timeout=timeout, collect=collect)

    def report_serialization() -> float:
        started = time.perf_counter()
        public = public_report(report, root=root, collection_enabled=collect)
        json.dumps(public, sort_keys=True, ensure_ascii=True)
        return time.perf_counter() - started

    def filesystem_measurement() -> float:
        started = time.perf_counter()
        _directory_size_bytes(root)
        _process_rss_bytes()
        _directory_size_bytes(root)
        return time.perf_counter() - started

    for _ in range(warmup):
        report_serialization()
        filesystem_measurement()

    report_durations = [report_serialization() for _ in range(runs)]
    measurement_durations = [filesystem_measurement() for _ in range(runs)]
    return {
        "mode": "harness_overhead",
        "instrumentation": ["report serialization", "disk measurement", "RSS measurement"],
        "fixture_definition": fixture_definition,
        "runs": runs,
        "warmup_runs": warmup,
        "collection_enabled": collect,
        "report_serialization": _summary(report_durations),
        "filesystem_and_rss_measurement": _summary(measurement_durations),
        "measurement_scope": {
            "analysis": "not included; one un-timed run_plan call only supplies a report object",
            "report_serialization": "public_report and JSON serialization of the same report object",
            "filesystem_and_rss_measurement": "two fixture byte walks plus platform RSS query",
        },
    }


def _single_mode(
    mode: Mode,
    root: Path,
    runs: int,
    timeout: float,
    collect: bool,
    warmup: int,
    fixture_size: FixtureSize,
) -> dict[str, Any]:
    definition = _fixture_definition(fixture_size)
    if mode == "production":
        return _measure_production(root, runs, timeout, collect, warmup, definition)
    if mode == "harness":
        return _measure_harness(root, runs, timeout, collect, warmup, definition)
    result = measure(
        root,
        runs,
        timeout,
        collect,
        fixture=fixture_size,
        warmup=warmup,
        fixture_definition=definition,
    )
    return {
        "mode": "legacy_tracemalloc_instrumented",
        "instrumentation": ["tracemalloc"],
        **result,
        "measurement_scope": {
            **result["measurement_scope"],
            "timed_wall": "existing scripts/measure_performance.py method, including tracemalloc overhead",
        },
    }


def _run_child(
    mode: Mode,
    root: Path,
    runs: int,
    timeout: float,
    collect: bool,
    warmup: int,
    fixture_size: FixtureSize,
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--mode",
        mode,
        "--root",
        str(root),
        "--fixture-size",
        fixture_size,
        "--runs",
        str(runs),
        "--timeout",
        str(timeout),
        "--warmup",
        str(warmup),
    ]
    if collect:
        command.append("--trust-collection")
    environment = os.environ.copy()
    completed = subprocess.run(command, check=True, capture_output=True, text=True, env=environment)
    return json.loads(completed.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("all", "production", "instrumented", "harness"), default="all")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--fixture-size", choices=("small", "medium", "large"), required=True)
    parser.add_argument("--fixture-root", type=Path)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--trust-collection", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.runs < 1 or args.timeout <= 0 or args.warmup < 0:
        parser.error("--runs and --timeout must be positive; --warmup cannot be negative")

    root = args.root.resolve()
    fixture_size: FixtureSize = args.fixture_size
    fixture_root = args.fixture_root.resolve() if args.fixture_root else root
    fixture_definition: dict[str, int | str]
    fixture_creation_seconds: float | None = None
    if args.mode == "all":
        if args.fixture_root is None:
            parser.error("--fixture-root is required with --mode all")
        started = time.perf_counter()
        fixture_definition = create_fixture(fixture_root, fixture_size)
        fixture_creation_seconds = time.perf_counter() - started
        methods = {
            mode: _run_child(
                mode,
                fixture_root,
                args.runs,
                args.timeout,
                args.trust_collection,
                args.warmup,
                fixture_size,
            )
            for mode in ("production", "instrumented", "harness")
        }
        payload: dict[str, Any] = {
            "receipt_type": "greengap-performance-methodology",
            "fixture": fixture_size,
            "fixture_definition": fixture_definition,
            "fixture_root": str(fixture_root),
            "fixture_creation_seconds": fixture_creation_seconds,
            "machine": {
                "os": platform.system(),
                "os_release": platform.release(),
                "architecture": platform.machine(),
                "python": platform.python_version(),
            },
            "runs": args.runs,
            "warmup_runs": args.warmup,
            "collection_enabled": args.trust_collection,
            "methods": methods,
            "decision": {
                "slo_seconds": 5.0,
                "production_path_p95_seconds": methods["production"]["p95_wall_seconds"],
                "production_performance": (
                    "PASS"
                    if methods["production"]["p95_wall_seconds"] <= 5.0
                    else "BLOCKED"
                ),
                "legacy_instrumented_p95_seconds": methods["instrumented"]["p95_wall_seconds"],
                "previous_timing_miss_classification": (
                    "BENCHMARK_INSTRUMENTATION_DISTORTION"
                    if methods["production"]["p95_wall_seconds"] <= 5.0
                    else "PRODUCTION_PATH_TIMING_MISS"
                ),
            },
            "notes": [
                "Production timing excludes tracemalloc and measures only run_plan; report serialization and platform measurements are recorded separately.",
                "The legacy method is delegated to scripts/measure_performance.py unchanged for comparability.",
                "Each method runs in a fresh child process against the same deterministic fixture.",
            ],
        }
    else:
        payload = _single_mode(
            args.mode,
            root,
            args.runs,
            args.timeout,
            args.trust_collection,
            args.warmup,
            fixture_size,
        )

    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
