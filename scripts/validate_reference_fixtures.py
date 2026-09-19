"""Validate the explicit Runtime Witness reference fixtures.

The harness is a development receipt generator, not a hidden runner.  It
copies each source-controlled fixture into a disposable Git checkout and runs
the commands declared by that fixture.  GreenGap supplies only the bounded
identity environment; pytest plugin activation, tox forwarding, uv locking,
and shard selection remain visible in the fixture or in this harness.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT / "src"))

_witness = importlib.import_module("greengap.witness")
_witness_config = importlib.import_module("greengap.witness_config")
WITNESS_PLUGIN_MODULE = _witness.WITNESS_PLUGIN_MODULE
analyze_witnesses = _witness.analyze_witnesses
create_manifest = _witness.create_manifest
execute_witness_command = _witness.execute_witness_command
load_witness = _witness.load_witness
source_snapshot = _witness.source_snapshot
load_explicit_witness_config = _witness_config.load_explicit_witness_config


FIXTURE_NAMES = ("direct-pytest", "tox", "uv", "matrix-shards")
RUN_ID = "reference-run-1"
RUN_ATTEMPT = "1"
REPOSITORY_PREFIX = "greengap-reference"


class ReferenceFixtureError(RuntimeError):
    """A fixture cannot produce a trustworthy validation receipt."""


class ToolUnavailable(ReferenceFixtureError):
    """A required local tool is not available for this development pass."""


@dataclass(frozen=True)
class SurfaceSpec:
    surface_id: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class SurfaceRun:
    surface_id: str
    role: str
    command: tuple[str, ...]
    returncode: int
    fragment_paths: tuple[Path, ...]
    payloads: tuple[dict[str, Any], ...]
    error: str | None

    @property
    def witness_ids(self) -> tuple[str, ...]:
        values: list[str] = []
        for payload in self.payloads:
            context = payload.get("execution_context", {})
            surface = context.get("surface_id")
            shard = context.get("shard") or "-"
            if isinstance(surface, str) and isinstance(shard, str):
                values.append(f"{surface}|{shard}")
        return tuple(sorted(set(values)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface_id": self.surface_id,
            "role": self.role,
            "command": list(self.command),
            "returncode": self.returncode,
            "fragment_paths": [str(path) for path in self.fragment_paths],
            "fragment_count": len(self.fragment_paths),
            "valid_fragment_count": len(self.payloads),
            "witness_ids": list(self.witness_ids),
            "complete_fragments": sum(payload.get("complete") is True for payload in self.payloads),
            "errors": sorted(
                {
                    str(value)
                    for payload in self.payloads
                    for value in payload.get("diagnostics", [])
                }
            ),
            "error": self.error,
        }


def _run_git(root: Path, args: Sequence[str]) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ReferenceFixtureError(f"GIT_COMMAND_FAILED:{args[0] if args else 'unknown'}")
    return completed.stdout.strip()


def _init_fixture_git(root: Path) -> str:
    _run_git(root, ("init", "-q"))
    _run_git(root, ("add", "--all"))
    completed = subprocess.run(
        [
            "git",
            "-c",
            "user.name=GreenGap reference fixture",
            "-c",
            "user.email=greengap-reference-fixture@example.invalid",
            "commit",
            "-qm",
            "reference fixture",
        ],
        cwd=root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ReferenceFixtureError("GIT_FIXTURE_COMMIT_FAILED")
    sha = _run_git(root, ("rev-parse", "HEAD"))
    if len(sha) != 40:
        raise ReferenceFixtureError("GIT_FIXTURE_SHA_INVALID")
    return sha


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="",
    )
    temporary.replace(path)


def _analysis_code(analysis: Any) -> int:
    if analysis.outcome == "COMPLETE":
        return 0
    if analysis.outcome == "BLOCKED":
        return 1
    return 2


def _analysis_receipt(
    name: str,
    analysis: Any,
    *,
    expected_outcome: str,
    expected_code: int,
    selected_file: str | None = None,
    baseline: Any | None = None,
) -> dict[str, Any]:
    actual_code = _analysis_code(analysis)
    false_confident = bool(
        (not analysis.complete and (analysis.not_run_files or actual_code != 2))
        or (expected_outcome == "INCOMPLETE" and actual_code != 2)
    )
    if selected_file is not None:
        false_confident = false_confident or bool(
            analysis.complete
            and analysis.outcome == "COMPLETE"
            and selected_file in analysis.not_run_files
        )
    receipt: dict[str, Any] = {
        "scenario": name,
        "expected_outcome": expected_outcome,
        "expected_exit_code": expected_code,
        "outcome": analysis.outcome,
        "exit_code": actual_code,
        "complete": analysis.complete,
        "collected_files": list(analysis.collected_files),
        "executed_files": list(analysis.executed_files),
        "not_run_files": list(analysis.not_run_files),
        "errors": list(analysis.errors),
        "selected_file": selected_file,
        "false_confident_conclusion": false_confident,
        "passed": actual_code == expected_code and analysis.outcome == expected_outcome,
    }
    if baseline is not None:
        receipt["restored_baseline_equal"] = bool(
            analysis.complete
            and baseline.complete
            and analysis.collected_files == baseline.collected_files
            and analysis.executed_files == baseline.executed_files
            and not analysis.not_run_files
        )
        receipt["passed"] = bool(receipt["passed"] and receipt["restored_baseline_equal"])
    return receipt


def _find_executable(name: str, *fallbacks: Path) -> str | None:
    discovered = shutil.which(name)
    if discovered:
        return discovered
    for fallback in fallbacks:
        if fallback.is_file():
            return str(fallback)
    return None


def _tox_executable(explicit: str | None) -> str:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    source_root = Path(__file__).resolve().parents[1]
    candidates.append(
        source_root.parent
        / "runtime-witness-dev-source-A02"
        / ".venv"
        / "Scripts"
        / "tox.exe"
    )
    value = _find_executable("tox", *candidates)
    if value is None:
        raise ToolUnavailable("TOX_NOT_AVAILABLE")
    return value


def _uv_executable(explicit: str | None) -> str:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(Path(local_app_data) / "hermes" / "bin" / "uv.exe")
    value = _find_executable("uv", *candidates)
    if value is None:
        raise ToolUnavailable("UV_NOT_AVAILABLE")
    return value


def _pytest_command(
    *,
    surface_id: str,
    source_sha: str,
    role: str,
    extra: Sequence[str] = (),
) -> tuple[str, ...]:
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        WITNESS_PLUGIN_MODULE,
        "--greengap-witness-role",
        role,
        "--greengap-surface-id",
        surface_id,
        "--greengap-source-sha",
        source_sha,
        "--greengap-run-id",
        RUN_ID,
        "--greengap-run-attempt",
        RUN_ATTEMPT,
        "--greengap-job-id",
        surface_id,
        "--greengap-provider",
        "local",
    ]
    if role == "collection":
        command.extend(("--collect-only", "--greengap-full-collection"))
    command.extend(extra)
    return tuple(command)


def _fixture_specs(
    fixture: str,
    source_sha: str,
    *,
    tox: str | None = None,
    uv: str | None = None,
) -> tuple[SurfaceSpec, tuple[SurfaceSpec, ...]]:
    collection = SurfaceSpec(
        "collection",
        _pytest_command(surface_id="collection", source_sha=source_sha, role="collection"),
    )
    if fixture == "direct-pytest":
        return collection, (SurfaceSpec("unit-py311", _pytest_command(surface_id="unit-py311", source_sha=source_sha, role="execution")),)
    if fixture == "matrix-shards":
        return collection, (
            SurfaceSpec(
                "unit-py311-shard-0",
                _pytest_command(
                    surface_id="unit-py311-shard-0",
                    source_sha=source_sha,
                    role="execution",
                    extra=("--ignore", "tests/test_b.py", "--ignore", "tests/test_c.py"),
                ),
            ),
            SurfaceSpec(
                "unit-py311-shard-1",
                _pytest_command(
                    surface_id="unit-py311-shard-1",
                    source_sha=source_sha,
                    role="execution",
                    extra=("--ignore", "tests/test_a.py"),
                ),
            ),
        )
    if fixture == "tox":
        if tox is None:
            raise ToolUnavailable("TOX_NOT_AVAILABLE")
        return collection, (
            SurfaceSpec("unit-py311", (tox, "-e", "execution")),
        )
    if fixture == "uv":
        if uv is None:
            raise ToolUnavailable("UV_NOT_AVAILABLE")
        return collection, (
            SurfaceSpec(
                "unit-py311",
                (uv, "run", "--locked", "pytest", "-p", WITNESS_PLUGIN_MODULE),
            ),
        )
    raise ReferenceFixtureError("FIXTURE_NAME_INVALID")


def _collection_spec_for(fixture: str, source_sha: str, *, tox: str | None, uv: str | None) -> SurfaceSpec:
    if fixture == "tox":
        if tox is None:
            raise ToolUnavailable("TOX_NOT_AVAILABLE")
        return SurfaceSpec("collection", (tox, "-e", "collection"))
    if fixture == "uv":
        if uv is None:
            raise ToolUnavailable("UV_NOT_AVAILABLE")
        return SurfaceSpec(
            "collection",
            (
                uv,
                "run",
                "--locked",
                "pytest",
                "-p",
                WITNESS_PLUGIN_MODULE,
                "--greengap-witness-role",
                "collection",
                "--greengap-surface-id",
                "collection",
                "--greengap-source-sha",
                source_sha,
                "--greengap-run-id",
                RUN_ID,
                "--greengap-run-attempt",
                RUN_ATTEMPT,
                "--greengap-job-id",
                "collection",
                "--greengap-provider",
                "local",
                "--collect-only",
                "--greengap-full-collection",
            ),
        )
    return SurfaceSpec(
        "collection",
        _pytest_command(surface_id="collection", source_sha=source_sha, role="collection"),
    )


def _execution_spec_with_omission(fixture: str, spec: SurfaceSpec, selected: str) -> SurfaceSpec:
    if fixture == "tox":
        return SurfaceSpec(spec.surface_id, (*spec.command, "--", "--ignore", selected))
    return SurfaceSpec(spec.surface_id, (*spec.command, "--ignore", selected))


def _run_surface(
    target: Path,
    spec: SurfaceSpec,
    *,
    fixture: str,
    role: str,
    source_sha: str,
    repository: str,
    evidence_root: Path,
) -> SurfaceRun:
    destination = evidence_root / spec.surface_id
    config_sha256 = hashlib.sha256((target / ".greengap.yml").read_bytes()).hexdigest()
    extra_environment = {"UV_CACHE_DIR": os.environ.get("UV_CACHE_DIR", "")}
    if fixture in {"direct-pytest", "matrix-shards"}:
        # The direct fixtures use the harness interpreter.  tox and uv own
        # their target environments and must not receive host site-packages.
        extra_environment["PYTHONPATH"] = os.environ.get("PYTHONPATH", "")
    result = execute_witness_command(
        target,
        spec.command,
        role=role,
        output_dir=str(destination),
        source_commit=source_sha,
        repository=repository,
        surface_id=spec.surface_id,
        run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT,
        config_sha256=config_sha256,
        extra_environment=extra_environment,
        timeout=300.0,
    )
    payloads: list[dict[str, Any]] = []
    paths: list[Path] = []
    errors: list[str] = []
    for name in result.fragment_names:
        path = destination / name
        paths.append(path)
        try:
            payloads.append(load_witness(path))
        except (OSError, ValueError, TypeError) as exc:
            errors.append(type(exc).__name__)
    error = result.error or ("WITNESS_FRAGMENT_INVALID" if errors else None)
    return SurfaceRun(
        spec.surface_id,
        role,
        spec.command,
        result.returncode,
        tuple(paths),
        tuple(payloads),
        error,
    )


def _write_manifest(target: Path, output_root: Path, collection: SurfaceRun, execution: Sequence[SurfaceRun]) -> Path:
    if len(collection.payloads) != 1:
        raise ReferenceFixtureError("COLLECTION_FRAGMENT_COUNT_INVALID")
    config = load_explicit_witness_config(target / ".greengap.yml")
    manifest = create_manifest(collection.payloads[0], execution_witness_ids=(), explicit_config=config)
    path = output_root / "manifest.json"
    _write_json(path, manifest)
    return path


def _copy_execution_paths(paths: Sequence[Path], destination: Path, *, mode: str) -> tuple[Path, ...]:
    copied: list[Path] = []
    for index, path in enumerate(paths):
        target = destination / f"execution-{index}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        if mode == "malformed" and index == 0:
            target.write_text("{not-json\n", encoding="utf-8")
        elif mode == "source-mismatch" and index == 0:
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["repository_identity"]["git_sha"] = "0" * 40
            _write_json(target, payload)
        else:
            shutil.copy2(path, target)
        copied.append(target)
    return tuple(copied)


def _target_source_equal(initial: Any, current: Any) -> bool:
    return bool(
        initial.complete
        and current.complete
        and initial.fingerprint == current.fingerprint
        and initial.files == current.files
    )


def validate_fixture(
    fixture: str,
    *,
    output_root: Path,
    tox: str | None,
    uv: str | None,
) -> dict[str, Any]:
    fixture_root = output_root / fixture
    target = fixture_root / "target"
    source_fixture = Path(__file__).resolve().parents[1] / "examples" / "reference-fixtures" / fixture
    if not source_fixture.is_dir():
        raise ReferenceFixtureError("FIXTURE_DIRECTORY_MISSING")
    shutil.copytree(source_fixture, target)
    source_sha = _init_fixture_git(target)
    repository = f"{REPOSITORY_PREFIX}/{fixture.replace('-', '_')}"
    collection_spec = _collection_spec_for(fixture, source_sha, tox=tox, uv=uv)
    _unused_collection, execution_specs = _fixture_specs(fixture, source_sha, tox=tox, uv=uv)
    initial_source = source_snapshot(target, timeout=10.0)
    receipt: dict[str, Any] = {
        "fixture": fixture,
        "repository": repository,
        "source_sha": source_sha,
        "source_snapshot": initial_source.fingerprint,
        "status": "STARTED",
        "false_confident_conclusions": 0,
    }

    collection_run = _run_surface(
        target,
        collection_spec,
        fixture=fixture,
        role="collection",
        source_sha=source_sha,
        repository=repository,
        evidence_root=fixture_root / "baseline" / "collection",
    )
    baseline_execution = tuple(
        _run_surface(
            target,
            spec,
            fixture=fixture,
            role="execution",
            source_sha=source_sha,
            repository=repository,
            evidence_root=fixture_root / "baseline" / "execution",
        )
        for spec in execution_specs
    )
    manifest_path = _write_manifest(target, fixture_root / "baseline", collection_run, baseline_execution)
    collection_paths = collection_run.fragment_paths
    baseline_execution_paths = tuple(path for run in baseline_execution for path in run.fragment_paths)
    baseline = analyze_witnesses(manifest_path, collection_paths, baseline_execution_paths)
    receipt["commands"] = {
        "collection": collection_run.to_dict(),
        "baseline_execution": [run.to_dict() for run in baseline_execution],
    }
    baseline_receipt = _analysis_receipt("baseline", baseline, expected_outcome="COMPLETE", expected_code=0)
    receipt["baseline"] = baseline_receipt

    selected_candidates = sorted(set(baseline.collected_files) & set(baseline.executed_files))
    selected_file = selected_candidates[0] if baseline.complete and selected_candidates else None
    receipt["selected_omission_file"] = selected_file
    omission_receipt: dict[str, Any]
    if selected_file is None:
        omission_receipt = {
            "scenario": "omission",
            "passed": False,
            "status": "NOT_RUN_BASELINE_INCOMPLETE",
            "selected_file": None,
            "false_confident_conclusion": False,
        }
    else:
        omission_specs = tuple(
            _execution_spec_with_omission(fixture, spec, selected_file)
            if any(selected_file in payload.get("execution", {}).get("call_executed_files", []) for payload in run.payloads)
            else spec
            for spec, run in zip(execution_specs, baseline_execution, strict=True)
        )
        omission_runs = tuple(
            _run_surface(
                target,
                spec,
                fixture=fixture,
                role="execution",
                source_sha=source_sha,
                repository=repository,
                evidence_root=fixture_root / "omission" / "execution",
            )
            for spec in omission_specs
        )
        omission_paths = tuple(path for run in omission_runs for path in run.fragment_paths)
        omission_analysis = analyze_witnesses(manifest_path, collection_paths, omission_paths)
        omission_receipt = _analysis_receipt(
            "omission",
            omission_analysis,
            expected_outcome="BLOCKED",
            expected_code=1,
            selected_file=selected_file,
        )
        omission_receipt["commands"] = [run.to_dict() for run in omission_runs]
    receipt["omission"] = omission_receipt

    missing_paths = baseline_execution_paths[:-1]
    missing = analyze_witnesses(manifest_path, collection_paths, missing_paths)
    receipt["missing_witness"] = _analysis_receipt(
        "missing-witness", missing, expected_outcome="INCOMPLETE", expected_code=2
    )

    malformed_paths = _copy_execution_paths(
        baseline_execution_paths,
        fixture_root / "malformed",
        mode="malformed",
    )
    malformed = analyze_witnesses(manifest_path, collection_paths, malformed_paths)
    receipt["malformed_witness"] = _analysis_receipt(
        "malformed-witness", malformed, expected_outcome="INCOMPLETE", expected_code=2
    )

    mismatch_paths = _copy_execution_paths(
        baseline_execution_paths,
        fixture_root / "source-mismatch",
        mode="source-mismatch",
    )
    mismatch = analyze_witnesses(manifest_path, collection_paths, mismatch_paths)
    receipt["source_mismatch"] = _analysis_receipt(
        "source-mismatch", mismatch, expected_outcome="INCOMPLETE", expected_code=2
    )

    restored_runs = tuple(
        _run_surface(
            target,
            spec,
            fixture=fixture,
            role="execution",
            source_sha=source_sha,
            repository=repository,
            evidence_root=fixture_root / "restored" / "execution",
        )
        for spec in execution_specs
    )
    restored_paths = tuple(path for run in restored_runs for path in run.fragment_paths)
    restored = analyze_witnesses(manifest_path, collection_paths, restored_paths)
    restoration_source = source_snapshot(target, timeout=10.0)
    restoration = _analysis_receipt(
        "restored",
        restored,
        expected_outcome="COMPLETE",
        expected_code=0,
        baseline=baseline,
    )
    restoration["source_restored"] = _target_source_equal(initial_source, restoration_source)
    restoration["passed"] = bool(restoration["passed"] and restoration["source_restored"])
    restoration["commands"] = [run.to_dict() for run in restored_runs]
    receipt["restoration"] = restoration

    scenarios = [
        receipt["baseline"],
        receipt["omission"],
        receipt["missing_witness"],
        receipt["malformed_witness"],
        receipt["source_mismatch"],
        receipt["restoration"],
    ]
    receipt["false_confident_conclusions"] = sum(
        bool(scenario.get("false_confident_conclusion")) for scenario in scenarios
    )
    receipt["status"] = "PASS" if all(bool(scenario.get("passed")) for scenario in scenarios) else "FAIL"
    _write_json(fixture_root / "fixture-receipt.json", receipt)
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", choices=("all", *FIXTURE_NAMES), default="all")
    parser.add_argument("--output", type=Path, help="evidence directory; defaults to a timestamped sibling")
    parser.add_argument("--tox-executable")
    parser.add_argument("--uv-executable")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    source_root = Path(__file__).resolve().parents[1]
    output_root = (args.output or source_root.parent / (
        "greengap-explicit-runtime-witness-reference-"
        + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    )).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    fixtures = FIXTURE_NAMES if args.fixture == "all" else (args.fixture,)
    tox: str | None = None
    uv: str | None = None
    try:
        if "tox" in fixtures:
            tox = _tox_executable(args.tox_executable)
        if "uv" in fixtures:
            uv = _uv_executable(args.uv_executable)
    except ToolUnavailable as exc:
        report = {"status": "NOT_RUN", "error": str(exc), "fixtures": list(fixtures)}
        _write_json(output_root / "reference-fixtures-report.json", report)
        print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
        return 2

    previous_provider = os.environ.get("GREENGAP_PROVIDER")
    previous_uv_cache = os.environ.get("UV_CACHE_DIR")
    os.environ["GREENGAP_PROVIDER"] = "local"
    os.environ["UV_CACHE_DIR"] = str(output_root / "uv-cache")
    results: list[dict[str, Any]] = []
    try:
        for fixture in fixtures:
            try:
                results.append(validate_fixture(fixture, output_root=output_root, tox=tox, uv=uv))
            except ToolUnavailable as exc:
                results.append({"fixture": fixture, "status": "NOT_RUN", "error": str(exc)})
            except (OSError, ReferenceFixtureError, ValueError, TypeError, json.JSONDecodeError) as exc:
                results.append({"fixture": fixture, "status": "FAIL", "error": str(exc)})
    finally:
        if previous_provider is None:
            os.environ.pop("GREENGAP_PROVIDER", None)
        else:
            os.environ["GREENGAP_PROVIDER"] = previous_provider
        if previous_uv_cache is None:
            os.environ.pop("UV_CACHE_DIR", None)
        else:
            os.environ["UV_CACHE_DIR"] = previous_uv_cache

    report = {
        "schema_version": 1,
        "artifact_type": "greengap_explicit_runtime_witness_reference_fixture_report",
        "status": "PASS" if results and all(item.get("status") == "PASS" for item in results) else "FAIL",
        "fixtures": results,
        "false_confident_conclusions": sum(
            int(item.get("false_confident_conclusions", 0)) for item in results
        ),
        "output_root": str(output_root),
    }
    if any(item.get("status") == "NOT_RUN" for item in results):
        report["status"] = "NOT_RUN"
    _write_json(output_root / "reference-fixtures-report.json", report)
    print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2 if report["status"] == "NOT_RUN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
