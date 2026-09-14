"""Run one bounded explicit-integration cycle against the A01-A09 corpus.

The corpus checkouts are inputs, not source trees owned by this repository.
This script copies each pinned checkout into a new disposable Git repository,
adds only the explicit Witness contract, and records all receipts outside the
target.  It intentionally does not inspect or rewrite a target workflow.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_ROOT = PROJECT_ROOT.parent
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT.parent / "explicit-runtime-witness-development-1"
WITNESS_PLUGIN_MODULE = "greengap.pytest_witness"
RUN_ID = "explicit-cohort-cycle-1"
RUN_ATTEMPT = "1"
MAX_COMMAND_SECONDS = 900.0

sys.path.insert(0, str(PROJECT_ROOT / "src"))
from greengap.witness import (  # noqa: E402
    WitnessError,
    analyze_witnesses,
    create_manifest,
    execute_witness_command,
    load_witness,
)
from greengap.witness_config import (  # noqa: E402
    ExplicitWitnessConfig,
    load_explicit_witness_config,
)


@dataclass(frozen=True)
class CohortCase:
    case_id: str
    repository: str
    upstream_sha: str
    mode: str
    focus_paths: tuple[str, ...]
    pythonpath: tuple[str, ...]
    dependencies: tuple[str, ...] = ()
    pytest_args: tuple[str, ...] = ()
    locked: bool = False
    uv_groups: tuple[str, ...] = ()
    target_plugins: tuple[str, ...] = ()

    @property
    def execution_surface(self) -> str:
        return f"{self.case_id.lower()}-unit-py313"

    @property
    def source_name(self) -> str:
        return f"runtime-witness-dev-source-{self.case_id}"


CASES = (
    CohortCase(
        "A01",
        "schireson/pytest-alembic",
        "4687f6524bd2e54780a1e8baad5731f2d3c5b3d5",
        "uv",
        ("tests/test_config.py", "tests/test_revision_data.py"),
        ("src",),
        locked=True,
        uv_groups=("all",),
    ),
    CohortCase(
        "A02",
        "pytest-dev/cookiecutter-pytest-plugin",
        "8f38e95b344f07071c1adada1fe209137c7effab",
        "tox",
        ("tests/test_create_template.py",),
        (),
        ("pytest>=8,<10", "pytest-cookies"),
    ),
    CohortCase(
        "A03",
        "pytest-dev/pytest-django",
        "67f97981cd444cabbbe4562ff172c466d85b4d1b",
        "tox",
        ("tests/test_runner.py",),
        (),
        ("pytest>=8,<10", "Django>=5.2,<6", "pytest-xdist"),
    ),
    CohortCase(
        "A04",
        "pytest-dev/pytest-testinfra",
        "04cccc3969ab786e88e2d67462c409c8778005e8",
        "uv",
        ("test/test_invocation.py",),
        ("src",),
        ("pytest>=8,<10", "pytest-cov", "pytest-xdist"),
        pytest_args=("--noconftest",),
    ),
    CohortCase(
        "A05",
        "avast/pytest-docker",
        "1ab8146b2f1c14cd1a2058ee576e4604f4c39c89",
        "uv",
        ("tests/test_docker_ip.py", "tests/test_dockercomposeexecutor.py"),
        ("src",),
        ("pytest>=8,<10", "attrs>=19.2,<26"),
    ),
    CohortCase(
        "A06",
        "microsoft/playwright-pytest",
        "d9bdbb39087fb026bf7e4be537008098825585ee",
        "uv",
        ("tests/test_sync.py",),
        ("pytest-playwright", "pytest-playwright-asyncio"),
        (
            "pytest>=8,<10",
            "pytest-cov",
            "pytest-xdist",
            "pytest-asyncio==1.3.0",
            "playwright>=1.60",
            "Django==4.2.24",
        ),
    ),
    CohortCase(
        "A07",
        "pytest-dev/pytest-env",
        "7ddd152601728be7635fb5063ac5eec70a044a1c",
        "uv",
        ("tests/test_version.py",),
        ("src",),
        ("pytest>=8,<10", "python-dotenv>=1.2.2"),
    ),
    CohortCase(
        "A08",
        "xmlrunner/unittest-xml-reporting",
        "ea4c4d66d316afcb05da682c998a6be641ec6045",
        "tox",
        ("tests/builder_test.py", "tests/discovery_test.py"),
        (),
        ("pytest>=8,<10", "lxml"),
    ),
    CohortCase(
        "A09",
        "TheKevJames/coveralls-python",
        "4c2d9e28d6ba4ccb87c36c1a9a8e49dabe399af7",
        "uv",
        ("tests/api_test.py", "tests/git_test.py"),
        (),
        locked=True,
        uv_groups=("dev",),
    ),
)

IGNORED_COPY_NAMES = {
    ".git",
    ".venv",
    ".tox",
    ".nox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    "witness-out-manual",
}


class CohortValidationError(RuntimeError):
    """A disposable cohort case cannot produce trustworthy evidence."""


def _git(root: Path, args: Sequence[str], *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _git_value(root: Path, expression: str) -> str:
    result = _git(root, ("rev-parse", expression))
    value = result.stdout.strip()
    if result.returncode != 0 or not value:
        raise CohortValidationError(f"GIT_IDENTITY_UNAVAILABLE:{expression}")
    return value


def _copy_ignore(_directory: str, names: list[str]) -> list[str]:
    return [name for name in names if name in IGNORED_COPY_NAMES or name.startswith(".pytest-")]


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="",
    )
    temporary.replace(path)


def _surface_config(case: CohortCase) -> str:
    return (
        "witness:\n"
        "  collection: collection\n"
        "  required:\n"
        f"    - {case.execution_surface}\n"
    )


def _pytest_config(case: CohortCase) -> str:
    parents = {str(Path(path).parent).replace("\\", "/") for path in case.focus_paths}
    if len(parents) != 1:
        raise CohortValidationError("FOCUS_TEST_DIRECTORY_INVALID")
    lines = ["[pytest]", "testpaths =", f"    {next(iter(parents))}", "python_files ="]
    lines.extend(f"    {Path(path).name}" for path in case.focus_paths)
    lines.extend(("addopts =", "doctest_glob = __greengap_never__"))
    if case.case_id == "A03":
        lines.append("DJANGO_SETTINGS_MODULE = pytest_django_test.settings_sqlite_file")
    return "\n".join(lines) + "\n"


def _tox_config(case: CohortCase) -> str:
    dependencies = "\n".join(
        f"    {value}" for value in ("PyYAML>=6.0", *case.dependencies)
    )
    plugins = " ".join(f"-p {value}" for value in case.target_plugins)
    plugin_args = f"{plugins} " if plugins else ""
    return (
        "[tox]\n"
        "env_list = greengap\n"
        "skipsdist = true\n"
        "\n"
        "[testenv]\n"
        "basepython = python\n"
        "skip_install = true\n"
        "deps =\n"
        f"{dependencies}\n"
        "pass_env =\n"
        "    GREENGAP_*\n"
        "    PYTHONPATH\n"
        "commands =\n"
        f"    python -m pytest {plugin_args}-p {WITNESS_PLUGIN_MODULE} -c .greengap-pytest.ini --doctest-glob=__greengap_never__ {{posargs}}\n"
        "\n"
        "[testenv:greengap-collection]\n"
        "commands =\n"
        f"    python -m pytest {plugin_args}-p {WITNESS_PLUGIN_MODULE} -c .greengap-pytest.ini --doctest-glob=__greengap_never__ --collect-only --greengap-full-collection\n"
    )


def _initialize_target(source: Path, target: Path, case: CohortCase) -> tuple[str, str, list[str]]:
    if not source.is_dir():
        raise CohortValidationError(f"SOURCE_CHECKOUT_MISSING:{source}")
    original_sha = _git_value(source, "HEAD")
    if original_sha.lower() != case.upstream_sha:
        raise CohortValidationError(
            f"UPSTREAM_DRIFT:{original_sha.lower()}:{case.upstream_sha}"
        )
    shutil.copytree(source, target, ignore=_copy_ignore)
    _write_text(target / ".greengap.yml", _surface_config(case))
    _write_text(target / ".greengap-pytest.ini", _pytest_config(case))
    changed = [".greengap.yml", ".greengap-pytest.ini"]
    if case.mode == "tox":
        _write_text(target / ".greengap-tox.ini", _tox_config(case))
        changed.append(".greengap-tox.ini")
    init = _git(target, ("init", "-q"))
    if init.returncode != 0:
        raise CohortValidationError("TARGET_GIT_INIT_FAILED")
    add = _git(target, ("add", "--all"))
    if add.returncode != 0:
        raise CohortValidationError("TARGET_GIT_ADD_FAILED")
    commit = _git(
        target,
        (
            "-c",
            "user.name=GreenGap explicit cohort",
            "-c",
            "user.email=greengap-explicit-cohort@example.invalid",
            "commit",
            "-qm",
            "explicit GreenGap Witness integration",
        ),
    )
    if commit.returncode != 0:
        raise CohortValidationError("TARGET_GIT_COMMIT_FAILED")
    adapted_sha = _git_value(target, "HEAD")
    return original_sha.lower(), adapted_sha.lower(), changed


def _resolve_tool(name: str, explicit: str | None, fallback: Path) -> str:
    candidates = [Path(explicit)] if explicit else []
    discovered = shutil.which(name)
    if discovered:
        candidates.append(Path(discovered))
    candidates.append(fallback)
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise CohortValidationError(f"{name.upper()}_NOT_AVAILABLE")


def _pytest_command(case: CohortCase, *, uv: str, omission: str | None = None) -> tuple[str, ...]:
    if case.mode != "uv":
        raise CohortValidationError("PYTEST_COMMAND_MODE_INVALID")
    command: list[str] = [uv, "run"]
    if case.locked:
        command.append("--frozen")
        if case.uv_groups == ("all",):
            command.append("--all-groups")
        else:
            for group in case.uv_groups:
                command.extend(("--group", group))
    else:
        command.append("--no-project")
        for dependency in ("PyYAML>=6.0", *case.dependencies):
            command.extend(("--with", dependency))
    command.extend(
        (
            "python",
            "-m",
            "pytest",
            "-c",
            ".greengap-pytest.ini",
            "--doctest-glob=__greengap_never__",
            "-p",
            WITNESS_PLUGIN_MODULE,
        )
    )
    command.extend(case.pytest_args)
    if omission is not None:
        command.extend(("--ignore", omission))
    return tuple(command)


def _tox_command(case: CohortCase, *, tox: str, target: Path, omission: str | None = None) -> tuple[str, ...]:
    if case.mode != "tox":
        raise CohortValidationError("TOX_COMMAND_MODE_INVALID")
    command: list[str] = [tox, "-c", ".greengap-tox.ini", "-e", "greengap"]
    if omission is not None:
        command.extend(("--", "--ignore", omission))
    _ = target
    return tuple(command)


def _tox_collection_command(tox: str) -> tuple[str, ...]:
    return (tox, "-c", ".greengap-tox.ini", "-e", "greengap-collection")


@contextmanager
def _target_environment(target: Path, case: CohortCase, output_root: Path) -> Iterator[None]:
    prior_pythonpath = os.environ.get("PYTHONPATH")
    prior_uv_cache = os.environ.get("UV_CACHE_DIR")
    prior_provider = os.environ.get("GREENGAP_PROVIDER")
    paths = [str(target / value) for value in case.pythonpath]
    paths.append(str(target))
    os.environ["PYTHONPATH"] = os.pathsep.join(paths)
    os.environ["UV_CACHE_DIR"] = str(output_root / "uv-cache")
    os.environ["GREENGAP_PROVIDER"] = "local"
    try:
        yield
    finally:
        if prior_pythonpath is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = prior_pythonpath
        if prior_uv_cache is None:
            os.environ.pop("UV_CACHE_DIR", None)
        else:
            os.environ["UV_CACHE_DIR"] = prior_uv_cache
        if prior_provider is None:
            os.environ.pop("GREENGAP_PROVIDER", None)
        else:
            os.environ["GREENGAP_PROVIDER"] = prior_provider


def _load_fragments(directory: Path) -> tuple[list[Path], list[dict[str, Any]], list[str]]:
    paths = sorted(
        path for path in directory.glob("greengap-*.json") if path.is_file() and not path.is_symlink()
    )
    payloads: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in paths:
        try:
            payloads.append(load_witness(path))
        except (OSError, TypeError, ValueError, WitnessError):
            errors.append(f"WITNESS_FRAGMENT_INVALID:{path.name}")
    return paths, payloads, errors


def _run_surface(
    *,
    target: Path,
    case: CohortCase,
    role: str,
    command: Sequence[str],
    destination: Path,
    adapted_sha: str,
) -> dict[str, Any]:
    result = execute_witness_command(
        target,
        command,
        role=role,
        output_dir=str(destination),
        source_commit=adapted_sha,
        repository=case.repository,
        surface_id="collection" if role == "collection" else case.execution_surface,
        run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT,
        timeout=MAX_COMMAND_SECONDS,
    )
    paths, payloads, errors = _load_fragments(destination)
    if result.error:
        errors.append(result.error)
    return {
        "role": role,
        "command": list(command),
        "returncode": result.returncode,
        "error": result.error,
        "fragment_paths": [str(path) for path in paths],
        "fragment_count": len(paths),
        "payloads": payloads,
        "errors": sorted(set(errors)),
        "witness_ids": sorted(
            {
                f"{payload.get('execution_context', {}).get('surface_id')}|{payload.get('execution_context', {}).get('shard') or '-'}"
                for payload in payloads
                if isinstance(payload.get("execution_context", {}).get("surface_id"), str)
            }
        ),
    }


def _analysis_code(analysis: Any) -> int:
    if analysis.outcome == "COMPLETE":
        return 0
    if analysis.outcome == "BLOCKED":
        return 1
    return 2


def _analysis_public(analysis: Any | None, error: str | None = None) -> dict[str, Any]:
    if analysis is None:
        return {
            "complete": False,
            "outcome": "INCOMPLETE",
            "exit_code": 2,
            "errors": [error or "ANALYSIS_NOT_AVAILABLE"],
            "collected_files": [],
            "executed_files": [],
            "not_run_files": [],
        }
    value = analysis.to_dict()
    value["exit_code"] = _analysis_code(analysis)
    return value


def _create_manifest(
    *,
    collection: dict[str, Any],
    config: ExplicitWitnessConfig,
    destination: Path,
) -> tuple[Path | None, str | None]:
    payloads = collection["payloads"]
    if len(payloads) != 1:
        return None, "COLLECTION_WITNESS_COUNT_INVALID"
    try:
        manifest = create_manifest(payloads[0], execution_witness_ids=(), explicit_config=config)
    except (WitnessError, TypeError, ValueError) as exc:
        return None, str(exc)
    path = destination / "manifest.json"
    _write_json(path, manifest)
    return path, None


def _run_case(
    *,
    case: CohortCase,
    source_root: Path,
    cycle_root: Path,
    tox: str,
    uv: str,
) -> dict[str, Any]:
    started = time.monotonic()
    case_root = cycle_root / case.case_id
    target = case_root / "target"
    evidence = case_root / "evidence"
    receipt: dict[str, Any] = {
        "case_id": case.case_id,
        "repository": case.repository,
        "upstream_sha_expected": case.upstream_sha,
        "mode": case.mode,
        "focus_paths": list(case.focus_paths),
        "status": "FAIL",
        "useful_determination": False,
        "omission_detected": False,
        "restored_baseline_verified": False,
        "false_confident_conclusions": 0,
    }
    try:
        original_sha, adapted_sha, changed = _initialize_target(
            source_root / case.source_name,
            target,
            case,
        )
        config = load_explicit_witness_config(target / ".greengap.yml")
        if config.collection_surface_id != "collection":
            raise CohortValidationError("COLLECTION_SURFACE_BINDING_INVALID")
        receipt.update(
            {
                "upstream_sha": original_sha,
                "adapted_sha": adapted_sha,
                "adaptation": {
                    "files_changed": changed,
                    "semantic_lines_added": 8 if case.mode == "tox" else 5,
                    "greengap_specific_commands": [
                        "python -m pytest -p greengap.pytest_witness",
                    ],
                    "required_concepts": [
                        "install GreenGap in the target pytest environment",
                        "set explicit witness identity variables",
                        "declare collection and execution surfaces",
                        "run full collection separately from execution",
                        "aggregate only named witness artifacts",
                    ],
                    "target_source_changed": False,
                    "test_configuration_changed": True,
                    "ci_workflow_changed": False,
                },
            }
        )
        if case.mode == "uv":
            baseline_command = _pytest_command(case, uv=uv)

            def omission_command(selected: str) -> tuple[str, ...]:
                return _pytest_command(case, uv=uv, omission=selected)
        else:
            baseline_command = _tox_command(case, tox=tox, target=target)

            def omission_command(selected: str) -> tuple[str, ...]:
                return _tox_command(case, tox=tox, target=target, omission=selected)
        with _target_environment(target, case, evidence):
            baseline_collection = _run_surface(
                target=target,
                case=case,
                role="collection",
                command=(
                    _tox_collection_command(tox)
                    if case.mode == "tox"
                    else tuple((*baseline_command, "--collect-only", "--greengap-full-collection"))
                ),
                destination=evidence / "baseline" / "collection",
                adapted_sha=adapted_sha,
            )
            receipt["baseline_collection"] = {
                key: value for key, value in baseline_collection.items() if key != "payloads"
            }
            if baseline_collection["returncode"] != 0 or baseline_collection["errors"]:
                raise CohortValidationError("COLLECTION_COMMAND_INCOMPLETE")
            manifest_path, manifest_error = _create_manifest(
                collection=baseline_collection,
                config=config,
                destination=evidence / "baseline",
            )
            if manifest_path is None:
                raise CohortValidationError(manifest_error or "MANIFEST_CREATE_FAILED")
            baseline_execution = _run_surface(
                target=target,
                case=case,
                role="execution",
                command=baseline_command,
                destination=evidence / "baseline" / "execution",
                adapted_sha=adapted_sha,
            )
            baseline_analysis = analyze_witnesses(
                manifest_path,
                tuple(Path(path) for path in baseline_collection["fragment_paths"]),
                tuple(Path(path) for path in baseline_execution["fragment_paths"]),
            )
            baseline_public = _analysis_public(baseline_analysis)
            receipt["baseline_execution"] = {
                key: value for key, value in baseline_execution.items() if key != "payloads"
            }
            receipt["baseline_analysis"] = baseline_public
            useful = bool(
                baseline_analysis.complete
                and baseline_analysis.outcome == "COMPLETE"
                and not baseline_analysis.not_run_files
            )
            receipt["useful_determination"] = useful
            selected = sorted(set(baseline_analysis.collected_files) & set(baseline_analysis.executed_files))
            receipt["selected_omission_file"] = selected[0] if selected else None
            if not useful or not selected:
                raise CohortValidationError("BASELINE_NOT_COMPLETE_OR_SELECTABLE")
            omission_execution = _run_surface(
                target=target,
                case=case,
                role="execution",
                command=omission_command(selected[0]),
                destination=evidence / "omission" / "execution",
                adapted_sha=adapted_sha,
            )
            omission_analysis = analyze_witnesses(
                manifest_path,
                tuple(Path(path) for path in baseline_collection["fragment_paths"]),
                tuple(Path(path) for path in omission_execution["fragment_paths"]),
            )
            omission_public = _analysis_public(omission_analysis)
            receipt["omission_execution"] = {
                key: value for key, value in omission_execution.items() if key != "payloads"
            }
            receipt["omission_analysis"] = omission_public
            omission_detected = bool(
                omission_analysis.complete
                and omission_analysis.outcome == "BLOCKED"
                and selected[0] in omission_analysis.not_run_files
                and selected[0] in omission_analysis.collected_files
                and selected[0] not in omission_analysis.executed_files
            )
            receipt["omission_detected"] = omission_detected
            restored_execution = _run_surface(
                target=target,
                case=case,
                role="execution",
                command=baseline_command,
                destination=evidence / "restored" / "execution",
                adapted_sha=adapted_sha,
            )
            restored_analysis = analyze_witnesses(
                manifest_path,
                tuple(Path(path) for path in baseline_collection["fragment_paths"]),
                tuple(Path(path) for path in restored_execution["fragment_paths"]),
            )
            restored_public = _analysis_public(restored_analysis)
            receipt["restored_execution"] = {
                key: value for key, value in restored_execution.items() if key != "payloads"
            }
            receipt["restored_analysis"] = restored_public
            receipt["restored_baseline_verified"] = bool(
                restored_analysis.complete
                and restored_analysis.outcome == "COMPLETE"
                and restored_analysis.collected_files == baseline_analysis.collected_files
                and restored_analysis.executed_files == baseline_analysis.executed_files
                and restored_analysis.not_run_files == baseline_analysis.not_run_files
            )
            analyses = (baseline_analysis, omission_analysis, restored_analysis)
            receipt["false_confident_conclusions"] = sum(
                1
                for analysis in analyses
                if not analysis.complete and _analysis_code(analysis) != 2
            )
            receipt["status"] = (
                "PASS"
                if useful and omission_detected and receipt["restored_baseline_verified"]
                else "FAIL"
            )
        receipt["post_run_git_status"] = _git(target, ("status", "--short")).stdout.splitlines()
    except (CohortValidationError, OSError, TypeError, ValueError, WitnessError) as exc:
        receipt["error"] = str(exc)
    receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
    _write_json(evidence / "case-summary.json", receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--case", choices=tuple(case.case_id for case in CASES))
    parser.add_argument("--tox", help="tox executable")
    parser.add_argument("--uv", help="uv executable")
    args = parser.parse_args()
    source_root = args.source_root.resolve()
    output_root = args.output.resolve()
    if output_root.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output_root}")
    output_root.mkdir(parents=True)
    try:
        tox = _resolve_tool(
            "tox",
            args.tox,
            source_root / "runtime-witness-dev-source-A02" / ".venv" / "Scripts" / "tox.exe",
        )
        uv = _resolve_tool(
            "uv",
            args.uv,
            Path(os.environ.get("LOCALAPPDATA", "")) / "hermes" / "bin" / "uv.exe",
        )
    except CohortValidationError as exc:
        _write_json(output_root / "cohort-summary.json", {"status": "INCOMPLETE", "error": str(exc)})
        print(json.dumps({"status": "INCOMPLETE", "error": str(exc)}, indent=2))
        return 2
    cases = tuple(case for case in CASES if args.case is None or case.case_id == args.case)
    results = []
    for case in cases:
        result = _run_case(
            case=case,
            source_root=source_root,
            cycle_root=output_root,
            tox=tox,
            uv=uv,
        )
        results.append(result)
        print(
            json.dumps(
                {
                    "case_id": case.case_id,
                    "status": result.get("status"),
                    "useful": result.get("useful_determination"),
                    "omission_detected": result.get("omission_detected"),
                    "restored": result.get("restored_baseline_verified"),
                    "error": result.get("error"),
                },
                sort_keys=True,
            )
        )
    useful = sum(value.get("useful_determination") is True for value in results)
    omissions = sum(value.get("omission_detected") is True for value in results if value["case_id"] <= "A06")
    restorations = sum(
        value.get("restored_baseline_verified") is True for value in results if value["case_id"] <= "A06"
    )
    false_confident = sum(int(value.get("false_confident_conclusions", 0)) for value in results)
    semantic_lines = [int(value.get("adaptation", {}).get("semantic_lines_added", 0)) for value in results]
    summary = {
        "status": "PASS"
        if useful >= 8 and omissions == 6 and restorations == 6 and false_confident == 0
        else "FAIL",
        "candidate_contract": "explicit_runtime_witness",
        "cycle": 1,
        "cases": results,
        "A01_A09_USEFUL": {"count": useful, "denominator": 9},
        "CONTROLLED_OMISSIONS_DETECTED": {"count": omissions, "denominator": 6},
        "CONTROLLED_OMISSION_RESTORATIONS": {"count": restorations, "denominator": 6},
        "FALSE_CONFIDENT_CONCLUSIONS": false_confident,
        "MEDIAN_INTEGRATION_SEMANTIC_LINES": sorted(semantic_lines)[len(semantic_lines) // 2]
        if semantic_lines
        else None,
        "MAX_INTEGRATION_SEMANTIC_LINES": max(semantic_lines, default=None),
        "tools": {"tox": tox, "uv": uv},
    }
    _write_json(output_root / "cohort-summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
