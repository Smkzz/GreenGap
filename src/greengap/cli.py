"""Command-line presentation and exit-code policy."""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import __version__
from .report import redact_shareable
from .util import MAX_RUNTIME_WITNESS_FRAGMENTS, terminal_safe_text

if TYPE_CHECKING:
    from .model import PlanReport, ScanReport


def run_scan(
    root: Path,
    timeout: float = 60.0,
    initial: Any | None = None,
    *,
    python_executable: str | None = None,
    collect: bool = False,
) -> ScanReport:
    from .model import ScanReport
    from .pytest_adapter import scan_pytest
    from .snapshot import workspace_snapshot
    from .util import PathReadContext

    root = root.resolve()
    read_context = PathReadContext(root)
    snapshot = initial or workspace_snapshot(
        root,
        timeout=min(timeout, 10.0),
        read_context=read_context,
    )
    candidates, collection = scan_pytest(
        root,
        timeout,
        python_executable=python_executable,
        collect=collect,
        read_context=read_context if initial is None else None,
    )
    final = workspace_snapshot(
        root,
        timeout=min(timeout, 10.0),
        read_context=read_context,
    )
    errors = list(snapshot.errors) + list(final.errors)
    stable = snapshot.fingerprint == final.fingerprint and snapshot.complete and final.complete
    if not stable:
        errors.append("workspace fingerprint changed or could not be read consistently")
    return ScanReport(
        repository=str(root),
        snapshot=snapshot,
        final_fingerprint=final.fingerprint,
        candidates=candidates,
        collection=collection,
        stable=stable,
        errors=tuple(dict.fromkeys(errors)),
    )


def run_plan(
    root: Path,
    timeout: float = 60.0,
    changed_files: tuple[str, ...] | None = None,
    event: str | None = None,
    ref: str | None = None,
    base_ref: str | None = None,
    activity: str | None = None,
    change_set_complete: bool = False,
    commit_count: int | None = None,
    changed_file_count: int | None = None,
    diff_timed_out: bool = False,
    *,
    python_executable: str | None = None,
    collect: bool = False,
    inside_greengap_reusable_workflow: bool = False,
) -> PlanReport:
    from .model import PlanReport
    from .pytest_adapter import scan_pytest
    from .reconcile import plan_is_complete, reconcile_plan
    from .snapshot import workspace_snapshot
    from .trace import trace_github_actions
    from .util import PathReadContext, checkout_source_equivalent_to_head

    root = root.resolve()
    read_context = PathReadContext(root)
    snapshot = workspace_snapshot(
        root,
        timeout=min(timeout, 10.0),
        read_context=read_context,
    )
    checkout_source_equivalent = checkout_source_equivalent_to_head(
        root, timeout=min(timeout, 10.0)
    )
    candidates, collection = scan_pytest(
        root,
        timeout,
        python_executable=python_executable,
        collect=collect,
        read_context=read_context,
    )
    trace = trace_github_actions(
        root,
        changed_files,
        event,
        ref,
        base_ref,
        activity,
        change_set_complete,
        commit_count,
        changed_file_count,
        diff_timed_out,
        workspace_clean=checkout_source_equivalent,
        discovery_timeout=min(timeout, 10.0),
        inside_reusable_workflow=inside_greengap_reusable_workflow,
    )
    final = workspace_snapshot(
        root,
        timeout=min(timeout, 10.0),
        read_context=read_context,
    )
    stable = snapshot.fingerprint == final.fingerprint and snapshot.complete and final.complete
    errors = list(snapshot.errors) + list(final.errors)
    if not stable:
        errors.append("workspace fingerprint changed or could not be read consistently")
    findings = reconcile_plan(candidates, collection, trace, stable=stable)
    complete = plan_is_complete(findings, collection, stable, trace=trace)
    if not collection.environment_valid:
        errors.append("pytest qualification environment is invalid or collection failed")
    return PlanReport(
        repository=str(root),
        snapshot=snapshot,
        final_fingerprint=final.fingerprint,
        candidates=candidates,
        collection=collection,
        trace=trace,
        findings=findings,
        complete=complete,
        stable=stable,
        errors=tuple(dict.fromkeys(errors)),
    )


def _human_scan(report: ScanReport, *, collection_enabled: bool) -> str:
    root = Path(report.repository)

    def safe(value: Any) -> str:
        return terminal_safe_text(str(redact_shareable(str(value), root)))

    lines = [
        f"GreenGap scan: {safe(report.repository)}",
        f"workspace: {'stable' if report.stable else 'UNSTABLE'} ({report.snapshot.fingerprint})",
        f"pytest collection: {'complete' if report.collection.complete else 'INCOMPLETE'}; "
        f"{len(report.collection.nodes)} nodes across {len(report.collection.paths)} files",
        f"repository candidates: {len(report.candidates)}",
        "collection mode: "
        + ("trusted checkout (repository code executed)" if collection_enabled else "non-executing"),
    ]
    for candidate in report.candidates:
        lines.append(
            f"  {candidate.confidence.upper():9} {safe(candidate.path)}"
        )
    if report.errors:
        lines.append("errors:")
        lines.extend(f"  - {safe(error)}" for error in report.errors)
    return "\n".join(lines)


def _human_plan(report: PlanReport, *, collection_enabled: bool) -> str:
    root = Path(report.repository)

    def safe(value: Any) -> str:
        return terminal_safe_text(str(redact_shareable(str(value), root)))

    if not report.complete:
        status = "INCOMPLETE / UNKNOWN"
    elif report.blockers:
        status = f"BLOCKED ({len(report.blockers)} proven NOT_PLANNED)"
    else:
        status = "COMPLETE / NO BLOCKERS"
    lines = [
        f"GreenGap plan: {safe(report.repository)}",
        f"status: {status}",
        f"workspace: {'stable' if report.stable else 'UNSTABLE'} ({report.snapshot.fingerprint})",
        f"pytest collection: {'complete' if report.collection.complete else 'INCOMPLETE'}",
        f"CI trace: {'complete' if report.trace.complete else 'INCOMPLETE'}",
        "collection mode: "
        + ("trusted checkout (repository code executed)" if collection_enabled else "non-executing"),
    ]
    for finding in report.findings:
        marker = "BLOCKING" if finding.blocking else "         "
        lines.append(
            f"{marker} {finding.state.value:13} "
            f"{safe(finding.path)} — {safe(finding.reason)}"
        )
    if report.trace.issues:
        lines.append("trace evidence:")
        for issue in report.trace.issues:
            scope = "relevant" if issue.relevant else "unrelated"
            lines.append(
                f"  - [{scope}] {issue.code}: {safe(issue.message)}"
            )
    if report.errors:
        lines.append("errors:")
        lines.extend(f"  - {safe(error)}" for error in report.errors)
    lines.append("exit semantics: 0=complete/no blockers, 1=proven gap, 2=incomplete/UNKNOWN")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="greengap",
        description="Find what your green CI never ran.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("scan", "inventory repository pytest candidates and real collection"),
        ("plan", "reconcile pytest collection against GitHub Actions plan"),
    ):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("repo", nargs="?", default=".")
        output = command.add_mutually_exclusive_group()
        output.add_argument("--json", action="store_true", dest="as_json")
        output.add_argument(
            "--sarif",
            action="store_true",
            dest="as_sarif",
            help="emit SARIF 2.1.0 findings with explicit completeness metadata",
        )
        command.add_argument("--timeout", type=float, default=60.0)
        command.add_argument(
            "--python",
            dest="python_executable",
            default=None,
            help="interpreter used for target pytest collection; dependencies are never installed",
        )
        execution = command.add_mutually_exclusive_group()
        execution.add_argument(
            "--trust-collection",
            action="store_true",
            dest="trust_collection",
            help="consent to executing the target repository's pytest collection code",
        )
        execution.add_argument(
            "--no-collect",
            action="store_false",
            dest="trust_collection",
            help="inspect source and workflows without executing repository code (default)",
        )
        command.set_defaults(as_json=False, as_sarif=False, trust_collection=False)
        command.add_argument(
            "--no-color",
            action="store_true",
            help="disable terminal color in any target pytest diagnostics",
        )
        if name == "plan":
            command.add_argument(
                "--inside-greengap-reusable-workflow",
                action="store_true",
                help="ignore GreenGap's canonical external self-call while tracing the caller's CI",
            )
            command.add_argument(
                "--changed-file",
                action="append",
                dest="changed_files",
                help="bind workflow path filters to a changed repository-relative file (repeatable)",
            )
            command.add_argument(
                "--event",
                dest="event",
                help="bind changed-file path filters to one GitHub event (for example pull_request)",
            )
            command.add_argument(
                "--ref",
                dest="ref",
                help="bind push branch/tag filters to a ref name or refs/* value",
            )
            command.add_argument(
                "--base-ref",
                dest="base_ref",
                help="bind pull-request branch filters to the base branch",
            )
            command.add_argument(
                "--activity",
                dest="activity",
                help="bind an event activity for workflow types filters (for example opened or closed)",
            )
            command.add_argument(
                "--change-set-complete",
                action="store_true",
                help="assert that the supplied changed-file set is complete for GitHub path-filter evaluation",
            )
            command.add_argument(
                "--commit-count",
                type=int,
                help="number of commits represented by the bound change set",
            )
            command.add_argument(
                "--changed-file-count",
                type=int,
                help="number of changed files represented by the bound change set",
            )
            command.add_argument(
                "--diff-timed-out",
                action="store_true",
                help="indicate that GitHub's path-filter diff computation timed out",
            )
    verify = subparsers.add_parser(
        "verify", help="parse JUnit evidence without claiming identity completeness"
    )
    verify.add_argument("repo", nargs="?", default=".")
    verify.add_argument("--junitxml", "--junit", dest="junitxml")
    verify.add_argument("--json", action="store_true", dest="as_json")
    verify.add_argument("--timeout", type=float, default=60.0)
    witness = subparsers.add_parser(
        "witness", help="aggregate native pytest runtime witnesses against a full collection"
    )
    witness.add_argument("repo", nargs="?", default=".")
    witness.add_argument(
        "--witness",
        "--input",
        action="append",
        dest="witnesses",
        required=True,
        help="one inert JSON witness (repeat for jobs or shards)",
    )
    witness.add_argument(
        "--denominator",
        required=True,
        help="JSON scan/witness report containing the complete pytest collection",
    )
    witness.add_argument(
        "--expected-witness",
        action="append",
        dest="expected_witnesses",
        help="predeclared witness identity (repeat for every expected job/shard)",
    )
    witness.add_argument(
        "--source-commit",
        dest="source_commit",
        help="required 40-character source commit binding the denominator and witnesses",
    )
    witness.add_argument(
        "--repository",
        dest="expected_repository",
        help="required GitHub repository identity (OWNER/REPOSITORY) for a complete result",
    )
    witness.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _verify(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    from .junit import parse_junit
    from .report import REPORT_VERSION, redact_shareable

    cases: list[dict[str, Any]] = []
    error: str | None = None
    report_root = Path(args.repo).resolve()
    if args.junitxml:
        try:
            cases = [
                redact_shareable(case.to_dict(), report_root)
                for case in parse_junit(Path(args.junitxml))
            ]
        except (OSError, ValueError, TypeError) as exc:
            error = redact_shareable(f"could not parse JUnit evidence: {exc}", report_root)
    payload: dict[str, Any] = {
        "report_version": REPORT_VERSION,
        "mode": "verify",
        "repository": ".",
        "tool": {"name": "greengap", "version": __version__, "runtime_proof": False},
        "environment": {
            "collection_mode": "non_executing",
            "execution_consent": False,
            "network_access": "not requested by the analyzer",
        },
        "identity_reconciliation": "NOT_CERTIFIED",
        "complete": False,
        "cases": cases,
        "case_count": len(cases),
        "error": error,
        "message": "JUnit evidence is parsed conservatively; cross-runner identity reconciliation is not certified.",
    }
    return payload, 2


def _witness(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    from .runtime import RuntimeWitnessError, aggregate_runtime_witnesses

    try:
        aggregate = aggregate_runtime_witnesses(
            tuple(Path(value) for value in args.witnesses),
            Path(args.denominator),
            expected_identities=(
                tuple(args.expected_witnesses) if args.expected_witnesses is not None else None
            ),
            expected_repository=args.expected_repository,
            source_commit=args.source_commit,
            repository_root=Path(args.repo).resolve(),
        )
        payload = aggregate.to_dict()
        return payload, 0 if payload["outcome"] == "COMPLETE" else 1 if payload["outcome"] == "BLOCKED" else 2
    except (OSError, ValueError, TypeError, RuntimeWitnessError) as exc:
        payload = {
            "schema_version": 1,
            "artifact_type": "greengap_pytest_runtime_aggregate",
            "mode": "witness",
            "complete": False,
            "outcome": "INCOMPLETE",
            "tool": {"name": "greengap", "version": __version__, "runtime_proof": False},
            "runtime_execution_identity": "NOT_CERTIFIED",
            "source_commit": None,
            "repository": None,
            "denominator": {"node_count": 0},
            "witnesses": {
                "count": 0,
                "identities": [],
                "union_executed_node_count": 0,
                "duplicate_node_observations": [],
            },
            "errors": [str(getattr(exc, "code", "WITNESS_AGGREGATION_FAILED"))],
            "findings": [],
        }
        return payload, 2


def _witness_action_parser(action: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=f"greengap witness {action}",
        description="caller-authorized pytest runtime witness operation",
    )
    if action in {"collect", "run"}:
        parser.add_argument("repo", nargs="?", default=".")
        parser.add_argument("--repo", dest="repo_option")
        parser.add_argument(
            "--output-dir",
            "--witness-dir",
            "--output",
            dest="output_dir",
            help="directory for unique witness fragments (defaults to a temporary directory)",
        )
        parser.add_argument("--source-commit", "--source-sha", dest="source_commit")
        parser.add_argument("--repository", dest="repository")
        parser.add_argument("--surface-id", dest="surface_id")
        parser.add_argument("--run-id", dest="run_id")
        parser.add_argument("--run-attempt", default="1", dest="run_attempt")
        parser.add_argument("--timeout", type=float, default=300.0)
        parser.add_argument("--json", action="store_true", default=True, dest="as_json")
        return parser
    if action == "analyze":
        parser.add_argument("--manifest", required=True)
        parser.add_argument(
            "--collection-witness",
            "--collection-witnesses",
            "--collection",
            action="append",
            dest="collection_witnesses",
            default=[],
            help="collection witness file or directory (repeatable)",
        )
        parser.add_argument(
            "--execution-witness",
            "--execution-witnesses",
            "--execution",
            action="append",
            dest="execution_witnesses",
            default=[],
            help="execution witness file or directory (repeatable)",
        )
        parser.add_argument(
            "--witness",
            action="append",
            dest="execution_witnesses",
            default=[],
            help="compatibility alias for an execution witness",
        )
        output = parser.add_mutually_exclusive_group()
        output.add_argument("--json", action="store_true", dest="as_json")
        output.add_argument("--sarif", action="store_true", dest="as_sarif")
        parser.set_defaults(as_json=True, as_sarif=False)
        return parser
    if action == "manifest":
        parser.add_argument("--collection-witness", required=True)
        parser.add_argument(
            "--config",
            dest="config_path",
            help="explicit .greengap.yml surface manifest",
        )
        parser.add_argument(
            "--execution-witness-id",
            action="append",
            dest="execution_witness_ids",
            help="compatibility surface identity (use --config for the explicit contract)",
        )
        parser.add_argument("--output", required=True)
        parser.add_argument("--json", action="store_true", default=True, dest="as_json")
        return parser
    raise ValueError(f"unsupported witness action: {action}")


def _split_witness_command(arguments: Sequence[str]) -> tuple[list[str], list[str]]:
    values = list(arguments)
    try:
        delimiter = values.index("--")
    except ValueError:
        return values, []
    return values[:delimiter], values[delimiter + 1 :]


def _expand_witness_inputs(values: Sequence[str]) -> tuple[Path, ...]:
    paths: list[Path] = []
    for value in values:
        path = Path(value)
        if path.is_symlink():
            raise ValueError("WITNESS_INPUT_SYMLINK")
        if path.is_dir():
            try:
                with os.scandir(path) as entries:
                    for entry in entries:
                        if not entry.name.startswith("greengap-") or not entry.name.endswith(".json"):
                            continue
                        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                            raise ValueError("WITNESS_INPUT_SYMLINK")
                        paths.append(Path(entry.path))
                        if len(paths) > MAX_RUNTIME_WITNESS_FRAGMENTS:
                            raise ValueError("WITNESS_FRAGMENT_SET_LIMIT_EXCEEDED")
            except OSError as exc:
                raise ValueError("WITNESS_INPUT_DIRECTORY_INVALID") from exc
        else:
            paths.append(path)
        if len(paths) > MAX_RUNTIME_WITNESS_FRAGMENTS:
            raise ValueError("WITNESS_FRAGMENT_SET_LIMIT_EXCEEDED")
    return tuple(paths)


def _command_witness_payload(action: str, result: Any) -> dict[str, Any]:
    from .witness import WitnessError, load_witness

    valid = 0
    complete = 0
    errors: list[str] = []
    source_commit = None
    source_fingerprint = None
    run_identity: dict[str, Any] = {"run_id": None, "run_attempt": None}
    for index, name in enumerate(result.fragment_names):
        try:
            payload = load_witness(result.output_dir / name)
        except (OSError, ValueError, TypeError, WitnessError):
            errors.append(f"FRAGMENT_{index + 1}_INVALID")
            continue
        valid += 1
        if source_commit is None:
            source_commit = payload["repository_identity"]["git_sha"]
            source_fingerprint = payload["source_identity"]["initial_fingerprint"]
            run_identity = {
                "run_id": payload["execution_context"]["run_id"],
                "run_attempt": payload["execution_context"]["run_attempt"],
            }
        if payload["complete"]:
            complete += 1
        else:
            errors.append(f"FRAGMENT_{index + 1}_INCOMPLETE")
    if result.error:
        errors.append(result.error)
    if action == "collect" and result.returncode != 0:
        errors.append("WITNESS_COLLECTION_INCOMPLETE")
    return {
        "schema_version": 1,
        "artifact_type": "greengap_pytest_runtime_command",
        "mode": "witness",
        "operation": action,
        "complete": not errors and valid > 0 and (action != "collect" or complete > 0),
        "command_exit_status": result.returncode,
        "source_commit": source_commit,
        "source_fingerprint": source_fingerprint,
        # Retain the v1 field name for consumers that only display the
        # summary; reconciliation is now bound to source_fingerprint.
        "workspace_fingerprint": source_fingerprint,
        "run_identity": run_identity,
        "fragment_count": len(result.fragment_names),
        "valid_fragment_count": valid,
        "complete_fragment_count": complete,
        "fragment_names": list(result.fragment_names),
        "errors": list(dict.fromkeys(errors)),
    }


def _run_witness_action(action: str, options: list[str], command: list[str]) -> int:
    from .util import json_dump
    from .witness import (
        WitnessError,
        analyze_witnesses,
        create_manifest,
        execute_witness_command,
        load_witness,
        resolve_witness_output_path,
        witness_sarif,
    )

    parser = _witness_action_parser(action)
    args = parser.parse_args(options)
    if action in {"collect", "run"}:
        if not command:
            parser.error("provide the caller-authorized command after --")
        root = Path(args.repo_option or args.repo).resolve()
        result = execute_witness_command(
            root,
            command,
            role="collection" if action == "collect" else "execution",
            output_dir=args.output_dir,
            source_commit=args.source_commit,
            repository=args.repository,
            surface_id=args.surface_id,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            collect_only=action == "collect",
            timeout=args.timeout,
        )
        payload = _command_witness_payload(action, result)
        print(json_dump(payload), end="")
        if action == "collect":
            return 0 if payload["complete"] else 2
        if result.error or not payload["complete"]:
            return 2
        return result.returncode

    if action == "analyze":
        try:
            collection_paths = _expand_witness_inputs(args.collection_witnesses)
            execution_paths = _expand_witness_inputs(args.execution_witnesses)
            if len(collection_paths) + len(execution_paths) > MAX_RUNTIME_WITNESS_FRAGMENTS:
                raise ValueError("WITNESS_FRAGMENT_SET_LIMIT_EXCEEDED")
        except (OSError, ValueError, TypeError) as exc:
            payload = {
                "schema_version": 1,
                "artifact_type": "greengap_pytest_runtime_analysis",
                "mode": "witness",
                "complete": False,
                "outcome": "INCOMPLETE",
                "runtime_execution_identity": "NOT_CERTIFIED",
                "source_commit": None,
                "repository": None,
                "run_identity": {"run_id": None, "run_attempt": None},
                "expected_witness_count": 0,
                "received_witness_count": 0,
                "fragment_count": 0,
                "collection_file_count": 0,
                "executed_file_count": 0,
                "not_run_file_count": 0,
                "collected_files": [],
                "executed_files": [],
                "not_run_files": [],
                "collection_witness_ids": [],
                "execution_witness_ids": [],
                "errors": [str(getattr(exc, "code", exc))],
                "findings": [],
            }
            print(json_dump(payload), end="")
            return 2
        analysis = analyze_witnesses(
            Path(args.manifest),
            collection_paths,
            execution_paths,
        )
        payload = witness_sarif(analysis) if args.as_sarif else analysis.to_dict()
        print(json_dump(payload), end="")
        if args.as_sarif:
            return 0 if analysis.complete and not analysis.not_run_files else 1 if analysis.complete else 2
        return 0 if analysis.outcome == "COMPLETE" else 1 if analysis.outcome == "BLOCKED" else 2

    if action == "manifest":
        try:
            from .witness_config import WitnessConfigError, load_explicit_witness_config

            collection = load_witness(Path(args.collection_witness))
            explicit_config = None
            if args.config_path:
                if args.execution_witness_ids:
                    raise WitnessConfigError("WITNESS_CONFIG_ID_OVERRIDE_FORBIDDEN")
                explicit_config = load_explicit_witness_config(Path(args.config_path))
            elif not args.execution_witness_ids:
                raise WitnessConfigError("WITNESS_CONFIG_REQUIRED")
            manifest = create_manifest(
                collection,
                execution_witness_ids=args.execution_witness_ids or (),
                explicit_config=explicit_config,
            )
            destination = resolve_witness_output_path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and (destination.is_symlink() or not destination.is_file()):
                raise WitnessError("WITNESS_OUTPUT_DIRECTORY_INVALID")
            encoded = json_dump(manifest)
            temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
            temporary.write_text(encoded, encoding="utf-8", newline="")
            temporary.replace(destination)
            payload = {"mode": "witness", "operation": "manifest", "complete": True}
            code = 0
        except (OSError, ValueError, TypeError, WitnessError) as exc:
            payload = {
                "mode": "witness",
                "operation": "manifest",
                "complete": False,
                "errors": [str(getattr(exc, "code", "MANIFEST_FAILED"))],
            }
            code = 2
        print(json_dump(payload), end="")
        return code

    return 2


def main(argv: Sequence[str] | None = None) -> int:
    try:
        for stream in (sys.stdout, sys.stderr):
            reconfigure = getattr(stream, "reconfigure", None)
            if reconfigure is not None:
                reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, OSError):
        pass
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if len(raw_argv) >= 2 and raw_argv[0] == "witness" and raw_argv[1] in {
        "collect",
        "run",
        "analyze",
        "manifest",
    }:
        options, command = _split_witness_command(raw_argv[2:])
        return _run_witness_action(raw_argv[1], options, command)
    parser = _build_parser()
    args = parser.parse_args(raw_argv)
    from .report import REPORT_VERSION, public_report, sarif_report
    from .util import json_dump

    if args.command == "verify":
        payload, code = _verify(args)
        if args.as_json:
            print(json_dump(payload), end="")
        else:
            print("GreenGap verify")
            print("identity reconciliation: NOT_CERTIFIED")
            print(f"JUnit cases parsed: {payload['case_count']}")
            if payload["error"]:
                print(f"error: {terminal_safe_text(payload['error'])}")
            print("verify does not claim witness completeness in the stable Plan-mode API.")
        return code

    if args.command == "witness":
        payload, code = _witness(args)
        if args.as_json:
            print(json_dump(payload), end="")
        else:
            print("GreenGap runtime witness")
            print(f"status: {payload['outcome']}")
            print(f"witnesses: {payload['witnesses']['count']}")
            print(f"collection denominator: {payload['denominator']['node_count']} nodes")
            print(f"observed nodes: {payload['witnesses']['union_executed_node_count']}")
            for finding in payload["findings"]:
                marker = "BLOCKING" if finding.get("blocking") else "         "
                print(f"{marker} {finding['state']:13} {finding['nodeid']}")
            if payload["errors"]:
                print("evidence:")
                for error in payload["errors"]:
                    print(f"  - {terminal_safe_text(error)}")
        return code

    root = Path(args.repo).resolve()
    if not root.is_dir():
        payload = {
            "report_version": REPORT_VERSION,
            "mode": args.command,
            "repository": ".",
            "complete": False,
            "error": "repository is not a directory",
            "outcome": "INCOMPLETE",
        }
        if args.as_sarif:
            print(
                json_dump(
                    {
                        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {
                                    "driver": {
                                        "name": "GreenGap",
                                        "version": __version__,
                                        "rules": [],
                                    }
                                },
                                "results": [],
                                "invocations": [
                                    {
                                        "executionSuccessful": False,
                                        "properties": {"analysisComplete": False},
                                    }
                                ],
                                "properties": {
                                    "greengapReportVersion": REPORT_VERSION,
                                    "analysisComplete": False,
                                },
                            }
                        ],
                    }
                ),
                end="",
            )
        elif args.as_json:
            print(json_dump(payload), end="")
        else:
            print(
                f"error: repository is not a directory: {terminal_safe_text(str(root))}",
                file=sys.stderr,
            )
        return 2
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.command == "scan":
        scan_report = run_scan(
            root,
            args.timeout,
            python_executable=args.python_executable,
            collect=args.trust_collection,
        )
        if args.as_sarif:
            print(
                json_dump(
                    sarif_report(
                        scan_report,
                        root=root,
                        python_executable=args.python_executable,
                        collection_enabled=args.trust_collection,
                    )
                ),
                end="",
            )
        elif args.as_json:
            print(
                json_dump(
                    public_report(
                        scan_report,
                        root=root,
                        python_executable=args.python_executable,
                        collection_enabled=args.trust_collection,
                    )
                ),
                end="",
            )
        else:
            print(_human_scan(scan_report, collection_enabled=args.trust_collection))
        return 0 if scan_report.stable and scan_report.collection.complete else 2

    plan_report = run_plan(
        root,
        args.timeout,
        tuple(args.changed_files) if args.changed_files else None,
        args.event,
        args.ref,
        args.base_ref,
        args.activity,
        args.change_set_complete,
        args.commit_count,
        args.changed_file_count,
        args.diff_timed_out,
        python_executable=args.python_executable,
        collect=args.trust_collection,
        inside_greengap_reusable_workflow=args.inside_greengap_reusable_workflow,
    )
    if args.as_sarif:
        print(
            json_dump(
                sarif_report(
                    plan_report,
                    root=root,
                    python_executable=args.python_executable,
                    collection_enabled=args.trust_collection,
                )
            ),
            end="",
        )
    elif args.as_json:
        print(
            json_dump(
                public_report(
                    plan_report,
                    root=root,
                    python_executable=args.python_executable,
                    collection_enabled=args.trust_collection,
                )
            ),
            end="",
        )
    else:
        print(_human_plan(plan_report, collection_enabled=args.trust_collection))
    if not plan_report.complete:
        return 2
    return 1 if plan_report.blockers else 0
