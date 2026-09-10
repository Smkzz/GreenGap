"""Command-line presentation and exit-code policy."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import __version__
from .report import redact_shareable
from .util import terminal_safe_text

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
    from .util import PathReadContext, git_workspace_clean

    root = root.resolve()
    read_context = PathReadContext(root)
    snapshot = workspace_snapshot(
        root,
        timeout=min(timeout, 10.0),
        read_context=read_context,
    )
    workspace_clean = git_workspace_clean(root, timeout=min(timeout, 10.0))
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
        workspace_clean=workspace_clean,
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


def main(argv: Sequence[str] | None = None) -> int:
    try:
        for stream in (sys.stdout, sys.stderr):
            reconfigure = getattr(stream, "reconfigure", None)
            if reconfigure is not None:
                reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, OSError):
        pass
    parser = _build_parser()
    args = parser.parse_args(argv)
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
