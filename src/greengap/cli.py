"""Command-line presentation and exit-code policy."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .junit import parse_junit
from .model import PlanReport, ScanReport
from .pytest_adapter import scan_pytest
from .reconcile import plan_is_complete, reconcile_plan
from .snapshot import workspace_snapshot
from .trace import trace_github_actions
from .util import json_dump


def run_scan(root: Path, timeout: float = 60.0, initial: Any | None = None) -> ScanReport:
    root = root.resolve()
    snapshot = initial or workspace_snapshot(root, timeout=min(timeout, 10.0))
    candidates, collection = scan_pytest(root, timeout)
    final = workspace_snapshot(root, timeout=min(timeout, 10.0))
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


def run_plan(root: Path, timeout: float = 60.0) -> PlanReport:
    root = root.resolve()
    snapshot = workspace_snapshot(root, timeout=min(timeout, 10.0))
    candidates, collection = scan_pytest(root, timeout)
    trace = trace_github_actions(root)
    final = workspace_snapshot(root, timeout=min(timeout, 10.0))
    stable = snapshot.fingerprint == final.fingerprint and snapshot.complete and final.complete
    errors = list(snapshot.errors) + list(final.errors)
    if not stable:
        errors.append("workspace fingerprint changed or could not be read consistently")
    findings = reconcile_plan(candidates, collection, trace, stable=stable)
    complete = plan_is_complete(findings, collection, stable)
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


def _human_scan(report: ScanReport) -> str:
    lines = [
        f"GreenGap scan: {report.repository}",
        f"workspace: {'stable' if report.stable else 'UNSTABLE'} ({report.snapshot.fingerprint})",
        f"pytest collection: {'complete' if report.collection.complete else 'INCOMPLETE'}; "
        f"{len(report.collection.nodes)} nodes across {len(report.collection.paths)} files",
        f"repository candidates: {len(report.candidates)}",
    ]
    for candidate in report.candidates:
        lines.append(f"  {candidate.confidence.upper():9} {candidate.path}")
    if report.errors:
        lines.append("errors:")
        lines.extend(f"  - {error}" for error in report.errors)
    return "\n".join(lines)


def _human_plan(report: PlanReport) -> str:
    if not report.complete:
        status = "INCOMPLETE / UNKNOWN"
    elif report.blockers:
        status = f"BLOCKED ({len(report.blockers)} proven NOT_PLANNED)"
    else:
        status = "COMPLETE / NO BLOCKERS"
    lines = [
        f"GreenGap plan: {report.repository}",
        f"status: {status}",
        f"workspace: {'stable' if report.stable else 'UNSTABLE'} ({report.snapshot.fingerprint})",
        f"pytest collection: {'complete' if report.collection.complete else 'INCOMPLETE'}",
        f"CI trace: {'complete' if report.trace.complete else 'INCOMPLETE'}",
    ]
    for finding in report.findings:
        marker = "BLOCKING" if finding.blocking else "         "
        lines.append(f"{marker} {finding.state.value:13} {finding.path} — {finding.reason}")
    if report.trace.issues:
        lines.append("trace evidence:")
        for issue in report.trace.issues:
            scope = "relevant" if issue.relevant else "unrelated"
            lines.append(f"  - [{scope}] {issue.code}: {issue.message}")
    if report.errors:
        lines.append("errors:")
        lines.extend(f"  - {error}" for error in report.errors)
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
        command.add_argument("--json", action="store_true", dest="as_json")
        command.add_argument("--timeout", type=float, default=60.0)
    verify = subparsers.add_parser(
        "verify", help="parse JUnit evidence without claiming identity completeness"
    )
    verify.add_argument("repo", nargs="?", default=".")
    verify.add_argument("--junitxml", "--junit", dest="junitxml")
    verify.add_argument("--json", action="store_true", dest="as_json")
    verify.add_argument("--timeout", type=float, default=60.0)
    return parser


def _verify(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    cases: list[dict[str, Any]] = []
    error: str | None = None
    if args.junitxml:
        try:
            cases = [case.to_dict() for case in parse_junit(Path(args.junitxml))]
        except (OSError, ValueError, TypeError) as exc:
            error = f"could not parse JUnit evidence: {exc}"
    payload: dict[str, Any] = {
        "mode": "verify",
        "repository": str(Path(args.repo).resolve()),
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
    if args.command == "verify":
        payload, code = _verify(args)
        if args.as_json:
            print(json_dump(payload), end="")
        else:
            print("GreenGap verify")
            print("identity reconciliation: NOT_CERTIFIED")
            print(f"JUnit cases parsed: {payload['case_count']}")
            if payload["error"]:
                print(f"error: {payload['error']}")
            print("verify does not claim witness completeness in v0.1.")
        return code

    root = Path(args.repo)
    if not root.is_dir():
        payload = {
            "mode": args.command,
            "repository": str(root.resolve()),
            "complete": False,
            "error": "repository is not a directory",
        }
        if args.as_json:
            print(json_dump(payload), end="")
        else:
            print(f"error: repository is not a directory: {root}", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.command == "scan":
        scan_report = run_scan(root, args.timeout)
        if args.as_json:
            print(json_dump(scan_report.to_dict()), end="")
        else:
            print(_human_scan(scan_report))
        return 0 if scan_report.stable and scan_report.collection.complete else 2

    plan_report = run_plan(root, args.timeout)
    if args.as_json:
        print(json_dump(plan_report.to_dict()), end="")
    else:
        print(_human_plan(plan_report))
    if not plan_report.complete:
        return 2
    return 1 if plan_report.blockers else 0
