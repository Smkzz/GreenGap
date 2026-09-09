"""Versioned, shareable report contracts for GreenGap."""

from __future__ import annotations

import platform
import re
import sys
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

from . import __version__
from .model import FindingState, PlanReport, ScanReport

REPORT_VERSION = "1.0"
SARIF_VERSION = "2.1.0"

_ABSOLUTE_PATH = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?:[a-z]:[\\/]|\\\\|"
    r"(?<![:/A-Za-z0-9_.-])/(?!/))[^\r\n\t]+"
)
_FILE_URI_ABSOLUTE_PATH = re.compile(
    r'(?i)\bfile:(?:/{1,3}|//[^/\s]+/)[^"\r\n\t,;}\]]+'
)
_SECRET_REFERENCE = re.compile(r"(?i)\$\{\{\s*secrets\.[^}\s]+\s*\}\}")
_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (
        ["']?(?<![A-Za-z0-9_-])
        (?:[A-Za-z0-9]+[_-])*
        (?:aws[_-]?secret[_-]?access[_-]?key|api[_-]?(?:key|token)|
        access[_-]?token|auth(?:orization)?|password|passwd|private[_-]?key|
        secret|token)
        ["']?\s*[:=]\s*
    )
    (
        "(?:\\.|[^"\\])*"
        | '(?:\\.|[^'\\])*'
        | [^\s,;}\]]+
    )"""
)
_BEARER_CREDENTIAL = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+")
_BASIC_AUTH_URL = re.compile(r"(?i)\b(https?://)[^/\s:@]+:[^@\s]+@")
_PEM_SECRET = re.compile(r"(?s)-----BEGIN [^-\r\n]+-----.*?-----END [^-\r\n]+-----")


def _semantic_version() -> str:
    match = re.fullmatch(r"(\d+\.\d+\.\d+)rc(\d+)", __version__)
    return f"{match.group(1)}-rc.{match.group(2)}" if match else __version__


def _redaction_replacements(root: Path) -> tuple[str, ...]:
    candidates = (root, root.resolve(), Path.cwd(), Path.home())
    replacements: list[str] = []
    for candidate in candidates:
        replacements.extend((str(candidate), candidate.as_posix()))
    return tuple(dict.fromkeys(replacements))


def _redact_text(value: str, replacements: tuple[str, ...]) -> str:
    """Remove analyst-local paths and secret-shaped values from diagnostics."""

    result = value
    for candidate in replacements:
        result = result.replace(candidate, "<repo>")
    result = _PEM_SECRET.sub("<redacted-secret-block>", result)
    result = _SECRET_REFERENCE.sub("<secret-reference>", result)
    result = _BASIC_AUTH_URL.sub(r"\1<redacted>@", result)
    result = _BEARER_CREDENTIAL.sub(r"\1<redacted>", result)
    result = _SECRET_ASSIGNMENT.sub(r"\1<redacted>", result)
    result = _FILE_URI_ABSOLUTE_PATH.sub("<absolute-path>", result)
    return _ABSOLUTE_PATH.sub("<absolute-path>", result)


def _redact(value: Any, replacements: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        return _redact_text(value, replacements)
    if isinstance(value, list):
        return [_redact(item, replacements) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact(item, replacements) for key, item in value.items()}
    return value


def redact_shareable(value: Any, root: Path) -> Any:
    """Redact local path-bearing values before they enter shareable output."""

    return _redact(value, _redaction_replacements(root))


def _environment_identity(python_executable: str, collection_enabled: bool) -> dict[str, Any]:
    interpreter = Path(python_executable).name or "python"
    return {
        "requested_interpreter": interpreter,
        "analyzer_python": platform.python_version(),
        "analyzer_implementation": platform.python_implementation(),
        "analyzer_platform": platform.system(),
        "collection_mode": "trusted_checkout" if collection_enabled else "non_executing",
        "execution_consent": collection_enabled,
        "pytest_invocation": "selected-interpreter -m pytest --collect-only -q",
        "dependency_installation": "caller responsibility; GreenGap never installs target dependencies",
        "network_access": "not requested by the analyzer",
    }


def _context(report: PlanReport | ScanReport) -> dict[str, Any]:
    if not isinstance(report, PlanReport):
        return {}
    trace = report.trace
    return {
        "event": trace.event,
        "activity": trace.activity,
        "ref": trace.ref,
        "base_ref": trace.base_ref,
        "changed_files": None if trace.changed_files is None else list(trace.changed_files),
        "change_set_complete": trace.change_set_complete,
        "commit_count": trace.commit_count,
        "changed_file_count": trace.changed_file_count,
        "diff_timed_out": trace.diff_timed_out,
    }


def _reason_codes(payload: dict[str, Any]) -> list[str]:
    codes: set[str] = set()
    for finding in payload.get("findings", []):
        code = finding.get("reason_code")
        if isinstance(code, str) and code:
            codes.add(code)
    for issue in payload.get("trace", {}).get("issues", []):
        code = issue.get("code")
        if isinstance(code, str) and code:
            codes.add(code)
    for error in payload.get("errors", []):
        if isinstance(error, str) and error:
            codes.add("ANALYSIS_ERROR")
    if not payload.get("collection", {}).get("complete", False):
        codes.add("COLLECTION_INCOMPLETE")
    if not payload.get("stable", False):
        codes.add("WORKSPACE_UNSTABLE")
    return sorted(codes)


def _analysis_complete(report: PlanReport | ScanReport) -> bool:
    """Return the one authoritative machine-facing analysis-complete value."""

    if isinstance(report, PlanReport):
        return report.complete
    return report.stable and report.collection.complete


def public_report(
    report: PlanReport | ScanReport,
    *,
    root: Path,
    python_executable: str | None = None,
    collection_enabled: bool = False,
) -> dict[str, Any]:
    """Return the stable JSON contract without analyst-local absolute paths."""

    payload = report.to_dict()
    replacements = _redaction_replacements(root)
    payload = cast(dict[str, Any], _redact(payload, replacements))
    payload["repository"] = "."
    payload["report_version"] = REPORT_VERSION
    payload["tool"] = {
        "name": "greengap",
        "version": __version__,
        "mode": payload.get("mode"),
        "runtime_proof": False,
    }
    payload["source"] = {
        "repository": ".",
        "workspace_fingerprint": report.final_fingerprint,
        "snapshot_method": report.snapshot.method,
        "file_count": len(report.snapshot.files),
    }
    payload["environment"] = _environment_identity(
        python_executable or sys.executable, collection_enabled
    )
    payload["context"] = _redact(_context(report), replacements)
    payload["completeness"] = {
        "analysis": _analysis_complete(report),
        "workspace_stable": report.stable,
        "collection_complete": report.collection.complete,
        "environment_valid": report.collection.environment_valid,
        "ci_trace_complete": report.trace.complete if isinstance(report, PlanReport) else None,
        "runtime_execution_identity": "NOT_CERTIFIED",
        "reason_codes": _reason_codes(payload),
    }
    if isinstance(report, ScanReport):
        payload["findings"] = []
        payload["blocker_count"] = 0
        payload["outcome"] = "COMPLETE" if _analysis_complete(report) else "INCOMPLETE"
    else:
        payload["outcome"] = (
            "INCOMPLETE"
            if not report.complete
            else "BLOCKED"
            if report.blockers
            else "COMPLETE"
        )
    return payload


def _sarif_rule(finding_state: FindingState) -> tuple[str, str, str, str]:
    if finding_state == FindingState.NOT_PLANNED:
        return (
            "GG001",
            "Collected test file is not in a proven CI pytest scope",
            "warning",
            "open",
        )
    if finding_state == FindingState.UNREGISTERED:
        return (
            "GG003",
            "A source candidate was not observed in completed pytest collection",
            "note",
            "review",
        )
    return (
        "GG002",
        "GreenGap evidence is incomplete",
        "note",
        "review",
    )


def sarif_report(
    report: PlanReport | ScanReport,
    *,
    root: Path,
    python_executable: str | None = None,
    collection_enabled: bool = False,
) -> dict[str, Any]:
    """Return SARIF 2.1.0 without turning UNKNOWN into a vulnerability claim."""

    payload = public_report(
        report,
        root=root,
        python_executable=python_executable,
        collection_enabled=collection_enabled,
    )
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        try:
            finding_state = FindingState(str(finding.get("state", FindingState.UNKNOWN.value)))
        except ValueError:
            finding_state = FindingState.UNKNOWN
        if finding_state == FindingState.PLANNED:
            continue
        rule_id, description, level, kind = _sarif_rule(finding_state)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": description},
                "fullDescription": {"text": description},
                "defaultConfiguration": {"level": level},
            },
        )
        next_action = (
            "Inspect the workflow scope and add the file to an intended pytest command."
            if finding_state == FindingState.NOT_PLANNED
            else "Provide complete collection, workflow, and event evidence before treating this as a claim."
        )
        path = str(finding.get("path", "<unknown-path>"))
        reason = str(finding.get("reason", "incomplete evidence"))
        evidence = finding.get("evidence", [])
        if not isinstance(evidence, list):
            evidence = []
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": quote(path.replace("\\", "/"), safe="/-._~"),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {"startLine": 1, "startColumn": 1},
            }
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "kind": kind,
                "message": {"text": f"{path}: {reason} Next action: {next_action}"},
                "locations": [location],
                "properties": {
                    "state": finding_state.value,
                    "blocking": bool(finding.get("blocking", False)),
                    "confidence": str(finding.get("confidence", "unknown")),
                    "reasonCode": str(finding.get("reason_code", finding_state.value)) or finding_state.value,
                    "evidence": evidence,
                },
            }
        )

    complete = bool(payload["completeness"]["analysis"])
    run_properties = {
        "greengapReportVersion": REPORT_VERSION,
        "analysisComplete": complete,
        "workspaceStable": report.stable,
        "collectionComplete": report.collection.complete,
        "runtimeExecutionIdentity": "NOT_CERTIFIED",
        "collectionMode": payload["environment"]["collection_mode"],
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GreenGap",
                        "version": __version__,
                        "semanticVersion": _semantic_version(),
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
                "invocations": [
                    {
                        "executionSuccessful": complete,
                        "properties": {
                            "analysisComplete": complete,
                            "collectionComplete": report.collection.complete,
                            "traceComplete": (
                                report.trace.complete if isinstance(report, PlanReport) else None
                            ),
                            "executionConsent": collection_enabled,
                        },
                    }
                ],
                "properties": run_properties,
            }
        ],
    }


def json_contract_summary(payload: dict[str, Any]) -> str:
    """Return a concise deterministic status line for human output."""

    outcome = str(payload.get("outcome", "INCOMPLETE"))
    codes = payload.get("completeness", {}).get("reason_codes", [])
    suffix = f"; reasons={','.join(codes)}" if codes else ""
    return f"outcome: {outcome}{suffix}"
