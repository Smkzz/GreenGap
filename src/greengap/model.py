"""Small immutable domain model used by the GreenGap adapters."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class FindingState(StrEnum):
    """User-facing semantic states."""

    UNREGISTERED = "UNREGISTERED"
    NOT_PLANNED = "NOT_PLANNED"
    NOT_SEEN = "NOT_SEEN"
    SKIPPED = "SKIPPED"
    EXECUTED_PASS = "EXECUTED_PASS"
    EXECUTED_FAIL = "EXECUTED_FAIL"
    UNKNOWN = "UNKNOWN"
    PLANNED = "PLANNED"


@dataclass(frozen=True)
class Candidate:
    path: str
    confidence: str
    symbols: tuple[str, ...] = ()
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "confidence": self.confidence,
            "symbols": list(self.symbols),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CollectedNode:
    nodeid: str
    path: str

    def to_dict(self) -> dict[str, Any]:
        return {"nodeid": self.nodeid, "path": self.path}


@dataclass(frozen=True)
class CollectionResult:
    complete: bool
    environment_valid: bool
    nodes: tuple[CollectedNode, ...] = ()
    paths: tuple[str, ...] = ()
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "environment_valid": self.environment_valid,
            "nodes": [node.to_dict() for node in self.nodes],
            "paths": list(self.paths),
            "returncode": self.returncode,
            "error": self.error,
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True)
class PytestInvocation:
    """A proven file-level pytest selection with its resolution provenance."""

    kind: str
    paths: tuple[str, ...] = ()
    selectors: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()
    complete: bool = True
    reason: str = ""
    # This is deliberately internal to the in-memory proof object.  Static
    # Plan invocations are always exact-case/portable (True); the optional
    # case-insensitive branch remains reserved for a future runtime-witness
    # layer and is not populated from workflow routing metadata.
    path_case_sensitive: bool = True

    def covers(self, path: str) -> bool:
        if not self.complete:
            return False
        if self.kind == "broad":
            return True
        if self.kind != "paths":
            return False
        if not self.path_case_sensitive:
            path = path.replace("\\", "/")
        normalized = posixpath.normpath(path)
        if normalized == ".":
            normalized = ""
        if not self.path_case_sensitive:
            normalized = normalized.casefold()
        if normalized == ".." or normalized.startswith("../"):
            return False
        for selected in self.paths:
            if not self.path_case_sensitive:
                selected = selected.replace("\\", "/")
            scope = posixpath.normpath(selected)
            if scope == ".":
                scope = ""
            if not self.path_case_sensitive:
                scope = scope.casefold()
            if scope == ".." or scope.startswith("../"):
                continue
            if not scope:
                return True
            if normalized == scope or normalized.startswith(scope + "/"):
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "paths": list(self.paths),
            "selectors": list(self.selectors),
            "provenance": list(self.provenance),
            "complete": self.complete,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class TraceIssue:
    code: str
    message: str
    provenance: tuple[str, ...] = ()
    relevant: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "provenance": list(self.provenance),
            "relevant": self.relevant,
        }


@dataclass(frozen=True)
class TraceResult:
    invocations: tuple[PytestInvocation, ...] = ()
    issues: tuple[TraceIssue, ...] = ()
    workflows: tuple[str, ...] = ()
    changed_files: tuple[str, ...] | None = None
    event: str | None = None
    activity: str | None = None
    ref: str | None = None
    base_ref: str | None = None
    change_set_complete: bool = False
    commit_count: int | None = None
    changed_file_count: int | None = None
    diff_timed_out: bool = False

    @property
    def relevant_incomplete(self) -> bool:
        return any(issue.relevant for issue in self.issues)

    @property
    def complete(self) -> bool:
        return not self.relevant_incomplete

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflows": list(self.workflows),
            "changed_files": (
                None if self.changed_files is None else list(self.changed_files)
            ),
            "event": self.event,
            "activity": self.activity,
            "ref": self.ref,
            "base_ref": self.base_ref,
            "change_set_complete": self.change_set_complete,
            "commit_count": self.commit_count,
            "changed_file_count": self.changed_file_count,
            "diff_timed_out": self.diff_timed_out,
            "invocations": [invocation.to_dict() for invocation in self.invocations],
            "issues": [issue.to_dict() for issue in self.issues],
            "complete": self.complete,
        }


@dataclass(frozen=True)
class Finding:
    path: str
    state: FindingState
    blocking: bool
    confidence: str
    reason: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "state": self.state.value,
            "blocking": self.blocking,
            "confidence": self.confidence,
            "reason": self.reason,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class WorkspaceSnapshot:
    fingerprint: str
    files: tuple[str, ...]
    method: str
    errors: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "file_count": len(self.files),
            "method": self.method,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class ScanReport:
    repository: str
    snapshot: WorkspaceSnapshot
    final_fingerprint: str
    candidates: tuple[Candidate, ...]
    collection: CollectionResult
    stable: bool
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": "scan",
            "repository": self.repository,
            "snapshot": self.snapshot.to_dict(),
            "final_fingerprint": self.final_fingerprint,
            "stable": self.stable,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "collection": self.collection.to_dict(),
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class PlanReport:
    repository: str
    snapshot: WorkspaceSnapshot
    final_fingerprint: str
    candidates: tuple[Candidate, ...]
    collection: CollectionResult
    trace: TraceResult
    findings: tuple[Finding, ...]
    complete: bool
    stable: bool
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def blockers(self) -> tuple[Finding, ...]:
        return tuple(finding for finding in self.findings if finding.blocking)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": "plan",
            "repository": self.repository,
            "snapshot": self.snapshot.to_dict(),
            "final_fingerprint": self.final_fingerprint,
            "stable": self.stable,
            "complete": self.complete,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "collection": self.collection.to_dict(),
            "trace": self.trace.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "blocker_count": len(self.blockers),
            "errors": list(self.errors),
        }
