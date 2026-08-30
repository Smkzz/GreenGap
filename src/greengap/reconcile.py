"""Fail-closed Plan-mode reconciliation policy."""

from __future__ import annotations

import posixpath

from .model import Candidate, CollectionResult, Finding, FindingState, PytestInvocation, TraceResult


def _scope_key(value: str, *, windows_paths: bool = False) -> str | None:
    """Normalize a repository path using the invocation runner's separators."""

    if windows_paths:
        value = value.replace("\\", "/")
    normalized = posixpath.normpath(value)
    if normalized == ".":
        return ""
    if normalized == ".." or normalized.startswith("../"):
        return None
    return normalized


def _path_prefixes(path: str, *, windows_paths: bool = False) -> tuple[str, ...]:
    normalized = _scope_key(path, windows_paths=windows_paths)
    if normalized is None or not normalized:
        return ("",)
    parts = normalized.split("/")
    return tuple(
        "/".join(parts[:index]) for index in range(len(parts), 0, -1)
    ) + ("",)


def _candidate_map(
    candidates: tuple[Candidate, ...], collected: CollectionResult
) -> dict[str, Candidate]:
    result = {candidate.path: candidate for candidate in candidates}
    for path in collected.paths:
        result.setdefault(
            path,
            Candidate(path, "collected", (), "observed in real pytest collection"),
        )
    return result


def reconcile_plan(
    candidates: tuple[Candidate, ...],
    collection: CollectionResult,
    trace: TraceResult,
    *,
    stable: bool = True,
) -> tuple[Finding, ...]:
    """Return file-level findings without converting missing evidence to blockers."""

    findings: list[Finding] = []
    all_candidates = _candidate_map(candidates, collection)
    collected_paths = set(collection.paths)
    case_sensitive_index: dict[str, list[PytestInvocation]] = {}
    case_insensitive_index: dict[str, list[PytestInvocation]] = {}
    for invocation in trace.invocations:
        if not invocation.complete:
            continue
        if invocation.kind == "broad":
            case_sensitive_index.setdefault("", []).append(invocation)
            continue
        if invocation.kind != "paths":
            continue
        index = (
            case_insensitive_index
            if not invocation.path_case_sensitive
            else case_sensitive_index
        )
        for scope in invocation.paths:
            key = _scope_key(scope, windows_paths=not invocation.path_case_sensitive)
            if key is not None:
                if not invocation.path_case_sensitive:
                    key = key.casefold()
                index.setdefault(key, []).append(invocation)
    covering_by_path: dict[str, tuple[PytestInvocation, ...]] = {}
    for path in collected_paths:
        matches: dict[PytestInvocation, None] = {}
        for prefix in _path_prefixes(path):
            for invocation in case_sensitive_index.get(prefix, ()):
                matches.setdefault(invocation, None)
        for prefix in _path_prefixes(path, windows_paths=True):
            for invocation in case_insensitive_index.get(prefix.casefold(), ()):
                matches.setdefault(invocation, None)
        covering_by_path[path] = tuple(matches)
    for path in sorted(all_candidates):
        candidate = all_candidates[path]
        if candidate.confidence == "low":
            findings.append(
                Finding(
                    path,
                    FindingState.UNKNOWN,
                    False,
                    candidate.confidence,
                    "low-confidence source candidate is not eligible for a blocking claim",
                )
            )
            continue
        if not stable:
            findings.append(
                Finding(
                    path,
                    FindingState.UNKNOWN,
                    False,
                    candidate.confidence,
                    "workspace bytes changed during analysis",
                )
            )
            continue
        if not collection.complete:
            findings.append(
                Finding(
                    path,
                    FindingState.UNKNOWN,
                    False,
                    candidate.confidence,
                    "pytest collection was incomplete; the collected subset cannot establish absence",
                )
            )
            continue
        if path not in collected_paths:
            findings.append(
                Finding(
                    path,
                    FindingState.UNREGISTERED,
                    False,
                    candidate.confidence,
                    "high-confidence repository candidate was absent from completed pytest collection",
                )
            )
            continue

        if trace.relevant_incomplete:
            findings.append(
                Finding(
                    path,
                    FindingState.UNKNOWN,
                    False,
                    candidate.confidence,
                    "the relevant CI command graph or selector semantics are incomplete",
                    tuple(issue.code for issue in trace.issues if issue.relevant),
                )
            )
            continue

        covering = covering_by_path.get(path, ())
        if covering:
            evidence = tuple(" -> ".join(invocation.provenance) for invocation in covering)
            findings.append(
                Finding(
                    path,
                    FindingState.PLANNED,
                    False,
                    candidate.confidence,
                    "collected file is covered by a proven pytest CI scope",
                    evidence,
                )
            )
        else:
            findings.append(
                Finding(
                    path,
                    FindingState.NOT_PLANNED,
                    True,
                    candidate.confidence,
                    "collected file is absent from the union of proven CI pytest scopes",
                )
            )
    return tuple(findings)


def plan_is_complete(
    findings: tuple[Finding, ...], collection: CollectionResult, stable: bool
) -> bool:
    if not stable or not collection.complete:
        return False
    return not any(
        finding.state == FindingState.UNKNOWN and finding.confidence != "low"
        for finding in findings
    )
