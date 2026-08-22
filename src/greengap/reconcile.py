"""Fail-closed Plan-mode reconciliation policy."""

from __future__ import annotations

from .model import Candidate, CollectionResult, Finding, FindingState, TraceResult


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
        if path not in set(collection.paths):
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

        covering = tuple(invocation for invocation in trace.invocations if invocation.covers(path))
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
        elif trace.relevant_incomplete:
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
