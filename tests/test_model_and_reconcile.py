from __future__ import annotations

import pytest

from greengap.model import (
    Candidate,
    CollectionResult,
    FindingState,
    PytestInvocation,
    TraceIssue,
    TraceResult,
)
from greengap.reconcile import plan_is_complete, reconcile_plan


def collection(*paths: str, complete: bool = True) -> CollectionResult:
    return CollectionResult(complete, True, paths=tuple(paths))


@pytest.mark.parametrize(
    ("kind", "paths", "target", "expected"),
    [
        ("broad", (), "tests/a.py", True),
        ("paths", ("tests",), "tests/a.py", True),
        ("paths", ("tests",), "src/a.py", False),
        ("paths", ("tests/a.py",), "tests/a.py", True),
        ("paths", ("tests/a.py",), "tests/a.py::test_x", False),
        ("unknown", (), "tests/a.py", False),
    ],
)
def test_invocation_file_coverage(
    kind: str, paths: tuple[str, ...], target: str, expected: bool
) -> None:
    assert PytestInvocation(kind, paths).covers(target) is expected


def test_broad_invocation_serializes_provenance() -> None:
    item = PytestInvocation("broad", provenance=("ci.yml", "run: pytest"))
    assert item.to_dict()["provenance"] == ["ci.yml", "run: pytest"]


def test_planned_when_broad_scope_covers_collected_file() -> None:
    candidate = (Candidate("tests/test_a.py", "high", ("test_a",)),)
    trace = TraceResult((PytestInvocation("broad", provenance=("ci.yml",)),), ())
    findings = reconcile_plan(candidate, collection("tests/test_a.py"), trace)
    assert findings[0].state == FindingState.PLANNED
    assert not findings[0].blocking


def test_path_scope_can_leave_collected_file_not_planned() -> None:
    candidates = (
        Candidate("tests/unit/test_a.py", "high"),
        Candidate("tests/integration/test_b.py", "high"),
    )
    trace = TraceResult((PytestInvocation("paths", ("tests/unit",)),), ())
    findings = reconcile_plan(
        candidates, collection("tests/unit/test_a.py", "tests/integration/test_b.py"), trace
    )
    states = {finding.path: finding.state for finding in findings}
    assert states["tests/unit/test_a.py"] == FindingState.PLANNED
    assert states["tests/integration/test_b.py"] == FindingState.NOT_PLANNED


def test_union_of_path_scopes_is_planned() -> None:
    candidates = (Candidate("tests/a.py", "high"), Candidate("tests/b.py", "high"))
    trace = TraceResult(
        (
            PytestInvocation("paths", ("tests/a.py",)),
            PytestInvocation("paths", ("tests/b.py",)),
        ),
        (),
    )
    findings = reconcile_plan(candidates, collection("tests/a.py", "tests/b.py"), trace)
    assert all(finding.state == FindingState.PLANNED for finding in findings)


def test_unregistered_is_nonblocking() -> None:
    findings = reconcile_plan(
        (Candidate("tests/test_missing.py", "high"),), collection(), TraceResult()
    )
    assert findings[0].state == FindingState.UNREGISTERED
    assert not findings[0].blocking


def test_low_confidence_is_unknown_and_nonblocking() -> None:
    findings = reconcile_plan(
        (Candidate("tests/test_name.py", "low"),), collection(), TraceResult()
    )
    assert findings[0].state == FindingState.UNKNOWN
    assert not findings[0].blocking


def test_incomplete_collection_downgrades_observed_and_candidates() -> None:
    candidates = (Candidate("tests/test_a.py", "high"), Candidate("tests/test_b.py", "high"))
    findings = reconcile_plan(
        candidates, collection("tests/test_a.py", complete=False), TraceResult()
    )
    assert all(finding.state == FindingState.UNKNOWN for finding in findings)
    assert not any(finding.blocking for finding in findings)


def test_relevant_incomplete_trace_downgrades_collected_file() -> None:
    trace = TraceResult(issues=(TraceIssue("DYNAMIC", "unknown selector"),))
    findings = reconcile_plan(
        (Candidate("tests/test_a.py", "high"),), collection("tests/test_a.py"), trace
    )
    assert findings[0].state == FindingState.UNKNOWN
    assert not findings[0].blocking


def test_relevant_incomplete_trace_downgrades_even_a_covering_scope() -> None:
    trace = TraceResult(
        invocations=(PytestInvocation("broad", provenance=("ci.yml",)),),
        issues=(TraceIssue("DYNAMIC", "unknown selector"),),
    )
    findings = reconcile_plan(
        (Candidate("tests/test_a.py", "high"),), collection("tests/test_a.py"), trace
    )
    assert findings[0].state == FindingState.UNKNOWN
    assert not findings[0].blocking


def test_unrelated_incomplete_trace_does_not_erase_broad_plan() -> None:
    trace = TraceResult(
        invocations=(PytestInvocation("broad", provenance=("good.yml",)),),
        issues=(TraceIssue("EXTERNAL", "unrelated external workflow", relevant=False),),
    )
    findings = reconcile_plan(
        (Candidate("tests/test_a.py", "high"),), collection("tests/test_a.py"), trace
    )
    assert findings[0].state == FindingState.PLANNED


def test_no_invocation_on_complete_graph_is_blocking() -> None:
    findings = reconcile_plan(
        (Candidate("tests/test_a.py", "high"),), collection("tests/test_a.py"), TraceResult()
    )
    assert findings[0].state == FindingState.NOT_PLANNED
    assert findings[0].blocking


def test_unstable_workspace_never_blocks() -> None:
    findings = reconcile_plan(
        (Candidate("tests/test_a.py", "high"),),
        collection("tests/test_a.py"),
        TraceResult(),
        stable=False,
    )
    assert findings[0].state == FindingState.UNKNOWN
    assert not findings[0].blocking
    assert not plan_is_complete(findings, collection("tests/test_a.py"), False)


def test_collected_only_file_is_retained_in_plan_surface() -> None:
    trace = TraceResult((PytestInvocation("broad"),), ())
    findings = reconcile_plan((), collection("tests/custom_name.py"), trace)
    assert findings[0].path == "tests/custom_name.py"
    assert findings[0].confidence == "collected"
    assert findings[0].state == FindingState.PLANNED


@pytest.mark.parametrize(
    "state",
    [
        FindingState.NOT_SEEN,
        FindingState.SKIPPED,
        FindingState.EXECUTED_PASS,
        FindingState.EXECUTED_FAIL,
    ],
)
def test_witness_states_are_serializable(state: FindingState) -> None:
    assert state.value.isupper()
