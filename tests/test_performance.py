from __future__ import annotations

from time import perf_counter

import pytest

from greengap.model import Candidate, CollectionResult, PytestInvocation, TraceResult
from greengap.reconcile import reconcile_plan


@pytest.mark.parametrize("count", [10_000, 50_000])
def test_reconciliation_screen_scales_to_large_candidate_sets(count: int) -> None:
    candidates = tuple(Candidate(f"tests/test_{index}.py", "high") for index in range(count))
    collection = CollectionResult(True, True, paths=tuple(candidate.path for candidate in candidates))
    trace = TraceResult((PytestInvocation("broad"),), ())

    started = perf_counter()
    findings = reconcile_plan(candidates, collection, trace)
    elapsed = perf_counter() - started

    assert len(findings) == count
    # This is deliberately a generous resilience screen, not a microbenchmark.
    assert elapsed < 10.0
