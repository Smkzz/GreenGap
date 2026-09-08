# GreenGap 1.0.0rc1 launch handoff

This is the canonical handoff for the stable-product mission. It is evidence,
not a release announcement.

## Candidate binding

| Field | Value |
| --- | --- |
| Baseline | immutable v0.1.3 release; `V0_1_3_MUTATED=0` |
| Candidate starting SHA | `2de5f22a0a1fe1aa8f5e30712e96077d923b104f` |
| Candidate starting tree | `c21113d1192dcd68a117c89b1805da41bc63e32d` |
| Candidate version | `1.0.0rc1` |
| Worktree | `qualification/post-hotfix-main-2de5f22-20260907` |
| Distribution channels | none published by this task |
| Current state | `GREENGAP_STABLE_LAUNCH_BLOCKED` until the open items below are closed |

The candidate deliberately does not alter, retag, recreate, or upload the
published v0.1.3 tag/release/assets. A final source SHA/tree and artifact
manifest must be recorded after the candidate is frozen and committed.

## Fast verification

From the candidate worktree:

```powershell
$python = (Get-Command python).Source
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
& $python -m pytest -p no:cacheprovider tests/test_cli.py tests/test_report_contract.py -q
& $python -m ruff check src tests
& $python -m mypy src
& $python -m compileall -q src tests scripts
& $python -m build
```

The repository's full acceptance command remains the one in
[`CONTRIBUTING.md`](../CONTRIBUTING.md). Use `--trust-collection` only for
disposable trusted fixtures; use `--no-collect` for untrusted checkouts.

## What is implemented here

- Explicit target-interpreter selection and a non-executing CLI default.
- A stable redacted JSON report contract with source/environment/context and
  completeness identities.
- SARIF 2.1.0 output with stable GreenGap rules and non-certifying invocation
  metadata.
- A maintained reusable GitHub Actions workflow that downloads one exact wheel,
  checks its digest, binds event/change metadata, and uploads inert evidence.
- Quickstart, support, trust, operations, standards, evaluation, performance,
  release-state, and demo documentation.
- Regression tests for mixed complete/incomplete/empty/failed report surfaces,
  consent behavior, redaction, SARIF structure, release-state transitions,
  process-tree cleanup, and trusted workflow provenance.

## Acceptance domains

| Domain | Candidate evidence | Status at handoff |
| --- | --- | --- |
| 1. Correct product | Existing v0.1.3 resolver plus report/CLI tests; 490 passed, 1 skipped | PASS for final local candidate |
| 2. Safe execution/fail-closed | explicit consent, bounded collection, threat model | PASS for refusal boundary; sandbox remains external |
| 3. CLI/agent interface | JSON/SARIF contract and exit-policy tests; 490 passed, 1 skipped | PASS for final local candidate |
| 4. Platform reliability | existing Ubuntu/Windows workflow lanes | EXTERNAL_BLOCKER for fresh hosted run |
| 5. Performance | small/medium/large five-run static matrix with RSS/disk; 10,000-file p95 57.926 s against 5 s target after bounded optimization | EXTERNAL_BLOCKER pending budget exception and Linux evidence |
| 6. CI/dependency security | pinned existing workflows plus reusable plan workflow | EXTERNAL_BLOCKER for hosted event verification |
| 7. Packaging/provenance | existing build/provenance workflow; candidate artifact not published | EXTERNAL_BLOCKER |
| 8. Documentation/onboarding | README and docs home | PASS for local content; link/command review remains owner action |
| 9. Operations/maintenance | operations and release-state documents | EXTERNAL_BLOCKER for accountable owner confirmation |
| 10. Authorized launch | no publication or human acceptance claimed | EXTERNAL_BLOCKER |

## Required owner or hosted actions

1. Freeze and commit the candidate after the full local gate passes; record the
   final SHA/tree and exact artifact bytes.
2. Obtain fresh exact-head machine review and genuine human review for any
   standard or launch decision that requires it.
3. Run the held-out repository cohort and five consenting first-run sessions;
   record actual evidence, not agent simulations as human validation.
4. Verify the actual hosted PR/main/schedule/branch-protection events and the
   immutable v1.0.0 draft assets.
5. Consolidate explicit approval for the exact version and channels, then
   publish once and perform public artifact verification. PyPI remains
   disabled until separately authorized.

No task in this handoff requests credentials, account registration, spending,
external outreach, merge bypass, tag movement, or release recreation.
