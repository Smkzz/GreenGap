# GreenGap 1.0.0rc1 launch handoff

This is the canonical evidence handoff for the release-candidate closure.
It is not a release announcement. The candidate remains blocked from stable
launch, merge, tagging, registry upload, and public publication.

## Candidate binding

| Field | Value |
| --- | --- |
| Baseline | immutable v0.1.3 release; `V0_1_3_MUTATED=0` |
| Original source checkpoint | `272ab74cf4416ee78f5d8b95c37bf9f88ba10f10` / `b1ac8855e5d2e782977f26c0350ad88e85b247b2` |
| Closure-document checkpoint | `ca2d25e42b443fdda2a9ac0e3bb36e244544e529` / `0870a442f35f7af084afa96f28311e85be482906` |
| Historical source freeze before external workflow fixes | `6f76949c47535a203ddb5a78a1f038afaecd6e88` / `bf8a2da0ac70a797c2dce32f5771edac8b501c34` |
| Current candidate source head | `c30543a4e3442a5238cf714c31f333e6cdfbb45e` / `ef915d9ce529da5849c3c002b7797d8394b56573` |
| Candidate version | `1.0.0rc1` |
| Promotion worktree | `qualification/promotion-clean-ca2d25e-20260909` |
| Remote branch | `release/greengap-1.0.0` |
| Pull request | [#11](https://github.com/Smkzz/GreenGap/pull/11) to `main` |
| PR state | open, not draft, `REVIEW_REQUIRED`, merge `BLOCKED`, no latest reviews |
| Published channels | none |
| Current state | `GREENGAP_STABLE_LAUNCH_BLOCKED` |

The 6f source freeze is retained as historical evidence. Real hosted workflow
exercises exposed concrete dependency, legacy-CLI, and canonical self-call
defects, so source was deliberately reopened. The product fix landed at
956285d; the current c30543a head adds only the final push-trigger test fixture
correction after that source fix. The current candidate therefore differs from
the historical freeze in the narrow analyzer/CLI/workflow fix and its tests;
the current Linux receipt is bound to c30543a itself. The reusable-workflow
success/PR/schedule cases, final artifacts, and the remaining human/owner/
authorization gates still require closure.

## Fast verification

From the promotion worktree, use the managed audit interpreter and keep
untrusted checkouts on `--no-collect`:

```powershell
$python = "C:\Projects\GreenGap\qualification\envs\greengap-audit\Scripts\python.exe"
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
& $python -m pytest -q
& $python -m ruff check src tests
& $python -m mypy src/greengap
& $python -m compileall -q src tests scripts
& $python -m greengap plan . --no-collect --json
```

The retained local receipt records `517 passed, 1 skipped`, Ruff, mypy,
compileall, and safe-default CLI evidence at the historical source checkpoint;
the exact c30543a hosted matrix records the current candidate checks. All
receipts are indexed in [`evidence/README.md`](evidence/README.md).

## Acceptance status

| Domain | Final evidence | Status |
| --- | --- | --- |
| 1. Correct product | Full local regression and final source freeze | PASS |
| 2. Safe execution/fail-closed | Safe default, explicit consent boundary, bounded tracing | PASS |
| 3. CLI/agent interface | Independent JSON/SARIF parsing and schema validation | PASS |
| 4. Platform reliability | Exact c30543a hosted Ubuntu/Windows matrix, audit, package, fuzz, and review checks | PASS |
| 5. Performance | Exact-c30543a hosted Linux timing/startup/RSS and exact 6f-source Windows timing pass | PASS |
| 6. CI/dependency security | Exact-source hosted checks plus bounded independent/security scans | PASS for observed scope; schedule/exact CodeQL scope open |
| 7. Packaging/provenance | Hosted package job passed; final local artifact/attestation not retained | PARTIAL |
| 8. Documentation/onboarding | Updated handoff, evidence index, and launch report | PASS |
| 9. Operations/maintenance | Owner confirmation is pending | BLOCKED |
| 10. Authorized launch | No human sign-off or publication authorization | BLOCKED |

The aggregate count is `7/10` domains passed; this does not qualify the
candidate for stable status.

## Open launch gates

1. Complete the real disposable caller gate for `greengap-plan.yml`: the
   current probe records concrete dependency/compatibility repairs but still
   tests immutable v0.1.3 and returns fail-closed
   `EXTERNAL_WORKFLOW_UNRESOLVED`/exit 2. No genuine `event=schedule` run has
   been observed. Obtain a compatible final artifact plus exact source-head
   success/PR/schedule/default-branch receiver evidence.
2. The three untouched holdouts now have isolated trusted-collection receipts
   with `FALSE_CONFIDENT_CONCLUSIONS=0`, but all remain UNKNOWN/exit 2 and
   produced zero useful determinations. Complete the usefulness threshold and
   the C11/C12 exclusion decisions for the frozen cohort.
3. Run five fresh consenting human first-use sessions with at least four
   successful integrations; agent simulations do not count.
4. Obtain accountable maintenance, support, rollback, and publication owner
   confirmation.
5. Retain a final-source package artifact and hosted provenance/attestation
   evidence, with independent verification of the exact bytes.
6. Obtain explicit authorization before any merge, tag, release, registry
   upload, PyPI publication, or public verification.

No credential request, spending, merge bypass, tag movement, release
recreation, or publication was performed by this task.
