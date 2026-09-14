# GreenGap 1.0 applicability cohort protocol

**Protocol version:** 1.0, pre-selection revision 1.1  
**Recorded date:** 2026-09-10  
**Status:** preregistered before repository selection or trusted execution  
**Candidate under test:** `c30543a4e3442a5238cf714c31f333e6cdfbb45e`  
**Candidate tree:** `89071e9aafdd92ddf7001f9ccdc60083289b5e86`

This protocol measures whether GreenGap is useful inside its documented 1.0
support envelope. It is a new prospective population. It does not replace,
repair, reinterpret, or silently exclude the original stress cohort.

## Preserved stress-cohort result

The original three frozen holdouts remain permanent evidence with their
original outcome:

```text
STRESS_COHORT_SOUNDNESS=PASS — 0 false confident conclusions
STRESS_COHORT_USEFULNESS=FAILED — 0 useful determinations
ORIGINAL_GATE_RESULT=COHORT_USEFULNESS_GATE_FAILED
```

The source receipt is
[`evidence/cohort-trusted-20260910-6f76949.json`](evidence/cohort-trusted-20260910-6f76949.json),
with the classification in
[`evidence/cohort-usefulness-20260910-c30543a.json`](evidence/cohort-usefulness-20260910-c30543a.json).
Those results remain a stress-boundary finding: GreenGap abstained safely,
but the cohort produced no useful determinations.

## Threshold recovery and prospective gate

The original committed launch and mission documentation was searched before
this protocol was written, including the README contract, the applicability
matrix, the frozen cohort manifest, the trusted-cohort receipt, and the
usefulness classification receipt. The records say that useful determinations
are required and that an all-`UNKNOWN` result is not a pass, but they do not
state a numeric usefulness threshold. Therefore:

```text
ORIGINAL_USEFULNESS_THRESHOLD=UNDERSPECIFIED
```

The prospective default, fixed before selection, is:

* at least `8/12` selected eligible repositories must produce at least one
  complete useful determination;
* at least `2/3` designated final holdouts must produce a complete useful
  determination; and
* `FALSE_CONFIDENT_CONCLUSIONS=0`.

A useful determination is a justified complete result with GreenGap exit `0`
or `1`. A complete `PLANNED`/no-gap result counts. A proven complete gap also
counts. `UNKNOWN` or exit `2` does not count, even when fail-closed behavior is
correct. A finding is not required for usefulness.

The historical manifest recorded a 12-repository target and at least three
holdouts; no stricter numeric sample requirement was found in the committed
launch records. That requirement is retained here as the minimum.

## Advertised applicability boundary

The static population is limited to public GitHub repositories that satisfy
all of these conditions at the pinned discovery revision:

1. The repository is publicly readable and is not GreenGap itself or a
   disposable GreenGap probe.
2. It is a Python project, shown by its repository language/configuration and
   Python source or packaging metadata.
3. It contains a pytest-based test suite with tracked pytest test files or
   equivalent pytest configuration.
4. A GitHub Actions workflow used for relevant tests is present in the
   repository.
5. At least one relevant pytest execution path is statically expressible by
   the stable resolver documented in the repository README: direct pytest or
   `python -m pytest`, supported local wrappers/composites/reusable workflows,
   static matrix rows, or another explicitly documented supported path.
6. The selected event can be bound concretely to the recorded event, ref or
   base ref, and changed-file context where that workflow uses it.

The eligibility decision is static. GreenGap is not run to decide whether a
repository is eligible. A candidate is excluded from the applicability
population when its only relevant test path fundamentally requires a known
unsupported boundary, including:

* an unresolved external reusable workflow;
* a runtime-generated selector GreenGap cannot resolve;
* an unavoidable opaque external test action;
* unsupported shell or control-flow boundaries;
* a workspace transformation that invalidates static proof; or
* a non-pytest primary test framework.

Every discovered repository is recorded in order with `ELIGIBLE` or an exact
exclusion code and reason. An unavailable permitted dependency recipe is also
recorded before selection as `DEPENDENCY_RECIPE_UNAVAILABLE`; it is not
silently repaired with guessed packages.

## Candidate discovery and deterministic selection

Discovery is mechanical and outcome-blind. Before selection, the protocol was
amended to use the pytest-targeted query below as the sole discovery source.
The broad Python query was read during planning but is not used to define the
population; removing that irrelevant source before any selection preserves a
clear, reproducible denominator and is not based on GreenGap outcomes. The
preregistered GitHub Search REST query is one page of up to 100 results,
sorted by descending stars:

```text
language:Python archived:false pytest
```

Results are de-duplicated by lower-case `owner/name`, retaining the discovery
position. The complete ordered discovery list, all static decisions,
and the resulting ordered eligible population will be retained in
`docs/evidence/applicability-cohort-discovery-20260910-c30543a.json`. The
static population must contain at least 30 eligible repositories before any
trusted execution is allowed. If it does not, the cohort stops as a failed
prerequisite; the query is not changed after outcomes are seen.

The fixed deterministic random seed is `20260910`. Selection uses Python's
`random.Random(20260910)` and a Fisher-Yates shuffle equivalent to
`random.shuffle` over the recorded ordered population. To guarantee the
separate omission-sensitivity minimum without outcome-based cherry picking:

1. Shuffle the full eligible population and the statically identified
   omission-capable population with the same seed-derived procedure.
2. Select six omission-capable repositories for the non-holdout group, then
   select three additional eligible repositories not already selected.
3. Designate the next three eligible repositories not already selected as the
   final holdouts.

This produces exactly 12 selected repositories when the preregistered minimums
are met: nine non-holdouts and three holdouts. If more are run, the additional
repositories are appended in the same recorded shuffled order; the threshold
denominator remains the preregistered 12 unless this protocol is amended and
committed before execution. The selected list and holdout identities are
recorded before the first trusted run in
`docs/evidence/applicability-cohort-selection-20260910-c30543a.json`.

No result, GreenGap output, or holdout outcome may affect eligibility, order,
selection, dependency recipes, or implementation decisions.

## Dependency and runner policy

Target dependencies are caller-supplied. For each selected repository, the
exact recipe is identified statically and recorded before trusted collection.
Permitted source order is:

1. the repository lock or requirements file used by its own CI;
2. a documented test/development extra; or
3. the exact installation procedure visibly used by the pinned CI workflow.

There is no interactive package guessing, owner credential, secret, write
token, or target-network access. Dependency preparation and real pytest
collection run only inside a disposable GitHub-hosted runner. Each job uses
empty workflow permissions, no secrets, anonymous public checkout where
practical, `persist-credentials: false`, a disposable `$RUNNER_TEMP`
workspace, and bounded job/command/filesystem budgets. The exact Python
version, runner image, checkout SHA, installation commands, event/ref/base-ref,
changed-file inputs, and exit/result receipts are retained for every run.

The candidate source is always the exact frozen GreenGap SHA above. The target
repository is always checked out at its recorded commit. The wrapper never
executes workflow YAML while tracing it; the target's real collection command
is executed only for the trusted qualification witness inside the disposable
runner.

## Qualification order and source-freeze rule

The work proceeds in this order:

1. mechanically discover and statically classify the candidate population;
2. record the complete population, deterministic selection, and holdouts;
3. run the nine non-holdouts with their predeclared dependency recipes;
4. run the separate controlled omission sensitivity exercise;
5. freeze the source and inspect the settled qualification evidence;
6. run the three final holdouts; and
7. adjudicate usefulness and false-confidence counts.

If a result exposes a truly supported GreenGap defect, only a minimal fix is
permitted. The defect, affected identities, and invalidated receipts must be
recorded. No holdout may be inspected for tuning, and no source change is
permitted after holdout execution begins.

## Controlled omission sensitivity

Natural cohort usefulness and omission sensitivity are separate measurements.
At least six non-holdout repositories must have a statically recognized broad
pytest path and at least two known pytest files suitable for a supported
test-only omission. For each of those six repositories:

1. establish and retain a complete baseline;
2. make a disposable workflow-only change that narrows the proven pytest path
   so one known collected pytest file is omitted while remaining in the
   supported grammar;
3. rerun GreenGap in the disposable checkout;
4. restore the workflow and rerun the baseline; and
5. retain the before/mutation/after identities and result receipts.

The sensitivity gate is:

```text
CONTROLLED_OMISSIONS_DETECTED=6/6
RESTORED_BASELINES_RETURN_TO_EXPECTED_STATE=6/6
```

These deliberate mutations never count as naturally occurring production
gaps or as natural-cohort usefulness.

## Result adjudication and stop rule

Each repository receipt records collection completeness, environment validity,
GreenGap exit/outcome, candidate and finding states, reason codes, useful
determination, and false-confident-conclusion status. A non-`UNKNOWN` result
whose independent pinned-workflow/collection adjudication contradicts the
reported conclusion is false confident. If the adjudication is incomplete,
GreenGap must remain `UNKNOWN`; it is not upgraded to usefulness.

The applicability gate passes only when all of the following hold:

```text
at least 8/12 selected repositories useful
at least 2/3 final holdouts useful
FALSE_CONFIDENT_CONCLUSIONS=0
CONTROLLED_OMISSIONS_DETECTED=6/6
RESTORED_BASELINES_RETURN_TO_EXPECTED_STATE=6/6
```

If the cohort produces zero or low usefulness, the launch stops and the
advertised support envelope is not claimed practically useful. If it passes,
the launch record may state:

```text
APPLICABILITY_COHORT=PASS
ORIGINAL_STRESS_COHORT=COHORT_USEFULNESS_GATE_FAILED
REAL_WORLD_USEFULNESS=PASS_WITHIN_DOCUMENTED_1_0_SUPPORT_SCOPE
```

Formal human sessions remain unconsumed until this gate passes. This protocol
does not authorize merge, tagging, artifact promotion, publication, or any
other release action.

## Preregistration boundary and receipts

This file and
[`evidence/applicability-cohort-preregistration.json`](evidence/applicability-cohort-preregistration.json)
must be committed before the discovery result, selected list, trusted runner,
or controlled omission job exists. The JSON receipt records the binding commit
after the boundary commit is created. Selection and execution remain forbidden
until that commit identity is read back and the receipt is finalized.

Planned later receipts are:

* `applicability-cohort-discovery-20260910-c30543a.json`;
* `applicability-cohort-selection-20260910-c30543a.json`;
* `applicability-cohort-qualification-20260910-c30543a.json`;
* `applicability-omission-sensitivity-20260910-c30543a.json`; and
* `applicability-cohort-final-holdouts-20260910-c30543a.json`; and
* `applicability-cohort-execution-20260910-34439845721-c30543a.json`.

The aggregate execution receipt records the exact hosted run and the fixed
gate failure: 0/12 useful determinations, 0/6 controlled omissions detected,
6/6 restored baselines, and 0/3 useful final holdouts. One designated holdout
(A12) was setup-incomplete because the frozen Python 3.10 collection
environment could not satisfy the hash-locked transitive dependency boundary.
This outcome receipt does not amend the preregistered population, selection,
thresholds, or fail-closed semantics; the launch status remains blocked.
