# GreenGap evidence

This directory contains evidence receipts for the `1.0.0rc1` release
candidate. Receipts named with `6f76949` are bound to the final source freeze
`6f76949c47535a203ddb5a78a1f038afaecd6e88` and tree
`bf8a2da0ac70a797c2dce32f5771edac8b501c34`. Earlier receipts are retained as
historical records and must not be read as evidence for that source freeze.
Receipts named with `83b4` bind the earlier workflow-correction candidate
head. Receipts named with `c30543a` bind the current candidate head, whose
product bytes include the narrow canonical self-call fix and whose final
follow-up commit is test-only. The exact-head hosted matrix and Linux
performance receipts now close those machine gates. The disposable direct-source
validation set is also recorded, while the reusable-workflow artifact,
schedule, cohort-usefulness, human, owner, and authorization gates remain
separate and open. The original cohort is retained as a failed-usefulness
stress cohort; the new applicability population is preregistered but has not
yet been selected or executed.

## Source-bound and candidate receipts

| Area | Receipt |
| --- | --- |
| Local regression, static checks, and safe CLI | [`local-gates-20260909-6f76949.json`](local-gates-20260909-6f76949.json) |
| Independent JSON/SARIF consumers | [`contract-consumer-20260909-6f76949.json`](contract-consumer-20260909-6f76949.json) |
| Startup timing | [`startup-20260909-6f76949.json`](startup-20260909-6f76949.json) |
| Windows/Linux performance | [`performance-methodology-20260909-final-6f76949.json`](performance-methodology-20260909-final-6f76949.json) |
| Hosted Linux exact-source performance probe | [`linux-performance-probe-20260910-6f76949.json`](linux-performance-probe-20260910-6f76949.json) |
| Hosted Linux exact-current-head performance probe | [`linux-performance-probe-20260910-83b4.json`](linux-performance-probe-20260910-83b4.json) |
| Hosted Linux exact-final-candidate performance probe | [`linux-performance-probe-20260910-c30543a.json`](linux-performance-probe-20260910-c30543a.json) |
| Hosted CI, package, audit, fuzz, and Scorecard checks | [`hosted-ci-20260909-6f76949.json`](hosted-ci-20260909-6f76949.json) |
| Hosted checks after workflow corrections | [`hosted-ci-20260910-83b4.json`](hosted-ci-20260910-83b4.json) |
| Hosted checks at exact final candidate head | [`hosted-ci-20260910-c30543a.json`](hosted-ci-20260910-c30543a.json) |
| Workflow event and reusable-workflow bindings | [`workflow-bindings-20260909-6f76949.json`](workflow-bindings-20260909-6f76949.json) |
| Real disposable reusable-workflow probe | [`reusable-workflow-probe-20260910-83b4.json`](reusable-workflow-probe-20260910-83b4.json) |
| Exact-candidate disposable reusable-workflow probe | [`reusable-workflow-probe-20260910-c30543a.json`](reusable-workflow-probe-20260910-c30543a.json) |
| Real disposable pull-request gap case | [`reusable-workflow-pr-gap-20260910-83b4.json`](reusable-workflow-pr-gap-20260910-83b4.json) |
| Exact-candidate disposable pull-request gap case | [`reusable-workflow-pr-gap-20260910-c30543a.json`](reusable-workflow-pr-gap-20260910-c30543a.json) |
| Exact-candidate disposable PASS/gap/UNKNOWN validation set | [`live-validation-set-20260910-c30543a.json`](live-validation-set-20260910-c30543a.json) |
| Scheduled receiver observation | [`schedule-receiver-20260910-c30543a.json`](schedule-receiver-20260910-c30543a.json) |
| Source, closure, branch, and PR identity | [`release-identity-20260909-6f76949.json`](release-identity-20260909-6f76949.json) |
| Bounded independent security coverage | [`independent-security-coverage-20260909-6f76949.json`](independent-security-coverage-20260909-6f76949.json) |
| Bounded review of post-freeze workflow corrections | [`independent-security-coverage-20260910-83b4.json`](independent-security-coverage-20260910-83b4.json) |
| Bounded review of the canonical self-call product fix | [`independent-security-coverage-20260910-956285d.json`](independent-security-coverage-20260910-956285d.json) |
| Isolated trusted collection for three frozen holdouts | [`cohort-trusted-20260910-6f76949.json`](cohort-trusted-20260910-6f76949.json) |
| Trusted cohort usefulness investigation | [`cohort-usefulness-20260910-c30543a.json`](cohort-usefulness-20260910-c30543a.json) |
| Frozen C11/C12 negative-shape decisions | [`cohort-exclusion-review-20260910-c30543a.json`](cohort-exclusion-review-20260910-c30543a.json) |
| Prospective applicability-cohort preregistration | [`applicability-cohort-preregistration.json`](applicability-cohort-preregistration.json) |
| Human usability gate | [`human-usability-20260909-6f76949.json`](human-usability-20260909-6f76949.json) |
| Owner confirmation gate | [`owner-confirmation-20260909-pending.json`](owner-confirmation-20260909-pending.json) |

The canonical aggregate is [`../launch-report.json`](../launch-report.json).
The release candidate remains `GREENGAP_STABLE_LAUNCH_BLOCKED`. A passing
receipt is evidence for its stated scope; it is not owner approval, merge
authorization, publication authorization, or proof of hosted ingestion unless
the receipt explicitly says so.

The performance receipts use five timed runs and one warmup against fresh,
non-executing static fixtures. Production timing measures `run_plan` without
tracemalloc, profiling, debugging, or coverage instrumentation. The live CLI
receipts intentionally use `--no-collect`, so `INCOMPLETE` and exit code `2`
are expected fail-closed results.

The older 2026-09-08/early-2026-09-09 receipts document prior candidate
states, package experiments, cohort acquisition, and historical measurements.
They are preserved for traceability and are not silently upgraded to final
source evidence.

The live validation-set receipt is direct-source evidence from the exact
candidate on a disposable runner. It covers one complete PASS/no-gap case, one
complete blocking proven-gap case, and one fail-closed UNKNOWN case. It does
not replace the reusable-workflow caller gate, which still requires a
compatible final artifact and genuine schedule evidence.
