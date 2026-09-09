# GreenGap evidence

This directory contains evidence receipts for the `1.0.0rc1` release
candidate. Receipts named with `6f76949` are bound to the final source freeze
`6f76949c47535a203ddb5a78a1f038afaecd6e88` and tree
`bf8a2da0ac70a797c2dce32f5771edac8b501c34`. Earlier receipts are retained as
historical records and must not be read as evidence for that source freeze.
Receipts named with `83b4` bind the current workflow-correction candidate
head; they do not supersede the historical 6f product receipts until exact-
head performance, reusable-workflow, artifact, human, owner, and authorization
gates close.

## Final source-freeze receipts

| Area | Receipt |
| --- | --- |
| Local regression, static checks, and safe CLI | [`local-gates-20260909-6f76949.json`](local-gates-20260909-6f76949.json) |
| Independent JSON/SARIF consumers | [`contract-consumer-20260909-6f76949.json`](contract-consumer-20260909-6f76949.json) |
| Startup timing | [`startup-20260909-6f76949.json`](startup-20260909-6f76949.json) |
| Windows/Linux performance | [`performance-methodology-20260909-final-6f76949.json`](performance-methodology-20260909-final-6f76949.json) |
| Hosted Linux exact-source performance probe | [`linux-performance-probe-20260910-6f76949.json`](linux-performance-probe-20260910-6f76949.json) |
| Hosted CI, package, audit, fuzz, and Scorecard checks | [`hosted-ci-20260909-6f76949.json`](hosted-ci-20260909-6f76949.json) |
| Hosted checks after workflow corrections | [`hosted-ci-20260910-83b4.json`](hosted-ci-20260910-83b4.json) |
| Workflow event and reusable-workflow bindings | [`workflow-bindings-20260909-6f76949.json`](workflow-bindings-20260909-6f76949.json) |
| Real disposable reusable-workflow probe | [`reusable-workflow-probe-20260910-83b4.json`](reusable-workflow-probe-20260910-83b4.json) |
| Real disposable pull-request gap case | [`reusable-workflow-pr-gap-20260910-83b4.json`](reusable-workflow-pr-gap-20260910-83b4.json) |
| Source, closure, branch, and PR identity | [`release-identity-20260909-6f76949.json`](release-identity-20260909-6f76949.json) |
| Bounded independent security coverage | [`independent-security-coverage-20260909-6f76949.json`](independent-security-coverage-20260909-6f76949.json) |
| Bounded review of post-freeze workflow corrections | [`independent-security-coverage-20260910-83b4.json`](independent-security-coverage-20260910-83b4.json) |
| Isolated trusted collection for three frozen holdouts | [`cohort-trusted-20260910-6f76949.json`](cohort-trusted-20260910-6f76949.json) |
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
