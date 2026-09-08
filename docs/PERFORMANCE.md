# Performance protocol

Performance numbers are project budgets, not universal thresholds. Measure
GreenGap overhead separately from the target project's dependency installation
and pytest collection time. Do not publish a benchmark without fixture size,
machine, interpreter, dependency versions, warm/cold state, and exclusions.

## Required fixtures

| Fixture | Definition | Required measurements |
| --- | --- | --- |
| Small | 10 test files, 1 workflow, no plugins | p50/p95 wall time, peak process memory, report bytes |
| Medium | 1,000 source/test files, 4 workflow shapes | same; separate static trace and collection |
| Large | 10,000 files under the input budget | same; investigate misses over 5 s / 512 MiB |

The candidate has no unsound cache. If a cache is added later, its key must
bind source bytes, configuration, environment, tool/report version, and policy,
and it must have poisoned/stale-cache tests.

## Reproduction

Run `scripts/measure_performance.py` after the candidate environment is
available, store its JSON beside the launch receipt, and repeat at least five
times per fixture. The harness can create deterministic disposable fixtures
with `--fixture-size small|medium|large --fixture-root <empty-root>`; it never
enables target collection unless `--trust-collection` is explicitly supplied.
A missing peak-memory or disk measurement is `UNKNOWN`, not zero.

The 2026-09-08 matrix was measured on Windows 11 AMD64 with Python 3.13.3,
five measured runs after one warmup, and `collection_enabled=false`:

| Fixture | Definition | p50 wall | p95 wall | peak parent RSS | disk delta | Result |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Small | 10 test files, 1 workflow | 0.234 s | 0.260 s | 39.9 MiB | 0 B | measured |
| Medium | 1,000 test files, 4 workflow files/shapes | 6.817 s | 7.048 s | 102.8 MiB | 0 B | timing budget miss |
| Large | 10,000 test files, 4 workflow files/shapes | 56.593 s | 57.926 s | 138.5 MiB | 0 B | timing budget miss |

Receipts: [`performance-small-20260908.json`](evidence/performance-small-20260908.json),
[`performance-medium-20260908.json`](evidence/performance-medium-20260908.json),
[`performance-large-20260908.json`](evidence/performance-large-20260908.json),
and the aggregate [`performance-20260908.json`](evidence/performance-20260908.json).
Startup timing is recorded separately in
[`startup-20260908.json`](evidence/startup-20260908.json): version p95 0.390 s
and help p95 0.291 s, both within the one-second startup budget.

The 10,000-file five-second static-analysis target is not met on this ordinary
Windows reference machine; the 512 MiB memory budget is met. A bounded
parallel snapshot/candidate-inspection optimization and one-time redaction
context reduced the large p95 from 108.348 s to 57.926 s without weakening
fail-closed workspace binding or adding a source cache. The launch decision
remains open pending an owner-approved budget exception, a separately reviewed
algorithmic change, and Linux evidence; the measurements are not presented as
a stable-performance pass.
