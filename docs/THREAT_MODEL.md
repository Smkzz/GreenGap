# GreenGap threat model

## Scope and security objective

GreenGap should never convert missing or ambiguous execution evidence into a
confident `PLANNED` or `NOT_PLANNED` claim. Its primary asset is soundness of a
repository-relative Plan report. Secondary assets are user source bytes,
credentials in the analyst environment, and the integrity of shareable
reports.

## Data flow

```text
checkout
  ├─ bounded source/config/workflow reads ──> candidate + static trace
  ├─ explicit --trust-collection ─────────> selected Python -m pytest --collect-only
  ├─ pre/post workspace snapshot ──────────> SHA-256 stability binding
  └─ report serializer ───────────────────> local JSON/SARIF file or stdout
```

The static resolver never executes workflow commands, shell scripts, Make
recipes, npm scripts, tox commands, downloaded evidence, or generated report
content. Collection is the intentional execution boundary and is disabled by
default. There is no default telemetry, repository upload, or target-network
request.

## Trust boundaries and permissions

| Boundary | Threat | Control | Regression/evidence |
| --- | --- | --- | --- |
| User -> CLI | Accidental execution of target code | `--trust-collection` is explicit; `--no-collect` is safe | `tests/test_cli.py` |
| Target source -> collector | Import hooks, plugins, subprocesses, hangs | explicit plugin binding, disabled autoload, process-tree termination, output/time limits | `tests/test_pytest_collection.py`, `tests/test_soundness_hardening.py` |
| Workflow text -> tracer | Command injection or false coverage | static bounded parsers; no shell/workflow execution; UNKNOWN on dynamic edges | `tests/test_trace.py`, post-release regressions |
| Checkout -> snapshot | Symlink/path traversal, mutation | containment checks, link-text hashing, budgets, pre/post fingerprints | `tests/test_snapshot_and_discovery.py` |
| Report -> consumer | Absolute-path or terminal/control leakage | repository-relative paths, redaction, JSON escaping, SARIF URI encoding | `tests/test_report_contract.py` |
| CI artifact -> reporter | Candidate-controlled instructions or credentials | upload inert report only; no privileged target-code job; separate policy gate | `.github/workflows/greengap-plan.yml` |
| PR fuzz checkout -> security reporting | Candidate build code inherits reporting authority or a forged report is uploaded | no `security-events` permission in fuzz job; only successful default-branch scheduled/manual `workflow_run` executions download the exact run's inert SARIF, check repository/event/path/head/workflow SHA and digest against the receipt, then validate shape before trusted upload | `.github/workflows/fuzz.yml`, `.github/workflows/fuzz-report.yml` |
| PR analysis checkout -> security reporting | Candidate-triggered CodeQL/Scorecard execution inherits reporting authority or a forged report is uploaded | analysis jobs retain read-only reporting posture; raw SARIF and exact-run receipts are inert artifacts; only successful default-branch push/scheduled `workflow_run` executions verify repository/event/path/ref/head/workflow SHA and digest before trusted upload | `.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml`, `.github/workflows/scorecard-report.yml` |
| Release tag -> publication | Unapproved tag code or tag drift reaches privileged release effects | read-only build job; default-branch `workflow_run` publisher; protected `release-publish` environment; active immutable tag-protection rule; repeated commit/tree/tag binding checks and `--target` release creation | `.github/workflows/release.yml`, `.github/workflows/release-publish.yml` |

The analyzer has the caller's filesystem permissions while reading the target
checkout. The candidate does not claim OS-level sandboxing, credential
scrubbing, network isolation, CPU/memory cgroups, or a complete descendant
process jail. Those properties require a separately selected isolation
environment and are an explicit launch limitation.

## Resource and parser boundaries

The existing v0.1.3 limits bound configuration/workflow bytes, workflow count,
matrix rows, recursion, workspace files/bytes, collection output, collection
duration, JUnit bytes/cases, XML entity declarations, and qualification process
trees. Malformed YAML/JSON/TOML/XML,
unsupported shell syntax, path escapes, symlinks, case/runner ambiguity, and
unresolved selection semantics become incomplete evidence. A stopped or
timed-out collection cannot produce a complete claim.

## Retention and sharing

Reports are emitted only when requested by the caller. They contain hashes,
repository-relative paths, bounded evidence strings, and status metadata; raw
collection output is not included in the public JSON contract. Users must
review any diagnostic bundle before sharing it. The reusable workflow uploads
only the validated inert JSON report and keeps the artifact retention policy in
the caller's control.

## Residual risks

The largest residual risk is intentional execution of an untrusted checkout if
an operator grants `--trust-collection` outside a real sandbox. The product
refuses to call a virtual environment a sandbox and does not pretend that a
GitHub-hosted runner is an isolation proof. A future isolated adapter requires
documented credential, mount, network, process, CPU, memory, output, timeout,
and descendant-cleanup controls before it can be added to the stable contract.
