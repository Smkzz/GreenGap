# Applicability and evidence matrix

Statuses are deliberately evidence-backed: `PASS`, `FAIL`,
`NOT_APPLICABLE` with a reason, or `EXTERNAL_BLOCKER`. A missing credential,
unrun hosted event, or failing result is never relabeled not applicable.

| ID | Requirement / rationale | Acceptance evidence | Scope | Status |
| --- | --- | --- | --- | --- |
| GG-CLI-01 | Help/version and predictable noninteractive exit codes | CLI tests and README semantics | local CLI | PASS: final local suite |
| GG-CLI-02 | Explicit code-execution consent | default `--no-collect`, `--trust-collection` tests | pytest collection | PASS |
| GG-CLI-03 | Machine stdout separated from diagnostics | JSON/SARIF tests and no raw collection output in contract | CLI | PASS: final local suite |
| GG-CLI-04 | Stable JSON schema and reason codes | schema, four examples, and independent Node structural consumer smoke | JSON consumers | EXTERNAL_BLOCKER: full schema-validator run is not available in the current audit environment; structural smoke passes |
| GG-CLI-05 | Genuine SARIF 2.1.0 with incomplete invocation | SARIF tests and independent Node structural consumer smoke | SARIF consumers | EXTERNAL_BLOCKER: full SARIF validator/ingestion run is not available in the current audit environment; structural smoke passes |
| GG-SOUND-01 | UNKNOWN never becomes a confident gap | existing v0.1.3 fail-closed regressions | resolver | PASS |
| GG-SOUND-02 | Changed workspace invalidates result | snapshot mutation tests | resolver | PASS |
| GG-SOUND-03 | Runtime identity is not certified | JSON/SARIF `NOT_CERTIFIED`, JUnit tests | witness boundary | PASS |
| GG-SAFE-01 | Parser/path/resource limits | existing hardening/fuzz/mutation evidence | hostile input | PASS: final local suite |
| GG-SAFE-02 | Untrusted collection is refused without isolation | safe default and limitation docs | collection | PASS |
| GG-CI-01 | Exact wheel installation and digest check | reusable workflow source review | GitHub Actions | EXTERNAL_BLOCKER: hosted run not executed |
| GG-CI-02 | Event/change metadata is bound | workflow diff binding and CLI context | PR/push | EXTERNAL_BLOCKER: hosted event not executed |
| GG-CI-03 | Incomplete policy remains distinct from gap | advisory/enforcement inputs and tests | CI | EXTERNAL_BLOCKER: hosted event not executed |
| GG-PKG-01 | Wheel/sdist metadata and license files | build, twine, install gates | packaging | EXTERNAL_BLOCKER: candidate artifact not frozen |
| GG-PKG-02 | Exact bytes, SBOM, checksums, provenance | existing release workflow; new artifact not published | distribution | EXTERNAL_BLOCKER |
| GG-PKG-03 | PyPI Trusted Publishing/PEP 740 | owner must authorize registry and configure identity | PyPI | EXTERNAL_BLOCKER |
| GG-EVAL-01 | Frozen >=12-repository cohort and >=3 holdouts | `docs/EVALUATION_COHORT.md` manifest | evaluation | EXTERNAL_BLOCKER: five repositories acquired, but trusted collection/useful-determination coverage remains open |
| GG-EVAL-02 | Independent oracle and mutation restoration | retained Stage 0E manifests/results | evaluation | EXTERNAL_BLOCKER: candidate-bound rerun remains outstanding |
| GG-PERF-01 | p50/p95 wall/memory/disk measurements | `docs/PERFORMANCE.md` harness/results | performance | EXTERNAL_BLOCKER: full matrix measured, but the 10,000-file timing budget is missed and owner budget/optimization decision remains open |
| GG-PLAT-01 | Linux and Windows release-style installs | existing workflow plus fresh candidate run | platforms | EXTERNAL_BLOCKER |
| GG-PLAT-02 | macOS claim is either tested or excluded | matrix explicitly excludes macOS | platforms | NOT_APPLICABLE: not claimed |
| GG-DOC-01 | Quickstart, support, trust, contracts, troubleshooting | README, docs home, and 15/15 relative-link check | docs | PASS: local content and link targets |
| GG-OPS-01 | Support, security response, rollback ownership | `docs/OPERATIONS.md`, SECURITY.md | operations | EXTERNAL_BLOCKER: owner confirmation |
| GG-HUMAN-01 | Five fresh first-run sessions, four successes | `docs/USABILITY_SESSIONS.md` | human review | EXTERNAL_BLOCKER |
| GG-RELEASE-01 | Resumable release state machine | `scripts/release_state.py` and tests | release | PASS: final local suite |
| GG-RELEASE-02 | Human authorization before publication | no publication performed | launch | EXTERNAL_BLOCKER |
| GG-RELEASE-03 | Public re-download/install/attestation verification | owner-run `gh release verify` packet | launch | EXTERNAL_BLOCKER |

This matrix is frozen for this candidate. Lowering a threshold or deleting an
unrun requirement would invalidate the launch assessment.
