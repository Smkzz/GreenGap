# GreenGap

> **Archived project — final release: v0.1.4 (2026-09-29).**
>
> GreenGap is no longer under active development. This repository remains public as a
> read-only historical snapshot of the final Plan-mode implementation and its verification
> evidence. The broader GreenGap 1.0 runtime-witness direction was not promoted. The focused
> runtime completion-proof mechanism continued separately as
> [pytest-run-witness](https://github.com/Smkzz/pytest-run-witness); it is complementary,
> not a drop-in replacement for GreenGap's static Plan analysis.

**Find what your green CI never ran.**

A green CI job proves that the command it executed returned successfully. It does **not**
by itself prove that every relevant test file was collected or that every collected test
was included in the CI command. GreenGap separates those evidence surfaces and refuses to
turn missing information into a confident accusation.

## What GreenGap checks

GreenGap v0.1.4 is a local, read-only Plan-mode analyzer for **pytest + GitHub Actions**:

```text
repository test candidates
          |
          v
real pytest collection
          |
          v
GitHub Actions pytest plan
          |
          +--> PLANNED
          +--> NOT_PLANNED
          +--> UNKNOWN / UNREGISTERED when proof is incomplete
```

Example:

```text
tests/unit/test_fast.py
tests/integration/test_database.py
```

with CI:

```yaml
- run: pytest tests/unit
```

can still be green. When GreenGap has enough evidence to prove the omission, it reports
`tests/integration/test_database.py` as `NOT_PLANNED`. If a dynamic workflow boundary
prevents proof, GreenGap reports `UNKNOWN` instead.

That fail-closed distinction is the core design goal.

## Final-release quickstart

The archived repository is the canonical distribution source. To reproduce the final
release:

```console
git clone https://github.com/Smkzz/GreenGap.git
cd GreenGap
git checkout v0.1.4

python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate

python -m pip install .
greengap --version
greengap scan .
greengap plan .
```

For machine-readable output:

```console
greengap scan . --json
greengap plan . --json
```

The [v0.1.4 release](https://github.com/Smkzz/GreenGap/releases/tag/v0.1.4)
also contains the final wheel/sdist, checksums, SBOM, provenance manifest, and GitHub
build-provenance attestations.

## Commands

### `greengap scan`

Inventory high-confidence pytest source candidates and compare them with a real pytest
collection:

```text
greengap scan [--json] [--timeout SECONDS] [REPO]
```

GreenGap runs the target repository's real pytest collection. This imports repository
Python code; see [Trust and security boundary](#trust-and-security-boundary).

### `greengap plan`

Reconcile collection against the GitHub Actions test plan:

```text
greengap plan [--json] [--timeout SECONDS] [REPO]
              [--event EVENT] [--ref REF] [--base-ref BASE_REF]
              [--activity ACTIVITY]
              [--changed-file PATH ...] [--change-set-complete]
              [--commit-count N] [--changed-file-count N] [--diff-timed-out]
```

When a workflow uses `paths`, `paths-ignore`, branch/tag filters, event activity
filters, or other context-dependent selectors, provide the corresponding event/change-set
facts. GreenGap does not invent missing GitHub context.

Typical pull-request binding:

```console
greengap plan . \
  --event pull_request \
  --base-ref main \
  --changed-file src/example.py \
  --change-set-complete
```

### `greengap verify`

Parse common JUnit XML evidence without claiming cross-runner identity certification:

```text
greengap verify [--junitxml PATH] [--json] [--timeout SECONDS] [REPO]
```

The verifier deliberately reports:

```text
identity reconciliation: NOT_CERTIFIED
```

JUnit testcase names are not a universal identity standard. GreenGap therefore does not
claim that a JUnit testcase is the same object as a pytest collection node.

## Exit behavior

`greengap plan` uses stable process outcomes:

| Exit | Meaning |
| ---: | --- |
| `0` | Analysis is complete enough and no blocking `NOT_PLANNED` finding exists |
| `1` | One or more `NOT_PLANNED` findings are proven |
| `2` | Evidence is incomplete, unsafe, changed during analysis, or otherwise cannot support a proof |

`UNKNOWN` does **not** become `NOT_PLANNED`. `UNREGISTERED` is also non-blocking:
it means a high-confidence source candidate was absent from completed pytest collection,
which is not proof that the test can never run.

## Supported Plan-mode surface

The final resolver supports a deliberately bounded subset of GitHub Actions and common
pytest launch paths, including:

- direct pytest commands and Python/coverage wrappers;
- explicitly invoked repository-local shell scripts;
- Make targets;
- npm, pnpm, and yarn scripts;
- local composite actions and local reusable workflows;
- uv and tox wrappers/configurations;
- static matrix rows;
- canonical Bash and PowerShell command forms;
- GitHub event, branch/tag, activity, and path-filter context when explicitly bound.

Unsupported or dynamic boundaries fail closed to `UNKNOWN`. Examples include selectors
whose values cannot be resolved statically, unknown executables, external test actions,
unsupported shell control flow, ambiguous runner-specific path semantics, and incomplete
change-set context.

GreenGap treats `runs-on` as routing metadata. It does not infer runner ownership,
ambient tools, default shell behavior, filesystem case policy, or other machine facts from
that field alone.

## What GreenGap does **not** prove

GreenGap is intentionally narrow. It does not:

- prove that every CI matrix job or shard actually executed;
- prove runtime completion of every collected test;
- provide a security sandbox for untrusted repositories;
- execute arbitrary workflow commands while tracing them;
- support Go, Vitest/Jest, Cargo/nextest, Gradle/JUnit, CTest, TAP/prove, or other
  ecosystems as certified adapters;
- convert incomplete static evidence into a blocking finding.

For runtime evidence that every collected pytest item reached a terminal outcome, see
[pytest-run-witness](https://github.com/Smkzz/pytest-run-witness).

## Trust and security boundary

GreenGap statically reads workflow-related repository files. It does **not** execute shell
scripts, Make recipes, npm scripts, tox commands, or workflow steps while tracing them.

It **does** execute the repository's real pytest collection command
(`python -m pytest --collect-only -q`). Pytest collection imports and executes repository
Python code. Analyze untrusted repositories only inside an isolation boundary with the
permissions and network access you are willing to grant them.

Additional final-release safeguards include:

- repository-relative containment checks;
- symlinks represented by link text instead of followed during workspace evidence binding;
- bounded file/count/byte inputs;
- pre/post workspace SHA-256 fingerprint checks;
- fail-closed parsing and reconciliation;
- entity-safe JUnit XML parsing via `defusedxml`;
- subprocess execution through argument vectors, not shell interpolation;
- hash-locked CI dependency sets;
- full-commit-SHA GitHub Actions references and repository-level SHA-pin enforcement;
- GitHub secret scanning + push protection;
- CodeQL, dependency review, dependency audit, and ClusterFuzzLite workflows.

See [SECURITY.md](SECURITY.md) for the archived security policy.

## Workspace evidence

GreenGap binds analysis to a SHA-256 fingerprint over relevant tracked and non-ignored
workspace paths and bytes. The snapshot is checked before and after analysis; a workspace
change invalidates the result instead of silently reusing stale evidence.

GreenGap does not reserve project-specific directory names. Ordinary repository content
is included unless it is a conventional transient/build/cache path or is ignored by the
target repository itself.

## Performance

The reconciliation layer is designed to remain inexpensive relative to pytest collection
and CI parsing. On the final local archival qualification machine, five consecutive runs
produced these median reconciliation times:

| Candidate set | Median of 5 runs |
| ---: | ---: |
| 10,000 | 0.060 s |
| 50,000 | 0.367 s |

These are reference measurements, not hardware-independent guarantees. The repository
retains a regression gate requiring the 50,000-candidate case to complete in under
10 seconds.

## Final qualification evidence

The v0.1.4 archival candidate is validated with:

- **439 passing tests** plus one platform-specific case-collision skip on Windows;
- Python **3.11–3.14** CI lanes;
- Linux and Windows CI;
- minimum and latest dependency lanes;
- Ruff;
- strict mypy across all source modules;
- bytecode compilation;
- wheel + sdist build and install checks;
- `pip-audit` dependency scanning;
- CodeQL;
- dependency review;
- ClusterFuzzLite;
- OpenSSF Scorecard evidence;
- full-history secret scanning;
- SBOM, SHA-256 checksums, provenance manifest, and build-provenance attestations for
  release artifacts.

The final audit also removed one-off release-qualification machinery that was not part of
the shipped analyzer and fixed a historical internal-path exclusion that could have hidden
legitimate target-project files named like GreenGap's former qualification directories.

## Repository layout

```text
src/greengap/        shipped analyzer
tests/               product and adversarial regression suite
fuzz_targets/        parser fuzz targets
.clusterfuzzlite/    fuzzing configuration
.github/workflows/   reproducible CI/security/release evidence
scripts/             release-provenance utility
```

Historical release-only qualification runners that did not belong to the product have
been removed from the final tree.

## Project status and history

GreenGap was an experiment in proving gaps between repository test candidates, real pytest
collection, and static CI planning. The v0.1.x line established a conservative Plan-mode
boundary with extensive adversarial regression coverage.

A broader 1.0 runtime-witness direction was explored but **not promoted as GreenGap 1.0**.
The useful runtime-completion mechanism was narrowed and continued independently as
`pytest-run-witness`. GreenGap itself is intentionally retired at v0.1.4.

This repository is kept public so that the code, tags, releases, design decisions, and
verification history remain inspectable. No new features are planned.

## Development / reproduction

For historical reproduction of the final source tree:

```console
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests
python -m mypy src
python -m compileall -q src tests
python -m build
```

The CI workflows use hash-locked dependency sets under `.github/` for reproducible
qualification.

## Contributing

The project is archived and is not accepting feature contributions. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the archival policy.

## License

Apache License 2.0. See [LICENSE](LICENSE).
