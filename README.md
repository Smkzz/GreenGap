# GreenGap

Find what your green CI never ran.

GreenGap is a local, read-only Plan-mode analyzer for GitHub Actions and
pytest. It compares three distinct surfaces:

```text
repository test candidates -> real pytest collection -> proven CI pytest plan
```

It can prove that a collected test file is outside the union of the safe CI
pytest scopes it traced. It does not measure code coverage, infer runtime
execution, or certify that a JUnit testcase is the same object as a pytest
node.

## First run

The default is deliberately non-executing. It reads source, configuration,
and workflows but does not import or run repository code:

```powershell
python -m pip install .
greengap plan . --no-collect
```

This returns exit code `2` with `UNKNOWN` findings because a complete pytest
denominator was not established. To consent to the target repository's real
`pytest --collect-only` command, use an interpreter from that project:

```powershell
greengap plan . --trust-collection --python .venv/Scripts/python.exe
greengap plan . --trust-collection --python .venv/Scripts/python.exe --json > greengap-report.json
greengap plan . --trust-collection --python .venv/Scripts/python.exe --sarif > greengap.sarif
```

GreenGap never installs target dependencies, invokes package-manager hooks, or
changes a global environment. A subprocess, virtual environment, or warning
is not a sandbox. Analyze an untrusted checkout in an isolation boundary you
control; otherwise keep the safe `--no-collect` mode.

## Result semantics

Finding severity and analysis completeness are separate:

| Result | Meaning | Blocking finding? |
| --- | --- | --- |
| `PLANNED` | Collection and CI tracing proved a pytest scope covers the file. | No |
| `NOT_PLANNED` | A collected file is absent from every proven pytest scope. | Yes |
| `UNREGISTERED` | A high-confidence source candidate was not in completed collection. | No |
| `UNKNOWN` | Required collection, workflow, selector, runner, event, or workspace evidence is incomplete. | No |

Exit codes are process outcomes, not finding severity: `0` means complete with
no proven gap, `1` means complete with at least one proven `NOT_PLANNED` file,
and `2` means the analysis is incomplete or its environment is invalid. An
advisory CI job may report code `2` without failing a build; an enforcement
policy must preserve the distinct incomplete result and must never turn it into
complete coverage.

Every actionable finding includes the repository-relative file, the relevant
workflow/step evidence when available, what was proved, the failed assumption,
and a safe next action. The `--json` contract is versioned at
[`schemas/greengap-report-v1.json`](schemas/greengap-report-v1.json). It omits
absolute analyst paths by default. The `--sarif` contract is SARIF 2.1.0 with
stable `GG001`/`GG002`/`GG003` rules and explicit invocation completeness;
`UNKNOWN` is a review item, not a vulnerability or a successful scan.

Representative reports are in [`schemas/examples`](schemas/examples/).

## Scope and support matrix

| Surface | Stable candidate contract | Evidence in this repository |
| --- | --- | --- |
| Analyzer Python | 3.11, 3.12, 3.13, 3.14 | GitHub CI matrix; Windows and Ubuntu lanes |
| Analyzer OS | Linux and Windows | GitHub CI matrix |
| macOS analyzer | Not claimed | No hosted macOS gate in this candidate |
| Target test framework | pytest collection, caller-selected interpreter | Real `--collect-only` adapter and fail-closed tests |
| Target pytest | Caller supplies dependencies; pytest 9.0.3 is the release-test lane | Other versions require separate qualification |
| Workflow model | GitHub Actions Plan mode | Static bounded resolver with UNKNOWN on unsupported edges |
| Runtime witness | Not certified | `greengap verify` remains evidence parsing only |

Supported workflow paths include direct pytest, bounded Python/coverage
wrappers, explicitly invoked local shell scripts, Make/npm/uv/tox paths,
local composite/reusable workflows, and static matrix rows. Dynamic selectors,
unknown executables, external test actions, shell control flow, unresolved
event/path metadata, runner-specific filesystem assumptions, and changed
workspaces abstain. External reusable workflows remain UNKNOWN because their
remote contents are not fetched; the official GreenGap reusable workflow makes
one explicit exception for its canonical external self-call while it traces
the caller's local CI graph. Other external reusable workflows still abstain.

Go, Jest/Vitest, Cargo/nextest, Gradle/JUnit, CTest, TAP/prove, SaaS
dashboards, telemetry, and runtime execution research are outside this
release's contract.

## CI integration

The maintained integration is the reusable workflow
`.github/workflows/greengap-plan.yml`. It installs one exact release wheel,
verifies its SHA-256 entry from `SHA256SUMS`, binds the GitHub change set, and
uploads only the inert JSON report. Collection is non-executing unless the
caller explicitly sets `trust-collection: true`; use that only for a trusted
checkout with no credentials exposed to target code.

Use an immutable release tag after the owner authorizes publication:

```yaml
jobs:
  greengap:
    uses: Smkzz/GreenGap/.github/workflows/greengap-plan.yml@<approved-immutable-release-tag>
    with:
      release-tag: <approved-release-tag>
      green-gap-source-ref: <approved-40-character-source-sha>
      python-version: "3.12"
      trust-collection: false
      fail-on-gap: false
```

The angle-bracket values are publication-bound inputs, not a claim that a
future tag is already live. Do not replace them with `main` or a floating
major alias. `green-gap-source-ref` must be the exact 40-character GreenGap
commit whose hash-locked runtime and trusted-collection dependencies are
installed. The trusted path installs only GreenGap's pinned pytest harness;
target-project dependencies remain the caller's responsibility. The workflow
is advisory by default; `fail-on-gap: true`
propagates `1` for a proven gap and `2` for incomplete evidence.

## Install, upgrade, verify, and uninstall

For this candidate, build and install the exact local wheel outside the source
directory:

```powershell
python -m build
python -m pip install --force-reinstall --no-deps dist/greengap-1.0.0rc1-py3-none-any.whl
greengap --version
python -m pip check
python -m pip uninstall greengap
```

After an authorized registry publication, use the exact approved version and
verify the downloaded wheel and release assets before upgrading:

```powershell
python -m pip install --upgrade greengap==<approved-version>
gh release verify <approved-tag>
gh release verify-asset <approved-tag> greengap-<approved-version>-py3-none-any.whl
```

The v0.1.3 release remains immutable and is not modified by this candidate.
The `1.0.0rc1` candidate is not a claim of public PyPI or GitHub release
publication.

## Trust, privacy, and limits

The analyzer reads repository files and may intentionally execute the selected
project's pytest collection only after `--trust-collection`. Collection can
import arbitrary code; it is not a sandbox. The static resolver never executes
workflow commands, shell scripts, Make recipes, npm scripts, or tox commands.

GreenGap has no default telemetry, repository upload, or target-network
access. It writes bounded pytest temporary state and caller-requested reports.
Workspace evidence is a SHA-256 binding over relevant tracked and non-ignored
files; symlinks, path containment, file budgets, output budgets, process trees,
timeouts, and changed-workspace checks fail closed. Reports use repository-
relative paths and redact analyst-local absolute paths by default.

The security policy is [`SECURITY.md`](SECURITY.md). Use GitHub's private
vulnerability reporting form; do not publish exploit details in an issue.

## Development and evidence

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests
python -m mypy src
python -m compileall -q src tests scripts
python -m build
```

The release candidate's launch ledger, acceptance matrix, threat model,
evaluation cohort, performance notes, and resumable release state are under
[`docs/`](docs/). The canonical handoff is
[`docs/START_HERE.md`](docs/START_HERE.md); it distinguishes engineering
evidence from owner-only publication, hosted-event, and human-review actions.

GreenGap is not SOC 2, ISO 27001, SLSA-certified, or universally compliant.
The standards profile records applicable controls and evidence without making
legal or certification claims.
