# GreenGap

Find what your green CI never ran.

Green CI does not prove that every test in a repository ran. A test can be
present in source, absent from pytest collection, or collected but omitted by
the actual CI command. GreenGap keeps those surfaces separate and compares
them without turning missing evidence into a confident accusation.

## What it checks

The first release is a local, read-only Plan-mode analyzer for GitHub Actions
and pytest:

```text
repository source candidates  ->  pytest collection  ->  CI pytest plan
```

For example, a repository may contain:

```text
tests/unit/test_fast.py
tests/integration/test_database.py
```

while CI runs:

```yaml
run: pytest tests/unit
```

The normal CI status can still be green. GreenGap reports
`test_database.py` as `NOT_PLANNED` when collection and the selection model
are complete enough to prove that result.

```powershell
python -m pip install .
greengap scan .
greengap plan .
greengap plan . --json
greengap plan . --changed-file src/greengap/trace.py
greengap plan . --event pull_request --base-ref main --changed-file src/greengap/trace.py
```

When a workflow uses `paths` or `paths-ignore`, supply the actual changed-file
set with one or more `--changed-file` options. Without that binding GreenGap
records the workflow scope as `UNKNOWN`; it never infers a change set and never
turns incomplete evidence into `NOT_PLANNED`.

When a workflow uses event, branch, tag, or path filters, bind the actual event
context as well. Use `--event push --ref main` for a push, or
`--event pull_request --base-ref main` for a pull request. GreenGap records
`UNKNOWN` when a filtered workflow cannot be evaluated without that context.

`greengap plan` exits with:

* `0` when analysis is complete and there are no blocking findings;
* `1` when one or more proven `NOT_PLANNED` files are found;
* `2` when evidence is incomplete, the workspace changed, or the collection
  environment is invalid.

`UNKNOWN` never blocks. `UNREGISTERED` is initially non-blocking because it
means a high-confidence source candidate was absent from completed pytest
collection; it is not proof that the test cannot run.

The model also contains `PLANNED`, `NOT_SEEN`, `SKIPPED`, `EXECUTED_PASS`, and
`EXECUTED_FAIL` for future witness adapters. `greengap verify` can parse common
JUnit evidence as groundwork, but it always says:

```text
identity reconciliation: NOT_CERTIFIED
```

JUnit names are not a universal identity standard, so v0.1 does not claim
that a runtime testcase is the same object as a pytest collection node.

## Why this is different

Code coverage and JUnit dashboards describe code or tests that executed. Flaky
test analytics describe observed failures and timing. Generic CI linters can
check workflow syntax. GreenGap establishes an independent denominator from
repository candidates and real pytest collection, then traces the selection
commands that CI plans to run. It does not guarantee that every test executes.

The resolver follows a deliberately small, deterministic subset of GitHub
Actions paths including direct pytest, Python and coverage wrappers, explicitly
invoked local shell scripts, Make targets, npm/pnpm/yarn scripts, local
composite actions, local reusable workflows, uv wrappers, tox configurations,
and static matrix rows. Unsupported selectors, conditions, shell control flow,
unknown executables, external test actions, or dynamic command boundaries
become `UNKNOWN`; an unrecognized command is never silently treated as “no
tests.” Commands without an explicit shell are accepted only in a tiny
runner-neutral grammar (portable whitespace-separated arguments); shell
operators, quoting, variables, assignments, globbing, substitutions, and
runner-native separators become `UNKNOWN`. Explicitly declared canonical Bash
and PowerShell shells have their own bounded parsers, but shell identity never
establishes filesystem case or path-separator semantics.

Current supported scope is GitHub Actions plus pytest in Plan mode. `runs-on`
is treated as routing metadata only: it does not attest runner ownership,
operating system, filesystem case policy, default shell, or ambient executable
contents. Static Plan proof is therefore limited to exact, portable
repository-relative paths and runner-neutral command semantics. A future
runtime witness may bind runner-specific facts; without one, those paths and
commands remain `UNKNOWN`. Go,
Vitest/Jest, Cargo/nextest, Gradle/JUnit, CTest, TAP/prove, and runtime
capability witnesses are roadmap items, not supported v0.1 adapters.

## Trust and safety model

GreenGap does not execute workflow commands, shell scripts, Make recipes, npm
scripts, or tox commands while tracing them. It only reads and statically
resolves those files. It does execute the repository's real pytest collection
command (`python -m pytest --collect-only -q`). Pytest collection imports and
executes repository Python code and is **not a security sandbox**. Run GreenGap
inside an appropriate sandbox when analyzing an untrusted repository.

Workspace evidence is bound to a SHA-256 fingerprint over relevant tracked and
non-ignored files, including their paths and bytes. Symlinks are represented by
their link text rather than followed, repository paths are containment-checked,
and file/count/total-byte budgets turn oversized or unsafe input into incomplete
evidence. The fingerprint is checked before and after analysis; a changed
workspace invalidates the result.

## Development

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests
python -m mypy
python -m compileall -q src tests
python -m build
```

The scripts under `scripts/` provide portable qualification entry points for
the pinned full-checkout and smaller upstream behavioral gates. They do not
clone repositories, push mutations, publish packages, or create releases.
