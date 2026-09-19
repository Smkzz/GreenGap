# Runtime Witness: explicit integration contract

Runtime Witness is GreenGap's opt-in, file-level evidence path for one narrow
question: which repository-relative test files did a declared pytest surface
actually reach during one run? It observes pytest's native hooks in the
caller-authorized test process. `greengap plan` remains a separate,
non-executing static advisory path and may return `UNKNOWN`.

The redesigned contract is explicit. GreenGap does not inject itself into
tox, uv, coverage, shell wrappers, or matrix jobs. Every relevant pytest
command must visibly load `greengap.pytest_witness`; every execution surface
must have a stable `surface_id`; and the manifest must name the complete
expected surface set. A missing declared surface is `INCOMPLETE`, never an
inferred pass.

## Small identity contract

The caller provides only these GreenGap variables to each instrumented
pytest process:

| Variable | Meaning |
| --- | --- |
| `GREENGAP_WITNESS_DIR` | directory for this session's JSON fragment |
| `GREENGAP_SURFACE_ID` | stable identity of this collection or execution surface |
| `GREENGAP_SOURCE_SHA` | exact Git `HEAD` expected for the run |
| `GREENGAP_RUN_ID` | shared run identity for collection and all executions |
| `GREENGAP_RUN_ATTEMPT` | run attempt, normally `1` |
| `GREENGAP_JOB_ID` | optional bounded job label |
| `GREENGAP_WITNESS_ROLE` | `collection` or `execution` |
| `GREENGAP_PROVIDER` | explicit provider label such as `github_actions` |
| `GREENGAP_CONFIG_SHA256` | SHA-256 of the exact `.greengap.yml` bytes |

Full collection also requires `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`. Any project
plugin needed by the test surface must be loaded explicitly in the visible
pytest command so entry-point plugins cannot silently change the denominator.

The plugin accepts equivalent command-line options. It does not mirror
`GITHUB_*`, arbitrary environment variables, node IDs, parameter values,
stdout/stderr, secrets, or target process objects into the artifact. The
source package must be installed in the target environment (or be available
on `PYTHONPATH` for a local qualification run).

The collection command is a separate, full, unfiltered `--collect-only`
command. The execution command is the real command used by that CI surface.
Both commands explicitly include `-p greengap.pytest_witness`.

## `.greengap.yml` surface manifest

Commit a small declaration of the complete witness universe:

```yaml
witness:
  collection: collection
  required:
    - unit-py311
    - unit-py312
```

Surface IDs are opaque bounded identifiers, not paths or commands. For a
matrix or shard, give each execution a distinct ID such as
`unit-py311-shard-0`; do not rely on an automatically discovered worker name.
The manifest command copies this declaration into the evidence manifest and
binds it to the collection witness.

## Primary recipe 1: direct pytest

Install GreenGap in the same target environment as pytest. In development,
install the exact local wheel produced from this checkout; do not depend on a
global installation or an unpinned package name:

```powershell
python -m pip install --force-reinstall --no-deps .\dist\greengap-<exact-version>-py3-none-any.whl
```

Run collection once, then run every declared surface with the same run ID.
The command lines below are the complete pytest semantics; GreenGap does not
add options behind the caller's back.

```powershell
$env:GREENGAP_WITNESS_DIR = "$pwd\evidence\collection"
$env:GREENGAP_SURFACE_ID = "collection"
$env:GREENGAP_SOURCE_SHA = (git rev-parse HEAD)
$env:GREENGAP_RUN_ID = "ci-run-42"
$env:GREENGAP_RUN_ATTEMPT = "1"
$env:GREENGAP_PROVIDER = "ci"
$env:GREENGAP_CONFIG_SHA256 = (Get-FileHash .greengap.yml -Algorithm SHA256).Hash.ToLowerInvariant()
$env:GREENGAP_WITNESS_ROLE = "collection"
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
python -m pytest -p greengap.pytest_witness --collect-only --greengap-full-collection

$env:GREENGAP_WITNESS_DIR = "$pwd\evidence\unit-py311"
$env:GREENGAP_SURFACE_ID = "unit-py311"
$env:GREENGAP_WITNESS_ROLE = "execution"
python -m pytest -p greengap.pytest_witness
```

For CI, set the variables in the job environment and use the job's own
pytest interpreter. A test failure is still an execution witness when its
`call` phase was observed; a setup failure is not.

## Primary recipe 2: tox

Declare the GreenGap dependency and forwarding allowlist in the tox
environment. The pytest invocation stays visible in `commands`:

```ini
[testenv:greengap]
deps =
    greengap
    pytest
pass_env =
    GREENGAP_WITNESS_DIR
    GREENGAP_SURFACE_ID
    GREENGAP_SOURCE_SHA
    GREENGAP_RUN_ID
    GREENGAP_RUN_ATTEMPT
    GREENGAP_JOB_ID
    GREENGAP_PROVIDER
    GREENGAP_CONFIG_SHA256
    GREENGAP_WITNESS_ROLE
    PYTEST_DISABLE_PLUGIN_AUTOLOAD
commands =
    python -m pytest -p greengap.pytest_witness
```

The target project may keep its existing dependency entries alongside these
GreenGap-specific lines. Use a separate explicit tox environment for
collection, with `--collect-only --greengap-full-collection`, and invoke the
execution environment once for each manifest surface. Do not depend on a
GreenGap wrapper to add `pass_env`, rewrite tox argv, or select a tox
environment.

<!-- The compact block above is the primary recipe; the expanded form below
     intentionally shows the required forwarding contract once. -->
```ini
[testenv:greengap-collection]
deps =
    greengap
    pytest
pass_env =
    GREENGAP_WITNESS_DIR
    GREENGAP_SURFACE_ID
    GREENGAP_SOURCE_SHA
    GREENGAP_RUN_ID
    GREENGAP_RUN_ATTEMPT
    GREENGAP_JOB_ID
    GREENGAP_PROVIDER
    GREENGAP_CONFIG_SHA256
    GREENGAP_WITNESS_ROLE
    PYTEST_DISABLE_PLUGIN_AUTOLOAD
commands =
    python -m pytest -p greengap.pytest_witness --collect-only --greengap-full-collection
```

## Primary recipe 3: uv

Keep the target dependency set locked and put the plugin in the visible pytest
command:

```powershell
$env:GREENGAP_PROVIDER = "ci"
$env:GREENGAP_CONFIG_SHA256 = (Get-FileHash .greengap.yml -Algorithm SHA256).Hash.ToLowerInvariant()
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
$env:GREENGAP_WITNESS_ROLE = "collection"
$env:GREENGAP_SURFACE_ID = "collection"
uv run --locked pytest -p greengap.pytest_witness --collect-only --greengap-full-collection
$env:GREENGAP_WITNESS_ROLE = "execution"
$env:GREENGAP_SURFACE_ID = "unit-py311"
uv run --locked pytest -p greengap.pytest_witness
```

Declare `greengap` in the project's test or development dependency group and
commit the resulting `uv.lock`. For development before publication, use the
exact local GreenGap wheel in that dependency declaration or an equivalent
locked local wheel source.

The first command runs with `GREENGAP_WITNESS_ROLE=collection` and
`GREENGAP_SURFACE_ID=collection`; the second runs with the execution surface
ID. Use `--frozen` when the CI image intentionally forbids lockfile
resolution. GreenGap does not install target dependencies or infer whether
uv forwarded an environment variable.

## GitHub matrix and shards

The collection job emits the `collection` witness. Each matrix row or shard
emits one execution witness with a unique explicit ID, uploads its fragment,
and uses the same `GREENGAP_RUN_ID`, `GREENGAP_RUN_ATTEMPT`, and
`GREENGAP_SOURCE_SHA`. An aggregator downloads only the named artifacts and
runs:

```powershell
greengap witness manifest --collection-witness evidence\collection --config .greengap.yml --output evidence\manifest.json
greengap witness analyze --manifest evidence\manifest.json --collection-witness evidence\collection --execution-witness evidence\unit-py311 --execution-witness evidence\unit-py312 --json
```

An optional GitHub helper may transport artifacts, but it must leave the
pytest command and surface IDs visible in the workflow. The helper is not a
test runner and must not hide tox/uv/wrapper semantics.

## Analysis and exit semantics

The analyzer computes only after validating every declared artifact:

```text
COLLECTED = union of complete collection witness files
EXECUTED  = union of call_executed_files from complete execution witnesses
NOT_RUN   = COLLECTED - EXECUTED
```

At the primary file-level boundary:

| Exit | Result | Meaning |
| --- | --- | --- |
| `0` | `COMPLETE` | all required witnesses are valid and no file is omitted |
| `1` | `BLOCKED` | all required witnesses are valid and one or more files are `NOT_RUN` |
| `2` | `INCOMPLETE` | missing/malformed/conflicting/stale/source-mismatched evidence |

Incomplete evidence never produces a `NOT_RUN` claim. The analyzer binds
source SHA/tree, source identity, repository identity, run identity, role,
surface IDs, session finalization, the exact SHA-256 of `.greengap.yml`, and
the complete manifest before computing the difference. Runtime output drift is
telemetry; source/configuration drift invalidates the witness.

## Controlled omission validation

The development acceptance test establishes a complete baseline, selects one
deterministic file from `COLLECTED ∩ EXECUTED`, and changes only a disposable
execution command/configuration to exclude it. It requires the selected file
to remain collected, absent from `call_executed_files`, and reported as
`NOT_RUN` with exit `1`. It then restores the disposable configuration and
requires the result to equal the baseline. Missing, malformed, or
source-mismatched witnesses must remain exit `2`.

The four reference fixtures are under
[`examples/reference-fixtures`](../examples/reference-fixtures): direct
pytest, tox, uv, and matrix/sharded pytest. They are intentionally small and
are evaluated from disposable Git copies rather than by changing an upstream
repository.

## Trust boundary and privacy

The plugin observes target code in the same pytest process; it is not
anti-malware attestation or a sandbox. It is intended for accidental CI
omissions in a trusted checkout. JSON fragments are bounded, written with
temporary-file plus atomic rename under a per-output-directory writer lock,
and contain repository-relative paths only. The command helper forwards only
the small platform/runtime allowlist plus variables explicitly supplied by the
caller; it is not a network, credential, or package-supply-chain sandbox.
CI staging copies only fresh regular `greengap-*.json` files into a dedicated
evidence root. Symlink/reparse boundaries, path traversal, oversized inputs,
conflicting duplicates, source/configuration drift, and undeclared surfaces
fail closed.

The older `greengap witness . --denominator ... --witness ...` node-level
aggregator remains a compatibility API. New integrations should use the
explicit plugin, `.greengap.yml`, manifest, and `witness analyze` path.
