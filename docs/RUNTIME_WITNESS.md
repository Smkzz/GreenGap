# Runtime Witness v1

Runtime Witness is GreenGap's opt-in, high-confidence path for answering a
narrow question: which repository-relative test files did a declared pytest
execution surface actually reach during one run? It observes pytest's native
hooks in the caller-authorized test process. Static `greengap plan` remains a
separate conservative advisory mode and is not a prerequisite for Witness
analysis.

Witness v1 is intentionally file-level. Public fragments contain normalized
repository-relative paths, never pytest node IDs or parameter values. They do
not contain the target process environment, secrets, authentication material,
stdout/stderr, fixture values, or executable content.

## Explicit collection and execution

The caller owns the target environment and must provide the real command after
`--`. GreenGap does not guess or install target dependencies. It injects the
local GreenGap source package through the target process environment and adds
the explicit `-p greengap.pytest_witness` pytest activation. The output
directory is a fragment directory; every pytest session writes a unique file.

```powershell
greengap witness collect C:\work\project `
  --output-dir C:\evidence\collection `
  --source-commit <target-head-sha> `
  -- python -m pytest --collect-only

greengap witness run C:\work\project `
  --output-dir C:\evidence\execution `
  --source-commit <target-head-sha> `
  --surface-id linux `
  --run-id ci-run-42 `
  -- python -m pytest
```

`collect` marks the collection as complete only when the caller asserted a
full unfiltered collection and pytest finalized successfully. A collection
failure, missing fragment, or incomplete session returns exit `2`. `run`
executes the supplied command and preserves its test-process exit status while
retaining the witness fragment. A failing test whose `call` report was
observed is still an executed file; its bounded call outcome is recorded
separately. A setup failure is attempted/completed telemetry with no
`call_executed` entry.

Supported command boundaries are direct pytest, `python -m pytest`, `uv run …
pytest`, and tox. For tox 4, an ephemeral `-x testenv.pass_env=...` passes only
the bounded instrumentation variables into the tox environment; the target
configuration is not edited. If a tox version or environment rejects that
explicit boundary, the missing or incomplete fragment is an exit-2 condition
rather than an inferred pass. xdist workers write independent
fragments named with a session UUID, process ID, and worker ID. A manifest
must declare worker shards explicitly when they are part of the expected
surface.

## Fragment contract

The versioned schema is
[`schemas/greengap-witness-v1.json`](../schemas/greengap-witness-v1.json).
Each fragment contains bounded repository/tree identity, initial and final
workspace fingerprints, pytest version/root/session identity, safe execution
context, and these file sets:

```text
collection.collected_files
execution.attempted_files
execution.call_executed_files
execution.completed_files
execution.call_outcomes
session.pytest_exitstatus
session.finalized
```

Fragments are written as UTF-8 JSON using a temporary file, flush/fsync, and
atomic rename. No process appends to a shared JSON document. The analyzer
limits fragment count, cumulative bytes, file count, path length, and
diagnostic count.

## Manifest and analysis

The manifest is a declaration of the complete witness universe, not a list of
whatever artifacts happened to be found. Its schema is
[`schemas/greengap-witness-manifest-v1.json`](../schemas/greengap-witness-manifest-v1.json).
The convenience command binds a complete collection fragment to expected
execution surface/shard IDs:

```powershell
greengap witness manifest `
  --collection-witness C:\evidence\collection\fragment.json `
  --execution-witness-id linux|- `
  --execution-witness-id windows|- `
  --output C:\evidence\manifest.json
```

Analyze only after all declared artifacts have arrived:

```powershell
greengap witness analyze `
  --manifest C:\evidence\manifest.json `
  --collection-witness C:\evidence\collection `
  --execution-witness C:\evidence\execution `
  --json
```

The calculation is:

```text
COLLECTED_FILES = union of complete declared collection fragments
EXECUTED_FILES  = union of call_executed_files from complete declared execution fragments
NOT_RUN         = COLLECTED_FILES - EXECUTED_FILES
```

Exit `0` means complete evidence and no gaps. Exit `1` means complete evidence
and one or more proven `GGW001` gaps. Exit `2` means incomplete, malformed,
stale, conflicting, source-mismatched, workspace-mismatched, duplicate,
missing, or undeclared-shard evidence. Incomplete evidence never becomes a
`NOT_RUN` claim. Each gap is scoped to “this collected test file was not
observed in the complete declared CI witness set for this run”; it is not a
claim about all historical execution.

JSON is the primary output. `--sarif` is available on `analyze` after the JSON
semantics and uses the distinct `GGW001` runtime-witness rule. Unknown or
incomplete evidence is represented as an incomplete invocation, not as a
security finding.

## Trust boundary

Witness is intended for accidental or inadvertent CI omission in a repository
whose test code is trusted to execute. It is not anti-malware attestation:
target code executing in the same pytest process could forge its own file. The
contract instead fails closed for malformed artifacts, stale source/run
identity, cross-run mixing, conflicting duplicates, path traversal, oversized
or bomb-like JSON, missing sessions/shards, partial downloads, and workspace
drift. Collection and test execution run target code and are not a sandbox.

The current implementation is local-only. GitHub Actions artifact transport
and final aggregation are intentionally not added until local witness
semantics and development-corpus validation are complete and separately
authorized.

The older `greengap witness . --denominator ... --witness ...` node-level
aggregator remains available as a compatibility API; new Witness integrations
should use `greengap.pytest_witness`, the manifest, and `witness analyze`.
