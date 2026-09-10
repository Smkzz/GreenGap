# Runtime pytest witnesses

Runtime Witness mode is GreenGap's high-confidence path when a workflow is too
dynamic for the static Plan resolver. It observes pytest's own native hooks in
the test process, rather than trying to reconstruct `tox`, matrices, scripts,
conditions, or external actions from YAML.

The plugin is inert unless the caller explicitly loads it and supplies an
output path:

```powershell
pytest -p greengap._runtime_plugin `
  --greengap-witness "$env:RUNNER_TEMP\greengap-witness.json" `
  --greengap-full-collection
```

`--greengap-full-collection` is an explicit caller assertion for the selected
pytest roots. The plugin rejects keyword, marker, node-ID, deselection, ignore,
and cache-based selectors when that assertion is supplied. Without it, the
witness remains valid evidence of the observed process but cannot be used as a
complete collection denominator.

`GREENGAP_WITNESS_FILE` and `GREENGAP_SOURCE_COMMIT` may be used instead of
the corresponding options. On GitHub Actions, the plugin reads the run,
attempt, job, repository, and optional `GREENGAP_MATRIX_ID` identity from the
standard environment. `PYTEST_XDIST_WORKER`, when present, becomes the shard
identity and the output is suffixed per worker to avoid concurrent writes.

Each artifact is bounded, UTF-8 JSON only, and contains the schema version,
GreenGap version, source commit, workspace fingerprints, pytest root, full
collected node identities, observed node reports, and session status. Test
output, environment dumps, fixtures, pickle, and executable content are not
captured. Collection and execution records include an opaque SHA-256
`node_identity` derived from the exact node ID and repository-relative path.
This lets a public scan report redact path-like parameter values without
breaking runtime reconciliation. The schema is
[`schemas/greengap-witness-v1.json`](../schemas/greengap-witness-v1.json).

## Aggregation

The final job must provide both a complete unfiltered runtime witness as
the denominator and the predeclared set of expected job/shard identities. A
public `scan` or `plan` report is not an authenticated runtime denominator and
is rejected by the witness aggregator. For example:

```powershell
greengap witness . `
  --denominator "$env:RUNNER_TEMP\full-collection-witness.json" `
  --witness "$env:RUNNER_TEMP\job-linux.json" `
  --witness "$env:RUNNER_TEMP\job-windows.json" `
  --repository "$env:GITHUB_REPOSITORY" `
  --expected-witness '123456|1|pytest-linux|-|-' `
  --expected-witness '123456|1|pytest-windows|-|-' `
  --source-commit "$env:GITHUB_SHA" `
  --json > greengap-witness-aggregate.json
```

The identity format is `run_id|run_attempt|job|matrix|shard`; use `-` for an
unavailable optional value. `--source-commit` and `--repository` are required
for a complete aggregation, and the aggregator also resolves the current
checkout's exact Git `HEAD` from the supplied repository root. A mismatch or
unreadable checkout is incomplete, so a valid artifact from another source
revision cannot be certified by a direct library call. The denominator's exact
node identities, collection scope, and provenance are validated as a runtime
witness before the aggregation joins any observations.

Aggregation is incomplete unless every expected witness is present and valid,
all source commits and repositories agree with the explicit bindings, the
workspace remained stable, the denominator is complete, and no duplicate or
conflicting observations exist. Missing jobs, missing shards, malformed
artifacts, inconsistent source/repository identities, conflicting node paths,
or an unknown execution phase never become `NOT_SEEN` claims. In those cases
findings remain `UNKNOWN` and the command exits `2`. The aggregator also caps
the number and cumulative size of witness inputs.

The schema remains version `1` for the pre-release contract, but this recovery
closure intentionally tightens it: old scan/plan reports and filtered or
legacy runtime witnesses must be regenerated and are not valid denominators.

With a complete set, an observed node is reported as `EXECUTED_PASS`,
`EXECUTED_FAIL`, or `SKIPPED`. A denominator node absent from the union of all
observed witnesses is a blocking `NOT_SEEN` finding and exits `1`.

Static `greengap plan` remains available as advisory, fail-closed workflow
analysis. It does not consume runtime witnesses and does not claim runtime
execution identity.
