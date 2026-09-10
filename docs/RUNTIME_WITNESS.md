# Runtime pytest witnesses

Runtime Witness mode is GreenGap's high-confidence path when a workflow is too
dynamic for the static Plan resolver. It observes pytest's own native hooks in
the test process, rather than trying to reconstruct `tox`, matrices, scripts,
conditions, or external actions from YAML.

The plugin is inert unless the caller explicitly loads it and supplies an
output path:

```powershell
pytest -p greengap._runtime_plugin `
  --greengap-witness "$env:RUNNER_TEMP\greengap-witness.json"
```

`GREENGAP_WITNESS_FILE` and `GREENGAP_SOURCE_COMMIT` may be used instead of
the corresponding options. On GitHub Actions, the plugin reads the run,
attempt, job, repository, and optional `GREENGAP_MATRIX_ID` identity from the
standard environment. `PYTEST_XDIST_WORKER`, when present, becomes the shard
identity and the output is suffixed per worker to avoid concurrent writes.

Each artifact is bounded, UTF-8 JSON only, and contains the schema version,
GreenGap version, source commit, workspace fingerprints, pytest root, full
collected node identities, observed node reports, and session status. Test
output, environment dumps, fixtures, pickle, and executable content are not
captured. The schema is [`schemas/greengap-witness-v1.json`](../schemas/greengap-witness-v1.json).

## Aggregation

The final job must provide both a complete full-collection denominator and the
predeclared set of expected job/shard identities. For example:

```powershell
greengap witness . `
  --denominator greengap-scan.json `
  --witness "$env:RUNNER_TEMP\job-linux.json" `
  --witness "$env:RUNNER_TEMP\job-windows.json" `
  --expected-witness '123456|1|pytest-linux|-|-' `
  --expected-witness '123456|1|pytest-windows|-|-' `
  --source-commit "$env:GITHUB_SHA" `
  --json > greengap-witness-aggregate.json
```

The identity format is `run_id|run_attempt|job|matrix|shard`; use `-` for an
unavailable optional value. `--source-commit` is required for a complete
aggregation so the denominator is explicitly bound to the observed source.

Aggregation is incomplete unless every expected witness is present and valid,
all source commits agree, the workspace remained stable, the denominator is
complete, and no duplicate or conflicting observations exist. Missing jobs,
missing shards, malformed artifacts, inconsistent source commits, and
conflicting node paths never become `NOT_SEEN` claims. In those cases findings
remain `UNKNOWN` and the command exits `2`.

With a complete set, an observed node is reported as `EXECUTED_PASS`,
`EXECUTED_FAIL`, or `SKIPPED`. A denominator node absent from the union of all
observed witnesses is a blocking `NOT_SEEN` finding and exits `1`.

Static `greengap plan` remains available as advisory, fail-closed workflow
analysis. It does not consume runtime witnesses and does not claim runtime
execution identity.
