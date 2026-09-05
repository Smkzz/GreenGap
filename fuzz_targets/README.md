# GreenGap fuzz targets

GreenGap analyzes untrusted GitHub Actions workflow text without executing the
workflow. The fuzz target exercises deterministic in-memory parsing functions
that influence whether a pytest invocation is considered portable, selected, or
unknown.

The target is `trace_fuzzer.py`, built and run by ClusterFuzzLite with Atheris.
Its four surfaces are deliberately bounded and side-effect-free:

* `_neutral_tokens` rejects shell syntax that cannot be interpreted identically
  across runner defaults. A tokenizer crash or accidental acceptance could
  change the analyzed pytest command.
* `_shell_segments` separates shell operators, continuations, heredocs, and
  control-flow fragments. Incorrect segmentation can hide a command or infer a
  test scope from the wrong segment.
* `_github_path_pattern_regex` translates GitHub path-filter wildcards. A
  translation error can select or exclude the wrong changed files.
* `_path_patterns_match` applies ordered path patterns and negations. Its
  result contributes directly to workflow applicability and therefore needs
  conservative handling of malformed or adversarial selectors.

Each input is truncated to 4096 bytes, split into at most eight fields, and
limits each path-pattern field to 512 bytes. The target performs no network
access, subprocess execution, filesystem mutation, or persistent state
changes. Product exceptions are not caught; an uncaught exception, timeout, or
resource failure is a real fuzzing failure.

## Local campaign

With Atheris installed in the active Python environment:

```text
python fuzz_targets/trace_fuzzer.py -runs=50000 -max_len=4096 -rss_limit_mb=512
```

The hosted workflow runs the same target through the official
`google/clusterfuzzlite/actions` v1 release, pinned to commit
`884713a6c30a92e5e8544c39945cd7cb630abcd1`.
