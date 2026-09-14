# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting form:

https://github.com/Smkzz/GreenGap/security/advisories/new

Do not open a public issue with exploit details. Include the affected version
or commit, impact, reproduction steps, and any proposed mitigation. We will
acknowledge a report within five business days, provide an initial triage within
fourteen days, and coordinate disclosure after a fix or mitigation is available.

## Supported versions

| Version line | Security support |
| --- | --- |
| `1.0.x` | Supported while the line is current after publication |
| `0.1.x` | Supported only for the immutable published v0.1.3 baseline |
| `<0.1.0` | Not supported |

Security fixes may be released outside the normal feature cadence. Please do
not include secrets or live exploit payloads in reports.

GreenGap defaults to a non-executing inspection path. The `--trust-collection`
flag is explicit consent to run the target repository's real pytest collection.
That collection imports and executes repository Python code and is **not a
security sandbox**. Analyze untrusted repositories only inside an appropriate
isolated environment with the permissions and network access you intend; the
candidate does not claim to provide a general-purpose sandbox.

The GitHub Actions resolver does not execute workflow commands, shell scripts,
Make recipes, npm scripts, or tox commands. It reads and statically resolves
them, with bounded recursion and fail-closed handling for dynamic edges.

The release workflow builds and checks artifacts in a read-only job. Attestation,
release creation, and uploads run only in the separately protected
`release-publish` environment, from the default-branch `workflow_run` publisher,
after the exact commit/tree/tag binding and an active immutable tag-protection
rule are rechecked. The ClusterFuzzLite pull-request job has no
`security-events` write permission; its SARIF and exact-run receipt are
transferred as inert artifacts, while only successful default-branch scheduled
or manually dispatched runs may reach the trusted `workflow_run` uploader after
origin, head-SHA, digest, and bounded-shape validation.

CodeQL and Scorecard analysis jobs likewise keep reporting authority out of
candidate-triggered execution. Their raw SARIF and exact-run receipts cross
the boundary as inert artifacts; only successful default-branch push or
scheduled runs may reach the separate `workflow_run` receivers, which verify
the originating workflow, repository, event, ref, head/workflow SHA, receipt,
and digest before trusted upload.

GreenGap has no default telemetry or repository-code upload. Reports are
repository-relative and redact local absolute paths by default. The candidate
threat model and retained-control mapping are in `docs/THREAT_MODEL.md`.
