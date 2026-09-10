# Operations and support

## Ownership

The repository owner is accountable for vulnerability response, release
approval, branch protection, registry identity, and routine dependency
maintenance. This candidate does not claim continuing monitoring by the agent
after the task ends. The owner must replace this sentence with a named
maintainer or maintained team before public launch.

## Support and security

The supported stable scope is the documented GitHub Actions + pytest Plan mode
on Linux and Windows with Python 3.11–3.14. Security reports go through the
private GitHub advisory form linked in `SECURITY.md`; the response windows
there remain the project commitment. Public issues are for non-sensitive
defects.

## Maintenance cadence

Before launch, configure free bounded dependency and workflow checks with
least-privilege permissions, bounded retention, concurrency, and time budgets.
The existing Dependabot, dependency-review, CodeQL, fuzz, package, and
Scorecard workflows are retained; hosted enablement and branch-protection
contexts still require owner verification.

## Recovery and rollback

Never move an immutable tag. Recover by a new release with a new source tree,
or ask consumers to pin a known-good version. Preserve checksums, provenance,
SBOMs, attestations, failed verification output, and the exact source/tree
binding. Do not delete and recreate a release to repair delayed platform
attestation.

## Privacy

There is no default telemetry or repository upload. Review diagnostic bundles
for secrets, local paths, and test data before sharing; sharing requires an
explicit human decision.
