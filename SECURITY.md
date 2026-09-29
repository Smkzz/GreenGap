# Security policy

## Project status

GreenGap is archived and no version line is under active maintenance. The final
archival release is `v0.1.4`.

The repository remains public so its implementation, historical releases, and
verification evidence can be inspected. Archival status means there is no
ongoing security-fix SLA and no promise that a newly reported issue will receive
a patched GreenGap release.

## Reporting a historical vulnerability

If you discover a security issue that materially affects the published
historical record, use GitHub private vulnerability reporting when available:

https://github.com/Smkzz/GreenGap/security/advisories/new

Do not open a public issue containing exploit details, credentials, secrets, or
live attack payloads. Include the affected version or commit, impact, and the
smallest safe reproduction you can provide.

A severe issue may justify temporarily unarchiving the repository to correct the
historical record, but archival status should not be interpreted as active
product support.

## Trust boundary

GreenGap deliberately runs the target repository's real pytest collection.
Collection imports and executes repository Python code and is **not a security
sandbox**. Analyze untrusted repositories only inside an isolation boundary with
the filesystem, process, credential, and network permissions you are willing to
grant that repository.

The GitHub Actions resolver itself does not execute workflow commands, shell
scripts, Make recipes, npm scripts, or tox commands while tracing them. It reads
and statically resolves those files with bounded recursion and fail-closed
handling for dynamic edges.

JUnit XML evidence is parsed with `defusedxml`, and repository inputs are
subject to bounded file/count/byte limits and workspace containment checks.
