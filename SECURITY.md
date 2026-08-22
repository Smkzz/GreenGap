# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting form:

https://github.com/Smkzz/GreenGap/security/advisories/new

If private reporting is unavailable, contact the repository owner through a
private GitHub message. Do not open a public issue with exploit details. Include
the affected version or commit, impact, reproduction steps, and any proposed
mitigation. We will acknowledge a report within five business days, provide an
initial triage within fourteen days, and coordinate disclosure after a fix or
mitigation is available.

## Supported versions

| Version line | Security support |
| --- | --- |
| `0.1.x` | Supported while the line is current |
| `<0.1.0` | Not supported |

Security fixes may be released outside the normal feature cadence. Please do
not include secrets or live exploit payloads in reports.

GreenGap deliberately runs the target repository's real pytest collection.
That collection imports and executes repository Python code and is **not a
security sandbox**. Analyze untrusted repositories only inside an appropriate
isolated environment with the permissions and network access you intend.

The GitHub Actions resolver does not execute workflow commands, shell scripts,
Make recipes, npm scripts, or tox commands. It reads and statically resolves
them, with bounded recursion and fail-closed handling for dynamic edges.
