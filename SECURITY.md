# Security policy

Please report suspected vulnerabilities privately to the repository owner
instead of opening a public issue with exploit details.

GreenGap deliberately runs the target repository's real pytest collection.
That collection imports and executes repository Python code and is **not a
security sandbox**. Analyze untrusted repositories only inside an appropriate
isolated environment with the permissions and network access you intend.

The GitHub Actions resolver does not execute workflow commands, shell scripts,
Make recipes, npm scripts, or tox commands. It reads and statically resolves
them, with bounded recursion and fail-closed handling for dynamic edges.
