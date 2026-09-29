# Changelog

## Unreleased

No unreleased changes. GreenGap is archived.

## 0.1.4 - 2026-09-29

Final archival release. Hardened JUnit XML parsing with `defusedxml`, removed
one-off release-qualification machinery that was not part of the shipped
analyzer, removed historical internal-path exclusions so target repositories
cannot accidentally hide legitimate files under those names, refreshed
reproducible dependency locks, simplified the final Scorecard gate, and updated
project metadata/documentation for inactive archival status. The broader
GreenGap 1.0 runtime-witness direction was not promoted.

## 0.1.3 - 2026-08-24

Corrective release following the v0.1.2 post-release adversarial audit. The
Plan-mode boundary now fails closed for pre-test workspace mutations, sparse
checkouts, native pytest configuration, tox and npm selection changes,
multi-target Make rules, arbitrary Python snippets, pre-commit hooks, and
workflow path filters without a bound change set. Pytest collection also
contains descendant processes, and release artifacts receive deterministic
byte-bound provenance with non-overwriting publication checks.

## 0.1.2 - 2026-08-23

Certification release for the hardened Plan-mode evidence boundary. Includes
workflow-context, matrix, condition, shell, pytest-configuration,
unknown-command, repository-boundary, and input-budget hardening, expanded
adversarial regression coverage, and release-assurance workflows.

## 0.1.0 - 2026-08-22

Initial public-quality candidate. Includes pytest source discovery, real
collection, workspace byte binding, conservative GitHub Actions Plan-mode
tracing, JUnit parsing groundwork, CLI JSON output, and local qualification
entry points.
