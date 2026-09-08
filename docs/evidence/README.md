# Candidate evidence

Generated evidence is kept small and linked from the launch handoff. Missing
measurements are represented as `null`/UNKNOWN rather than estimated. The
performance receipts are five-run non-executing static-plan measurements; they
are not proof of target pytest collection or dependency-install cost. The
2026-09-08 matrix includes process RSS and fixture-root disk deltas, plus a
separate help/version startup receipt.

The 2026-09-08 candidate also has an artifact checksum receipt, a minimal
SPDX-2.3 runtime SBOM for the declared `greengap`/PyYAML dependency scope, a
dirty-candidate provenance binding, and an explicit unavailable-attestation
receipt. The latter is retained to prevent unsigned local evidence from being
mistaken for a hosted build attestation.

The candidate was also installed from a wheel built from the exact recorded
sdist; that smoke result is recorded in the candidate-local
`provenance-20260908.json` receipt and the launch report.

The candidate-local `cohort-static-20260908.json` acquisition receipt records
the five newly acquired public checkouts, exact commits, licenses,
workflow-shape inspection, safe static-only results, and the reason trusted
collection was not performed.

The candidate-local `contract-consumer-20260908.json` receipt checks live
JSON/SARIF output and all four representative reports with a separate Node.js
parser; it does not claim full schema-validator or ingestion coverage.
