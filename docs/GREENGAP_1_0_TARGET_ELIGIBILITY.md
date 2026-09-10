# GreenGap 1.0 target eligibility during usefulness recovery

This recovery branch does not claim a release or publication authorization.
The failed applicability run remains permanent evidence and the launch status
remains `GREENGAP_1_0_USEFULNESS_RECOVERY_REQUIRED`.

## Python policy

GreenGap 1.0 collection is supported for Python 3.11 and newer, matching
`pyproject.toml`'s `requires-python = ">=3.11"` and its published Python
classifiers. Python 3.10 is outside the 1.0 product eligibility boundary.

The Python 3.10 holdout from the failed applicability run is consumed evidence
and is not a future holdout. It exposed a hash-locked resolver defect in the
qualification environment (`pytest==9.0.3` required the unpinned transitive
`exceptiongroup` dependency). This recovery does not reuse that holdout or
claim that the defect is a product qualification result.

Any future decision to support Python 3.10 requires a separately approved
product-contract change and a genuinely cross-version hash-locked collection
set, including every transitive dependency hash for every supported Python
version. It cannot be inferred from the current 3.11+ policy.
