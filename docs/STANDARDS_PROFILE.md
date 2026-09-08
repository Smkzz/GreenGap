# Standards applicability profile

This is an evidence profile, not a certification or legal-compliance claim.
Editions and publication status must be rechecked at freeze; the access date
for this candidate is 2026-09-08.

| Reference | Candidate scope | Claim boundary |
| --- | --- | --- |
| OpenSSF OSPS Baseline 2026-08-28 | Applicable Level 1 engineering controls; assess Level 2/3 controls | No organizational or non-human Level 3 approval claim |
| NIST SP 800-218 v1.1 | Secure development practices relevant to source, tests, review, and release | Not a NIST certification; draft v1.2 is not treated as final |
| SLSA v1.2 | Source/build provenance and hosted-build evidence | No SLSA level claimed until hosted provenance is verified |
| OpenSSF Best Practices | Evidence-backed criteria review | No badge or silver status claimed without program record |
| PyPA / PEP 740 | Metadata, wheel/sdist, Trusted Publishing preparation | PyPI publication and attestations require explicit owner approval |
| SARIF 2.1.0 | GreenGap export format | Schema-valid export is not ingestion proof |
| SemVer 2.0.0 | Versioned CLI/report contract | `1.0.0rc1` is a release candidate, not stable publication |
| WCAG 2.2 AA | Only applicable if a web documentation surface is shipped | No website is shipped in this candidate |
| ISO/IEC 25010:2023 | Product-quality vocabulary for internal assessment | Abstract/reference use is not clause-level compliance |

## Official-source revalidation

Revalidated on 2026-09-08 against the linked official pages before this
candidate handoff:

- [OpenSSF OSPS Baseline 2026.08.28](https://baseline.openssf.org/versions/2026-08-28) is explicitly versioned `2026.08.28`; Level 1 is the applicable engineering minimum, while higher-level organizational controls remain assessed rather than claimed.
- [NIST SSDF publications](https://csrc.nist.gov/projects/ssdf/publications) lists [SP 800-218 Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) as **Final** (2022-02-03) and SP 800-218 Rev. 1 / Version 1.2 as **Draft** (2025-12-17). This profile uses v1.1 as the published baseline and treats v1.2 as draft guidance.
- [SLSA v1.2](https://slsa.dev/spec/v1.2/) remains the provenance reference; no SLSA level is claimed without hosted-build evidence.
- [OpenSSF Best Practices criteria](https://www.bestpractices.dev/en/criteria) remains the assessment reference; no badge, silver status, or reviewer identity is claimed.
- [PyPA GitHub release guidance](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/), [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/), and [PEP 740](https://peps.python.org/pep-0740/) are the packaging/provenance references; registry publication remains disabled and unauthorized.
- [GitHub secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use) and [release-integrity verification](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/verify-release-integrity) are the CI and public-verification references; hosted verification has not been performed for this candidate.
- [SARIF 2.1.0](https://www.oasis-open.org/standard/sarifv2-1-os/), [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html), [WCAG 2.2](https://www.w3.org/TR/WCAG22/), and [ISO/IEC 25010:2023](https://www.iso.org/standard/78176.html) remain the format, versioning, accessibility-scope, and quality-model references. The candidate ships no web surface, and ISO is used only as an internal quality vocabulary.

The launch report must include the exact controls assessed, evidence paths,
unknown organizational controls, and any human-review requirement.
