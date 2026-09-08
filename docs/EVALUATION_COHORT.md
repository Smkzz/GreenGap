# Frozen evaluation cohort

The cohort is frozen before candidate outcomes are used for tuning. A repository
is run only from the recorded commit in a disposable, isolated environment;
findings are not sent upstream. Ordinary unmodified repositories and controlled
synthetic mutations are reported separately.

The existing local evidence contains seven independent public repositories and
one GreenGap self-checkout. The self-checkout is excluded from the external
cohort. Five additional repositories were acquired at the exact commits below
in disposable checkouts. Safe static-only runs were recorded for those five;
trusted collection was not run because this workspace did not provide the
documented OS-level isolation profile. The required 12-repository launch
target is therefore not claimed complete.

| Cohort ID | Repository | Recorded commit | Workflow shape | Holdout | Status |
| --- | --- | --- | --- | --- | --- |
| C01 | encode/httpcore | `10a658221deb38a4c5b16db55ab554b0bf731707` | matrix + scripts | no | acquired |
| C02 | pytest-dev/iniconfig | `00e7d87c7353b1ffecc4cd55f19acfffedd5233e` | pre-commit + pytest | no | acquired |
| C03 | pytest-dev/iniconfig historical checkout | `a0cd289631bd5b6b4b4c9dac5f524e798a0fc8c5` | historical workflow | yes | acquired |
| C04 | pallets/itsdangerous | `672971d66a2ef9f85151e53283113f33d642dabd` | tox + matrix | no | acquired |
| C05 | pallets/markupsafe | `b2e4d9c7687be25695fffbe93a37622302b24fb1` | tox + publish | yes | acquired |
| C06 | python-trio/outcome | `03ed6218b08001877745bb1a9e180c8c5cf7c903` | reusable CI | no | acquired |
| C07 | psf/requests | `8f8b212de8c2129d7954c6cd373762880375620a` | multiple workflows | yes | acquired |
| C08 | pydantic/pydantic | `2261ae19e2e09f792f06613360c83fc829238111` | matrix + reusable workflows | no | acquired; safe static-only run |
| C09 | pallets/flask | `d318b683471101618febed18996405ad26462110` | tox + scripts | no | acquired; safe static-only run |
| C10 | pytest-dev/pytest | `0fabaa620d204fd040066eefd2a3ea2aad8d84cc` | matrix + plugins | yes | acquired; safe static-only run |
| C11 | python/cpython | `23180c50082fe98784c78511b335d7274ed87fb7` | generated/build selection; no verified pytest workflow | no | acquired; negative-shape review |
| C12 | scientific-python/array-api | `ff497ed83220372eb689a4fb0878c831470f93bc` | reusable workflow + matrix; no pytest reference | yes | acquired; negative-shape review |

Selection criteria: public repository, pytest tests, GitHub Actions workflow,
permissive source license, at least four distinct workflow shapes, and no
repository chosen after observing GreenGap outcomes. C11 and C12 remain
explicitly marked for exclusion review because their current workflow shapes
did not provide a verified pytest execution reference. The final packet must
record URL, exact commit, license, setup command, exclusions, isolation
profile, oracle source, candidate count, useful determinations, UNKNOWN count,
and any holdout repair disclosure.

## Acquisition and execution receipt

The five additional checkouts were acquired from their public repositories at
the exact commits in the table. Each safe run used the target-side CLI with
`--no-collect --json`, an explicit candidate source path, and a non-secret
allowlisted environment. No target test code or collection hook was executed.
The full machine-readable receipt is the candidate-local
`docs/evidence/cohort-static-20260908.json` file.

| Cohort | URL | License | Workflow inspection | Candidate / finding result | Useful determinations | UNKNOWN / reason summary |
| --- | --- | --- | --- | ---: | ---: | --- |
| C08 | `https://github.com/pydantic/pydantic` | MIT | 10 workflows; 14 pytest references | 234 / 234 | 0 | 234 `COLLECTION_INCOMPLETE` |
| C09 | `https://github.com/pallets/flask` | BSD-3-Clause | 5 workflows; 3 pytest references | 27 / 27 | 0 | 27 `COLLECTION_INCOMPLETE` |
| C10 | `https://github.com/pytest-dev/pytest` | MIT | 6 workflows; 16 pytest references | 123 / 123 | 0 | 5 `COLLECTION_INCOMPLETE`; 118 `LOW_CONFIDENCE_CANDIDATE` |
| C11 | `https://github.com/python/cpython` | PSF-2.0 | 25 workflows; 5 pytest references; no verified pytest job | 891 / 891 | 0 | 353 `COLLECTION_INCOMPLETE`; 538 `LOW_CONFIDENCE_CANDIDATE` |
| C12 | `https://github.com/scientific-python/array-api` | MIT | 3 workflows; no pytest reference | 0 / 0 | 0 | no candidate files; exclusion review |

These results are acquisition and safe-boundary evidence, not a claim that the
12-repository useful-determination or trusted-collection target has passed.
