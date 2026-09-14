# Local demo

The demo is a real omitted-file fixture, not a staged report. Create a
temporary directory containing:

```text
tests/test_fast.py
tests/test_database.py
.github/workflows/ci.yml   # run: pytest tests/test_fast.py
```

Run the safe path first:

```powershell
greengap plan . --no-collect --json
```

The result is incomplete because collection was refused. In a disposable
trusted fixture, run:

```powershell
greengap plan . --trust-collection --python .venv/Scripts/python.exe --json
```

The expected result contains `tests/test_database.py` with
`NOT_PLANNED`, `blocking: true`, `reason_code: COLLECTED_FILE_NOT_PLANNED`,
and workflow provenance. The text equivalent must state that the finding is a
plan omission, not proof that the test never executes. The checked-in fixture is
[`examples/demo-fixture`](../examples/demo-fixture), and the transcript below
was generated from the packaged release candidate:

[`evidence/demo-transcript-20260908.txt`](evidence/demo-transcript-20260908.txt)
