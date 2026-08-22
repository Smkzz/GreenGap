# Contributing to GreenGap

GreenGap is verification infrastructure. Contributions should preserve its
fail-closed semantics: incomplete evidence must remain `UNKNOWN`, and generic
logic must not become a repository-name exception.

Before opening a change, run:

```powershell
python -m pytest
python -m ruff check src tests
python -m mypy
python -m compileall -q src tests
python -m build
```

Add a regression test for every parser or reconciliation edge case. Keep
subprocesses bounded and do not add network, telemetry, database, dashboard,
LLM, or hosted-service requirements to the core. Do not execute workflow
commands while tracing them.
