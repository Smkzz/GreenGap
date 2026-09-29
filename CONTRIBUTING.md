# Contributing to GreenGap

GreenGap is archived and is not accepting feature work or routine maintenance
contributions.

The repository remains public as a historical, reproducible record. If you want
to experiment with the code, fork it and preserve the original fail-closed
semantics: incomplete evidence must remain `UNKNOWN`, and generic logic should
not become a repository-name exception.

For historical reproduction of the final source tree:

```console
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests
python -m mypy src
python -m compileall -q src tests
python -m build
```

Security-sensitive historical issues should be reported through the process in
[SECURITY.md](SECURITY.md), not as public exploit reports.
