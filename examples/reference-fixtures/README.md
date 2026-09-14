# Explicit Runtime Witness reference fixtures

These fixtures are intentionally tiny, source-controlled examples of the
supported integration boundary.  A harness copies one fixture into a
disposable Git checkout, supplies the five explicit identity variables, and
loads `greengap.pytest_witness` in the command that the fixture declares.

Each fixture is expected to demonstrate the same evidence matrix:

| Case | Required result |
| --- | --- |
| complete collection plus every required execution surface | exit 0 / `COMPLETE` |
| one selected collected file omitted from an otherwise complete surface | exit 1 / `BLOCKED` |
| a required surface witness is absent | exit 2 / `INCOMPLETE` |
| malformed witness JSON | exit 2 / `INCOMPLETE` |
| source identity differs from the manifest | exit 2 / `INCOMPLETE` |

The fixture commands never rely on GreenGap to discover or rewrite tox, uv,
coverage, shell, or matrix behavior.  The caller owns those commands and
explicitly includes `-p greengap.pytest_witness`.
