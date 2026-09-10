# GreenGap omitted-test demo fixture

The workflow deliberately runs only `tests/test_fast.py`, while pytest
collection sees both test files. GreenGap should report
`tests/test_database.py` as `NOT_PLANNED` with reason code
`COLLECTED_FILE_NOT_PLANNED`.
