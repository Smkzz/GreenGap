from __future__ import annotations

import os
import subprocess

import pytest

from greengap.junit import parse_junit
from greengap.pytest_adapter import _BoundedProcessResult, collect_pytest
from greengap.snapshot import workspace_snapshot
from greengap.trace import _matrix_rows, trace_github_actions

from .conftest import write_files


def workflow(command: str) -> str:
    return f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - shell: bash
        run: |
          {command.replace(chr(10), chr(10) + "          ")}
"""


def test_github_include_matches_all_original_rows_and_creates_rows() -> None:
    rows, error = _matrix_rows(
        {
            "fruit": ["apple", "pear"],
            "animal": ["cat", "dog"],
            "include": [
                {"color": "green"},
                {"color": "pink", "animal": "cat"},
                {"fruit": "apple", "shape": "circle"},
                {"fruit": "banana"},
                {"fruit": "banana", "animal": "cat"},
            ],
        }
    )

    assert error is None
    assert rows is not None
    assert len(rows) == 6
    assert sum(row.get("color") == "pink" for row in rows) == 2
    assert sum(row.get("shape") == "circle" for row in rows) == 2
    assert sum(row.get("fruit") == "banana" for row in rows) == 2


def test_github_include_only_matrix_creates_one_row_per_include() -> None:
    rows, error = _matrix_rows(
        {"include": [{"os": "ubuntu", "python": "3.11"}, {"os": "windows", "python": "3.13"}]}
    )
    assert error is None
    assert rows == [
        {"os": "ubuntu", "python": "3.11"},
        {"os": "windows", "python": "3.13"},
    ]


def test_false_step_condition_is_not_test_evidence(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    if: true
    runs-on: ubuntu-latest
    steps:
      - if: false
        run: pytest tests/integration
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert not result.relevant_incomplete


def test_dynamic_job_condition_is_unknown(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    if: ${{ github.ref == 'refs/heads/main' }}
    runs-on: ubuntu-latest
    steps:
      - run: pytest tests
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "CONDITION_UNKNOWN" for issue in result.issues)


def test_distinct_workflow_event_contexts_are_not_merged(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/pr.yml": """name: PR
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest tests/unit
""",
            ".github/workflows/nightly.yml": """name: Nightly
on:
  schedule:
    - cron: '0 0 * * *'
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert any(issue.code == "WORKFLOW_CONTEXT_AMBIGUOUS" for issue in result.issues)


def test_unrelated_release_context_does_not_poison_pull_request_trace(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/pr.yml": """name: PR
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest tests
""",
            ".github/workflows/release.yml": """name: Release
on: release
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: example/publish@v1
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.complete
    assert any(
        issue.code == "EXTERNAL_ACTION_UNKNOWN" and not issue.relevant for issue in result.issues
    )


@pytest.mark.parametrize(
    "command",
    [
        "if false; then\npytest tests/integration\nfi\npytest tests/unit",
        "pytest tests/unit || pytest tests/integration",
        "pytest tests/unit; pytest tests/integration",
        "cd backend && pytest tests",
    ],
)
def test_shell_control_flow_is_unknown(command: str, tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow(command)})
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "SHELL_CONTROL_FLOW_UNKNOWN" for issue in result.issues)


def test_one_line_shell_condition_is_unknown(tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow("if false; then pytest tests; fi")})
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "SHELL_CONTROL_FLOW_UNKNOWN" for issue in result.issues)


def test_shell_cd_separated_from_test_is_unknown(tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow("cd backend; pytest tests")})
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "SHELL_CONTROL_FLOW_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize("shell", ["cmd"])
def test_unsupported_shell_is_unknown(shell: str, tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - shell: {shell}
        run: pytest tests
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "SHELL_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize("shell", ["pwsh", "powershell"])
def test_direct_powershell_shell_is_supported(shell: str, tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - shell: {shell}
        run: pytest tests
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.invocations
    assert not result.issues


def test_powershell_control_flow_is_unknown(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - shell: pwsh
        run: |
          if ($false) {
            pytest tests
          }
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "SHELL_CONTROL_FLOW_UNKNOWN" for issue in result.issues)


def test_pytest_dot_covers_repository(tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow("pytest .")})
    result = trace_github_actions(tmp_path)
    assert result.invocations
    assert result.invocations[0].covers("tests/test_a.py")


def test_workflow_default_working_directory_does_not_reuse_root_pytest_context(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
defaults:
  run:
    working-directory: backend
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest tests
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)


def test_step_working_directory_override_does_not_reuse_root_pytest_context(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
defaults:
  run:
    working-directory: backend
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - working-directory: frontend
        run: pytest tests
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize("command", [
    "pytest -o testpaths=tests/unit",
    "pytest -c alt.ini",
    "PYTEST_ADDOPTS=tests/unit pytest",
])
def test_pytest_configuration_that_can_narrow_collection_is_unknown(command: str, tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow(command)})
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize(
    "command",
    ["python scripts/run_tests.py", "./ci", "nox -s tests", "invoke test", "just test"],
)
def test_unknown_test_runner_is_not_silence(command: str, tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow(command)})
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "UNKNOWN_TEST_RUNNER" for issue in result.issues)


def test_direct_wrapper_is_unknown_even_when_file_contains_pytest(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("./ci"),
            "ci": "#!/bin/sh\npytest tests\n",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "UNKNOWN_TEST_RUNNER" for issue in result.issues)


def test_matrix_condition_is_evaluated_per_row(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    strategy:
      matrix:
        lane: [unit, integration]
    runs-on: ubuntu-latest
    steps:
      - if: matrix.lane == 'unit'
        run: pytest tests/unit
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert len(result.invocations) == 1
    assert result.invocations[0].paths == ("tests/unit",)


def test_external_marketplace_action_is_unknown(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: example/test-action@v1
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert any(issue.code == "EXTERNAL_ACTION_UNKNOWN" for issue in result.issues)


def test_release_only_known_action_does_not_poison_test_plan(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/release.yml": """name: Release
on: [push, pull_request]
jobs:
  release:
    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')
    runs-on: ubuntu-latest
    steps:
      - uses: softprops/action-gh-release@v2
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.complete
    assert not result.relevant_incomplete
    assert any(
        issue.code == "CONDITION_UNKNOWN" and not issue.relevant for issue in result.issues
    )


def test_outside_working_directory_is_unknown(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - working-directory: ../outside
        run: pytest
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "PATH_OUTSIDE_REPOSITORY" for issue in result.issues)


def test_snapshot_hashes_symlink_metadata_not_external_target(tmp_path) -> None:
    outside = tmp_path.parent / "greengap-outside-target.txt"
    link = tmp_path / "tracked-link.txt"
    outside.write_text("one", encoding="utf-8")
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    write_files(tmp_path, {".gitignore": ""})
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)

    first = workspace_snapshot(tmp_path)
    outside.write_text("two", encoding="utf-8")
    second = workspace_snapshot(tmp_path)

    assert first.fingerprint == second.fingerprint


def test_matrix_over_github_limit_is_unknown(tmp_path) -> None:
    values = ", ".join(str(value) for value in range(257))
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    strategy:
      matrix:
        value: [{values}]
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "MATRIX_LIMIT_EXCEEDED" for issue in result.issues)


def test_deep_yaml_is_structured_unknown(tmp_path) -> None:
    nested = ""
    for depth in range(300):
        nested += "  " * depth + "a:\n"
    nested += "  " * 300 + "value: 1\n"
    write_files(tmp_path, {".github/workflows/deep.yml": nested})
    result = trace_github_actions(tmp_path)
    assert any(issue.code == "WORKFLOW_PARSE_ERROR" for issue in result.issues)


def test_junit_size_limit_is_explicit(monkeypatch, tmp_path) -> None:
    path = tmp_path / "results.xml"
    path.write_text("<testsuite>12345</testsuite>", encoding="utf-8")
    monkeypatch.setattr("greengap.junit.MAX_JUNIT_BYTES", 10)
    with pytest.raises(ValueError, match="size limit"):
        parse_junit(path)


def test_junit_case_limit_is_explicit(monkeypatch, tmp_path) -> None:
    path = tmp_path / "results.xml"
    path.write_text(
        "<testsuite><testcase name='a'/><testcase name='b'/></testsuite>", encoding="utf-8"
    )
    monkeypatch.setattr("greengap.junit.MAX_JUNIT_CASES", 1)
    with pytest.raises(ValueError, match="testcase count"):
        parse_junit(path)


def test_collection_output_limit_is_explicit(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "greengap.pytest_adapter._run_pytest_bounded",
        lambda *args, **kwargs: _BoundedProcessResult(
            -15, "partial", "", output_limited=True
        ),
    )
    result = collect_pytest(tmp_path)
    assert not result.complete
    assert "output exceeds" in (result.error or "")


def test_dynamic_condition_unknown_runner_is_relevant(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - if: ${{ github.ref == 'refs/heads/main' }}
        run: python scripts/run_tests.py
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert any(issue.code == "CONDITION_UNKNOWN" and issue.relevant for issue in result.issues)


def test_workflow_size_limit_is_structured_unknown(monkeypatch, tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow("pytest tests")})
    monkeypatch.setattr("greengap.trace.MAX_CONFIG_BYTES", 10)
    result = trace_github_actions(tmp_path)
    assert any(issue.code == "WORKFLOW_SIZE_LIMIT" for issue in result.issues)


def test_workflow_symlink_is_not_followed(tmp_path) -> None:
    outside = tmp_path.parent / "greengap-workflow-outside.yml"
    outside.write_text(workflow("pytest tests"), encoding="utf-8")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    try:
        os.symlink(outside, workflows / "ci.yml")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "PATH_OUTSIDE_REPOSITORY" for issue in result.issues)
