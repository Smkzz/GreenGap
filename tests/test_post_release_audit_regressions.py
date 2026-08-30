from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
import scripts.qualify_stage0e_full as stage0e
from scripts.create_release_provenance import create_manifest
from scripts.qualify_stage0e_full import (
    abstention_compatibility_report,
    expected_unknown_baseline,
    load_mutation_manifest,
    mutation_certification_report,
    sparse_checkout_enabled,
    validate_checkout,
)

from greengap.pytest_adapter import _run_pytest_bounded, discover_candidates, pytest_config
from greengap.trace import trace_github_actions

from .conftest import write_files


def workflow(command: str) -> str:
    indented = command.replace("\n", "\n          ")
    return f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {indented}
"""


def two_step_workflow(first: str, second: str) -> str:
    return f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: {first}
      - run: {second}
"""


def test_pretest_file_mutation_invalidates_the_selection_graph(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(
                "rm -f generated.py\ncp fixture.py tests/test_generated.py\npytest tests"
            ),
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PRETEST_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_cross_step_file_mutation_invalidates_later_test_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: rm tests/test_a.py
      - run: pytest
""",
            "tests/test_a.py": "def test_a():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_helper_script_mutation_invalidates_the_selection_graph(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("./scripts/prepare.sh\npytest tests"),
            "scripts/prepare.sh": "#!/usr/bin/env bash\ncp fixture.py tests/test_generated.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert any(issue.code == "PRETEST_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_repository_install_helper_side_effects_invalidate_later_test_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow("scripts/install", "pytest tests"),
            "scripts/install": "#!/bin/sh\npython -m venv .venv\n",
            "tests/test_a.py": "def test_a():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)


def test_arbitrary_setup_command_invalidates_later_test_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(
                "node scripts/generate-tests.js", "pytest tests"
            ),
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_package_install_from_repository_invalidates_later_test_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(
                "python -m pip install .", "pytest tests"
            ),
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    ("variable", "value", "command", "issue_code"),
    [
        ("BASH_ENV", "scripts/bootstrap.sh", "echo setup", "BASH_STARTUP_ENV_UNKNOWN"),
        ("PYTHONPATH", "scripts", "python -m pytest", "PYTHON_MODULE_PATH_UNKNOWN"),
        (
            "NODE_OPTIONS",
            "--require ./scripts/preload.js",
            "npm test",
            "NODE_STARTUP_OPTIONS_UNKNOWN",
        ),
        ("PYTHONHOME", ".venv", "python -m pytest", "PYTHON_STARTUP_ENV_UNKNOWN"),
        ("COVERAGE_FILE", "pytest.ini", "coverage run -m pytest", "COVERAGE_STARTUP_ENV_UNKNOWN"),
        (
            "COVERAGE_RCFILE",
            "scripts/coverage.ini",
            "python -m coverage run -m pytest",
            "COVERAGE_STARTUP_ENV_UNKNOWN",
        ),
    ],
)
def test_startup_environment_can_change_later_test_execution(
    tmp_path, variable: str, value: str, command: str, issue_code: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
env:
  {variable}: {value}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: {command}
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == issue_code for issue in result.issues)
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    ("command", "config_name", "config"),
    [
        ("ruff check .", "pyproject.toml", "[tool.ruff]\nfix = true\n"),
        ("python -m ruff check .", "pyproject.toml", "[tool.ruff]\nfix = true\n"),
        ("mypy src", "mypy.ini", "[mypy]\nplugins = scripts/plugin.py\n"),
        ("python -m mypy src", "mypy.ini", "[mypy]\nplugins = scripts/plugin.py\n"),
        ("coverage run -m pytest", ".coveragerc", "[run]\nplugins = scripts/plugin.py\n"),
        (
            "python -m coverage run -m pytest",
            ".coveragerc",
            "[run]\nplugins = scripts/plugin.py\n",
        ),
    ],
)
def test_implicit_tool_configuration_invalidates_later_pytest(
    tmp_path, command: str, config_name: str, config: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(command, "pytest"),
            config_name: config,
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize("option", ["-p ci_plugin", "--basetemp=tests", "--basetemp tests"])
def test_pytest_precollection_options_invalidate_later_inference(tmp_path, option: str) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(f"pytest {option}", "pytest"),
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize("command", ["pyright --createstub package", "greengap plan . || true"])
def test_modeled_commands_with_execution_or_write_effects_invalidate_later_pytest(
    tmp_path, command: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(command, "pytest"),
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_nested_composite_workspace_effect_propagates_to_parent(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/prepare
      - run: pytest tests
""",
            ".github/actions/prepare/action.yml": """name: prepare
description: prepare workspace
runs:
  using: composite
  steps:
    - shell: bash
      run: rm tests/test_a.py
""",
            "tests/test_a.py": "def test_a():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_local_reusable_workflow_uses_workflow_call_trigger_context(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: caller
on: pull_request
jobs:
  test:
    uses: ./.github/workflows/reusable.yml
""",
            ".github/workflows/reusable.yml": """name: reusable
on:
  workflow_call:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest tests
""",
        },
    )

    result = trace_github_actions(tmp_path, event="pull_request")

    assert result.invocations
    assert not any(issue.code == "WORKFLOW_EVENT_FILTER_UNKNOWN" for issue in result.issues)


def test_pipeline_mutation_is_not_hidden_by_setup_allowlist(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(
                "cp ci/pytest.ini pytest.ini | cat", "pytest"
            ),
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "SHELL_PIPE_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_bash_command_substitution_is_not_hidden_by_outer_setup_command(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(
                'echo "$(cp ci/pytest.ini pytest.ini)"', "pytest"
            ),
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "SHELL_COMMAND_SUBSTITUTION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_python_build_backend_execution_invalidates_later_test_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow("python -m build", "pytest"),
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTHON_EXECUTION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_external_action_outputs_invalidate_later_test_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ossf/scorecard-action@0123456789abcdef0123456789abcdef01234567
        with:
          results_file: pytest.ini
          results_format: sarif
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "EXTERNAL_ACTION_WORKSPACE_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    ("action", "with_block"),
    [
        (
            "anchore/sbom-action@0123456789abcdef0123456789abcdef01234567",
            "with:\n          output-file: pytest.ini\n          format: spdx-json",
        ),
        ("hynek/build-and-inspect-python-package@0123456789abcdef0123456789abcdef01234567", ""),
        ("github/codeql-action/autobuild@0123456789abcdef0123456789abcdef01234567", ""),
    ],
)
def test_known_external_actions_are_not_workspace_trusted(
    tmp_path, action: str, with_block: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: {action}
        {with_block}
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "EXTERNAL_ACTION_WORKSPACE_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_pipeline_nested_make_effects_propagate_to_later_pytest(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow("make prepare | cat", "pytest"),
            "Makefile": "prepare:\n\tcp ci/pytest.ini pytest.ini\n",
            "ci/pytest.ini": "[pytest]\npython_files = check_*.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_pipeline_nested_shell_effects_propagate_to_later_pytest(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow("bash scripts/prepare.sh | cat", "pytest"),
            "scripts/prepare.sh": "#!/usr/bin/env bash\ncp ci/pytest.ini pytest.ini\n",
            "ci/pytest.ini": "[pytest]\npython_files = check_*.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_pipeline_nested_tox_effects_propagate_to_later_pytest(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow("tox run -e py | cat", "pytest"),
            "tox.ini": "[tox]\nenvlist = py\n[testenv]\ncommands_pre = rm pytest.ini\ncommands = pytest\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_pipeline_redirection_is_not_rewritten_as_quoted_data(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow("echo config | cat > pytest.ini", "pytest"),
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_bash_substitution_inside_double_quote_with_apostrophe_is_unknown(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(
                'echo "it\'s $(cp ci/pytest.ini pytest.ini)"', "pytest"
            ),
            "ci/pytest.ini": "[pytest]\npython_files = check_*.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "SHELL_COMMAND_SUBSTITUTION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_bash_process_substitution_is_not_hidden_execution(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(
                "cat <(cp ci/pytest.ini pytest.ini)", "pytest"
            ),
            "ci/pytest.ini": "[pytest]\npython_files = check_*.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "SHELL_COMMAND_SUBSTITUTION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_sourced_shell_script_effects_propagate_to_later_pytest(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(". scripts/rewrite.sh", "pytest"),
            "scripts/rewrite.sh": "cp ci/pytest.ini pytest.ini\n",
            "ci/pytest.ini": "[pytest]\npython_files = check_*.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    "command",
    [
        "sort -o pytest.ini ci/pytest.ini",
        "coverage xml -o pytest.ini",
        "python -m coverage xml -o pytest.ini",
        "pip install --target=tests package",
        "mkdocs build",
    ],
)
def test_option_driven_setup_writers_invalidate_later_test_inference(
    tmp_path, command: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(command, "pytest"),
            "ci/pytest.ini": "[pytest]\npython_files = check_*.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_git_branch_edit_description_is_not_read_only(tmp_path) -> None:
    write_files(
        tmp_path,
        {".github/workflows/ci.yml": two_step_workflow("git branch --edit-description", "pytest")},
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "GIT_COMMAND_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_git_external_diff_execution_invalidates_later_test_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {".github/workflows/ci.yml": two_step_workflow("git diff --ext-diff", "pytest")},
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "GIT_COMMAND_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    ("action", "with_block"),
    [
        (
            "actions/cache@v4",
            "with:\n          path: .\n          key: source",
        ),
        ("actions/cache@v4", "with:\n          key: source"),
        ("actions/download-artifact@v4", "with:\n          name: test-config"),
    ],
)
def test_workspace_restoring_actions_invalidate_later_test_inference(
    tmp_path, action: str, with_block: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: {action}
        {with_block}
      - run: pytest tests
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "WORKSPACE_RESTORE_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    ("action", "with_block", "issue_code"),
    [
        (
            "actions/cache@v4",
            "with:\n          path: .\n          key: source",
            "WORKSPACE_RESTORE_UNKNOWN",
        ),
        (
            "actions/download-artifact@v4",
            "with:\n          name: generated\n          path: .",
            "WORKSPACE_RESTORE_UNKNOWN",
        ),
    ],
)
def test_unknown_condition_propagates_workspace_restoring_action_effect(
    tmp_path, action: str, with_block: str, issue_code: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - if: ${{{{ github.ref == 'refs/heads/main' }}}}
        uses: {action}
        {with_block}
      - run: pytest tests
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == issue_code for issue in result.issues)
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_unknown_condition_propagates_checkout_workspace_effect(tmp_path) -> None:
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
        uses: actions/checkout@v4
      - run: pytest tests
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "CHECKOUT_CONDITION_UNKNOWN" for issue in result.issues)
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_unknown_condition_propagates_local_composite_workspace_effect(tmp_path) -> None:
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
        uses: ./.github/actions/prepare
      - run: pytest tests
""",
            ".github/actions/prepare/action.yml": """name: prepare
description: prepare workspace
runs:
  using: composite
  steps:
    - shell: bash
      run: rm tests/test_a.py
""",
            "tests/test_a.py": "def test_a():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "COMPOSITE_CONDITION_UNKNOWN" for issue in result.issues)
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_gh_release_download_is_not_treated_as_setup_only(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: gh release download v0.1.3 --dir .
      - run: pytest tests
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_read_only_gh_release_view_does_not_poison_test_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: gh release view v0.1.3
      - run: pytest tests
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert not any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)


def test_cache_of_known_generated_metadata_does_not_poison_test_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: .mypy_cache
          key: mypy
      - run: pytest tests
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert not any(issue.code == "WORKSPACE_RESTORE_UNKNOWN" for issue in result.issues)


def test_sparse_checkout_inputs_require_a_bound_workspace_surface(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          sparse-checkout: |
            tests/unit
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert any(issue.code == "CHECKOUT_SPARSE_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize("input_name", ["repository", "ref", "path", "filter"])
def test_checkout_surface_inputs_require_a_bound_workspace(tmp_path, input_name: str) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          {input_name}: changed-value
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "CHECKOUT_WORKSPACE_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_stage0e_rejects_a_real_sparse_checkout(tmp_path) -> None:
    (tmp_path / "tracked.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_value.py").write_text(
        "def test_value():\n    assert True\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=GreenGap", "-c", "user.email=greengap@example.invalid", "commit", "-qm", "fixture"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    expected = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True, capture_output=True, check=True
    ).stdout.strip()
    subprocess.run(["git", "sparse-checkout", "init", "--cone"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "sparse-checkout", "set", "tests"], cwd=tmp_path, check=True, capture_output=True
    )

    assert sparse_checkout_enabled(tmp_path)
    valid, reason = validate_checkout(tmp_path, expected)
    assert not valid
    assert "sparse" in reason.lower()


def test_stage0e_accepts_a_stable_valid_unknown_as_expected_abstention() -> None:
    plan = {
        "stable": True,
        "complete": False,
        "blocker_count": 0,
        "snapshot": {"fingerprint": "fixture-fingerprint"},
        "collection": {"complete": True, "environment_valid": True},
        "errors": [],
        "findings": [
            {
                "state": "UNKNOWN",
                "evidence": ["PYTHON_EXECUTION_UNKNOWN", "WORKSPACE_MUTATION_UNKNOWN"],
            },
            {
                "state": "UNKNOWN",
                "evidence": ["PYTHON_EXECUTION_UNKNOWN", "WORKSPACE_MUTATION_UNKNOWN"],
            },
        ],
        "trace": {
            "issues": [
                {"code": "PYTHON_EXECUTION_UNKNOWN", "relevant": True},
                {"code": "WORKSPACE_MUTATION_UNKNOWN", "relevant": True},
            ]
        },
    }

    assert expected_unknown_baseline("outcome", plan)


def test_stage0e_allows_only_the_bound_plugin_autoload_abstention() -> None:
    plan = {
        "stable": True,
        "complete": False,
        "blocker_count": 0,
        "snapshot": {"fingerprint": "fixture-fingerprint"},
        "collection": {
            "complete": False,
            "environment_valid": False,
            "error": "pytest collection environment contains unbound pytest11 plugins: fixture.plugin",
        },
        "errors": ["pytest qualification environment is invalid or collection failed"],
        "findings": [
            {
                "state": "UNKNOWN",
                "confidence": "high",
                "evidence": [],
            }
        ],
        "trace": {
            "issues": [
                {"code": "PYTHON_EXECUTION_UNKNOWN", "relevant": True},
                {"code": "WORKSPACE_MUTATION_UNKNOWN", "relevant": True},
            ]
        },
    }

    assert expected_unknown_baseline("outcome", plan)
    bad_plan = {
        **plan,
        "collection": {
            "complete": False,
            "environment_valid": False,
            "error": "pytest collection exited with code 2",
        },
    }
    assert not expected_unknown_baseline("outcome", bad_plan)


def test_stage0e_requires_exact_expected_unknown_evidence() -> None:
    plan = {
        "stable": True,
        "complete": False,
        "blocker_count": 0,
        "snapshot": {"fingerprint": "fixture-fingerprint"},
        "collection": {"complete": True, "environment_valid": True},
        "errors": [],
        "findings": [
            {
                "state": "UNKNOWN",
                "evidence": [
                    "PYTHON_EXECUTION_UNKNOWN",
                    "WORKSPACE_MUTATION_UNKNOWN",
                    "UNEXPECTED_EXTRA_REASON",
                ],
            }
        ],
    }

    assert not expected_unknown_baseline("outcome", plan)


def test_stage0e_keeps_mixed_findings_as_a_false_positive() -> None:
    plan = {
        "stable": True,
        "complete": False,
        "blocker_count": 0,
        "snapshot": {"fingerprint": "fixture-fingerprint"},
        "collection": {"complete": True, "environment_valid": True},
        "errors": [],
        "findings": [{"state": "UNKNOWN"}, {"state": "PLANNED"}],
    }

    assert not expected_unknown_baseline("outcome", plan)


def test_stage0e_does_not_accept_an_unqualified_unknown_repository() -> None:
    plan = {
        "stable": True,
        "complete": False,
        "blocker_count": 0,
        "snapshot": {"fingerprint": "fixture-fingerprint"},
        "collection": {"complete": True, "environment_valid": True},
        "errors": [],
        "findings": [
            {
                "state": "UNKNOWN",
                "evidence": ["PYTHON_EXECUTION_UNKNOWN", "WORKSPACE_MUTATION_UNKNOWN"],
            }
        ],
    }

    assert not expected_unknown_baseline("requests", plan)


def test_stage0e_separates_abstention_compatibility_from_mutation_certification() -> None:
    results = [
        {"repository": name, "status": "EXPECTED_UNKNOWN"}
        for name in sorted(
            {"outcome", "requests", "itsdangerous", "httpcore", "markupsafe"}
        )
    ]

    compatibility = abstention_compatibility_report(results)
    mutation = mutation_certification_report(results)

    assert compatibility["status"] == "PASS"
    assert mutation["status"] == "NOT_PASSED"
    assert mutation["mutation_executed"] == 0


def test_stage0e_mutation_certification_requires_a_clean_exact_candidate_identity() -> None:
    assert stage0e.candidate_identity_is_exact(
        {"commit": "a" * 40, "tree": "b" * 40, "clean": True}
    )
    assert not stage0e.candidate_identity_is_exact(
        {"commit": "a" * 40, "tree": "b" * 40, "clean": False}
    )
    assert not stage0e.candidate_identity_is_exact(
        {"commit": "not-a-sha", "tree": "b" * 40, "clean": True}
    )
    assert not stage0e.candidate_identity_is_exact(
        {"commit": "a" * 40, "tree": "b" * 40, "clean": True, "error": "git failed"}
    )


def _mutation_result(
    *,
    status: str = "PASS",
    executed: int = 2,
    passed: int = 2,
    restored: int = 2,
    exact_restored: bool = True,
    deterministic: bool = True,
) -> dict[str, object]:
    return {
        "repository": "fixture",
        "status": status,
        "mutation_executed": executed,
        "mutation_passed": passed,
        "mutation_restored": restored,
        "restored": exact_restored,
        "deterministic": deterministic,
    }


def test_stage0e_mutation_report_requires_executed_exact_deterministic_cases() -> None:
    assert mutation_certification_report([])["status"] == "NOT_CONFIGURED"
    assert mutation_certification_report(
        [_mutation_result(status="BASELINE_NOT_COMPLETE", executed=0, passed=0, restored=0)]
    )["status"] == "NOT_PASSED"
    assert mutation_certification_report(
        [_mutation_result(status="RESTORATION_FAILED", restored=1, exact_restored=False)]
    )["status"] == "NOT_PASSED"
    assert mutation_certification_report(
        [_mutation_result(), _mutation_result(status="FALSE_NEGATIVE", passed=0)]
    )["status"] == "NOT_PASSED"
    assert mutation_certification_report([_mutation_result()])["status"] == "PASS"


def test_stage0e_mutation_manifest_rejects_missing_exactness_fields(tmp_path) -> None:
    manifest = tmp_path / "mutation.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repositories": [
                    {
                        "name": "fixture",
                        "repository": "https://github.com/example/fixture",
                        "path": "fixture",
                        "expected_head": "0" * 40,
                        "base_ref": "main",
                        "runs": 1,
                        "mutation": {
                            "path": "ci.yml",
                            "old": "pytest tests",
                            "new": "pytest tests/test_one.py",
                            "expected": "tests/test_two.py",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="at least twice"):
        load_mutation_manifest(manifest)


def test_stage0e_combined_gate_binds_separate_roots_and_interpreters(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "mutation.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repositories": [
                    {
                        "name": "fixture",
                        "repository": "https://github.com/example/fixture",
                        "path": "mutation-clones/fixture",
                        "expected_head": "a" * 40,
                        "base_ref": "main",
                        "runs": 2,
                        "mutation": {
                            "path": "ci.yml",
                            "old": "pytest tests",
                            "new": "pytest tests/test_kept.py",
                            "expected": "tests/test_omitted.py",
                            "original_sha256": "b" * 64,
                            "mutated_sha256": "c" * 64,
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    abstention_root = tmp_path / "abstention"
    mutation_root = tmp_path / "mutation"
    calls: list[tuple[str, str, Path]] = []

    def fake_qualify_one(name: str, root: Path, interpreter: str) -> dict[str, object]:
        calls.append(("abstention", interpreter, root))
        return {"repository": name, "status": "EXPECTED_UNKNOWN"}

    def fake_qualify_case(
        name: str, root: Path, interpreter: str, *args: object, **kwargs: object
    ) -> dict[str, object]:
        del args, kwargs
        calls.append(("mutation", interpreter, root))
        return _mutation_result() | {"repository": name}

    monkeypatch.setattr(stage0e, "qualify_one", fake_qualify_one)
    monkeypatch.setattr(stage0e, "qualify_case", fake_qualify_case)
    monkeypatch.setattr(
        stage0e,
        "candidate_identity",
        lambda root: {"commit": "d" * 40, "tree": "e" * 40, "clean": True},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualify_stage0e_full.py",
            str(tmp_path / "unused"),
            "--gate",
            "all",
            "--abstention-root",
            str(abstention_root),
            "--mutation-root",
            str(mutation_root),
            "--abstention-python",
            "abstention-python",
            "--mutation-python",
            "mutation-python",
            "--mutation-manifest",
            str(manifest),
        ],
    )

    assert stage0e.main() == 0
    assert calls[:5] == [
        ("abstention", "abstention-python", abstention_root / name)
        for name in stage0e.PINNED
    ]
    assert calls[5] == (
        "mutation",
        "mutation-python",
        mutation_root / "mutation-clones" / "fixture",
    )


def test_stage0e_exact_mutation_case_detects_target_and_restores_bytes(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "ci.yml"
    original = b"run: pytest tests\n"
    mutated = b"run: pytest tests/test_kept.py\n"
    target.write_bytes(original)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "add", "ci.yml"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=GreenGap", "-c", "user.email=greengap@example.invalid", "commit", "-qm", "fixture"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/example/fixture.git"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    expected_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True, capture_output=True, check=True
    ).stdout.strip()
    baseline = {
        "stable": True,
        "complete": True,
        "blocker_count": 0,
        "errors": [],
        "collection": {"complete": True, "environment_valid": True},
        "final_fingerprint": "baseline-fingerprint",
        "findings": [],
    }
    mutation_plan = {
        **baseline,
        "blocker_count": 1,
        "final_fingerprint": "mutation-fingerprint",
        "findings": [
            {
                "path": "tests/test_omitted.py",
                "state": "NOT_PLANNED",
                "blocking": True,
            }
        ],
    }

    def fake_run_plan(
        repo: Path,
        python_executable: str,
        changed_files: tuple[str, ...],
        base_ref: str,
        event: str = "pull_request",
        ref: str | None = None,
    ) -> tuple[int, dict[str, object]]:
        del python_executable, changed_files, base_ref, event, ref
        if (repo / "ci.yml").read_bytes() == mutated:
            return 1, mutation_plan
        return 0, baseline

    monkeypatch.setattr(stage0e, "run_plan", fake_run_plan)
    result = stage0e.qualify_case(
        "fixture",
        tmp_path,
        sys.executable,
        expected_head,
        stage0e.Mutation(
            "ci.yml",
            b"pytest tests",
            b"pytest tests/test_kept.py",
            "tests/test_omitted.py",
            original_sha256=stage0e.digest_bytes(original),
            mutated_sha256=stage0e.digest_bytes(mutated),
        ),
        "main",
        repository="https://github.com/example/fixture",
        runs=2,
    )

    assert result["status"] == "PASS"
    assert result["mutation_executed"] == 2
    assert result["mutation_passed"] == 2
    assert result["mutation_restored"] == 2
    assert target.read_bytes() == original
    assert stage0e._canonical_repository_url("python-trio/outcome") == (
        stage0e._canonical_repository_url("https://github.com/python-trio/outcome.git")
    )
    valid, reason = validate_checkout(
        tmp_path, expected_head, "https://github.com/example/different-fixture"
    )
    assert not valid
    assert "origin" in reason
    assert not subprocess.run(
        ["git", "status", "--porcelain"], cwd=tmp_path, text=True, capture_output=True, check=True
    ).stdout


@pytest.mark.parametrize(
    ("config_name", "config"),
    [
        ("pytest.toml", '[pytest]\npython_files = ["check_*.py"]\npython_functions = ["check_*"]\n'),
        (
            "pyproject.toml",
            '[tool.pytest]\npython_files = ["check_*.py"]\npython_functions = ["check_*"]\n',
        ),
    ],
)
def test_native_pytest_configuration_formats_drive_candidate_discovery(
    tmp_path, config_name: str, config: str
) -> None:
    write_files(
        tmp_path,
        {
            config_name: config,
            "tests/check_math.py": "def check_addition():\n    assert 1 + 1 == 2\n",
        },
    )

    options, selected = pytest_config(tmp_path)
    candidates = discover_candidates(tmp_path)

    assert selected == (tmp_path / config_name).as_posix()
    assert options["python_files"] == ["check_*.py"]
    assert any(candidate.path == "tests/check_math.py" and candidate.confidence == "high" for candidate in candidates)


@pytest.mark.parametrize(
    ("config_name", "config"),
    [
        (".pytest.toml", '[pytest]\npython_files = ["check_*.py"]\npython_functions = ["check_*"]\n'),
        (".pytest.ini", "[pytest]\npython_files = check_*.py\npython_functions = check_*\n"),
    ],
)
def test_hidden_pytest_configuration_formats_drive_candidate_discovery(
    tmp_path, config_name: str, config: str
) -> None:
    write_files(
        tmp_path,
        {
            config_name: config,
            "tests/check_math.py": "def check_addition():\n    assert 1 + 1 == 2\n",
        },
    )

    options, selected = pytest_config(tmp_path)
    candidates = discover_candidates(tmp_path)

    assert selected == (tmp_path / config_name).as_posix()
    assert any(candidate.path == "tests/check_math.py" for candidate in candidates)


def test_bare_pyproject_does_not_mask_pytest_tox_configuration(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            "pyproject.toml": "[project]\nname = 'fixture'\n",
            "tox.ini": "[pytest]\npython_files = check_*.py\npython_functions = check_*\n",
            "tests/check_math.py": "def check_addition():\n    assert 1 + 1 == 2\n",
        },
    )

    options, selected = pytest_config(tmp_path)
    candidates = discover_candidates(tmp_path)

    assert selected == (tmp_path / "tox.ini").as_posix()
    assert options["python_files"] == "check_*.py"
    assert any(candidate.path == "tests/check_math.py" for candidate in candidates)


def test_tox_setenv_pytest_addopts_invalidates_file_scope(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("tox -e py311"),
            "tox.ini": """[tox]
envlist = py311
[testenv]
skip_install = true
setenv =
    PYTEST_ADDOPTS = tests/unit
commands = pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize(
    "tox_field",
    [
        "changedir = tests/unit",
        "change_dir = tests/unit",
        "commands_pre = rm generated.py",
        "commands_post = cp ci/pytest.ini pytest.ini",
    ],
)
def test_tox_execution_context_fields_invalidate_file_scope(tmp_path, tox_field: str) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("tox -e py311"),
            "tox.ini": f"""[tox]
envlist = py311
[testenv]
skip_install = true
{tox_field}
commands = pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "TOX_EXECUTION_CONTEXT_UNKNOWN" for issue in result.issues)


def test_changed_files_require_event_binding_for_mixed_event_filters(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on:
  push:
  pull_request:
    paths:
      - src/**
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        },
    )

    unbound = trace_github_actions(tmp_path, ("tests/test_a.py",))
    pull_request = trace_github_actions(
        tmp_path,
        ("tests/test_a.py",),
        event="pull_request",
        change_set_complete=True,
        commit_count=1,
        changed_file_count=1,
    )
    push = trace_github_actions(tmp_path, ("tests/test_a.py",), event="push")

    assert not unbound.invocations
    assert any(issue.code == "WORKFLOW_PATH_FILTER_UNKNOWN" for issue in unbound.issues)
    assert not pull_request.invocations
    assert not any(issue.code == "WORKFLOW_PATH_FILTER_UNKNOWN" for issue in pull_request.issues)
    assert push.invocations


def test_event_context_excludes_workflows_for_other_events(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path, event="pull_request")

    assert not result.invocations
    assert not result.relevant_incomplete


def test_branch_filters_require_bound_ref_context(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on:
  push:
    branches:
      - main
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        },
    )

    unbound = trace_github_actions(tmp_path, event="push")
    bound = trace_github_actions(tmp_path, event="push", ref="main")
    excluded = trace_github_actions(tmp_path, event="push", ref="feature")

    assert not unbound.invocations
    assert any(issue.code == "WORKFLOW_EVENT_FILTER_UNKNOWN" for issue in unbound.issues)
    assert bound.invocations
    assert not excluded.invocations


def test_unsupported_question_mark_glob_is_unknown(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on:
  pull_request:
    paths:
      - '*.jsx?'
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        },
    )

    result = trace_github_actions(
        tmp_path,
        ("page.js",),
        event="pull_request",
        change_set_complete=True,
        commit_count=1,
        changed_file_count=1,
    )

    assert not result.invocations
    assert any(issue.code == "WORKFLOW_PATH_FILTER_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_npm_test_includes_the_pretest_lifecycle_script(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("npm test"),
            "package.json": '{"scripts": {"pretest": "pytest tests/preflight", "test": "echo ok"}}',
        },
    )

    result = trace_github_actions(tmp_path)

    assert any(invocation.covers("tests/preflight/test_config.py") for invocation in result.invocations)


def test_unknown_npm_pretest_lifecycle_is_not_ignored(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("npm test"),
            "package.json": '{"scripts": {"pretest": "node scripts/generate.js", "test": "pytest tests"}}',
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "NPM_PRETEST_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_multi_target_make_rules_are_resolved(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("make test"),
            "Makefile": """test: unit integration
unit integration:
	pytest tests/unit
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert any(invocation.covers("tests/unit/test_one.py") for invocation in result.invocations)


def test_static_make_requirements_install_taints_a_later_test_command(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow("make", "pytest tests"),
            "Makefile": "init:\n\tpython -m pip install -r requirements.txt\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    ("makefile", "code"),
    [
        ("SHELL := bash scripts/wrapper.sh\ntest:\n\tpytest tests\n", "MAKE_SHELL_UNKNOWN"),
        ("include ci/runner.mk\ntest:\n\tpytest tests\n", "MAKEFILE_INCLUDE_UNKNOWN"),
    ],
)
def test_make_execution_boundary_configuration_is_not_assumed_safe(
    tmp_path, makefile: str, code: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("make test"),
            "Makefile": makefile,
            "scripts/wrapper.sh": "#!/bin/sh\nexit 0\n",
            "ci/runner.mk": "SHELL := bash scripts/wrapper.sh\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == code for issue in result.issues)
    assert result.relevant_incomplete


def test_unmodeled_make_option_does_not_select_the_default_makefile(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("make -f ci/Makefile test"),
            "Makefile": "test:\n\tpytest tests\n",
            "ci/Makefile": "test:\n\tpytest tests/test_one.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "MAKE_COMMAND_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    ("extra_files", "environment"),
    [
        ({".npmrc": "script-shell=scripts/wrapper.sh\n"}, ""),
        ({}, "          NPM_CONFIG_SCRIPT_SHELL: ${{ inputs.shell }}\n"),
    ],
)
def test_package_script_shell_configuration_is_not_assumed_transparent(
    tmp_path, extra_files: dict[str, str], environment: str
) -> None:
    workflow_text = f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - env:
{environment or '          {}'}
        run: npm test
"""
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow_text,
            "package.json": '{"scripts": {"test": "pytest tests"}}',
            "scripts/wrapper.sh": "#!/bin/sh\nexit 0\n",
            **extra_files,
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PACKAGE_EXECUTION_CONTEXT_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_shell_wrapper_flags_are_not_silently_dropped(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("bash --noprofile scripts/test.sh"),
            "scripts/test.sh": "#!/bin/sh\npytest tests\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "SHELL_SCRIPT_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_unmodeled_tox_config_option_is_not_silently_dropped(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("tox -c ci/tox.ini -e py"),
            "tox.ini": "[tox]\nenvlist = py\n[testenv]\nskip_install = true\ncommands = pytest tests\n",
            "ci/tox.ini": "[tox]\nenvlist = py\n[testenv]\nskip_install = true\ncommands = pytest tests/test_one.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "TOX_COMMAND_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_arbitrary_python_c_is_not_assumed_to_be_harmless(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(
                "python -c \"from pathlib import Path; Path('tests/generated.py').write_text('x')\"\npytest"
            ),
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTHON_CODE_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_read_only_python_diagnostic_is_explicitly_allowlisted(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(
                "python -c \"import sys, struct; print(sys.version, struct.calcsize('P'))\"\npytest"
            ),
        },
    )

    result = trace_github_actions(tmp_path)

    assert result.invocations
    assert not any(issue.code == "PYTHON_CODE_UNKNOWN" for issue in result.issues)


def test_python_script_execution_invalidates_later_test_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {".github/workflows/ci.yml": workflow("python scripts/rewrite.py\npytest")},
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTHON_EXECUTION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_unknown_python_module_invalidates_later_test_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {".github/workflows/ci.yml": workflow("python -m repository_rewriter\npytest")},
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTHON_EXECUTION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_unasync_check_mode_is_modeled_as_read_only(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(
                "python scripts/unasync.py --check\npytest tests"
            ),
            "scripts/unasync.py": "print('check-only helper')\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert result.invocations
    assert not any(issue.code == "PYTHON_EXECUTION_UNKNOWN" for issue in result.issues)


def test_git_archive_output_is_not_read_only(tmp_path) -> None:
    write_files(
        tmp_path,
        {".github/workflows/ci.yml": two_step_workflow("git archive --output=pytest.ini HEAD", "pytest")},
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "GIT_COMMAND_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_nested_tox_workspace_effects_propagate_to_later_pytest(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("tox run -e py311"),
            "tox.ini": "[tox]\nenvlist = py311\n[testenv]\nskip_install = true\ncommands =\n    rm pytest.ini\n    pytest\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)


def test_nested_precommit_workspace_effect_propagates_to_later_pytest(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(
                "pre-commit run mutate --all-files", "pytest"
            ),
            ".pre-commit-config.yaml": """repos:
  - repo: local
    hooks:
      - id: mutate
        entry: rm pytest.ini
        language: system
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_nested_package_script_workspace_effect_propagates_to_later_pytest(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("npm test"),
            "package.json": '{"scripts": {"test": "python scripts/rewrite.py\\npytest"}}',
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTHON_EXECUTION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_npm_exec_is_not_treated_as_a_modeled_package_transition(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(
                "npm exec -c 'cp ci/pytest.ini pytest.ini'", "pytest"
            ),
            "ci/pytest.ini": "[pytest]\npython_files = check_*.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PACKAGE_COMMAND_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_pytest_output_target_invalidates_subsequent_selection(tmp_path) -> None:
    write_files(
        tmp_path,
        {".github/workflows/ci.yml": two_step_workflow("pytest tests/unit --junitxml=pytest.ini", "pytest")},
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert any(issue.code == "PYTEST_WORKSPACE_OUTPUT_UNKNOWN" for issue in result.issues)
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_python_module_precommit_resolves_test_bearing_local_hooks(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("python -m pre_commit run --all-files"),
            ".pre-commit-config.yaml": """repos:
  - repo: local
    hooks:
      - id: pytest-hook
        name: pytest hook
        entry: pytest tests/hooks
        language: system
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert any(invocation.covers("tests/hooks/test_hook.py") for invocation in result.invocations)


def test_precommit_selected_hook_does_not_resolve_unselected_test_hooks(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("pre-commit run lint --all-files"),
            ".pre-commit-config.yaml": """repos:
  - repo: local
    hooks:
      - id: lint
        entry: echo lint
        language: system
      - id: pytest-hook
        entry: pytest tests/hooks
        language: system
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert not any(issue.code == "PRE_COMMIT_HOOKS_UNKNOWN" for issue in result.issues)


def test_workflow_path_filters_require_an_actual_change_set(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on:
  pull_request:
    paths:
      - src/**
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert any(issue.code == "WORKFLOW_PATH_FILTER_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete

    bound = trace_github_actions(
        tmp_path,
        ("src/main.py",),
        change_set_complete=True,
        commit_count=1,
        changed_file_count=1,
    )

    assert bound.changed_files == ("src/main.py",)
    assert not any(issue.code == "WORKFLOW_PATH_FILTER_UNKNOWN" for issue in bound.issues)
    assert bound.invocations


def test_github_path_star_does_not_cross_directory_boundaries(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on:
  pull_request:
    paths:
      - src/*
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        },
    )

    nested = trace_github_actions(
        tmp_path,
        ("src/a/b.py",),
        change_set_complete=True,
        commit_count=1,
        changed_file_count=1,
    )
    root_file = trace_github_actions(
        tmp_path,
        ("src/a.py",),
        change_set_complete=True,
        commit_count=1,
        changed_file_count=1,
    )

    assert not nested.invocations
    assert not any(issue.code == "WORKFLOW_PATH_FILTER_UNKNOWN" for issue in nested.issues)
    assert root_file.invocations


def test_push_branch_and_tag_filters_apply_only_to_the_matching_ref_type(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on:
  push:
    branches:
      - main
    tags:
      - v*
    paths:
      - src/**
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        },
    )
    binding = {
        "changed_files": ("src/main.py",),
        "change_set_complete": True,
        "commit_count": 1,
        "changed_file_count": 1,
    }

    branch = trace_github_actions(tmp_path, event="push", ref="refs/heads/main", **binding)
    other_branch = trace_github_actions(
        tmp_path, event="push", ref="refs/heads/feature", **binding
    )
    tag = trace_github_actions(
        tmp_path,
        event="push",
        ref="refs/tags/v1.0.0",
        changed_files=("docs/readme.md",),
        change_set_complete=True,
        commit_count=1,
        changed_file_count=1,
    )
    other_tag = trace_github_actions(
        tmp_path,
        event="push",
        ref="refs/tags/nightly",
        changed_files=("docs/readme.md",),
        change_set_complete=True,
        commit_count=1,
        changed_file_count=1,
    )

    assert branch.invocations
    assert not other_branch.invocations
    assert tag.invocations
    assert not other_tag.invocations


def test_workflow_event_types_require_and_match_activity_binding(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on:
  pull_request:
    types: [closed]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        },
    )

    unbound = trace_github_actions(tmp_path, event="pull_request")
    opened = trace_github_actions(tmp_path, event="pull_request", activity="opened")
    closed = trace_github_actions(tmp_path, event="pull_request", activity="closed")

    assert not unbound.invocations
    assert any(issue.code == "WORKFLOW_EVENT_FILTER_UNKNOWN" for issue in unbound.issues)
    assert not opened.invocations
    assert not opened.relevant_incomplete
    assert closed.invocations


def test_path_filters_require_complete_change_set_metadata(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on:
  push:
    paths:
      - src/**
  pull_request:
    paths:
      - src/**
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        },
    )

    missing = trace_github_actions(
        tmp_path, ("src/main.py",), event="pull_request", base_ref="main"
    )
    complete = trace_github_actions(
        tmp_path,
        ("src/main.py",),
        event="pull_request",
        base_ref="main",
        change_set_complete=True,
        commit_count=1,
        changed_file_count=1,
    )
    oversized = trace_github_actions(
        tmp_path,
        ("src/main.py",),
        event="pull_request",
        base_ref="main",
        change_set_complete=True,
        commit_count=1,
        changed_file_count=3001,
    )
    push_ref_unbound = trace_github_actions(
        tmp_path,
        ("src/main.py",),
        event="push",
        change_set_complete=True,
        commit_count=1,
        changed_file_count=1,
    )

    assert not missing.invocations
    assert any(issue.code == "WORKFLOW_PATH_FILTER_UNKNOWN" for issue in missing.issues)
    assert complete.invocations
    assert not any(issue.code == "WORKFLOW_PATH_FILTER_UNKNOWN" for issue in complete.issues)
    assert not oversized.invocations
    assert any(issue.code == "WORKFLOW_PATH_FILTER_UNKNOWN" for issue in oversized.issues)
    assert not push_ref_unbound.invocations
    assert any(issue.code == "WORKFLOW_PATH_FILTER_UNKNOWN" for issue in push_ref_unbound.issues)


def _pid_exists(pid: int) -> bool:
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True,
            text=True,
            check=False,
        )
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _stop_process(pid: int) -> None:
    if not _pid_exists(pid):
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            check=False,
        )
    else:
        os.kill(pid, signal.SIGTERM)


def test_pytest_collection_terminates_descendant_processes(tmp_path) -> None:
    pid_file = tmp_path / "child.pid"
    child_code = (
        "import os, time\n"
        "from pathlib import Path\n"
        f"Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
        "time.sleep(60)\n"
    )
    parent_code = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
        "time.sleep(60)\n"
    )
    child_pid: int | None = None
    try:
        result = _run_pytest_bounded(
            [sys.executable, "-c", parent_code],
            tmp_path,
            os.environ.copy(),
            timeout=0.25,
        )
        deadline = time.monotonic() + 2.0
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        if pid_file.exists():
            child_pid = int(pid_file.read_text(encoding="utf-8"))
        assert result.timed_out
        assert child_pid is not None
        deadline = time.monotonic() + 2.0
        while _pid_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _pid_exists(child_pid)
    finally:
        if child_pid is not None:
            _stop_process(child_pid)


def test_pytest_collection_cleans_descendants_after_parent_exit(tmp_path) -> None:
    pid_file = tmp_path / "child.pid"
    child_code = (
        "import os, time\n"
        "from pathlib import Path\n"
        f"Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
        "time.sleep(60)\n"
    )
    parent_code = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
        "time.sleep(0.5)\n"
    )
    child_pid: int | None = None
    try:
        result = _run_pytest_bounded(
            [sys.executable, "-c", parent_code],
            tmp_path,
            os.environ.copy(),
            timeout=2.0,
        )
        deadline = time.monotonic() + 2.0
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        if pid_file.exists():
            child_pid = int(pid_file.read_text(encoding="utf-8"))
        assert result.returncode == 0
        assert child_pid is not None
        deadline = time.monotonic() + 2.0
        while _pid_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _pid_exists(child_pid)
    finally:
        if child_pid is not None:
            _stop_process(child_pid)


def test_release_workflow_is_build_once_and_non_overwriting() -> None:
    repository_root = Path(__file__).parents[1]
    workflow_text = (repository_root / ".github/workflows/release.yml").read_text(encoding="utf-8")
    package_requirements = (repository_root / ".github/requirements-package.txt").read_text(
        encoding="utf-8"
    )

    assert "--clobber" not in workflow_text
    assert "workflow_dispatch:" in workflow_text
    assert "refs/tags/${{ inputs.tag }}" in workflow_text
    assert "types: [published]" not in workflow_text
    assert "git rev-parse HEAD" in workflow_text
    assert "PROVENANCE.json" in workflow_text
    assert "sha256sum -c SHA256SUMS" in workflow_text
    assert "--draft" in workflow_text
    assert "--verify-tag" in workflow_text
    assert "Attest exact release bytes" in workflow_text
    assert "gh release view" in workflow_text
    assert "refusing to replace or resume it" in workflow_text
    assert "gh release upload" in workflow_text
    assert "python -m pip install --require-hashes -r .github/requirements-package.txt" in workflow_text
    assert "build==1.5.0" in package_requirements
    assert "twine==7.0.0" in package_requirements


def test_sdist_manifest_includes_certification_support_files() -> None:
    manifest = (Path(__file__).parents[1] / "MANIFEST.in").read_text(encoding="utf-8")

    assert "recursive-include tests *.py" in manifest
    assert "recursive-include scripts *.py" in manifest


def test_release_provenance_manifest_binds_exact_artifact_bytes(tmp_path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / "greengap-0.1.3-py3-none-any.whl"
    sdist = dist / "greengap-0.1.3.tar.gz"
    wheel.write_bytes(b"wheel bytes")
    sdist.write_bytes(b"sdist bytes")
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    create_manifest(dist, first, "v0.1.3", "a" * 40, "b" * 40)
    create_manifest(dist, second, "v0.1.3", "a" * 40, "b" * 40)

    assert first.read_bytes() == second.read_bytes()
    payload = json.loads(first.read_text(encoding="utf-8"))
    assert payload["tag"] == "v0.1.3"
    assert payload["commit"] == "a" * 40
    assert payload["tree"] == "b" * 40
    assert [item["name"] for item in payload["artifacts"]] == [wheel.name, sdist.name]
    assert payload["artifacts"][0]["size"] == len(b"wheel bytes")


def test_repository_path_in_path_invalidates_bare_pytest_identity(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      PATH: scripts:$PATH
    steps:
      - run: pytest
""",
            "scripts/pytest": "#!/bin/sh\necho fake runner\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "EXECUTABLE_IDENTITY_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    ("command", "shadowed_executable"),
    [
        ("ruff check .", "ruff"),
        ("python -m ruff check .", "python"),
    ],
)
def test_repository_path_in_path_invalidates_bare_tool_identity(
    tmp_path, command: str, shadowed_executable: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      PATH: scripts:$PATH
    steps:
      - run: {command}
      - run: pytest
""",
            f"scripts/{shadowed_executable}": "#!/bin/sh\necho shadowed\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "EXECUTABLE_IDENTITY_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    "command",
    [
        "ruff check --fix tests",
        "ruff check --output-file pytest.ini tests",
        "ruff check --add-noqa tests",
        "ruff check --config lint.fix=true tests",
        "mypy --junit-xml pytest.ini",
        "mypy --config-file unsafe.ini",
        "mypy --html-report pytest.ini",
        "mypy --xml-report pytest.ini",
        "mypy --any-exprs-report pytest.ini",
        "pip-audit -o pytest.ini",
        "python -m ruff check --fix tests",
        "python -m ruff check --output-file pytest.ini tests",
        "python -m ruff check --add-noqa tests",
        "python -m ruff check --config lint.fix=true tests",
        "python -m mypy --junit-xml pytest.ini",
        "python -m mypy --config-file unsafe.ini",
        "python -m mypy --html-report pytest.ini",
        "python -m mypy --xml-report pytest.ini",
        "python -m mypy --any-exprs-report pytest.ini",
        "python -m pip_audit -o pytest.ini",
        "pip install --editable=.",
        "pip install src/",
        "python -m pip install --editable=.",
        "python -m pip install src/",
        "python -m coverage run scripts/rewrite.py",
        "coverage run scripts/rewrite.py",
        "coverage run --rcfile .coveragerc -m pytest",
        "python -m coverage run --rcfile .coveragerc -m pytest",
    ],
)
def test_tool_output_or_execution_options_invalidate_later_pytest(tmp_path, command: str) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": two_step_workflow(command, "pytest")})

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_pip_requirements_recursively_detect_local_project_inputs(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(
                "pip install -r requirements.txt", "pytest"
            ),
            "requirements.txt": "-r base.txt\n",
            "base.txt": "-e .\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    "command",
    [
        "pip install pytest-cov",
        "python -m pip install pytest-cov",
        "pip uninstall -y pytest",
        "pip install -r requirements.txt",
    ],
)
def test_pip_commands_that_can_change_pytest_plugins_or_identity_taint_later_pytest(
    tmp_path, command: str
) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": two_step_workflow(command, "pytest")})

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_core_pip_and_pytest_bootstrap_remains_supported(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(
                "python -m pip install --upgrade pip\npip install pytest\npytest tests"
            )
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].paths == ("tests",)
    assert not result.relevant_incomplete


@pytest.mark.parametrize("first", ['echo "unterminated', "$PYTHON pytest"])
def test_unparsed_or_dynamic_predecessor_taints_later_pytest(tmp_path, first: str) -> None:
    write_files(
        tmp_path,
        {".github/workflows/ci.yml": two_step_workflow(first, "pytest tests")},
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_standard_precommit_hooks_are_not_assumed_workspace_safe(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(
                "pre-commit run --all-files", "pytest"
            ),
            ".pre-commit-config.yaml": """repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PRE_COMMIT_HOOKS_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_precommit_only_job_does_not_make_unknown_hook_relevant(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("pre-commit run --all-files"),
            ".pre-commit-config.yaml": """repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PRE_COMMIT_HOOKS_UNKNOWN" for issue in result.issues)
    assert not any(issue.relevant for issue in result.issues)
    assert not result.relevant_incomplete


@pytest.mark.parametrize(
    "selector",
    ["tests/test_*.py", "tests/test_mod.py::test_func", "@pytest.args"],
)
def test_unmodeled_pytest_selector_forms_fail_closed(tmp_path, selector: str) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow(f"pytest {selector}")})

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_SELECTOR_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_unmodeled_pytest_option_taints_later_selection(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow(
                "pytest --log-file pytest.ini", "pytest"
            )
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_SELECTOR_UNKNOWN" for issue in result.issues)
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_tox_default_packaging_phase_invalidates_pytest_inference(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("tox -e py311"),
            "tox.ini": "[tox]\nenvlist = py311\n[testenv]\ncommands = pytest\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "TOX_PACKAGING_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_pipeline_nested_make_effects_are_composed(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("make prepare | cat\npytest"),
            "Makefile": "prepare:\n\tcp ci/pytest.ini pytest.ini\n",
            "ci/pytest.ini": "[pytest]\npython_files = check_*.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_bash_command_substitution_inside_double_quotes_is_unknown(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(
                'echo "it\'s $(cp ci/pytest.ini pytest.ini)"\npytest'
            ),
            "ci/pytest.ini": "[pytest]\npython_files = check_*.py\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "SHELL_COMMAND_SUBSTITUTION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_known_external_actions_default_to_unknown_workspace_effect(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: anchore/sbom-action@v0.17.0
        with:
          output-file: pytest.ini
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "EXTERNAL_ACTION_WORKSPACE_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_completed_pytest_taints_a_later_pytest_in_same_job(tmp_path) -> None:
    write_files(
        tmp_path,
        {".github/workflows/ci.yml": two_step_workflow("pytest tests", "pytest")},
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize("first", ["pytest --collect-only", "pytest"])
def test_pytest_collection_mode_cannot_be_used_as_a_proven_runner(tmp_path, first: str) -> None:
    files = {
        ".github/workflows/ci.yml": two_step_workflow(first, "pytest"),
    }
    if first == "pytest":
        files["pytest.ini"] = "[pytest]\naddopts = --collect-only\n"
    write_files(tmp_path, files)

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_custom_shell_template_is_not_treated_as_builtin_bash(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - shell: 'bash -e {0}'
        run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "SHELL_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    "first",
    ["pytest tests/test_prepare.py", "pytest tests/test_delete.py"],
)
def test_executed_pytest_taints_a_later_selection_even_for_narrow_first_scope(
    tmp_path, first: str
) -> None:
    """Fixtures/tests may rewrite config or delete tests after the first run."""

    write_files(tmp_path, {".github/workflows/ci.yml": two_step_workflow(first, "pytest")})

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].paths == (first.removeprefix("pytest "),)
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)


def test_final_pytest_keeps_its_own_proven_selection(tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow("pytest tests")})

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].paths == ("tests",)
    assert not result.relevant_incomplete


def test_static_optional_requirements_install_taints_later_pytest(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(
                "python -m pip install --upgrade pip\n"
                "if [ -f requirements.txt ]; then pip install -r requirements.txt; fi\n"
                "pytest tests"
            ),
            "requirements.txt": "pytest\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


def test_static_missing_optional_requirements_branch_is_not_treated_as_execution(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(
                "if [ -f requirements.txt ]; then scripts/untrusted-installer; fi\npytest tests"
            ),
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].paths == ("tests",)
    assert not result.relevant_incomplete


def test_static_file_condition_with_an_else_branch_remains_unknown(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(
                "if [ -f requirements.txt ]; then pip install -r requirements.txt; else scripts/install; fi\n"
                "pytest tests"
            ),
            "requirements.txt": "pytest\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    "command",
    [
        "pytest --collect-only",
        "pytest --co",
        "pytest tests --collect-only",
        "pytest --setup-only",
        "pytest --setup-plan",
        "pytest --maxfail 1",
        "pytest -x",
        "pytest -qx",
        "pytest --cov=src",
    ],
)
def test_nonexecuting_or_execution_interrupting_pytest_modes_do_not_prove_scope(
    tmp_path, command: str
) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow(command)})

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    ("config_name", "config"),
    [
        ("pytest.ini", "[pytest]\naddopts = --collect-only\n"),
        ("pytest.ini", "[pytest]\naddopts = --co\n"),
        (
            "pyproject.toml",
            "[tool.pytest.ini_options]\naddopts = '--collect-only'\n",
        ),
    ],
)
def test_implicit_collect_only_addopts_do_not_prove_execution(
    tmp_path, config_name: str, config: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("pytest tests"),
            config_name: config,
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)


def test_nested_pytest_config_that_can_be_selected_by_target_is_not_ignored(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("pytest tests/nested"),
            "tests/nested/pytest.ini": "[pytest]\naddopts = --collect-only\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_safe_implicit_pytest_display_addopts_remain_supported(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("pytest tests"),
            "pytest.ini": "[pytest]\naddopts = -ra\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].paths == ("tests",)


def test_declared_pytest_plugins_do_not_prove_a_direct_pytest_scope(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      PYTEST_DISABLE_PLUGIN_AUTOLOAD: "1"
    steps:
      - run: pytest tests
""",
            "conftest.py": "pytest_plugins = ('ci_plugin',)\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_conftest_collection_hook_does_not_prove_a_direct_pytest_scope(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("pytest tests"),
            "conftest.py": """def pytest_collection_modifyitems(config, items):
    items[:] = []
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_nonempty_conftest_import_does_not_prove_a_direct_pytest_scope(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("pytest tests"),
            "conftest.py": "from pathlib import Path\nPath('pytest.ini').write_text('[pytest]')\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_windows_case_variant_conftest_does_not_prove_a_direct_pytest_scope(tmp_path) -> None:
    """Windows loads a case-variant conftest even when the analyzer runs elsewhere."""

    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - run: pytest tests
""",
            "Conftest.py": "from pathlib import Path\nPath('pytest.ini').write_text('[pytest]')\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_pytest11_project_entry_point_does_not_prove_a_direct_pytest_scope(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("pytest tests"),
            "pyproject.toml": """[project]
name = "fixture"
version = "0"
[project.entry-points.pytest11]
fixture = "fixture.pytest_plugin"
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)


def test_explicitly_disabled_pytest_plugin_autoload_is_a_supported_environment_control(
    tmp_path,
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      PYTEST_DISABLE_PLUGIN_AUTOLOAD: "true"
    steps:
      - run: pytest tests
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].paths == ("tests",)
    assert not result.relevant_incomplete


def test_pytest_addopts_environment_taints_successor_state(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - env:
          PYTEST_ADDOPTS: ${{ inputs.pytest_options }}
        run: pytest tests/test_prepare.py
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize(
    ("name", "command", "issue"),
    [
        ("PYTHONPATH", "python -m pytest tests", "PYTHON_MODULE_PATH_UNKNOWN"),
        ("BASH_ENV", "pytest tests", "BASH_STARTUP_ENV_UNKNOWN"),
        ("PATH", "pytest tests", "EXECUTABLE_IDENTITY_UNKNOWN"),
        ("PYTEST_PLUGINS", "pytest tests", "PYTEST_CONFIGURATION_UNKNOWN"),
        ("PIP_CONFIG_FILE", "pip install pytest\npytest tests", "PIP_STARTUP_ENV_UNKNOWN"),
    ],
)
def test_dynamic_startup_environment_never_leaks_a_proven_pytest_scope(
    tmp_path, name: str, command: str, issue: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - env:
          {name}: ${{{{ inputs.dynamic_value }}}}
        run: |
          {command.replace(chr(10), chr(10) + '          ')}
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(item.code == issue for item in result.issues)
    assert result.relevant_incomplete


def test_git_diff_is_not_assumed_read_only_before_pytest(tmp_path) -> None:
    """A Git diff driver/helper can execute code before the visible test command."""

    write_files(
        tmp_path,
        {".github/workflows/ci.yml": workflow("git diff\npytest tests")},
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PRETEST_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_dynamic_setup_python_runtime_taints_later_pytest_identity(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ inputs.python_version }}
      - run: pytest tests
"""
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTHON_RUNTIME_UNKNOWN" for issue in result.issues)
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    "shell_block",
    [
        "shell: 'bash scripts/wrapper.sh {0}'",
        "shell: '${{ inputs.shell }}'",
    ],
)
def test_custom_shell_boundary_taints_a_later_pytest(tmp_path, shell_block: str) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - {shell_block}
        run: echo wrapper-can-rewrite-pytest-ini-or-skip-generated-script
      - run: pytest
""",
            "scripts/wrapper.sh": "#!/bin/sh\nexit 0\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "SHELL_UNKNOWN" for issue in result.issues)
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize(
    "defaults",
    [
        """defaults:
  run:
    shell: 'bash scripts/wrapper.sh {0}'
""",
        """jobs:
  test:
    defaults:
      run:
        shell: 'bash scripts/wrapper.sh {0}'
""",
    ],
)
def test_default_custom_shell_template_is_not_a_safe_execution_boundary(
    tmp_path, defaults: str
) -> None:
    if defaults.startswith("jobs:"):
        workflow_text = f"""name: CI
on: pull_request
{defaults}    runs-on: ubuntu-latest
    steps:
      - run: echo wrapper
      - run: pytest
"""
    else:
        workflow_text = f"""name: CI
on: pull_request
{defaults}jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo wrapper
      - run: pytest
"""
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow_text,
            "scripts/wrapper.sh": "#!/bin/sh\nexit 0\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "SHELL_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize("shell", ["bash {0}", "bash --noprofile --norc -e -o pipefail {0}"])
def test_explicit_canonical_bash_templates_are_supported(tmp_path, shell: str) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - shell: '{shell}'
        run: pytest tests
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].paths == ("tests",)


def test_powershell_wrapper_template_is_not_assumed_to_be_builtin(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - shell: 'pwsh -File {0}'
        run: pytest tests
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "SHELL_UNKNOWN" for issue in result.issues)


def test_conditional_pytest_can_taint_successor_state(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - if: github.ref == 'refs/heads/main'
        run: pytest tests/test_prepare.py
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "CONDITION_UNKNOWN" for issue in result.issues)
    assert any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize("command", ["pytest", "python -m pytest", "coverage run -m pytest"])
def test_non_root_bare_pytest_is_not_treated_as_repository_wide(tmp_path, command: str) -> None:
    """A nested CI working directory cannot reuse the root denominator as broad scope."""

    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - working-directory: tests/unit
        run: {command}
""",
            "tests/unit/test_unit.py": "def test_unit():\n    assert True\n",
            "tests/integration/test_integration.py": "def test_integration():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    ("name", "workflow_text"),
    [
        (
            "workflow_default",
            """name: CI
on: pull_request
defaults:
  run:
    working-directory: tests/unit
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        ),
        (
            "job_default",
            """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: tests/unit
    steps:
      - run: pytest
""",
        ),
        (
            "step_override",
            """name: CI
on: pull_request
defaults:
  run:
    working-directory: tests/integration
jobs:
  test:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: tests/integration
    steps:
      - working-directory: tests/unit
        run: pytest
""",
        ),
    ],
)
def test_non_root_bare_pytest_defaults_do_not_leak_root_scope(
    tmp_path, name: str, workflow_text: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow_text,
            "tests/unit/test_unit.py": "def test_unit():\n    assert True\n",
            "tests/integration/test_integration.py": "def test_integration():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations, name
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize(
    "working_directory, command",
    [
        ("tests", "pytest unit"),
        ("src/project", "pytest ../../tests/unit"),
    ],
)
def test_non_root_pytest_target_requires_a_congruent_context(
    tmp_path, working_directory: str, command: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - working-directory: {working_directory}
        run: {command}
""",
            "tests/unit/test_unit.py": "def test_unit():\n    assert True\n",
            "src/project/__init__.py": "",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_root_bare_pytest_retains_the_root_collection_control(tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow("pytest")})

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].kind == "broad"
    assert not result.relevant_incomplete


def test_unknown_runner_platform_does_not_prove_bare_pytest(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: self-hosted
    steps:
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_runner_label_substring_does_not_infer_windows_filesystem(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: self-hosted-windows-lab
    steps:
      - run: pytest Tests
""",
            "tests/test_a.py": "def test_a():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_runner_label_array_with_linux_is_static(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: [self-hosted, linux]
    steps:
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].kind == "broad"
    assert result.relevant_incomplete is False


def test_macos_hosted_runner_has_bounded_path_semantics(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: macos-latest
    steps:
      - run: pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].kind == "broad"
    assert result.relevant_incomplete is False


def test_windows_working_directory_preserves_native_separators(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - working-directory: .\\tests
        run: pytest unit
""",
            "tests/unit/test_unit.py": "def test_unit():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_windows_root_config_case_variant_is_recognized(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - run: pytest
""",
            "Pytest.ini": "[pytest]\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].kind == "broad"
    assert result.relevant_incomplete is False


def test_root_explicit_directory_without_nested_config_retains_path_scope(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("pytest tests/unit"),
            "tests/unit/test_unit.py": "def test_unit():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].paths == ("tests/unit",)
    assert not result.relevant_incomplete


def test_windows_runner_target_uses_case_insensitive_scope_matching(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - run: pytest Tests
""",
            "tests/test_a.py": "def test_a():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert not result.invocations[0].path_case_sensitive
    assert result.invocations[0].covers("tests/test_a.py")
    assert not result.relevant_incomplete


def test_linux_runner_case_variant_target_is_not_canonicalized_by_host(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("pytest tests"),
            "Tests/test_a.py": "def test_a():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    "command",
    [
        r"pytest .\tests\unit",
        r"python -m pytest .\tests\unit",
        r"coverage run -m pytest .\tests\unit",
    ],
)
def test_windows_powershell_paths_preserve_runner_separators(tmp_path, command: str) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": f"""name: CI
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - shell: pwsh
        run: {command}
""",
            "tests/unit/test_unit.py": "def test_unit():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert len(result.invocations) == 1
    assert result.invocations[0].paths == ("tests/unit",)
    assert not result.invocations[0].path_case_sensitive
    assert not result.relevant_incomplete


def test_windows_bash_backslash_target_is_not_reinterpreted(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - shell: bash
        run: pytest tests\\unit
""",
            "tests/unit/test_unit.py": "def test_unit():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    ("config_name", "config", "target"),
    [
        ("pytest.ini", "[pytest]\npython_files = check_*.py\n", "tests/nested"),
        (".pytest.ini", "[pytest]\npython_files = check_*.py\n", "tests/nested"),
        ("pytest.toml", "[pytest]\npython_files = [\"check_*.py\"]\n", "tests/nested"),
        (".pytest.toml", "[pytest]\npython_files = [\"check_*.py\"]\n", "tests/nested"),
        (
            "pyproject.toml",
            "[tool.pytest.ini_options]\npython_files = \"check_*.py\"\n",
            "tests/nested",
        ),
        ("pytest.ini", "[pytest]\npython_files = check_*.py\n", "tests/nested/test_a.py"),
    ],
)
def test_target_selected_nested_pytest_config_cannot_reuse_root_denominator(
    tmp_path, config_name: str, config: str, target: str
) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(f"pytest {target}"),
            f"tests/nested/{config_name}": config,
            "tests/nested/test_a.py": "def test_a():\n    assert True\n",
            "tests/nested/check_b.py": "def check_b():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_multiple_pytest_targets_with_nested_config_are_context_unknown(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("pytest tests/unit tests/nested"),
            "tests/unit/test_unit.py": "def test_unit():\n    assert True\n",
            "tests/nested/pytest.ini": "[pytest]\npython_files = check_*.py\n",
            "tests/nested/check_nested.py": "def check_nested():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)


def test_working_directory_and_nested_config_compose_to_unknown_context(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - working-directory: tests
        run: pytest nested
""",
            "tests/nested/pytest.ini": "[pytest]\npython_files = check_*.py\n",
            "tests/nested/check_nested.py": "def check_nested():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)


def test_windows_case_variant_nested_pytest_config_is_context_unknown(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - run: pytest tests/Nested
""",
            "tests/Nested/Pytest.ini": "[pytest]\npython_files = check_*.py\n",
            "tests/Nested/check_nested.py": "def check_nested():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize("directory", [".venv", "venv", ".tox", ".nox", ".git"])
def test_pytest_target_inside_ignored_subtree_is_context_unknown(tmp_path, directory: str) -> None:
    """Ignored denominator paths cannot make their own pytest context safe."""

    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(f"pytest {directory}/tests"),
            f"{directory}/tests/pytest.ini": "[pytest]\npython_files = check_*.py\n",
            f"{directory}/tests/check_nested.py": "def check_nested():\n    assert True\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete
