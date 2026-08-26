from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from scripts.create_release_provenance import create_manifest
from scripts.qualify_stage0e_full import (
    expected_unknown_baseline,
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
    }

    assert expected_unknown_baseline("outcome", plan)


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


def test_static_make_setup_does_not_poison_a_later_test_command(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": two_step_workflow("make", "pytest tests"),
            "Makefile": "init:\n\tpython -m pip install -r requirements.txt\n",
        },
    )

    result = trace_github_actions(tmp_path)

    assert result.invocations
    assert not any(issue.code == "WORKSPACE_MUTATION_UNKNOWN" for issue in result.issues)


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
    "command",
    [
        "ruff check --fix tests",
        "ruff check --output-file pytest.ini tests",
        "mypy --junit-xml pytest.ini",
        "pip-audit -o pytest.ini",
        "python -m coverage run scripts/rewrite.py",
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
