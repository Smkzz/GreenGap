from __future__ import annotations

import json

import pytest

from greengap.trace import (
    _github_path_pattern_regex,
    _path_patterns_match,
    trace_github_actions,
)

from .conftest import write_files


def workflow(command: str, extra: str = "") -> str:
    return f"""name: CI
jobs:
  test:
    runs-on: ubuntu-latest
{extra}    steps:
      - name: tests
        shell: bash
        run: |
          {command.replace(chr(10), chr(10) + "          ")}
"""


@pytest.mark.parametrize(
    ("command", "kind", "paths"),
    [
        ("pytest", "broad", ()),
        ("pytest tests", "paths", ("tests",)),
        ("pytest tests/test_a.py", "paths", ("tests/test_a.py",)),
        ("python -m pytest", "broad", ()),
        ("coverage run -m pytest tests", "paths", ("tests",)),
        ("python -m coverage run -m pytest tests", "paths", ("tests",)),
    ],
)
def test_direct_runner_shapes_are_traced(
    tmp_path, command: str, kind: str, paths: tuple[str, ...]
) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow(command)})
    result = trace_github_actions(tmp_path)
    assert not result.issues
    assert len(result.invocations) == 1
    assert result.invocations[0].kind == kind
    assert result.invocations[0].paths == paths


@pytest.mark.parametrize(
    "selector",
    [
        "-k fast",
        "-m unit",
        "--ignore tests/slow",
        "--ignore-glob '*/slow/*'",
        "--deselect tests/test_a.py::test_x",
        "--lf",
        "--failed-first",
        "--stepwise",
        "--pyargs package_name",
        "--unknown-selector value",
    ],
)
def test_unsupported_selectors_are_unknown_not_broad(selector: str, tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow(f"pytest {selector}")})
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "PYTEST_SELECTOR_UNKNOWN" for issue in result.issues)


@pytest.mark.parametrize(
    "option",
    [
        "--junitxml out.xml",
        "--maxfail 1",
        "--tb short",
        "--color no",
        "-o foo=bar",
        "-c pytest.ini",
    ],
)
def test_value_consuming_pytest_options_do_not_become_paths(option: str, tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow(f"pytest {option}")})
    result = trace_github_actions(tmp_path)
    if option.split()[0] in {"-o", "-c"}:
        assert not result.invocations
        assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)
    elif option.split()[0] == "--maxfail":
        assert not result.invocations
        assert any(issue.code == "PYTEST_SELECTOR_UNKNOWN" for issue in result.issues)
    else:
        assert result.invocations[0].kind == "broad"
        assert not result.invocations[0].paths


def test_make_c_non_root_pytest_context_is_not_reused_as_root_scope(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("make -C backend test"),
            "backend/Makefile": "test:\n\tpytest tests/unit\n",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "PYTEST_INVOCATION_CONTEXT_UNKNOWN" for issue in result.issues)


def test_make_variable_assignment_is_expanded(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("TEST_SCOPE=tests/unit make test"),
            "Makefile": "TEST_SCOPE = tests\ntest:\n\tpytest $(TEST_SCOPE)\n",
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.invocations[0].paths == ("tests/unit",)


def test_make_special_declarations_do_not_become_the_default_target(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("make"),
            "Makefile": ".PHONY: docs\ninit:\n\tpytest tests/unit\ndocs:\n\tmake html\n",
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.invocations[0].paths == ("tests/unit",)
    assert not result.relevant_incomplete


def test_bound_event_name_resolves_event_guard(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - if: ${{ github.event_name == 'pull_request' }}
        run: pytest tests
""",
        },
    )
    result = trace_github_actions(tmp_path, event="pull_request")
    assert result.invocations[0].paths == ("tests",)
    assert not result.relevant_incomplete


def test_shell_script_with_static_prefix_branch_has_unproven_runner_identity(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("bash ci.sh"),
            "ci.sh": 'PREFIX=""\nif [ -d venv ]; then\n  PREFIX="venv/bin/"\nfi\n${PREFIX}coverage run -m pytest tests/_sync\n',
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "EXECUTABLE_IDENTITY_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


@pytest.mark.parametrize(
    "assignment",
    ['PREFIX="echo "', 'PREFIX="$(something)"', 'PREFIX="$OTHER"', 'PREFIX="foo; rm -rf /"'],
)
def test_shell_dynamic_prefix_is_unknown(assignment: str, tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("bash ci.sh"),
            "ci.sh": f"{assignment}\n${{PREFIX}}coverage run -m pytest\n",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "DYNAMIC_EXECUTABLE_PREFIX" for issue in result.issues)


def test_nested_npm_scripts_are_traced(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("npm test"),
            "package.json": json.dumps(
                {"scripts": {"test": "npm run unit", "unit": "pytest tests/unit"}}
            ),
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.invocations[0].paths == ("tests/unit",)


@pytest.mark.parametrize("manager", ["npm", "pnpm", "yarn"])
def test_package_manager_equivalents_are_supported(manager: str, tmp_path) -> None:
    command = f"{manager} run test" if manager != "yarn" else "yarn test"
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(command),
            "package.json": json.dumps({"scripts": {"test": "pytest tests"}}),
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.invocations[0].paths == ("tests",)


@pytest.mark.parametrize("manager", ["pnpm", "yarn"])
def test_non_npm_lifecycle_hooks_are_not_invented(manager: str, tmp_path) -> None:
    command = f"{manager} run test" if manager == "pnpm" else f"{manager} test"
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(command),
            "package.json": json.dumps(
                {
                    "scripts": {
                        "pretest": "pytest tests/preflight",
                        "test": "echo test",
                    }
                }
            ),
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "PACKAGE_LIFECYCLE_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_local_composite_action_is_resolved(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/test
""",
            ".github/actions/test/action.yml": """name: local
runs:
  using: composite
  steps:
    - shell: bash
      run: pytest tests
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.invocations[0].paths == ("tests",)


def test_local_reusable_workflow_is_resolved(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: parent
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
""",
            ".github/workflows/reusable.yml": workflow("pytest tests/unit"),
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.invocations[0].paths == ("tests/unit",)


def test_external_reusable_workflow_is_incomplete(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: parent
jobs:
  call:
    uses: owner/repo/.github/workflows/test.yml@v1
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert result.issues[0].code == "EXTERNAL_WORKFLOW_UNRESOLVED"


def test_matrix_axes_include_and_exclude_expand(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: matrix
jobs:
  test:
    strategy:
      matrix:
        python: ["3.11", "3.12"]
        include:
          - python: "3.13"
        exclude:
          - python: "3.11"
    runs-on: ubuntu-latest
    steps:
      - run: pytest tests
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert len(result.invocations) == 2
    assert not result.issues


def test_matrix_expression_selects_tox_environment(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: matrix
jobs:
  test:
    strategy:
      matrix:
        python: ["3.11"]
    env:
      TOX_ENV: ${{ matrix.tox || format('py{0}', matrix.python) }}
    runs-on: ubuntu-latest
    steps:
      - run: tox run
""",
            "pyproject.toml": """[tool.tox]
env_list = ["py311"]
[tool.tox.env_run_base]
skip_install = true
commands = ["pytest tests"]
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.invocations[0].paths == ("tests",)


def test_tox_ini_selection_and_posargs_are_resolved(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("tox -e py311 -- tests/test_one.py"),
            "tox.ini": "[tox]\nenvlist = py311\n[testenv]\nskip_install = true\ncommands = pytest {posargs}\n",
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.invocations[0].paths == ("tests/test_one.py",)


def test_uv_run_does_not_shift_to_pytest(tmp_path) -> None:
    write_files(
        tmp_path, {".github/workflows/ci.yml": workflow("uv run pytest tests")}
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert result.issues[0].code == "UV_COMMAND_UNKNOWN"


def test_dynamic_nonselection_setup_is_ignored(tmp_path) -> None:
    write_files(
        tmp_path,
        {".github/workflows/ci.yml": workflow("python -m venv .venv\nexport TOKEN=$(secret)")},
    )
    result = trace_github_actions(tmp_path)
    assert not result.issues


def test_uv_nonrun_setup_command_is_ignored(tmp_path) -> None:
    write_files(
        tmp_path, {".github/workflows/ci.yml": workflow("uv pip install -r requirements.txt")}
    )
    result = trace_github_actions(tmp_path)
    assert not result.issues


def test_process_substitution_setup_is_nonrelevant(tmp_path) -> None:
    write_files(
        tmp_path,
        {".github/workflows/ci.yml": workflow("bash <(curl -s https://example.test/setup)")},
    )
    result = trace_github_actions(tmp_path)
    assert not result.relevant_incomplete
    assert result.issues[0].relevant is False


def test_pytest_warning_report_options_are_not_selectors(tmp_path) -> None:
    write_files(tmp_path, {".github/workflows/ci.yml": workflow("pytest -W error -ra tests")})
    result = trace_github_actions(tmp_path)
    assert result.invocations[0].paths == ("tests",)
    assert not result.relevant_incomplete


def test_modern_tox_nested_argv_and_nonpytest_lane(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow("uv run --locked tox run -e py311"),
            "pyproject.toml": """[tool.tox]
env_list = ["py311", "typing"]
[tool.tox.env_run_base]
skip_install = true
commands = [["pytest", "-v", "--basetemp={env_tmp_dir}", {replace = "posargs", default = [], extend = true}]]
[tool.tox.env.typing]
commands = [["mypy"]]
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert not result.invocations
    assert any(issue.code == "UV_COMMAND_UNKNOWN" for issue in result.issues)
    assert result.relevant_incomplete


def test_unrelated_unresolved_edge_is_kept_as_nonrelevant(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".github/workflows/ci.yml": """name: CI
jobs:
  good:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
  weird:
    runs-on: ubuntu-latest
    steps:
      - run: ${{ unknown.command }}
""",
        },
    )
    result = trace_github_actions(tmp_path)
    assert result.invocations
    assert not result.relevant_incomplete


def test_repeated_path_wildcards_do_not_create_a_backtracking_timeout() -> None:
    """Fuzzed repeated stars must remain bounded during path matching."""

    pattern = "*" * 64 + "\ufffd"
    regex = _github_path_pattern_regex(pattern)

    assert regex == ".*\ufffd"
    assert _path_patterns_match(pattern, [pattern]) is True
