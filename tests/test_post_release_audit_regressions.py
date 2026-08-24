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
from scripts.qualify_stage0e_full import sparse_checkout_enabled, validate_checkout

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
setenv =
    PYTEST_ADDOPTS = tests/unit
commands = pytest
""",
        },
    )

    result = trace_github_actions(tmp_path)

    assert not result.invocations
    assert any(issue.code == "PYTEST_CONFIGURATION_UNKNOWN" for issue in result.issues)


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

    bound = trace_github_actions(tmp_path, ("src/main.py",))

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

    nested = trace_github_actions(tmp_path, ("src/a/b.py",))
    root_file = trace_github_actions(tmp_path, ("src/a.py",))

    assert not nested.invocations
    assert not any(issue.code == "WORKFLOW_PATH_FILTER_UNKNOWN" for issue in nested.issues)
    assert root_file.invocations


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
    workflow_text = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text(
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
    assert "pip==26.2.1" in workflow_text
    assert "build==1.5.0" in workflow_text
    assert "twine==7.0.0" in workflow_text


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
