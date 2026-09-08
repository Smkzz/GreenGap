from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from greengap.environment import collection_environment
from greengap.pytest_adapter import (
    _BoundedProcessResult,
    _explicit_project_plugin_args,
    collect_pytest,
)

from .conftest import write_files


def test_collection_environment_is_allowlisted(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-cross-the-boundary")
    monkeypatch.setenv("PIP_INDEX_URL", "https://example.invalid/simple")

    environment = collection_environment({"PYTHONPATH": "target-src", "PIP_NO_INDEX": "1"})

    assert environment["PYTHONPATH"] == "target-src"
    assert environment["PIP_NO_INDEX"] == "1"
    assert "GITHUB_TOKEN" not in environment
    assert "PIP_INDEX_URL" not in environment


def test_real_collection_returns_node_ids_and_paths(tmp_path) -> None:
    write_files(tmp_path, {"tests/test_a.py": "def test_a():\n    assert True\n"})
    result = collect_pytest(tmp_path, timeout=30)
    assert result.complete
    assert result.environment_valid
    assert result.paths == ("tests/test_a.py",)
    assert result.nodes[0].nodeid.startswith("tests/test_a.py::")


def test_real_collection_keeps_pytest_cache_out_of_the_workspace(tmp_path) -> None:
    write_files(tmp_path, {"tests/test_a.py": "def test_a():\n    assert True\n"})

    result = collect_pytest(tmp_path, timeout=30)

    assert result.complete
    assert not (tmp_path / ".pytest_cache").exists()


def test_real_collection_does_not_inherit_parent_pytest_configuration(tmp_path) -> None:
    checkout = tmp_path / "host-project" / "nested-checkout"
    write_files(
        tmp_path,
        {
            "host-project/pyproject.toml": "[tool.pytest.ini_options]\naddopts = '--collect-only'\n",
            "host-project/nested-checkout/tests/test_a.py": "def test_a():\n    assert True\n",
        },
    )

    result = collect_pytest(checkout, timeout=30)

    assert result.complete
    assert result.environment_valid
    assert result.paths == ("tests/test_a.py",)


def test_real_collection_does_not_inherit_ambient_secret_environment(monkeypatch, tmp_path) -> None:
    secret_name = "GREENGAP_TEST_SENTINEL_SECRET"
    monkeypatch.setenv(secret_name, "must-not-cross-the-boundary")
    observed = tmp_path / "observed-secret.txt"
    write_files(
        tmp_path,
        {
            "tests/test_environment.py": (
                "import os\n"
                "from pathlib import Path\n"
                f"Path({str(observed)!r}).write_text(os.getenv({secret_name!r}, 'MISSING'))\n"
                "def test_environment():\n"
                "    pass\n"
            )
        },
    )

    result = collect_pytest(tmp_path, timeout=30)

    assert result.complete
    assert observed.read_text(encoding="utf-8") == "MISSING"
    assert os.environ[secret_name] == "must-not-cross-the-boundary"


def test_real_collection_can_collect_zero_tests(tmp_path) -> None:
    write_files(tmp_path, {"README.md": "empty\n"})
    result = collect_pytest(tmp_path, timeout=30)
    assert result.complete
    assert result.paths == ()


def test_collection_failure_is_incomplete(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            "tests/test_good.py": "def test_good():\n    pass\n",
            "tests/test_bad.py": "raise RuntimeError('collection exploded')\n",
        },
    )
    result = collect_pytest(tmp_path, timeout=30)
    assert not result.complete
    assert not result.nodes or "tests/test_good.py" in result.paths
    assert result.error is not None


def test_collection_import_failure_is_not_called_unregistered(tmp_path) -> None:
    write_files(
        tmp_path,
        {"tests/test_missing.py": "import package_that_does_not_exist\ndef test_x():\n    pass\n"},
    )
    result = collect_pytest(tmp_path, timeout=30)
    assert not result.complete
    assert not result.environment_valid


def test_collection_timeout_preserves_partial_output(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "greengap.pytest_adapter._run_pytest_bounded",
        lambda *args, **kwargs: _BoundedProcessResult(
            None, "tests/test_a.py::test_a\n", "", timed_out=True
        ),
    )
    result = collect_pytest(tmp_path, timeout=1)
    assert not result.complete
    assert result.timed_out
    assert result.paths == ("tests/test_a.py",)


def test_collection_start_failure_is_explicit(monkeypatch, tmp_path) -> None:
    def failure(*args, **kwargs):
        raise OSError("python unavailable")

    monkeypatch.setattr("greengap.pytest_adapter._run_pytest_bounded", failure)
    result = collect_pytest(tmp_path)
    assert not result.complete
    assert "could not start" in (result.error or "")


def test_declared_marker_plugins_are_loaded_explicitly(monkeypatch, tmp_path) -> None:
    write_files(
        tmp_path,
        {
            "pyproject.toml": '[project]\ndependencies = ["pytest-trio"]\n',
            "tests/test_a.py": "import pytest\n@pytest.mark.trio\ndef test_a():\n    pass\n",
        },
    )
    entry_point = SimpleNamespace(
        name="trio",
        value="pytest_trio.plugin",
        dist=SimpleNamespace(name="pytest-trio"),
    )
    monkeypatch.setattr(
        "greengap.pytest_adapter.importlib.metadata.entry_points",
        lambda **kwargs: (entry_point,),
    )
    assert _explicit_project_plugin_args(tmp_path) == ("-p", "pytest_trio.plugin")


def test_unrelated_manifest_text_does_not_bind_a_pytest_plugin(monkeypatch, tmp_path) -> None:
    write_files(
        tmp_path,
        {
            "pyproject.toml": '[project]\ndependencies = []\n# pytest-trio is not installed by this project\n',
            "tests/test_a.py": "import pytest\n@pytest.mark.trio\ndef test_a():\n    pass\n",
        },
    )
    entry_point = SimpleNamespace(
        name="trio",
        value="pytest_trio.plugin",
        dist=SimpleNamespace(name="pytest-trio"),
    )
    monkeypatch.setattr(
        "greengap.pytest_adapter.importlib.metadata.entry_points",
        lambda **kwargs: (entry_point,),
    )

    assert _explicit_project_plugin_args(tmp_path) == ()


def test_unbound_installed_pytest_plugins_invalidate_collection(monkeypatch, tmp_path) -> None:
    entry_point = SimpleNamespace(
        name="foreign",
        value="foreign_pytest_plugin.plugin",
        dist=SimpleNamespace(name="foreign-plugin"),
    )
    monkeypatch.setattr(
        "greengap.pytest_adapter.importlib.metadata.entry_points",
        lambda **kwargs: (entry_point,),
    )

    result = collect_pytest(tmp_path)

    assert not result.complete
    assert not result.environment_valid
    assert "unbound pytest11 plugins" in (result.error or "")


@pytest.mark.parametrize("exit_code", [1, 2, 3, 4])
def test_nonzero_collection_codes_are_not_complete(exit_code: int, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "greengap.pytest_adapter._run_pytest_bounded",
        lambda *args, **kwargs: _BoundedProcessResult(exit_code, "", "error"),
    )
    result = collect_pytest(tmp_path)
    assert not result.complete
