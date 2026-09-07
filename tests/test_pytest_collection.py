from __future__ import annotations

from types import SimpleNamespace

import pytest

from greengap.pytest_adapter import (
    _BoundedProcessResult,
    _explicit_project_plugin_args,
    collect_pytest,
)

from .conftest import write_files


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
