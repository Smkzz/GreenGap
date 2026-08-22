from __future__ import annotations

import subprocess

import pytest

from greengap.pytest_adapter import collect_pytest

from .conftest import write_files


def test_real_collection_returns_node_ids_and_paths(tmp_path) -> None:
    write_files(tmp_path, {"tests/test_a.py": "def test_a():\n    assert True\n"})
    result = collect_pytest(tmp_path, timeout=30)
    assert result.complete
    assert result.environment_valid
    assert result.paths == ("tests/test_a.py",)
    assert result.nodes[0].nodeid.startswith("tests/test_a.py::")


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
    def timeout(*args, **kwargs):
        command = kwargs.get("args", args[0] if args else [])
        raise subprocess.TimeoutExpired(command, 1, output=b"tests/test_a.py::test_a\n")

    monkeypatch.setattr("greengap.pytest_adapter.subprocess.run", timeout)
    result = collect_pytest(tmp_path, timeout=1)
    assert not result.complete
    assert result.timed_out
    assert result.paths == ("tests/test_a.py",)


def test_collection_start_failure_is_explicit(monkeypatch, tmp_path) -> None:
    def failure(*args, **kwargs):
        raise OSError("python unavailable")

    monkeypatch.setattr("greengap.pytest_adapter.subprocess.run", failure)
    result = collect_pytest(tmp_path)
    assert not result.complete
    assert "could not start" in (result.error or "")


@pytest.mark.parametrize("exit_code", [1, 2, 3, 4])
def test_nonzero_collection_codes_are_not_complete(exit_code: int, monkeypatch, tmp_path) -> None:
    completed = subprocess.CompletedProcess(["pytest"], exit_code, "", "error")
    monkeypatch.setattr("greengap.pytest_adapter.subprocess.run", lambda *args, **kwargs: completed)
    result = collect_pytest(tmp_path)
    assert not result.complete
