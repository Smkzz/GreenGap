from __future__ import annotations

import json
import os

import pytest

from greengap.environment import collection_environment
from greengap.model import PytestPlugin
from greengap.pytest_adapter import (
    _BoundedProcessResult,
    _parse_plugin_manifest,
    _plugin_args_from_manifest,
    _target_pytest_plugin_manifest,
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
        "greengap.pytest_adapter._target_pytest_plugin_manifest",
        lambda *args, **kwargs: ((), None),
    )
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
    monkeypatch.setattr(
        "greengap.pytest_adapter._target_pytest_plugin_manifest",
        lambda *args, **kwargs: ((), None),
    )

    def failure(*args, **kwargs):
        raise OSError("python unavailable")

    monkeypatch.setattr("greengap.pytest_adapter._run_pytest_bounded", failure)
    result = collect_pytest(tmp_path)
    assert not result.complete
    assert "could not start" in (result.error or "")


def test_target_plugin_manifest_is_validated_and_sorted() -> None:
    manifest, error = _parse_plugin_manifest(
        "noise\n"
        'GREENGAP_PYTEST_PLUGIN_MANIFEST=[{"distribution":"pytest-cov","version":"6.0.0","entry_point":"pytest_cov","module":"pytest_cov.plugin"}]\n'
    )

    assert error is None
    assert manifest == (
        PytestPlugin("pytest-cov", "6.0.0", "pytest_cov", "pytest_cov.plugin"),
    )


def test_malformed_or_duplicate_target_plugin_manifest_is_unknown() -> None:
    malformed, malformed_error = _parse_plugin_manifest(
        "GREENGAP_PYTEST_PLUGIN_MANIFEST={not-json}\n"
    )
    duplicate, duplicate_error = _parse_plugin_manifest(
        "GREENGAP_PYTEST_PLUGIN_MANIFEST="
        + json.dumps(
            [
                {
                    "distribution": "plugin",
                    "version": "1",
                    "entry_point": "plugin",
                    "module": "plugin",
                },
                {
                    "distribution": "plugin",
                    "version": "1",
                    "entry_point": "plugin",
                    "module": "plugin",
                },
            ]
        )
        + "\n"
    )

    assert malformed is None and malformed_error
    assert duplicate is None and duplicate_error


def test_plugin_args_use_selected_target_manifest_and_honor_config_disable() -> None:
    manifest = (
        PytestPlugin("pytest-cov", "6.0.0", "pytest_cov", "pytest_cov.plugin"),
        PytestPlugin("pytest-asyncio", "1.0.0", "asyncio", "pytest_asyncio.plugin"),
    )

    assert _plugin_args_from_manifest(manifest, {"pytest_cov"}) == (
        "-p",
        "pytest_asyncio.plugin",
    )


def test_plugin_manifest_inspection_uses_selected_interpreter(monkeypatch, tmp_path) -> None:
    observed: dict[str, object] = {}

    def fake_run(args, root, environment, timeout):
        observed["args"] = args
        observed["environment"] = environment
        return _BoundedProcessResult(
            0,
            "GREENGAP_PYTEST_PLUGIN_MANIFEST=[]\n",
            "",
        )

    monkeypatch.setattr("greengap.pytest_adapter._run_pytest_bounded", fake_run)

    manifest, error = _target_pytest_plugin_manifest(
        "target-python", tmp_path, {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}, 10
    )

    assert error is None
    assert manifest == ()
    assert observed["args"][0] == "target-python"
    assert observed["args"][1] == "-c"
    assert observed["environment"]["PYTHONNOUSERSITE"] == "1"


def test_collection_explicitly_loads_selected_target_plugins(monkeypatch, tmp_path) -> None:
    write_files(tmp_path, {"tests/test_a.py": "def test_a():\n    pass\n"})
    manifest = (
        PytestPlugin("pytest-cov", "6.0.0", "pytest_cov", "pytest_cov.plugin"),
        PytestPlugin("pytest-asyncio", "1.0.0", "asyncio", "pytest_asyncio.plugin"),
    )
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        "greengap.pytest_adapter._target_pytest_plugin_manifest",
        lambda *args, **kwargs: (manifest, None),
    )

    def fake_run(args, root, environment, timeout):
        observed["args"] = args
        observed["environment"] = environment
        witness = {
            "version": 1,
            "nodes": [{"nodeid": "tests/test_a.py::test_a", "path": "tests/test_a.py"}],
        }
        with open(environment["GREENGAP_COLLECTION_FILE"], "w", encoding="utf-8") as handle:
            json.dump(witness, handle)
        return _BoundedProcessResult(0, "tests/test_a.py::test_a\n", "")

    monkeypatch.setattr("greengap.pytest_adapter._run_pytest_bounded", fake_run)

    result = collect_pytest(tmp_path)

    assert result.complete
    assert result.plugin_manifest == manifest
    assert result.plugin_manifest_complete
    assert observed["environment"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    args = observed["args"]
    assert args[args.index("-p") + 1 : args.index("--rootdir")] == [
        "greengap._collection_plugin",
        "-p",
        "pytest_asyncio.plugin",
        "-p",
        "pytest_cov.plugin",
    ]


@pytest.mark.parametrize("exit_code", [1, 2, 3, 4])
def test_nonzero_collection_codes_are_not_complete(exit_code: int, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "greengap.pytest_adapter._target_pytest_plugin_manifest",
        lambda *args, **kwargs: ((), None),
    )
    monkeypatch.setattr(
        "greengap.pytest_adapter._run_pytest_bounded",
        lambda *args, **kwargs: _BoundedProcessResult(exit_code, "", "error"),
    )
    result = collect_pytest(tmp_path)
    assert not result.complete
