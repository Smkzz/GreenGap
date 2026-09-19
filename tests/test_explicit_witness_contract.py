from __future__ import annotations

import json
from pathlib import Path

import pytest

from greengap.cli import main
from greengap.util import MAX_RUNTIME_WITNESS_FRAGMENTS
from greengap.witness import WitnessError, create_manifest, validate_manifest
from greengap.witness_config import (
    WitnessConfigError,
    load_explicit_witness_config,
    validate_explicit_witness_config,
)

SOURCE = "a" * 40
TREE = "b" * 40
FINGERPRINT = "c" * 64


def _collection() -> dict:
    return {
        "schema_version": 1,
        "witness_version": 1,
        "artifact_type": "greengap_pytest_runtime_witness",
        "kind": "pytest_runtime",
        "role": "collection",
        "greengap_version": "0.2.0.dev1",
        "repository_identity": {"git_sha": SOURCE, "git_tree": TREE, "repository": "example/project"},
        "workspace_identity": {
            "initial_fingerprint": FINGERPRINT,
            "final_fingerprint": FINGERPRINT,
            "stable": True,
        },
        "source_identity": {
            "initial_fingerprint": FINGERPRINT,
            "final_fingerprint": FINGERPRINT,
            "stable": True,
        },
        "runtime_workspace_state": {
            "initial_fingerprint": FINGERPRINT,
            "final_fingerprint": FINGERPRINT,
            "stable": True,
        },
        "pytest": {"version": "9.1.1", "rootpath": ".", "session_id": "1" * 32},
        "execution_context": {
            "provider": "local",
            "run_id": "run-1",
            "run_attempt": "1",
            "job": "collection",
            "matrix_identity": None,
            "event": None,
            "ref": None,
            "surface_id": "collection",
            "shard": None,
            "worker_id": None,
            "pid": 1234,
            "config_sha256": "d" * 64,
        },
        "collection": {"complete": True, "collected_files": ["tests/test_a.py"]},
        "execution": {
            "attempted_files": [],
            "call_executed_files": [],
            "completed_files": [],
            "call_outcomes": [],
        },
        "session": {"pytest_exitstatus": 0, "finalized": True},
        "complete": True,
        "diagnostics": [],
    }


def test_explicit_config_normalizes_complete_surface_set(tmp_path: Path) -> None:
    path = tmp_path / ".greengap.yml"
    path.write_text(
        "version: 1\n"
        "witness:\n"
        "  collection: collection\n"
        "  required:\n"
        "    - unit-py312\n"
        "    - unit-py311\n",
        encoding="utf-8",
    )

    config = load_explicit_witness_config(path)

    assert config.collection_surface_id == "collection"
    assert config.required_execution_surface_ids == ("unit-py311", "unit-py312")
    assert config.execution_witness_ids == ("unit-py311|-", "unit-py312|-")


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ({"witness": {"collection": "collection", "required": ["unit", "unit"]}}, "WITNESS_CONFIG_DUPLICATE_SURFACE"),
        ({"witness": {"collection": "../collection", "required": ["unit"]}}, "WITNESS_CONFIG_SURFACE_ID_INVALID"),
        ({"witness": {"collection": "collection", "required": ["collection"]}}, "WITNESS_CONFIG_COLLECTION_CONFLICT"),
        ({"witness": {"collection": "collection", "required": ["unit"], "extra": True}}, "WITNESS_CONFIG_SCHEMA_INVALID"),
    ],
)
def test_explicit_config_rejects_ambiguous_or_unsafe_declarations(payload: dict, error: str) -> None:
    with pytest.raises(WitnessConfigError) as raised:
        validate_explicit_witness_config(payload)
    assert raised.value.code == error


def test_explicit_manifest_binds_surface_declaration() -> None:
    from greengap.witness_config import ExplicitWitnessConfig

    manifest = create_manifest(
        _collection(),
        execution_witness_ids=(),
        explicit_config=ExplicitWitnessConfig(
            "collection", ("unit-py311", "unit-py312"), "d" * 64
        ),
    )

    assert manifest["contract"] == "explicit"
    assert manifest["surface_manifest"] == {
        "collection_surface_id": "collection",
        "required_execution_surface_ids": ["unit-py311", "unit-py312"],
        "config_sha256": "d" * 64,
    }
    assert validate_manifest(manifest) == manifest


def test_explicit_manifest_rejects_surface_id_conflict() -> None:
    from greengap.witness_config import ExplicitWitnessConfig

    manifest = create_manifest(
        _collection(),
        execution_witness_ids=(),
        explicit_config=ExplicitWitnessConfig("collection", ("unit-py311",), "d" * 64),
    )
    manifest["surface_manifest"]["required_execution_surface_ids"] = ["unit-py312"]

    with pytest.raises(WitnessError) as raised:
        validate_manifest(manifest)
    assert raised.value.code == "MANIFEST_SURFACE_ID_CONFLICT"


def test_cli_manifest_accepts_explicit_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    collection_path = tmp_path / "collection.json"
    config_path = tmp_path / ".greengap.yml"
    output_path = tmp_path / "manifest.json"
    collection_path.write_text(json.dumps(_collection()), encoding="utf-8")
    config_path.write_text(
        "witness:\n  collection: collection\n  required:\n    - unit-py311\n",
        encoding="utf-8",
    )

    code = main(
        [
            "witness",
            "manifest",
            "--collection-witness",
            str(collection_path),
            "--config",
            str(config_path),
            "--output",
            str(output_path),
        ]
    )

    assert code == 0
    assert json.loads(capsys.readouterr().out)["complete"] is True
    assert json.loads(output_path.read_text(encoding="utf-8"))["contract"] == "explicit"


def test_cli_analyze_bounds_directory_expansion(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fragments = tmp_path / "fragments"
    fragments.mkdir()
    for index in range(MAX_RUNTIME_WITNESS_FRAGMENTS + 1):
        (fragments / f"greengap-{index:04d}.json").write_text("{}", encoding="utf-8")

    code = main(
        [
            "witness",
            "analyze",
            "--manifest",
            str(tmp_path / "manifest.json"),
            "--collection-witness",
            str(fragments),
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["outcome"] == "INCOMPLETE"
    assert "WITNESS_FRAGMENT_SET_LIMIT_EXCEEDED" in payload["errors"]
