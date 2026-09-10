from __future__ import annotations

import json
from pathlib import Path

import pytest

from greengap.cli import main
from greengap.model import FindingState
from greengap.runtime import (
    RuntimeWitnessError,
    aggregate_runtime_witnesses,
    load_runtime_witness,
)

SOURCE = "a" * 40
FINGERPRINT = "b" * 64


def _witness(*, source: str = SOURCE, job: str = "pytest", complete: bool = True) -> dict:
    return {
        "schema_version": 1,
        "artifact_type": "greengap_pytest_runtime_witness",
        "greengap_version": "1.0.0rc1",
        "source_commit": source,
        "repository": "example/project",
        "workspace_fingerprint": FINGERPRINT,
        "workspace_fingerprint_final": FINGERPRINT,
        "workspace_stable": True,
        "pytest_root": ".",
        "github": {
            "run_id": "123",
            "run_attempt": "1",
            "job": job,
            "matrix": None,
            "shard": None,
            "repository": "example/project",
        },
        "collection": [
            {"nodeid": "tests/test_a.py::test_a", "path": "tests/test_a.py"},
            {"nodeid": "tests/test_b.py::test_b", "path": "tests/test_b.py"},
        ],
        "executed": [
            {
                "nodeid": "tests/test_a.py::test_a",
                "path": "tests/test_a.py",
                "started": True,
                "finished": True,
                "reports": [{"when": "call", "outcome": "passed"}],
            }
        ],
        "session": {
            "exit_status": 0,
            "collection_complete": True,
            "session_complete": True,
        },
        "complete": complete,
        "errors": [],
    }


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _denominator(path: Path) -> Path:
    return _write(
        path,
        {
            "mode": "scan",
            "stable": True,
            "collection": {"complete": True, "nodes": _witness()["collection"]},
        },
    )


def test_runtime_witness_validation_is_strict_and_normalized(tmp_path: Path) -> None:
    path = _write(tmp_path / "witness.json", _witness())

    loaded = load_runtime_witness(path)

    assert loaded["source_commit"] == SOURCE
    assert loaded["collection"][0]["path"] == "tests/test_a.py"

    secret_payload = _witness()
    secret_payload["unexpected_secret"] = "do-not-copy"
    with pytest.raises(RuntimeWitnessError) as error:
        load_runtime_witness(_write(tmp_path / "secret.json", secret_payload))
    assert error.value.code == "WITNESS_SCHEMA_INVALID"


def test_runtime_aggregate_reports_observed_and_unseen_nodes(tmp_path: Path) -> None:
    witness = _write(tmp_path / "witness.json", _witness())
    denominator = _denominator(tmp_path / "denominator.json")

    result = aggregate_runtime_witnesses(
        (witness,),
        denominator,
        expected_identities=("123|1|pytest|-|-",),
        source_commit=SOURCE,
    )

    assert result.complete
    assert result.executed_count == 1
    assert result.findings[0].state == FindingState.EXECUTED_PASS
    assert result.findings[1].state == FindingState.NOT_SEEN
    assert result.findings[1].blocking
    assert result.to_dict()["outcome"] == "BLOCKED"


def test_runtime_aggregate_requires_a_predeclared_witness_set(tmp_path: Path) -> None:
    witness = _write(tmp_path / "witness.json", _witness())
    denominator = _denominator(tmp_path / "denominator.json")

    result = aggregate_runtime_witnesses((witness,), denominator, source_commit=SOURCE)

    assert not result.complete
    assert "EXPECTED_WITNESS_SET_MISSING" in result.errors
    assert all(finding.state == FindingState.UNKNOWN for finding in result.findings)
    assert result.to_dict()["runtime_execution_identity"] == "NOT_CERTIFIED"


def test_runtime_aggregate_rejects_missing_and_inconsistent_witnesses(tmp_path: Path) -> None:
    first = _write(tmp_path / "first.json", _witness(job="pytest-linux"))
    second_payload = _witness(source="c" * 40, job="pytest-windows")
    second = _write(tmp_path / "second.json", second_payload)
    denominator = _denominator(tmp_path / "denominator.json")

    result = aggregate_runtime_witnesses(
        (first, second),
        denominator,
        expected_identities=(
            "123|1|pytest-linux|-|-",
            "123|1|pytest-windows|-|-",
        ),
        source_commit=SOURCE,
    )

    assert not result.complete
    assert "SOURCE_COMMIT_INCONSISTENT" in result.errors
    assert "SOURCE_COMMIT_MISMATCH" in result.errors
    assert all(finding.state == FindingState.UNKNOWN for finding in result.findings)


def test_runtime_aggregate_rejects_duplicate_witness_identity(tmp_path: Path) -> None:
    first = _write(tmp_path / "first.json", _witness())
    duplicate = _write(tmp_path / "duplicate.json", _witness())
    denominator = _denominator(tmp_path / "denominator.json")

    result = aggregate_runtime_witnesses(
        (first, duplicate),
        denominator,
        expected_identities=("123|1|pytest|-|-",),
        source_commit=SOURCE,
    )

    assert not result.complete
    assert "DUPLICATE_WITNESS_IDENTITY" in result.errors


def test_runtime_witness_cli_preserves_runtime_contract(capsys, tmp_path: Path) -> None:
    witness = _write(tmp_path / "witness.json", _witness())
    denominator = _denominator(tmp_path / "denominator.json")

    code = main(
        [
            "witness",
            str(tmp_path),
            "--denominator",
            str(denominator),
            "--witness",
            str(witness),
            "--expected-witness",
            "123|1|pytest|-|-",
            "--source-commit",
            SOURCE,
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert code == 1
    assert output["mode"] == "witness"
    assert output["runtime_execution_identity"] == "CERTIFIED"
    assert output["findings"][1]["state"] == "NOT_SEEN"
