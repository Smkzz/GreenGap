from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import greengap._runtime_plugin as runtime_plugin
import greengap.runtime as runtime_module
from greengap.cli import main
from greengap.model import (
    CollectedNode,
    CollectionResult,
    FindingState,
    ScanReport,
    WorkspaceSnapshot,
)
from greengap.report import public_report
from greengap.runtime import (
    RuntimeWitnessError,
    aggregate_runtime_witnesses,
    load_runtime_witness,
)
from greengap.util import pytest_node_identity

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
    return _write(path, _witness())


def test_runtime_plugin_rejects_explicit_source_claim_that_differs_from_head(monkeypatch) -> None:
    class Config:
        rootpath = "."

        def getoption(self, name, default=None):
            return SOURCE

    monkeypatch.setattr(
        runtime_plugin.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="c" * 40),
    )
    errors: list[str] = []

    assert runtime_plugin._source_commit(Config(), errors) is None
    assert errors == ["SOURCE_COMMIT_MISMATCH"]


def test_runtime_plugin_accepts_explicit_source_claim_matching_head(monkeypatch) -> None:
    class Config:
        rootpath = "."

        def getoption(self, name, default=None):
            return SOURCE

    monkeypatch.setattr(
        runtime_plugin.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=SOURCE),
    )
    errors: list[str] = []

    assert runtime_plugin._source_commit(Config(), errors) == SOURCE
    assert errors == []


def test_runtime_plugin_applies_nodeid_bound_before_accepting_item_path(tmp_path: Path) -> None:
    witness = object.__new__(runtime_plugin._Witness)
    witness.root = tmp_path
    nodeid = "tests/test_a.py::test_" + "x" * runtime_plugin._MAX_NODEID_BYTES

    assert witness._path_for(nodeid, tmp_path / "tests" / "test_a.py") is None


@pytest.mark.parametrize(
    ("reports", "expected"),
    [
        (
            [
                {"when": "setup", "outcome": "passed"},
                {"when": "call", "outcome": "skipped"},
                {"when": "teardown", "outcome": "passed"},
            ],
            FindingState.SKIPPED,
        ),
        ([{"when": "setup", "outcome": "passed"}], FindingState.UNKNOWN),
        (
            [
                {"when": "setup", "outcome": "passed"},
                {"when": "call", "outcome": "passed"},
                {"when": "teardown", "outcome": "passed"},
            ],
            FindingState.EXECUTED_PASS,
        ),
    ],
)
def test_runtime_state_requires_a_passing_call_phase(reports, expected) -> None:
    assert runtime_module._state_for_execution({"reports": reports}) == expected


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


def test_runtime_witness_rejects_conflicting_node_identity(tmp_path: Path) -> None:
    payload = _witness()
    payload["collection"][0]["node_identity"] = "c" * 64

    with pytest.raises(RuntimeWitnessError) as error:
        load_runtime_witness(_write(tmp_path / "conflict.json", payload))

    assert error.value.code == "WITNESS_NODE_IDENTITY_CONFLICT"


def test_runtime_aggregate_reports_observed_and_unseen_nodes(tmp_path: Path) -> None:
    witness = _write(tmp_path / "witness.json", _witness())
    denominator = _denominator(tmp_path / "denominator.json")

    result = aggregate_runtime_witnesses(
        (witness,),
        denominator,
        expected_identities=("123|1|pytest|-|-",),
        expected_repository="example/project",
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


def test_runtime_aggregate_requires_a_target_repository_binding(tmp_path: Path) -> None:
    witness = _write(tmp_path / "witness.json", _witness())
    denominator = _denominator(tmp_path / "denominator.json")

    result = aggregate_runtime_witnesses(
        (witness,),
        denominator,
        expected_identities=("123|1|pytest|-|-",),
        source_commit=SOURCE,
    )

    assert not result.complete
    assert "EXPECTED_REPOSITORY_MISSING" in result.errors
    assert all(finding.state == FindingState.UNKNOWN for finding in result.findings)


def test_runtime_aggregate_rejects_public_scan_denominator(tmp_path: Path) -> None:
    witness = _write(tmp_path / "witness.json", _witness())
    denominator = _write(
        tmp_path / "scan.json",
        {
            "mode": "scan",
            "stable": True,
            "collection": {"complete": True, "nodes": _witness()["collection"]},
        },
    )

    result = aggregate_runtime_witnesses(
        (witness,),
        denominator,
        expected_identities=("123|1|pytest|-|-",),
        expected_repository="example/project",
        source_commit=SOURCE,
    )

    assert not result.complete
    assert "DENOMINATOR_RUNTIME_WITNESS_REQUIRED" in result.errors


def test_runtime_aggregate_rejects_repository_mismatch(tmp_path: Path) -> None:
    witness = _write(tmp_path / "witness.json", _witness())
    denominator = _denominator(tmp_path / "denominator.json")

    result = aggregate_runtime_witnesses(
        (witness,),
        denominator,
        expected_identities=("123|1|pytest|-|-",),
        expected_repository="other/project",
        source_commit=SOURCE,
    )

    assert not result.complete
    assert "REPOSITORY_MISMATCH" in result.errors
    assert all(finding.state == FindingState.UNKNOWN for finding in result.findings)


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
        expected_repository="example/project",
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
        expected_repository="example/project",
        source_commit=SOURCE,
    )

    assert not result.complete
    assert "DUPLICATE_WITNESS_IDENTITY" in result.errors


def test_runtime_aggregate_bounds_outer_witness_set(tmp_path: Path, monkeypatch) -> None:
    witness = _write(tmp_path / "witness.json", _witness())
    denominator = _denominator(tmp_path / "denominator.json")
    monkeypatch.setattr(runtime_module, "MAX_RUNTIME_WITNESSES", 1)

    result = aggregate_runtime_witnesses(
        (witness, witness),
        denominator,
        expected_identities=("123|1|pytest|-|-",),
        expected_repository="example/project",
        source_commit=SOURCE,
    )

    assert not result.complete
    assert "WITNESS_SET_LIMIT_EXCEEDED" in result.errors


def test_runtime_aggregate_bounds_expected_identity_set(tmp_path: Path, monkeypatch) -> None:
    witness = _write(tmp_path / "witness.json", _witness())
    denominator = _denominator(tmp_path / "denominator.json")
    monkeypatch.setattr(runtime_module, "MAX_RUNTIME_EXPECTED_IDENTITIES", 1)

    result = aggregate_runtime_witnesses(
        (witness,),
        denominator,
        expected_identities=("123|1|pytest|-|-", "123|1|other|-|-"),
        expected_repository="example/project",
        source_commit=SOURCE,
    )

    assert not result.complete
    assert "EXPECTED_WITNESS_SET_LIMIT_EXCEEDED" in result.errors


def test_runtime_aggregate_bounds_cumulative_artifact_size(tmp_path: Path, monkeypatch) -> None:
    witness = _write(tmp_path / "witness.json", _witness())
    denominator = _denominator(tmp_path / "denominator.json")
    monkeypatch.setattr(runtime_module, "MAX_RUNTIME_AGGREGATE_BYTES", 1)

    result = aggregate_runtime_witnesses(
        (witness,),
        denominator,
        expected_identities=("123|1|pytest|-|-",),
        expected_repository="example/project",
        source_commit=SOURCE,
    )

    assert not result.complete
    assert "WITNESS_TOTAL_SIZE_LIMIT_EXCEEDED" in result.errors


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
            "--repository",
            "example/project",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert code == 1
    assert output["mode"] == "witness"
    assert output["runtime_execution_identity"] == "CERTIFIED"
    assert output["findings"][1]["state"] == "NOT_SEEN"


def test_public_collection_redaction_preserves_exact_node_identity(tmp_path: Path) -> None:
    nodeid = "tests/test_a.py::test_case[pytest /home/alice/private]"
    path = "tests/test_a.py"
    report = ScanReport(
        repository=str(tmp_path),
        snapshot=WorkspaceSnapshot(FINGERPRINT, (path,), "filesystem"),
        final_fingerprint=FINGERPRINT,
        candidates=(),
        collection=CollectionResult(
            complete=True,
            environment_valid=True,
            nodes=(CollectedNode(nodeid, path),),
            paths=(path,),
        ),
        stable=True,
    )

    payload = public_report(report, root=tmp_path, collection_enabled=True)
    rendered = payload["collection"]["nodes"][0]

    assert rendered["nodeid"] != nodeid
    assert rendered["node_identity"] == pytest_node_identity(nodeid, path)


@pytest.mark.parametrize(
    ("equivalent", "error"),
    [
        (False, "CHECKOUT_SOURCE_NOT_EQUIVALENT_START"),
        (None, "CHECKOUT_SOURCE_EQUIVALENCE_UNKNOWN_START"),
    ],
)
def test_runtime_witness_fails_closed_for_checkout_source_drift(
    monkeypatch, tmp_path: Path, equivalent: bool | None, error: str
) -> None:
    witness = object.__new__(runtime_plugin._Witness)
    witness.root = tmp_path
    witness.errors = []
    monkeypatch.setattr(
        runtime_plugin,
        "checkout_source_equivalent_to_head",
        lambda root, timeout: equivalent,
    )

    witness._check_checkout_source("start")

    assert witness.errors == [error]
