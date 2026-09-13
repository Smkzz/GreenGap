from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import greengap.witness as witness_module
from greengap.witness import (
    WitnessError,
    analyze_witnesses,
    load_witness,
    validate_witness,
)

SOURCE = "a" * 40
TREE = "b" * 40
FINGERPRINT = "c" * 64


def _fragment(
    *,
    session_id: str = "1" * 32,
    role: str = "execution",
    surface: str = "execution",
    shard: str | None = None,
    source: str = SOURCE,
    fingerprint: str = FINGERPRINT,
    collection_complete: bool = True,
    collected: list[str] | None = None,
    attempted: list[str] | None = None,
    call_executed: list[str] | None = None,
    completed: list[str] | None = None,
    outcomes: list[dict[str, str]] | None = None,
    complete: bool = True,
    diagnostics: list[str] | None = None,
) -> dict:
    collected = collected if collected is not None else ["tests/test_a.py"]
    attempted = attempted if attempted is not None else list(collected)
    call_executed = call_executed if call_executed is not None else list(collected)
    completed = completed if completed is not None else list(collected)
    return {
        "schema_version": 1,
        "witness_version": 1,
        "artifact_type": "greengap_pytest_runtime_witness",
        "kind": "pytest_runtime",
        "role": role,
        "greengap_version": "1.0.0rc1",
        "repository_identity": {
            "git_sha": source,
            "git_tree": TREE,
            "repository": "example/project",
        },
        "workspace_identity": {
            "initial_fingerprint": fingerprint,
            "final_fingerprint": fingerprint,
            "stable": True,
        },
        "pytest": {
            "version": "9.1.1",
            "rootpath": ".",
            "session_id": session_id,
        },
        "execution_context": {
            "provider": "ci",
            "run_id": "run-1",
            "run_attempt": "1",
            "job": surface,
            "matrix_identity": None,
            "event": "pull_request",
            "ref": "refs/heads/main",
            "surface_id": surface,
            "shard": shard,
            "worker_id": shard,
            "pid": 1234,
        },
        "collection": {
            "complete": collection_complete,
            "collected_files": collected,
        },
        "execution": {
            "attempted_files": attempted,
            "call_executed_files": call_executed,
            "completed_files": completed,
            "call_outcomes": outcomes or [
                {"file": path, "outcome": "passed"} for path in call_executed
            ],
        },
        "session": {"pytest_exitstatus": 0, "finalized": True},
        "complete": complete,
        "diagnostics": diagnostics or [],
    }


def _manifest(*, execution: list[str] | None = None, fingerprint: str = FINGERPRINT) -> dict:
    execution = execution if execution is not None else ["execution|-"]
    return {
        "schema_version": 1,
        "manifest_version": 1,
        "artifact_type": "greengap_pytest_runtime_witness_manifest",
        "repository_identity": {
            "git_sha": SOURCE,
            "git_tree": TREE,
            "repository": "example/project",
        },
        "workspace_identity": {"fingerprint": fingerprint},
        "run_identity": {"run_id": "run-1", "run_attempt": "1"},
        "collection": {"expected_witness_ids": ["collection|-"]},
        "execution": {"expected_witness_ids": execution},
        "required_witness_ids": sorted({"collection|-", *execution}),
    }


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _inputs(tmp_path: Path, *, collection: dict | None = None, execution: list[dict] | None = None):
    collection_path = _write(tmp_path / "collection.json", collection or _fragment(role="collection", surface="collection"))
    execution_payloads = execution if execution is not None else [_fragment()]
    execution_paths = tuple(_write(tmp_path / f"execution-{index}.json", payload)
                            for index, payload in enumerate(execution_payloads))
    manifest_path = _write(tmp_path / "manifest.json", _manifest())
    return manifest_path, collection_path, execution_paths


def test_all_collected_files_execute(tmp_path: Path) -> None:
    manifest, collection, execution = _inputs(tmp_path)
    result = analyze_witnesses(manifest, (collection,), execution)
    assert result.complete
    assert result.outcome == "COMPLETE"
    assert result.not_run_files == ()


def test_one_collected_file_is_proven_omitted(tmp_path: Path) -> None:
    collection_payload = _fragment(
        role="collection", surface="collection", collected=["tests/test_a.py", "tests/test_b.py"]
    )
    execution_payload = _fragment(call_executed=["tests/test_a.py"])
    manifest, collection, _ = _inputs(tmp_path, collection=collection_payload, execution=[execution_payload])
    result = analyze_witnesses(manifest, (collection,), (tmp_path / "execution-0.json",))
    assert result.complete
    assert result.outcome == "BLOCKED"
    assert result.not_run_files == ("tests/test_b.py",)


def test_incomplete_collection_is_unknown(tmp_path: Path) -> None:
    collection_payload = _fragment(
        role="collection", surface="collection", collection_complete=False, complete=False,
        diagnostics=["COLLECTION_FAILED"]
    )
    manifest, collection, execution = _inputs(tmp_path, collection=collection_payload)
    result = analyze_witnesses(manifest, (collection,), execution)
    assert not result.complete
    assert result.outcome == "INCOMPLETE"


def test_missing_expected_execution_witness_is_unknown(tmp_path: Path) -> None:
    manifest, collection, _ = _inputs(tmp_path, execution=[])
    _write(manifest, _manifest(execution=["execution|-", "windows|-"]))
    result = analyze_witnesses(manifest, (collection,), ())
    assert not result.complete
    assert "EXPECTED_EXECUTION_WITNESS_MISSING" in result.errors


def test_source_sha_mismatch_is_unknown(tmp_path: Path) -> None:
    manifest, collection, execution = _inputs(tmp_path, execution=[_fragment(source="d" * 40)])
    result = analyze_witnesses(manifest, (collection,), execution)
    assert not result.complete
    assert "SOURCE_COMMIT_MISMATCH" in result.errors


def test_workspace_fingerprint_mismatch_is_unknown(tmp_path: Path) -> None:
    manifest, collection, execution = _inputs(tmp_path, execution=[_fragment(fingerprint="d" * 64)])
    result = analyze_witnesses(manifest, (collection,), execution)
    assert not result.complete
    assert "WORKSPACE_FINGERPRINT_MISMATCH" in result.errors


def test_malformed_witness_is_unknown(tmp_path: Path) -> None:
    manifest, collection, _ = _inputs(tmp_path)
    malformed = _write(tmp_path / "bad.json", {"schema_version": 1, "oops": []})
    result = analyze_witnesses(manifest, (collection,), (malformed,))
    assert not result.complete
    assert any("WITNESS_MALFORMED" in error or "WITNESS_SCHEMA_INVALID" in error for error in result.errors)


def test_path_traversal_is_rejected(tmp_path: Path) -> None:
    payload = _fragment(role="collection", surface="collection")
    payload["collection"]["collected_files"] = ["../secret.py"]
    with pytest.raises(WitnessError) as error:
        validate_witness(payload)
    assert error.value.code == "WITNESS_PATH_INVALID"


def test_duplicate_identical_fragments_merge_deterministically(tmp_path: Path) -> None:
    manifest, collection, execution = _inputs(tmp_path)
    result = analyze_witnesses(manifest, (collection,), (execution[0], execution[0]))
    assert result.complete
    assert result.fragment_count == 2
    assert result.received_witness_count == 2


def test_duplicate_conflicting_fragments_fail_closed(tmp_path: Path) -> None:
    first = _fragment()
    second = _fragment()
    second["execution"]["call_executed_files"] = []
    second["execution"]["call_outcomes"] = []
    manifest, collection, _ = _inputs(tmp_path, execution=[first, second])
    result = analyze_witnesses(manifest, (collection,), (tmp_path / "execution-0.json", tmp_path / "execution-1.json"))
    assert not result.complete
    assert "CONFLICTING_DUPLICATE_FRAGMENT" in result.errors


def test_failing_call_phase_is_executed_and_outcome_is_retained(tmp_path: Path) -> None:
    payload = _fragment(outcomes=[{"file": "tests/test_a.py", "outcome": "failed"}])
    manifest, collection, execution = _inputs(tmp_path, execution=[payload])
    loaded = load_witness(execution[0])
    assert loaded["execution"]["call_executed_files"] == ["tests/test_a.py"]
    assert loaded["execution"]["call_outcomes"] == [{"file": "tests/test_a.py", "outcome": "failed"}]
    assert analyze_witnesses(manifest, (collection,), execution).outcome == "COMPLETE"


def test_setup_failure_is_attempted_but_not_call_executed(tmp_path: Path) -> None:
    payload = _fragment(
        attempted=["tests/test_a.py"], call_executed=[], completed=["tests/test_a.py"], outcomes=[]
    )
    manifest, collection, execution = _inputs(tmp_path, execution=[payload])
    loaded = load_witness(execution[0])
    assert loaded["execution"]["attempted_files"] == ["tests/test_a.py"]
    assert loaded["execution"]["call_executed_files"] == []
    result = analyze_witnesses(manifest, (collection,), execution)
    assert result.outcome == "BLOCKED"


def test_multiple_sessions_union_without_shared_mutation(tmp_path: Path) -> None:
    first = _fragment(session_id="1" * 32, call_executed=["tests/test_a.py"])
    second = _fragment(
        session_id="2" * 32,
        call_executed=["tests/test_b.py"],
        collected=["tests/test_b.py"],
    )
    collection_payload = _fragment(
        role="collection", surface="collection", collected=["tests/test_a.py", "tests/test_b.py"]
    )
    manifest = _write(tmp_path / "manifest.json", _manifest())
    collection = _write(tmp_path / "collection.json", collection_payload)
    execution_a = _write(tmp_path / "execution-a.json", first)
    execution_b = _write(tmp_path / "execution-b.json", second)
    result = analyze_witnesses(manifest, (collection,), (execution_a, execution_b))
    assert result.complete
    assert result.executed_files == ("tests/test_a.py", "tests/test_b.py")


def test_command_activation_is_explicit_for_direct_tox_and_uv(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(witness_module, "git_repository_identity", lambda root: (SOURCE, TREE))
    seen: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(command, **kwargs):
        seen.append((list(command), dict(kwargs["env"])))
        if command[0] == "no-witness":
            return SimpleNamespace(returncode=0)
        output_dir = Path(kwargs["env"]["GREENGAP_WITNESS_DIR"])
        output_dir.mkdir(parents=True, exist_ok=True)
        _write(output_dir / f"{Path(command[0]).name}-fragment.json", _fragment())
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(witness_module.subprocess, "run", fake_run)
    for command in (
        ["python", "-m", "pytest"],
        ["tox"],
        ["uv", "run", "pytest"],
    ):
        output = tmp_path / Path(command[0]).name
        result = witness_module.execute_witness_command(
            tmp_path, command, role="execution", output_dir=str(output)
        )
        assert result.fragment_names
    collection_output = tmp_path / "collection"
    collection_result = witness_module.execute_witness_command(
        tmp_path,
        ["python", "-m", "pytest"],
        role="collection",
        collect_only=True,
        output_dir=str(collection_output),
    )
    assert collection_result.fragment_names

    assert len(seen) == 4
    for actual_command, env in seen:
        options = env["PYTEST_ADDOPTS"].split()
        assert options[-2:] == ["-p", witness_module.WITNESS_PLUGIN_MODULE] or options[
            -3:-1
        ] == ["-p", witness_module.WITNESS_PLUGIN_MODULE]
        assert "PYTHONPATH" in env
        if actual_command[0] == "tox":
            assert actual_command[1:3] == [
                "-x",
                "testenv.pass_env=PYTHONPATH,PYTEST_ADDOPTS,GREENGAP_*,GITHUB_*",
            ]
        else:
            assert "-x" not in actual_command
    assert "--collect-only" in seen[-1][1]["PYTEST_ADDOPTS"].split()
    assert witness_module._is_tox_command(["tox", "--override-ini", "pass_env=PYTHONPATH"])
    uv_tox = witness_module._tox_instrumented_command(["uv", "run", "--with", "tox", "tox", "-e", "py"])
    assert uv_tox[5:7] == [
        "-x",
        "testenv.pass_env=PYTHONPATH,PYTEST_ADDOPTS,GREENGAP_*,GITHUB_*",
    ]

    fallback_output = tmp_path / "fallback"
    fallback = witness_module.execute_witness_command(
        tmp_path,
        ["no-witness"],
        role="collection",
        output_dir=str(fallback_output),
    )
    assert fallback.fragment_names
    fallback_payload = load_witness(fallback.output_dir / fallback.fragment_names[0])
    assert not fallback_payload["complete"]
    assert not fallback_payload["collection"]["complete"]
    assert "WITNESS_PROCESS_INCOMPLETE" in fallback_payload["diagnostics"]


def test_undeclared_xdist_shard_fails_closed(tmp_path: Path) -> None:
    execution_payload = _fragment(shard="gw0")
    manifest, collection, _ = _inputs(tmp_path, execution=[execution_payload])
    result = analyze_witnesses(manifest, (collection,), (tmp_path / "execution-0.json",))
    assert not result.complete
    assert "UNEXPECTED_WITNESS_ID" in result.errors
    assert "EXPECTED_EXECUTION_WITNESS_MISSING" in result.errors


def test_manifest_and_witness_outputs_are_parameter_free(tmp_path: Path) -> None:
    secret_parameter = "pytest /home/private/secret"
    payload = _fragment()
    payload["execution_context"]["surface_id"] = "pytest"
    encoded = json.dumps(payload)
    assert secret_parameter not in encoded
    loaded = validate_witness(payload)
    assert "pytest" in loaded["execution_context"]["surface_id"]
