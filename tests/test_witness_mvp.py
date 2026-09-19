from __future__ import annotations

import json
import subprocess
import sys
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
    source_fingerprint: str | None = None,
    source_final_fingerprint: str | None = None,
    source_stable: bool = True,
    runtime_fingerprint: str | None = None,
    runtime_final_fingerprint: str | None = None,
    runtime_stable: bool = True,
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
    source_fingerprint = source_fingerprint or fingerprint
    source_final_fingerprint = source_final_fingerprint or source_fingerprint
    runtime_fingerprint = runtime_fingerprint or fingerprint
    runtime_final_fingerprint = runtime_final_fingerprint or runtime_fingerprint
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
            "initial_fingerprint": runtime_fingerprint,
            "final_fingerprint": runtime_final_fingerprint,
            "stable": runtime_stable,
        },
        "source_identity": {
            "initial_fingerprint": source_fingerprint,
            "final_fingerprint": source_final_fingerprint,
            "stable": source_stable,
        },
        "runtime_workspace_state": {
            "initial_fingerprint": runtime_fingerprint,
            "final_fingerprint": runtime_final_fingerprint,
            "stable": runtime_stable,
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


def _manifest(
    *,
    execution: list[str] | None = None,
    fingerprint: str = FINGERPRINT,
    source_fingerprint: str | None = None,
) -> dict:
    execution = execution if execution is not None else ["execution|-"]
    source_fingerprint = source_fingerprint or fingerprint
    return {
        "schema_version": 1,
        "manifest_version": 1,
        "artifact_type": "greengap_pytest_runtime_witness_manifest",
        "repository_identity": {
            "git_sha": SOURCE,
            "git_tree": TREE,
            "repository": "example/project",
        },
        "source_identity": {"fingerprint": source_fingerprint},
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


def test_transient_runtime_workspace_state_does_not_invalidate_source_identity(tmp_path: Path) -> None:
    payload = _fragment(
        runtime_fingerprint="d" * 64,
        runtime_final_fingerprint="e" * 64,
        runtime_stable=False,
    )
    manifest, collection, execution = _inputs(tmp_path, execution=[payload])
    result = analyze_witnesses(manifest, (collection,), execution)
    assert result.complete
    assert result.outcome == "COMPLETE"


def test_source_identity_mismatch_is_unknown(tmp_path: Path) -> None:
    manifest, collection, execution = _inputs(
        tmp_path,
        execution=[_fragment(source_fingerprint="d" * 64)],
    )
    result = analyze_witnesses(manifest, (collection,), execution)
    assert not result.complete
    assert "SOURCE_IDENTITY_MISMATCH" in result.errors


def test_source_identity_mutation_is_unknown(tmp_path: Path) -> None:
    manifest, collection, execution = _inputs(
        tmp_path,
        execution=[_fragment(source_final_fingerprint="d" * 64)],
    )
    result = analyze_witnesses(manifest, (collection,), execution)
    assert not result.complete
    assert "SOURCE_IDENTITY_UNSTABLE" in result.errors


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


def test_command_activation_does_not_rewrite_direct_tox_or_uv(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(witness_module, "git_repository_identity", lambda root: (SOURCE, TREE))
    monkeypatch.setenv("GITHUB_TOKEN", "should-not-cross-process-boundary")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--ignore=hidden-selector")
    seen: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(command, **kwargs):
        seen.append((list(command), dict(kwargs["env"])))
        if command[0] == "no-witness":
            return SimpleNamespace(returncode=0)
        output_dir = Path(kwargs["env"]["GREENGAP_WITNESS_DIR"])
        output_dir.mkdir(parents=True, exist_ok=True)
        _write(output_dir / f"{Path(command[0]).name}-fragment.json", _fragment())
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(witness_module, "run_process_tree", fake_run)
    for index, command in enumerate((
        ["python", "-m", "pytest"],
        ["tox"],
        ["python", "-m", "tox"],
        ["python", "-m", "coverage", "run", "-m", "pytest"],
        ["uv", "run", "pytest"],
    )):
        output = tmp_path / f"command-{index}"
        result = witness_module.execute_witness_command(
            tmp_path,
            command,
            role="execution",
            output_dir=str(output),
            surface_id="unit-py311",
            run_id="run-1",
        )
        assert result.fragment_names
    collection_output = tmp_path / "collection"
    collection_command = [
        "python",
        "-m",
        "pytest",
        "-p",
        witness_module.WITNESS_PLUGIN_MODULE,
        "--collect-only",
        "--greengap-full-collection",
    ]
    collection_result = witness_module.execute_witness_command(
        tmp_path,
        collection_command,
        role="collection",
        collect_only=True,
        output_dir=str(collection_output),
        surface_id="collection",
        run_id="run-1",
    )
    assert collection_result.fragment_names

    assert len(seen) == 6
    assert [entry[0] for entry in seen] == [
        ["python", "-m", "pytest"],
        ["tox"],
        ["python", "-m", "tox"],
        ["python", "-m", "coverage", "run", "-m", "pytest"],
        ["uv", "run", "pytest"],
        collection_command,
    ]
    for _actual_command, env in seen:
        assert "PYTHONPATH" in env
        assert "PYTEST_ADDOPTS" not in env
        assert "GITHUB_TOKEN" not in env
        assert env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
        assert env["PYTHONNOUSERSITE"] == "1"
    assert seen[0][1]["GREENGAP_SURFACE_ID"] == "unit-py311"
    assert seen[-1][1]["GREENGAP_SURFACE_ID"] == "collection"
    assert seen[-1][0] == collection_command

    fallback_output = tmp_path / "fallback"
    fallback = witness_module.execute_witness_command(
        tmp_path,
        ["no-witness"],
        role="collection",
        output_dir=str(fallback_output),
        surface_id="collection",
        run_id="run-1",
    )
    assert fallback.fragment_names
    fallback_payload = load_witness(fallback.output_dir / fallback.fragment_names[0])
    assert not fallback_payload["complete"]
    assert not fallback_payload["collection"]["complete"]
    assert "WITNESS_PROCESS_INCOMPLETE" in fallback_payload["diagnostics"]


def test_real_witness_separates_runtime_outputs_from_source_identity(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".pytest_cache/\n", encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_a.py").write_text(
        "from pathlib import Path\n"
        "def test_a():\n"
        "    Path('coverage.xml').write_text('runtime output', encoding='utf-8')\n"
        "    assert True\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=GreenGap tests",
            "-c",
            "user.email=greengap-tests@example.invalid",
            "commit",
            "-qm",
            "base",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    output_dir = tmp_path / "witness-output"
    result = witness_module.execute_witness_command(
        tmp_path,
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            witness_module.WITNESS_PLUGIN_MODULE,
            "tests/test_a.py",
        ],
        role="execution",
        output_dir=str(output_dir),
        surface_id="unit-py311",
        run_id="run-1",
        extra_environment={
            "PYTHONPATH": str(Path(pytest.__file__).parent.parent),
        },
        timeout=30,
    )
    assert result.fragment_names
    payload = load_witness(output_dir / result.fragment_names[0])
    assert payload["complete"]
    assert payload["source_identity"]["stable"]
    assert payload["runtime_workspace_state"]["initial_fingerprint"] != payload["runtime_workspace_state"]["final_fingerprint"]


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
