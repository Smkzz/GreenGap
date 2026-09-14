from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from greengap.witness import (
    WITNESS_PLUGIN_MODULE,
    analyze_witnesses,
    create_manifest,
    execute_witness_command,
    load_witness,
)
from greengap.witness_config import load_explicit_witness_config


def _git_commit(root: Path) -> str:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=GreenGap explicit-contract tests",
            "-c",
            "user.email=greengap-explicit-tests@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _command(*, role: str, surface: str, source: str) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        WITNESS_PLUGIN_MODULE,
        "--greengap-witness-role",
        role,
        "--greengap-surface-id",
        surface,
        "--greengap-source-sha",
        source,
        "--greengap-run-id",
        "run-1",
        "--greengap-run-attempt",
        "1",
        "--greengap-job-id",
        surface,
    ]
    if role == "collection":
        command.extend(["--collect-only", "--greengap-full-collection"])
    return command


def test_direct_pytest_contract_proves_baseline_omission_and_incompleteness(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(
        "collection-witness/\nexecution-witness/\nomission-witness/\n*.pyc\n",
        encoding="utf-8",
    )
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_a.py").write_text("def test_a():\n    assert True\n", encoding="utf-8")
    (tests / "test_b.py").write_text("def test_b():\n    assert True\n", encoding="utf-8")
    (tmp_path / ".greengap.yml").write_text(
        "witness:\n  collection: collection\n  required:\n    - unit-py311\n",
        encoding="utf-8",
    )
    source = _git_commit(tmp_path)
    config = load_explicit_witness_config(tmp_path / ".greengap.yml")

    collection_dir = tmp_path / "collection-witness"
    collection_run = execute_witness_command(
        tmp_path,
        _command(role="collection", surface="collection", source=source),
        role="collection",
        output_dir=str(collection_dir),
        source_commit=source,
        surface_id="collection",
        run_id="run-1",
        timeout=60,
    )
    assert collection_run.returncode == 0
    assert collection_run.fragment_names
    collection = load_witness(collection_dir / collection_run.fragment_names[0])
    assert collection["complete"] is True

    execution_dir = tmp_path / "execution-witness"
    execution_run = execute_witness_command(
        tmp_path,
        _command(role="execution", surface="unit-py311", source=source),
        role="execution",
        output_dir=str(execution_dir),
        source_commit=source,
        surface_id="unit-py311",
        run_id="run-1",
        timeout=60,
    )
    assert execution_run.returncode == 0
    execution = execution_dir / execution_run.fragment_names[0]
    manifest = create_manifest(collection, execution_witness_ids=(), explicit_config=config)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    baseline = analyze_witnesses(manifest_path, (collection_dir / collection_run.fragment_names[0],), (execution,))
    assert baseline.complete
    assert baseline.outcome == "COMPLETE"
    assert baseline.not_run_files == ()

    omission_dir = tmp_path / "omission-witness"
    omission_run = execute_witness_command(
        tmp_path,
        _command(role="execution", surface="unit-py311", source=source) + ["tests/test_a.py"],
        role="execution",
        output_dir=str(omission_dir),
        source_commit=source,
        surface_id="unit-py311",
        run_id="run-1",
        timeout=60,
    )
    assert omission_run.returncode == 0
    omitted = analyze_witnesses(
        manifest_path,
        (collection_dir / collection_run.fragment_names[0],),
        (omission_dir / omission_run.fragment_names[0],),
    )
    assert omitted.complete
    assert omitted.outcome == "BLOCKED"
    assert omitted.not_run_files == ("tests/test_b.py",)

    missing = analyze_witnesses(manifest_path, (collection_dir / collection_run.fragment_names[0],), ())
    assert not missing.complete
    assert missing.outcome == "INCOMPLETE"
    assert missing.not_run_files == ()

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not-json", encoding="utf-8")
    malformed_result = analyze_witnesses(
        manifest_path,
        (collection_dir / collection_run.fragment_names[0],),
        (malformed,),
    )
    assert not malformed_result.complete
    assert malformed_result.outcome == "INCOMPLETE"

    wrong_payload = json.loads(execution.read_text(encoding="utf-8"))
    wrong_payload["repository_identity"]["git_sha"] = "d" * 40
    wrong = tmp_path / "wrong-source.json"
    wrong.write_text(json.dumps(wrong_payload), encoding="utf-8")
    mismatch = analyze_witnesses(
        manifest_path,
        (collection_dir / collection_run.fragment_names[0],),
        (wrong,),
    )
    assert not mismatch.complete
    assert mismatch.outcome == "INCOMPLETE"
    assert "SOURCE_COMMIT_MISMATCH" in mismatch.errors

    restored = analyze_witnesses(manifest_path, (collection_dir / collection_run.fragment_names[0],), (execution,))
    assert restored.complete
    assert restored.outcome == "COMPLETE"
