from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import greengap.witness as witness_module
from greengap.witness import (
    WITNESS_PLUGIN_MODULE,
    analyze_witnesses,
    create_manifest,
    execute_witness_command,
    load_witness,
)
from greengap.witness_config import load_explicit_witness_config

_PYTEST_SITE_PACKAGES = str(Path(pytest.__file__).parent.parent)


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
        "collection-witness/\nfiltered-witness/\nexecution-witness/\nomission-witness/\n*.pyc\n",
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
        config_sha256=config.config_sha256,
        extra_environment={"PYTHONPATH": _PYTEST_SITE_PACKAGES},
        timeout=60,
    )
    assert collection_run.returncode == 0
    assert collection_run.fragment_names
    collection = load_witness(collection_dir / collection_run.fragment_names[0])
    assert collection["complete"] is True

    filtered_dir = tmp_path / "filtered-witness"
    filtered_run = execute_witness_command(
        tmp_path,
        _command(role="collection", surface="collection", source=source) + ["tests/test_a.py"],
        role="collection",
        output_dir=str(filtered_dir),
        source_commit=source,
        surface_id="collection",
        run_id="run-1",
        config_sha256=config.config_sha256,
        extra_environment={"PYTHONPATH": _PYTEST_SITE_PACKAGES},
        timeout=60,
    )
    assert filtered_run.returncode == 0
    filtered = load_witness(filtered_dir / filtered_run.fragment_names[0])
    assert filtered["complete"] is False
    assert filtered["collection"]["complete"] is False
    assert "COLLECTION_SELECTOR_PRESENT" in filtered["diagnostics"]

    execution_dir = tmp_path / "execution-witness"
    execution_run = execute_witness_command(
        tmp_path,
        _command(role="execution", surface="unit-py311", source=source),
        role="execution",
        output_dir=str(execution_dir),
        source_commit=source,
        surface_id="unit-py311",
        run_id="run-1",
        config_sha256=config.config_sha256,
        extra_environment={"PYTHONPATH": _PYTEST_SITE_PACKAGES},
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
        config_sha256=config.config_sha256,
        extra_environment={"PYTHONPATH": _PYTEST_SITE_PACKAGES},
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

    wrong_config_payload = json.loads(execution.read_text(encoding="utf-8"))
    wrong_config_payload["execution_context"]["config_sha256"] = "e" * 64
    wrong_config = tmp_path / "wrong-config.json"
    wrong_config.write_text(json.dumps(wrong_config_payload), encoding="utf-8")
    config_mismatch = analyze_witnesses(
        manifest_path,
        (collection_dir / collection_run.fragment_names[0],),
        (wrong_config,),
    )
    assert not config_mismatch.complete
    assert config_mismatch.outcome == "INCOMPLETE"
    assert "CONFIG_DIGEST_MISMATCH" in config_mismatch.errors

    restored = analyze_witnesses(manifest_path, (collection_dir / collection_run.fragment_names[0],), (execution,))
    assert restored.complete
    assert restored.outcome == "COMPLETE"


def test_timeout_after_a_complete_pytest_fragment_still_blocks_analysis(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".gitignore").write_text(
        "collection-witness/\nexecution-witness/\n*.pyc\n",
        encoding="utf-8",
    )
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_a.py").write_text("def test_a():\n    assert True\n", encoding="utf-8")
    config_path = tmp_path / ".greengap.yml"
    config_path.write_text(
        "witness:\n  collection: collection\n  required:\n    - unit-py311\n",
        encoding="utf-8",
    )
    source = _git_commit(tmp_path)
    config = load_explicit_witness_config(config_path)
    collection_dir = tmp_path / "collection-witness"
    collection_run = execute_witness_command(
        tmp_path,
        _command(role="collection", surface="collection", source=source),
        role="collection",
        output_dir=str(collection_dir),
        source_commit=source,
        surface_id="collection",
        run_id="run-timeout",
        config_sha256=config.config_sha256,
        extra_environment={"PYTHONPATH": _PYTEST_SITE_PACKAGES},
        timeout=60,
    )
    assert collection_run.returncode == 0
    collection = load_witness(collection_dir / collection_run.fragment_names[0])
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(create_manifest(collection, execution_witness_ids=(), explicit_config=config)),
        encoding="utf-8",
    )

    original_run_process_tree = witness_module.run_process_tree

    def finish_then_timeout(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        completed = original_run_process_tree(command, **kwargs)  # type: ignore[arg-type]
        assert completed.returncode == 0
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(witness_module, "run_process_tree", finish_then_timeout)
    execution_dir = tmp_path / "execution-witness"
    execution_run = execute_witness_command(
        tmp_path,
        _command(role="execution", surface="unit-py311", source=source),
        role="execution",
        output_dir=str(execution_dir),
        source_commit=source,
        surface_id="unit-py311",
        run_id="run-timeout",
        config_sha256=config.config_sha256,
        extra_environment={"PYTHONPATH": _PYTEST_SITE_PACKAGES},
        timeout=60,
    )
    assert execution_run.returncode == 124
    assert execution_run.error == "COMMAND_TIMEOUT"

    result = analyze_witnesses(
        manifest_path,
        (collection_dir / collection_run.fragment_names[0],),
        tuple(execution_dir / name for name in execution_run.fragment_names),
    )
    assert not result.complete
    assert result.outcome == "INCOMPLETE"


def test_concurrent_fragment_publication_keeps_each_complete_file(tmp_path: Path) -> None:
    output_dir = tmp_path / "concurrent-witness"
    output_dir.mkdir()
    expected = set(range(32))

    def publish(value: int) -> str | None:
        return witness_module._write_incomplete_fragment(output_dir, {"value": value})

    with ThreadPoolExecutor(max_workers=16) as executor:
        names = tuple(executor.map(publish, expected))

    assert all(name is not None for name in names)
    assert len(set(names)) == len(expected)
    values = {
        json.loads((output_dir / name).read_text(encoding="utf-8"))["value"]
        for name in names
        if name is not None
    }
    assert values == expected
