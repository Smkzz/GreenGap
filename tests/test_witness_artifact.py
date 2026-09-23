from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest
from scripts import witness_artifact

from greengap.witness import create_manifest
from greengap.witness_config import ExplicitWitnessConfig
from tests.test_explicit_witness_contract import _collection

_POSIX_ARTIFACT_APIS = pytest.mark.skipif(
    os.name != "posix",
    reason="artifact staging and readback require POSIX no-follow descriptor APIs",
)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _make_artifact(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "source"
    (source / "collection").mkdir(parents=True)
    (source / "execution").mkdir()
    config_bytes = b"witness:\n  collection: collection\n  required:\n    - unit-py311\n"
    config_digest = hashlib.sha256(config_bytes).hexdigest()

    collection = _collection()
    collection["execution_context"]["config_sha256"] = config_digest
    _write_json(source / "collection" / "greengap-collection.json", collection)

    execution = json.loads(json.dumps(collection))
    execution["role"] = "execution"
    execution["execution_context"]["job"] = "unit-py311"
    execution["execution_context"]["surface_id"] = "unit-py311"
    execution["execution"]["attempted_files"] = ["tests/test_a.py"]
    execution["execution"]["call_executed_files"] = ["tests/test_a.py"]
    execution["execution"]["completed_files"] = ["tests/test_a.py"]
    execution["execution"]["call_outcomes"] = [
        {"file": "tests/test_a.py", "outcome": "passed"}
    ]
    _write_json(source / "execution" / "greengap-execution.json", execution)

    root = tmp_path / "runtime-witness"
    witness_artifact.stage_fragments(source, root)
    manifest = create_manifest(
        collection,
        execution_witness_ids=(),
        explicit_config=ExplicitWitnessConfig(
            "collection", ("unit-py311",), config_digest
        ),
    )
    _write_json(root / "manifest.json", manifest)
    witness_artifact.create_input_inventory(root)
    analysis, status = witness_artifact._run_analysis(root, witness_artifact._REPO_ROOT)
    assert status == 0
    assert analysis["outcome"] == "COMPLETE"
    _write_json(root / "analysis.json", analysis)
    receipt_digest = witness_artifact.seal_artifact(root, witness_artifact._REPO_ROOT)
    return root, receipt_digest


def _archive(root: Path, path: Path) -> str:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(root.rglob("*")):
            if source.is_file():
                archive.write(source, source.relative_to(root).as_posix())
    return hashlib.sha256(path.read_bytes()).hexdigest()


@_POSIX_ARTIFACT_APIS
def test_readback_accepts_the_exact_sealed_analysis_inputs(tmp_path: Path) -> None:
    root, receipt_digest = _make_artifact(tmp_path)
    archive = tmp_path / "upload.zip"
    archive_digest = _archive(root, archive)

    witness_artifact.verify_archive(
        archive,
        expected_archive_digest=archive_digest,
        expected_receipt_digest=receipt_digest,
        repository_root=witness_artifact._REPO_ROOT,
        temporary_parent=tmp_path,
    )


@_POSIX_ARTIFACT_APIS
def test_readback_rejects_a_fragment_added_after_analysis(tmp_path: Path) -> None:
    root, receipt_digest = _make_artifact(tmp_path)
    late_fragment = root / "execution" / "greengap-late.json"
    late_fragment.write_text("{}", encoding="utf-8")
    archive = tmp_path / "late-upload.zip"
    archive_digest = _archive(root, archive)

    with pytest.raises(witness_artifact.ArtifactIntegrityError) as raised:
        witness_artifact.verify_archive(
            archive,
            expected_archive_digest=archive_digest,
            expected_receipt_digest=receipt_digest,
            repository_root=witness_artifact._REPO_ROOT,
            temporary_parent=tmp_path,
        )

    assert str(raised.value) == "ARTIFACT_UPLOADED_FILE_MISMATCH"


@_POSIX_ARTIFACT_APIS
def test_inventory_rejects_a_fragment_replaced_after_staging(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "collection").mkdir(parents=True)
    (source / "execution").mkdir()
    (source / "collection" / "greengap-collection.json").write_text("{}", encoding="utf-8")
    root = tmp_path / "runtime-witness"
    witness_artifact.stage_fragments(source, root)

    staged_fragment = root / "collection" / "greengap-collection.json"
    staged_fragment.write_text('{"replacement":true}', encoding="utf-8")
    with pytest.raises(witness_artifact.ArtifactIntegrityError) as raised:
        witness_artifact.create_input_inventory(root)

    assert str(raised.value) == "ARTIFACT_STAGED_FRAGMENTS_CHANGED"


@_POSIX_ARTIFACT_APIS
def test_inventory_rejects_a_complete_fragment_from_a_failed_or_timed_out_command(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    (source / "collection").mkdir(parents=True)
    (source / "execution").mkdir()
    (source / "collection" / "greengap-collection.json").write_text("{}", encoding="utf-8")
    root = tmp_path / "runtime-witness"
    witness_artifact.stage_fragments(
        source,
        root,
        collection_outcome="failure",
        execution_outcome="skipped",
    )

    with pytest.raises(witness_artifact.ArtifactIntegrityError) as raised:
        witness_artifact.create_input_inventory(root)

    assert str(raised.value) == "ARTIFACT_COMMAND_OUTCOME_NOT_SUCCESS"


@_POSIX_ARTIFACT_APIS
def test_readback_extracts_the_same_archive_handle_that_was_hashed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, receipt_digest = _make_artifact(tmp_path)
    archive = tmp_path / "upload.zip"
    archive_digest = _archive(root, archive)
    replacement = tmp_path / "replacement.zip"
    replacement.write_bytes(b"replacement archive bytes")
    original_extract = witness_artifact._extract_archive

    def replace_path_then_extract(archive_source: object, destination: Path) -> set[str]:
        assert hasattr(archive_source, "read")
        os.replace(replacement, archive)
        return original_extract(archive_source, destination)  # type: ignore[arg-type]

    monkeypatch.setattr(witness_artifact, "_extract_archive", replace_path_then_extract)
    witness_artifact.verify_archive(
        archive,
        expected_archive_digest=archive_digest,
        expected_receipt_digest=receipt_digest,
        repository_root=witness_artifact._REPO_ROOT,
        temporary_parent=tmp_path,
    )

    assert archive.read_bytes() == b"replacement archive bytes"


@_POSIX_ARTIFACT_APIS
def test_archive_digest_must_match_the_uploaded_bytes(tmp_path: Path) -> None:
    root, receipt_digest = _make_artifact(tmp_path)
    archive = tmp_path / "upload.zip"
    expected_digest = _archive(root, archive)
    archive.write_bytes(archive.read_bytes() + b"tamper")

    with pytest.raises(witness_artifact.ArtifactIntegrityError) as raised:
        witness_artifact.verify_archive(
            archive,
            expected_archive_digest=expected_digest,
            expected_receipt_digest=receipt_digest,
            repository_root=witness_artifact._REPO_ROOT,
            temporary_parent=tmp_path,
        )

    assert str(raised.value) == "ARTIFACT_UPLOAD_DIGEST_MISMATCH"


def test_archive_rejects_symlink_directory_entries() -> None:
    with zipfile.ZipFile(io.BytesIO(), "w") as archive:
        archive.writestr("collection/", "")
        info = archive.getinfo("collection/")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with pytest.raises(witness_artifact.ArtifactIntegrityError) as raised:
            witness_artifact._archive_file_names(archive)

    assert str(raised.value) == "ARTIFACT_ARCHIVE_DIRECTORY_INVALID"


@pytest.mark.parametrize(
    "value",
    [
        "collection//greengap-item.json",
        "collection/./greengap-item.json",
        "collection/../greengap-item.json",
    ],
)
def test_archive_paths_must_be_canonical(value: str) -> None:
    with pytest.raises(witness_artifact.ArtifactIntegrityError):
        witness_artifact._validate_relative_file(value)


def test_reanalysis_uses_a_minimal_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        return subprocess.CompletedProcess(command, 0, '{"outcome":"COMPLETE"}', "")

    monkeypatch.setenv("GITHUB_TOKEN", "must-not-cross-the-boundary")
    monkeypatch.setenv("PYTHONHOME", "C:/attacker/python")
    monkeypatch.setenv("PYTHONPATH", "C:/attacker/modules")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--ignore=tests/private")
    monkeypatch.setattr(witness_artifact.subprocess, "run", fake_run)

    witness_artifact._run_analysis(tmp_path, witness_artifact._REPO_ROOT)

    command = captured["command"]
    environment = captured["environment"]
    assert isinstance(command, list)
    assert command[1:4] == ["-P", "-m", "greengap"]
    assert isinstance(environment, dict)
    assert environment["PYTHONPATH"] == str(witness_artifact._REPO_ROOT / "src")
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONSAFEPATH"] == "1"
    assert not {"GITHUB_TOKEN", "PYTHONHOME", "PYTEST_ADDOPTS"}.intersection(environment)


@_POSIX_ARTIFACT_APIS
def test_staging_rejects_symlinked_witness_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "collection").mkdir(parents=True)
    (source / "execution").mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (source / "collection" / "greengap-linked.json").symlink_to(outside)

    with pytest.raises(witness_artifact.ArtifactIntegrityError) as raised:
        witness_artifact.stage_fragments(source, tmp_path / "runtime-witness")

    assert str(raised.value) == "STAGE_SOURCE_NOT_REGULAR"


@pytest.mark.parametrize(
    ("limit_name", "payloads", "limit", "expected_error"),
    [
        (
            "MAX_RUNTIME_WITNESS_FRAGMENTS",
            {"greengap-a.json": b"{}", "greengap-b.json": b"{}"},
            1,
            "STAGE_FRAGMENT_COUNT_LIMIT_EXCEEDED",
        ),
        (
            "MAX_RUNTIME_WITNESS_BYTES",
            {"greengap-large.json": b"12345"},
            4,
            "STAGE_FILE_SIZE_LIMIT_EXCEEDED",
        ),
        (
            "MAX_RUNTIME_AGGREGATE_BYTES",
            {"greengap-a.json": b"123", "greengap-b.json": b"456"},
            5,
            "STAGE_AGGREGATE_SIZE_LIMIT_EXCEEDED",
        ),
    ],
)
@_POSIX_ARTIFACT_APIS
def test_staging_enforces_fragment_and_byte_limits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    limit_name: str,
    payloads: dict[str, bytes],
    limit: int,
    expected_error: str,
) -> None:
    source = tmp_path / "source"
    collection = source / "collection"
    collection.mkdir(parents=True)
    (source / "execution").mkdir()
    for name, payload in payloads.items():
        (collection / name).write_bytes(payload)
    monkeypatch.setattr(witness_artifact, limit_name, limit)

    with pytest.raises(witness_artifact.ArtifactIntegrityError) as raised:
        witness_artifact.stage_fragments(source, tmp_path / "runtime-witness")

    assert str(raised.value) == expected_error


@_POSIX_ARTIFACT_APIS
def test_staging_rejects_symlinked_source_directories(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "greengap-fragment.json").write_text("{}", encoding="utf-8")
    (source / "collection").symlink_to(outside, target_is_directory=True)
    (source / "execution").mkdir()

    with pytest.raises(witness_artifact.ArtifactIntegrityError) as raised:
        witness_artifact.stage_fragments(source, tmp_path / "runtime-witness")

    assert str(raised.value) == "STAGE_DIRECTORY_OPEN_FAILED"


def test_ci_stages_then_analyzes_seals_uploads_and_reads_back() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    runtime_job = workflow[
        workflow.index("  runtime-witness:") : workflow.index("  runtime-fixtures:")
    ]
    stage = workflow.index("python scripts/witness_artifact.py stage")
    inventory = workflow.index("python scripts/witness_artifact.py inventory")
    analyze = workflow.index("python -m greengap witness analyze", inventory)
    seal = workflow.index("python scripts/witness_artifact.py seal", analyze)
    upload = workflow.index("uses: actions/upload-artifact@", seal)
    readback = workflow.index("python scripts/witness_artifact.py verify", upload)

    assert stage < inventory < analyze < seal < upload < readback
    assert "runtime-witness-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    assert "overwrite: false" in workflow
    verify_step = workflow[workflow.rindex("- name: Verify the exact uploaded artifact bytes") :]
    assert "if: ${{ always() }}" in verify_step
    assert '[[ "${ARTIFACT_ID}" =~ ^[0-9]+$ ]]' in verify_step
    assert '[[ -n "${ARTIFACT_DIGEST}" ]]' in verify_step
    assert '[[ -n "${INTEGRITY_DIGEST}" ]]' in verify_step
    assert "GH_TOKEN" not in verify_step and "Authorization: Bearer" not in verify_step
    assert "X-GitHub-Api-Version: 2026-03-10" in verify_step
    assert "steps.witness_collect.outcome" in workflow
    assert "steps.witness_execute.outcome" in workflow
    assert '"${WITNESS_COLLECTION_OUTCOME}" != "success"' in workflow
    assert '"${WITNESS_EXECUTION_OUTCOME}" != "success"' in workflow
    assert "persist-credentials: false" in runtime_job
