from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest
from scripts.package_transport import (
    MANIFEST_NAME,
    PACKAGE_NAME,
    PACKAGE_VERSION,
    PackageTransportError,
    _canonical_json,
    create_manifest,
    verify_payload,
)

SOURCE_SHA = "a" * 40
SOURCE_TREE = "b" * 40
WHEEL_NAME = f"{PACKAGE_NAME}-{PACKAGE_VERSION}-py3-none-any.whl"
SDIST_NAME = f"{PACKAGE_NAME}-{PACKAGE_VERSION}.tar.gz"
METADATA = f"Metadata-Version: 2.4\nName: {PACKAGE_NAME}\nVersion: {PACKAGE_VERSION}\n\n"


def _write_wheel(path: Path, *, comment: bytes = b"A") -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.comment = comment
        archive.writestr(f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA", METADATA)
        archive.writestr(f"{PACKAGE_NAME}/__init__.py", "__version__ = '0.2.0.dev1'\n")


def _write_sdist(path: Path) -> None:
    root = f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    data = METADATA.encode("utf-8")
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo(f"{root}/PKG-INFO")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
        source = b"__version__ = '0.2.0.dev1'\n"
        info = tarfile.TarInfo(f"{root}/src/{PACKAGE_NAME}/__init__.py")
        info.size = len(source)
        archive.addfile(info, io.BytesIO(source))


def _payload(root: Path) -> tuple[Path, str]:
    root.mkdir()
    (root / WHEEL_NAME).parent.mkdir(parents=True, exist_ok=True)
    _write_wheel(root / WHEEL_NAME)
    _write_sdist(root / SDIST_NAME)
    manifest = create_manifest(root, SOURCE_SHA, SOURCE_TREE)
    return root, _canonical_json(manifest).decode("utf-8").strip()


def test_package_transport_manifest_verifies_exact_wheel_and_sdist(tmp_path: Path) -> None:
    directory, manifest_json = _payload(tmp_path / "payload")

    result = verify_payload(directory, manifest_json, SOURCE_SHA, SOURCE_TREE)

    assert result["source"] == {"sha": SOURCE_SHA, "tree": SOURCE_TREE}
    assert {entry["name"] for entry in result["files"]} == {WHEEL_NAME, SDIST_NAME}


def test_package_transport_rejects_missing_artifact_directory(tmp_path: Path) -> None:
    directory, manifest_json = _payload(tmp_path / "payload")

    with pytest.raises(PackageTransportError, match="ARTIFACT_DIRECTORY_MISSING"):
        verify_payload(directory / "missing", manifest_json, SOURCE_SHA, SOURCE_TREE)


def test_package_transport_rejects_missing_file(tmp_path: Path) -> None:
    directory, manifest_json = _payload(tmp_path / "payload")
    (directory / WHEEL_NAME).unlink()

    with pytest.raises(PackageTransportError, match="ARTIFACT_FILE_SET_MISMATCH"):
        verify_payload(directory, manifest_json, SOURCE_SHA, SOURCE_TREE)


def test_package_transport_rejects_unexpected_file(tmp_path: Path) -> None:
    directory, manifest_json = _payload(tmp_path / "payload")
    (directory / "unexpected.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(PackageTransportError, match="ARTIFACT_FILE_SET_MISMATCH"):
        verify_payload(directory, manifest_json, SOURCE_SHA, SOURCE_TREE)


def test_package_transport_rejects_renamed_distribution(tmp_path: Path) -> None:
    directory, manifest_json = _payload(tmp_path / "payload")
    (directory / WHEEL_NAME).rename(directory / "renamed.whl")

    with pytest.raises(PackageTransportError, match="ARTIFACT_FILE_SET_MISMATCH"):
        verify_payload(directory, manifest_json, SOURCE_SHA, SOURCE_TREE)


def test_package_transport_rejects_hash_mismatch(tmp_path: Path) -> None:
    directory, manifest_json = _payload(tmp_path / "payload")
    _write_wheel(directory / WHEEL_NAME, comment=b"B")

    with pytest.raises(PackageTransportError, match=f"HASH_MISMATCH:{WHEEL_NAME}"):
        verify_payload(directory, manifest_json, SOURCE_SHA, SOURCE_TREE)


def test_package_transport_rejects_truncated_distribution(tmp_path: Path) -> None:
    directory, manifest_json = _payload(tmp_path / "payload")
    wheel = directory / WHEEL_NAME
    wheel.write_bytes(wheel.read_bytes()[:-8])

    with pytest.raises(PackageTransportError, match=f"SIZE_MISMATCH:{WHEEL_NAME}"):
        verify_payload(directory, manifest_json, SOURCE_SHA, SOURCE_TREE)


def test_package_transport_rejects_source_identity_mismatch(tmp_path: Path) -> None:
    directory, manifest_json = _payload(tmp_path / "payload")

    with pytest.raises(PackageTransportError, match="SOURCE_ID_MISMATCH"):
        verify_payload(directory, manifest_json, "c" * 40, SOURCE_TREE)


def test_package_transport_manifest_file_is_canonical(tmp_path: Path) -> None:
    directory, manifest_json = _payload(tmp_path / "payload")

    assert (directory / MANIFEST_NAME).read_text(encoding="utf-8").strip() == json.dumps(
        json.loads(manifest_json), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
