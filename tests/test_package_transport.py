from __future__ import annotations

import io
import json
import stat
import struct
import subprocess
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts import package_transport
from scripts.package_transport import (
    MANIFEST_NAME,
    PACKAGE_NAME,
    PACKAGE_VERSION,
    PackageTransportError,
    _canonical_json,
    _inspect_sdist,
    _inspect_wheel,
    _safe_archive_name,
    create_manifest,
    verify_payload,
)

WHEEL_NAME = f"{PACKAGE_NAME}-{PACKAGE_VERSION}-py3-none-any.whl"
SDIST_NAME = f"{PACKAGE_NAME}-{PACKAGE_VERSION}.tar.gz"
METADATA = f"Metadata-Version: 2.4\nName: {PACKAGE_NAME}\nVersion: {PACKAGE_VERSION}\n\n"
WINDOWS_STYLE_UNSAFE_NAMES = (
    "..\\evil.py",
    "foo\\..\\evil.py",
    "C:\\evil.py",
    "C:/evil.py",
    "C:evil.py",
    "\\\\server\\share\\evil.py",
    "//server/share/evil.py",
    "../evil.py",
    "a/../../evil.py",
    "a//evil.py",
    "a/./evil.py",
    "a/../evil.py",
    "/absolute/path",
    "",
    "nul.txt",
    "trailing.",
    "trailing ",
    "file:stream",
    "nul\x00name",
)


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return result.stdout.strip()


def _repository_with_payload(root: Path) -> tuple[Path, Path, str, str]:
    root.mkdir(parents=True)
    source = root / "src" / PACKAGE_NAME / "__init__.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"__version__ = '0.2.0.dev1'\n")
    script = root / "scripts" / "package_transport.py"
    script.parent.mkdir(parents=True)
    script.write_bytes(b"transport_version = 'fixture'\n")
    (root / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n",
        encoding="utf-8",
    )
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "GreenGap package transport test")
    _git(root, "config", "user.email", "greengap-package-transport@example.invalid")
    _git(root, "add", "--", ".")
    _git(root, "commit", "-qm", "package transport fixture")
    source_sha = _git(root, "rev-parse", "--verify", "HEAD")
    source_tree = _git(root, "rev-parse", "--verify", "HEAD^{tree}")

    dist_dir = root / "dist"
    dist_dir.mkdir()
    _write_wheel(dist_dir / WHEEL_NAME)
    _write_sdist(dist_dir / SDIST_NAME)
    return root, dist_dir, source_sha, source_tree


def _payload(root: Path) -> tuple[Path, str, str, str, Path]:
    repo_root, dist_dir, source_sha, source_tree = _repository_with_payload(root)
    manifest = create_manifest(dist_dir, repo_root, source_sha, source_tree)
    manifest_json = _canonical_json(manifest).decode("utf-8").strip()
    return dist_dir, manifest_json, source_sha, source_tree, repo_root


def _write_zip_member(
    archive: zipfile.ZipFile,
    name: str,
    content: str | bytes,
    *,
    create_system: int = 3,
    unix_mode: int = stat.S_IFREG | 0o644,
    dos_attributes: int = 0,
) -> None:
    info = zipfile.ZipInfo(name)
    info.create_system = create_system
    info.external_attr = (unix_mode << 16) | dos_attributes
    info.compress_type = zipfile.ZIP_STORED
    archive.writestr(info, content)


def _write_wheel(
    path: Path,
    *,
    comment: bytes = b"A",
    extra_member: tuple[str, str | bytes, int, int, int] | None = None,
) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.comment = comment
        _write_zip_member(
            archive,
            f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA",
            METADATA,
        )
        _write_zip_member(
            archive,
            f"{PACKAGE_NAME}/__init__.py",
            "__version__ = '0.2.0.dev1'\n",
        )
        if extra_member is not None:
            name, content, create_system, unix_mode, dos_attributes = extra_member
            _write_zip_member(
                archive,
                name,
                content,
                create_system=create_system,
                unix_mode=unix_mode,
                dos_attributes=dos_attributes,
            )


def _write_deflated_wheel(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in (
            (f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA", METADATA),
            (f"{PACKAGE_NAME}/__init__.py", "__version__ = '0.2.0.dev1'\n"),
        ):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)


def _write_sdist(
    path: Path,
    *,
    extra_member: str | None = None,
    extra_type: bytes = tarfile.REGTYPE,
    extra_members: tuple[str, ...] = (),
) -> None:
    root = f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    with tarfile.open(path, "w:gz") as archive:
        data = METADATA.encode("utf-8")
        info = tarfile.TarInfo(f"{root}/PKG-INFO")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
        source = b"__version__ = '0.2.0.dev1'\n"
        info = tarfile.TarInfo(f"{root}/src/{PACKAGE_NAME}/__init__.py")
        info.size = len(source)
        archive.addfile(info, io.BytesIO(source))
        script = b"transport_version = 'fixture'\n"
        info = tarfile.TarInfo(f"{root}/scripts/package_transport.py")
        info.size = len(script)
        archive.addfile(info, io.BytesIO(script))
        member_names = ((extra_member,) if extra_member is not None else ()) + extra_members
        for member_name in member_names:
            info = tarfile.TarInfo(member_name)
            info.type = extra_type
            if extra_type in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                info.linkname = "target"
                archive.addfile(info)
            elif extra_type in {tarfile.REGTYPE, tarfile.AREGTYPE}:
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            else:
                archive.addfile(info)


def _simulate_reparse_point(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original_lstat = Path.lstat

    def lstat_with_reparse_attribute(candidate: Path) -> object:
        result = original_lstat(candidate)
        if candidate == path:
            return SimpleNamespace(
                st_mode=result.st_mode,
                st_file_attributes=0x400,
            )
        return result

    monkeypatch.setattr(Path, "lstat", lstat_with_reparse_attribute)


def test_package_transport_manifest_verifies_exact_wheel_and_sdist(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, _ = _payload(tmp_path / "payload")

    result = verify_payload(directory, manifest_json, source_sha, source_tree)

    assert result["source"] == {"sha": source_sha, "tree": source_tree}
    assert {entry["name"] for entry in result["files"]} == {WHEEL_NAME, SDIST_NAME}


def test_package_transport_rejects_missing_artifact_directory(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, _ = _payload(tmp_path / "payload")

    with pytest.raises(PackageTransportError, match="ARTIFACT_DIRECTORY_MISSING"):
        verify_payload(directory / "missing", manifest_json, source_sha, source_tree)


def test_package_transport_rejects_reparse_point_artifact_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, manifest_json, source_sha, source_tree, _ = _payload(tmp_path / "payload")
    _simulate_reparse_point(directory, monkeypatch)

    with pytest.raises(PackageTransportError, match="ARTIFACT_DIRECTORY_MISSING"):
        verify_payload(directory, manifest_json, source_sha, source_tree)


def test_package_transport_rejects_reparse_point_payload_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, _, _, _, _ = _payload(tmp_path / "payload")
    wheel_path = directory / WHEEL_NAME
    _simulate_reparse_point(wheel_path, monkeypatch)

    with pytest.raises(PackageTransportError, match="REPARSE_POINT_REJECTED"):
        package_transport._read_regular_file(wheel_path)


def test_package_transport_rejects_missing_file(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, _ = _payload(tmp_path / "payload")
    (directory / WHEEL_NAME).unlink()

    with pytest.raises(PackageTransportError, match="ARTIFACT_FILE_SET_MISMATCH"):
        verify_payload(directory, manifest_json, source_sha, source_tree)


def test_package_transport_rejects_unexpected_file(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, _ = _payload(tmp_path / "payload")
    (directory / "unexpected.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(PackageTransportError, match="ARTIFACT_FILE_SET_MISMATCH"):
        verify_payload(directory, manifest_json, source_sha, source_tree)


def test_package_transport_rejects_renamed_distribution(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, _ = _payload(tmp_path / "payload")
    (directory / WHEEL_NAME).rename(directory / "renamed.whl")

    with pytest.raises(PackageTransportError, match="ARTIFACT_FILE_SET_MISMATCH"):
        verify_payload(directory, manifest_json, source_sha, source_tree)


def test_package_transport_rejects_hash_mismatch(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, _ = _payload(tmp_path / "payload")
    _write_wheel(directory / WHEEL_NAME, comment=b"B")

    with pytest.raises(PackageTransportError, match=f"HASH_MISMATCH:{WHEEL_NAME}"):
        verify_payload(directory, manifest_json, source_sha, source_tree)


def test_package_transport_rejects_truncated_distribution(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, _ = _payload(tmp_path / "payload")
    wheel = directory / WHEEL_NAME
    wheel.write_bytes(wheel.read_bytes()[:-8])

    with pytest.raises(PackageTransportError, match=f"SIZE_MISMATCH:{WHEEL_NAME}"):
        verify_payload(directory, manifest_json, source_sha, source_tree)


def test_package_transport_rejects_source_identity_mismatch(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, _ = _payload(tmp_path / "payload")

    with pytest.raises(PackageTransportError, match="SOURCE_ID_MISMATCH"):
        verify_payload(directory, manifest_json, "c" * 40, source_tree)


def test_package_transport_manifest_file_is_canonical(tmp_path: Path) -> None:
    directory, manifest_json, _, _, _ = _payload(tmp_path / "payload")

    assert (directory / MANIFEST_NAME).read_text(encoding="utf-8").strip() == json.dumps(
        json.loads(manifest_json), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


@pytest.mark.parametrize("wrong_field", ("sha", "tree"))
def test_create_rejects_wrong_expected_git_identity_without_manifest(
    tmp_path: Path, wrong_field: str
) -> None:
    repo_root, dist_dir, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    if wrong_field == "sha":
        source_sha = "c" * 40
    else:
        source_tree = "d" * 40

    with pytest.raises(PackageTransportError, match="SOURCE_ID_MISMATCH"):
        create_manifest(dist_dir, repo_root, source_sha, source_tree)

    assert not (dist_dir / MANIFEST_NAME).exists()


def test_create_rejects_stale_package_bytes_for_current_source_commit(tmp_path: Path) -> None:
    repo_root, dist_dir, _, _ = _repository_with_payload(tmp_path / "repo")
    source = repo_root / "src" / PACKAGE_NAME / "__init__.py"
    source.write_text("__version__ = '0.2.0.dev1'\nstale_payload = True\n", encoding="utf-8")
    _git(repo_root, "add", "--", "src/greengap/__init__.py")
    _git(repo_root, "commit", "-qm", "new package source")
    source_sha = _git(repo_root, "rev-parse", "--verify", "HEAD")
    source_tree = _git(repo_root, "rev-parse", "--verify", "HEAD^{tree}")

    with pytest.raises(PackageTransportError, match="WHEEL_SOURCE_FILES_MISMATCH"):
        create_manifest(dist_dir, repo_root, source_sha, source_tree)

    assert not (dist_dir / MANIFEST_NAME).exists()


def test_create_rejects_stale_tracked_sdist_source_for_current_commit(tmp_path: Path) -> None:
    repo_root, dist_dir, _, _ = _repository_with_payload(tmp_path / "repo")
    source = repo_root / "scripts" / "package_transport.py"
    source.write_bytes(b"transport_version = 'updated'\n")
    _git(repo_root, "add", "--", "scripts/package_transport.py")
    _git(repo_root, "commit", "-qm", "new transport source")
    source_sha = _git(repo_root, "rev-parse", "--verify", "HEAD")
    source_tree = _git(repo_root, "rev-parse", "--verify", "HEAD^{tree}")

    with pytest.raises(PackageTransportError, match="SDIST_SOURCE_FILES_MISMATCH"):
        create_manifest(dist_dir, repo_root, source_sha, source_tree)

    assert not (dist_dir / MANIFEST_NAME).exists()


def test_create_rejects_modified_tracked_source_and_removes_stale_manifest(
    tmp_path: Path,
) -> None:
    repo_root, dist_dir, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    manifest_path = dist_dir / MANIFEST_NAME
    manifest_path.write_text("stale manifest", encoding="utf-8")
    (repo_root / "src" / PACKAGE_NAME / "__init__.py").write_text(
        "__version__ = 'changed'\n", encoding="utf-8"
    )

    with pytest.raises(PackageTransportError, match="SOURCE_WORKTREE_MODIFIED"):
        create_manifest(dist_dir, repo_root, source_sha, source_tree)

    assert not manifest_path.exists()


def test_create_rejects_staged_tracked_source(tmp_path: Path) -> None:
    repo_root, dist_dir, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    source = repo_root / "src" / PACKAGE_NAME / "__init__.py"
    source.write_text("__version__ = 'staged'\n", encoding="utf-8")
    _git(repo_root, "add", "--", "src/greengap/__init__.py")

    with pytest.raises(PackageTransportError, match="SOURCE_WORKTREE_MODIFIED"):
        create_manifest(dist_dir, repo_root, source_sha, source_tree)

    assert not (dist_dir / MANIFEST_NAME).exists()


def test_create_rejects_deleted_tracked_source(tmp_path: Path) -> None:
    repo_root, dist_dir, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    (repo_root / "src" / PACKAGE_NAME / "__init__.py").unlink()

    with pytest.raises(PackageTransportError, match="SOURCE_WORKTREE_MODIFIED"):
        create_manifest(dist_dir, repo_root, source_sha, source_tree)

    assert not (dist_dir / MANIFEST_NAME).exists()


@pytest.mark.parametrize("index_flag", ("--assume-unchanged", "--skip-worktree"))
def test_create_rejects_git_index_flags_that_hide_source_changes(
    tmp_path: Path, index_flag: str
) -> None:
    repo_root, dist_dir, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    source_relative = "src/greengap/__init__.py"
    _git(repo_root, "update-index", index_flag, "--", source_relative)
    (repo_root / source_relative).write_text("__version__ = 'hidden'\n", encoding="utf-8")

    with pytest.raises(PackageTransportError, match="SOURCE_INDEX_FLAGS_INVALID"):
        create_manifest(dist_dir, repo_root, source_sha, source_tree)

    assert not (dist_dir / MANIFEST_NAME).exists()


def test_create_rejects_relevant_untracked_source(tmp_path: Path) -> None:
    repo_root, dist_dir, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    (repo_root / "src" / PACKAGE_NAME / "extra.py").write_text("unsafe = True\n", encoding="utf-8")

    with pytest.raises(PackageTransportError, match="SOURCE_WORKTREE_NOT_EQUIVALENT"):
        create_manifest(dist_dir, repo_root, source_sha, source_tree)

    assert not (dist_dir / MANIFEST_NAME).exists()


def test_create_allows_only_known_generated_package_build_outputs(tmp_path: Path) -> None:
    repo_root, dist_dir, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    generated = {
        repo_root / "build" / "lib" / PACKAGE_NAME / "generated.py": "generated = True\n",
        repo_root / "src" / f"{PACKAGE_NAME}.egg-info" / "PKG-INFO": "generated metadata\n",
    }
    for path, content in generated.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    manifest = create_manifest(dist_dir, repo_root, source_sha, source_tree)

    assert manifest["source"] == {"sha": source_sha, "tree": source_tree}
    assert (dist_dir / MANIFEST_NAME).is_file()


def test_create_rejects_mutation_between_source_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root, dist_dir, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    original_inspect = package_transport._inspect_distribution
    changed = False

    def mutate_after_payload_read(
        data: bytes,
        filename: str,
        expected_source_files: dict[str, tuple[int, str]] | None = None,
        *,
        source_repo_root: Path | None = None,
        tracked_paths: set[str] | None = None,
    ) -> None:
        nonlocal changed
        original_inspect(
            data,
            filename,
            expected_source_files,
            source_repo_root=source_repo_root,
            tracked_paths=tracked_paths,
        )
        if not changed and filename == SDIST_NAME:
            source = repo_root / "src" / PACKAGE_NAME / "__init__.py"
            source.write_text("__version__ = 'mutated during inspection'\n", encoding="utf-8")
            changed = True

    monkeypatch.setattr(package_transport, "_inspect_distribution", mutate_after_payload_read)

    with pytest.raises(PackageTransportError, match="SOURCE_WORKTREE_MODIFIED"):
        create_manifest(dist_dir, repo_root, source_sha, source_tree)

    assert changed
    assert not (dist_dir / MANIFEST_NAME).exists()


@pytest.mark.parametrize("name", WINDOWS_STYLE_UNSAFE_NAMES)
def test_archive_name_validator_rejects_cross_platform_aliases(name: str) -> None:
    assert not _safe_archive_name(name)


@pytest.mark.parametrize(
    "name",
    tuple(
        name
        for name in WINDOWS_STYLE_UNSAFE_NAMES
        if name and "\x00" not in name
    ),
)
def test_wheel_inspector_rejects_unsafe_member_paths(tmp_path: Path, name: str) -> None:
    wheel_path = tmp_path / "unsafe.whl"
    _write_wheel(wheel_path, extra_member=(name, b"payload", 3, stat.S_IFREG | 0o644, 0))

    with pytest.raises(PackageTransportError, match="WHEEL_PATH_INVALID"):
        _inspect_wheel(wheel_path.read_bytes(), WHEEL_NAME)


@pytest.mark.parametrize(
    "name",
    tuple(
        name
        for name in WINDOWS_STYLE_UNSAFE_NAMES
        if name and "\x00" not in name
    ),
)
def test_sdist_inspector_rejects_unsafe_member_paths(tmp_path: Path, name: str) -> None:
    archive_path = tmp_path / "unsafe.tar.gz"
    _write_sdist(archive_path, extra_member=name)

    with pytest.raises(PackageTransportError, match="SDIST_PATH_INVALID"):
        _inspect_sdist(archive_path.read_bytes(), SDIST_NAME)


@pytest.mark.parametrize(
    ("create_system", "unix_mode", "dos_attributes"),
    (
        (3, stat.S_IFLNK | 0o777, 0),
        (3, stat.S_IFIFO | 0o600, 0),
        (3, stat.S_IFSOCK | 0o600, 0),
        (3, stat.S_IFCHR | 0o600, 0),
        (3, stat.S_IFBLK | 0o600, 0),
        (3, 0o644, 0),
        (0, stat.S_IFREG | 0o644, 0),
        (3, stat.S_IFREG | 0o644, 0x10),
    ),
)
def test_wheel_inspector_rejects_nonregular_or_ambiguous_members(
    tmp_path: Path, create_system: int, unix_mode: int, dos_attributes: int
) -> None:
    wheel_path = tmp_path / "special.whl"
    _write_wheel(
        wheel_path,
        extra_member=(
            f"{PACKAGE_NAME}/special-member",
            b"member data",
            create_system,
            unix_mode,
            dos_attributes,
        ),
    )

    with pytest.raises(PackageTransportError, match="WHEEL_MEMBER_TYPE_INVALID"):
        _inspect_wheel(wheel_path.read_bytes(), WHEEL_NAME)


@pytest.mark.parametrize(
    "member_type",
    (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE),
    ids=("symlink", "hardlink", "fifo", "character-device", "block-device"),
)
def test_sdist_inspector_rejects_nonregular_members(
    tmp_path: Path, member_type: bytes
) -> None:
    archive_path = tmp_path / "special.tar.gz"
    _write_sdist(
        archive_path,
        extra_member=f"{PACKAGE_NAME}-{PACKAGE_VERSION}/special-member",
        extra_type=member_type,
    )

    with pytest.raises(PackageTransportError, match="SDIST_MEMBER_TYPE_INVALID"):
        _inspect_sdist(archive_path.read_bytes(), SDIST_NAME)


def test_sdist_inspector_rejects_casefold_member_collisions(tmp_path: Path) -> None:
    archive_path = tmp_path / "casefold-collision.tar.gz"
    _write_sdist(
        archive_path,
        extra_member=f"{PACKAGE_NAME}-{PACKAGE_VERSION}/src/{PACKAGE_NAME}/__INIT__.PY",
    )

    with pytest.raises(PackageTransportError, match="SDIST_MEMBER_SET_INVALID"):
        _inspect_sdist(archive_path.read_bytes(), SDIST_NAME)


def test_wheel_inspector_wraps_malformed_deflate_data(tmp_path: Path) -> None:
    wheel_path = tmp_path / "malformed-deflate.whl"
    _write_deflated_wheel(wheel_path)
    payload = bytearray(wheel_path.read_bytes())
    metadata_name = f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA"
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        member = archive.getinfo(metadata_name)
    header_offset = member.header_offset
    header = struct.unpack_from("<IHHHHHIIIHH", payload, header_offset)
    data_offset = header_offset + 30 + header[9] + header[10]
    payload[data_offset] = 0x07  # Reserved DEFLATE block type.

    with pytest.raises(PackageTransportError, match="WHEEL_ARCHIVE_INVALID"):
        _inspect_wheel(bytes(payload), WHEEL_NAME)


def test_package_transport_rejects_wheel_directory_members(tmp_path: Path) -> None:
    wheel_path = tmp_path / "directory.whl"
    _write_wheel(
        wheel_path,
        extra_member=(
            f"{PACKAGE_NAME}/nested/",
            b"",
            3,
            stat.S_IFDIR | 0o755,
            0x10,
        ),
    )

    with pytest.raises(PackageTransportError, match="WHEEL_PATH_INVALID"):
        _inspect_wheel(wheel_path.read_bytes(), WHEEL_NAME)


def test_sdist_inspector_accepts_expected_directory_entries(tmp_path: Path) -> None:
    archive_path = tmp_path / "directory.tar.gz"
    root = f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    with tarfile.open(archive_path, "w:gz") as archive:
        directory = tarfile.TarInfo(f"{root}/src/")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        data = METADATA.encode("utf-8")
        metadata = tarfile.TarInfo(f"{root}/PKG-INFO")
        metadata.size = len(data)
        archive.addfile(metadata, io.BytesIO(data))

    _inspect_sdist(archive_path.read_bytes(), SDIST_NAME)
