from __future__ import annotations

import gzip
import hashlib
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
    (source.parent / "cli.py").write_bytes(b"def main() -> int:\n    return 0\n")
    script = root / "scripts" / "package_transport.py"
    script.parent.mkdir(parents=True)
    script.write_bytes(b"transport_version = 'fixture'\n")
    (root / "LICENSE").write_bytes(b"fixture license bytes\n")
    (root / "README.md").write_bytes(b"# GreenGap fixture\n")
    (root / "setup.py").write_bytes(b"from setuptools import setup\nsetup()\n")
    (root / "MANIFEST.in").write_text(
        "include LICENSE README.md pyproject.toml setup.py\n"
        "recursive-include src/greengap *.py py.typed\n"
        "recursive-include scripts *.py\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        "[build-system]\n"
        "requires = ['setuptools==84.0.0']\n"
        "build-backend = 'setuptools.build_meta'\n\n"
        "[project]\n"
        "name = 'greengap'\n"
        "dynamic = ['version']\n"
        "description = 'Find what your green CI never ran.'\n"
        "readme = 'README.md'\n"
        "license = 'Apache-2.0'\n"
        "license-files = ['LICENSE']\n"
        "authors = [{ name = 'GreenGap package transport test' }]\n"
        "keywords = ['test']\n"
        "requires-python = '>=3.11'\n"
        "dependencies = ['PyYAML>=6.0']\n\n"
        "[project.optional-dependencies]\n"
        "dev = ['pytest>=9.0.3']\n\n"
        "[project.scripts]\n"
        "greengap = 'greengap.cli:main'\n\n"
        "[tool.setuptools.dynamic]\n"
        "version = { attr = 'greengap.__version__' }\n",
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
    source_map = package_transport._source_map_from_git_objects(
        root, source_sha, source_tree
    )
    _write_wheel(dist_dir / WHEEL_NAME, source_map=source_map)
    _write_sdist(dist_dir / SDIST_NAME, source_map=source_map)
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
    source_map: package_transport._PackageSourceMap,
    comment: bytes = b"",
    extra_member: tuple[str, str | bytes, int, int, int] | None = None,
    extra_members: tuple[tuple[str, str | bytes, int, int, int], ...] = (),
    source_overrides: dict[str, bytes] | None = None,
    generated_overrides: dict[str, bytes] | None = None,
) -> None:
    members = package_transport._expected_wheel_members(source_map)
    if source_overrides:
        for source_path, content in source_overrides.items():
            if not source_path.startswith(f"src/{PACKAGE_NAME}/"):
                continue
            wheel_path = f"{PACKAGE_NAME}/{source_path[len(f'src/{PACKAGE_NAME}/') :]}"
            members[wheel_path] = content
    metadata_path = f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA"
    record_path = f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/RECORD"
    members[metadata_path] = _metadata_bytes(source_map)
    if generated_overrides:
        members.update(generated_overrides)
    members.pop(record_path)
    extras = list(extra_members)
    if extra_member is not None:
        extras.append(extra_member)
    record_members = dict(members)
    for name, content, _, _, _ in extras:
        if isinstance(content, str):
            content = content.encode("utf-8")
        record_members.setdefault(name, content)
    members[record_path] = package_transport._wheel_record(record_members, record_path)
    if generated_overrides and record_path in generated_overrides:
        members[record_path] = generated_overrides[record_path]
    records = list(members.items())
    records.extend(
        (name, content.encode("utf-8") if isinstance(content, str) else content)
        for name, content, _, _, _ in extras
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.comment = comment
        for name, content in records:
            create_system, unix_mode, dos_attributes = 3, stat.S_IFREG | 0o644, 0
            for extra_name, _, extra_system, extra_mode, extra_dos in extras:
                if extra_name == name:
                    create_system, unix_mode, dos_attributes = (
                        extra_system,
                        extra_mode,
                        extra_dos,
                    )
                    break
            _write_zip_member(
                archive,
                name,
                content,
                create_system=create_system,
                unix_mode=unix_mode,
                dos_attributes=dos_attributes,
            )


def _write_deflated_wheel(
    path: Path, *, source_map: package_transport._PackageSourceMap
) -> None:
    members = package_transport._expected_wheel_members(source_map)
    metadata_path = f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA"
    record_path = f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/RECORD"
    members[metadata_path] = _metadata_bytes(source_map)
    members.pop(record_path)
    members[record_path] = package_transport._wheel_record(members, record_path)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)


def _write_sdist(
    path: Path,
    *,
    source_map: package_transport._PackageSourceMap,
    extra_member: str | None = None,
    extra_type: bytes = tarfile.REGTYPE,
    extra_members: tuple[str, ...] = (),
    source_overrides: dict[str, bytes] | None = None,
    generated_overrides: dict[str, bytes] | None = None,
) -> None:
    root = f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    source_files = dict(source_map.sdist_files)
    if source_overrides:
        source_files.update(source_overrides)
    generated = package_transport._sdist_generated_files(source_map)
    if generated_overrides:
        generated.update(generated_overrides)
    metadata = _metadata_bytes(source_map)
    files = {**source_files, **generated, "PKG-INFO": metadata}
    files[f"src/{PACKAGE_NAME}.egg-info/PKG-INFO"] = metadata
    directory_paths = package_transport._sdist_expected_directories(set(files))
    extras = ((extra_member,) if extra_member is not None else ()) + extra_members
    with tarfile.open(path, "w:gz") as archive:
        root_info = tarfile.TarInfo(root)
        root_info.type = tarfile.DIRTYPE
        archive.addfile(root_info)
        for directory in sorted(directory_paths - {""}):
            info = tarfile.TarInfo(f"{root}/{directory}/")
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        for relative_path, content in sorted(files.items()):
            info = tarfile.TarInfo(f"{root}/{relative_path}")
            info.type = tarfile.REGTYPE
            info.mode = 0o644
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        for member_name in extras:
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


def _metadata_bytes(source_map: package_transport._PackageSourceMap) -> bytes:
    headers = "".join(f"{name}: {value}\n" for name, value in source_map.metadata_headers)
    return f"{headers}\n".encode() + source_map.readme


def _manifest_with_updated_file(
    manifest_json: str, artifact_path: Path, artifact_name: str
) -> str:
    manifest = json.loads(manifest_json)
    content = artifact_path.read_bytes()
    for entry in manifest["files"]:
        if entry["name"] == artifact_name:
            entry["size"] = len(content)
            entry["sha256"] = hashlib.sha256(content).hexdigest()
            break
    else:
        raise AssertionError(f"artifact missing from manifest: {artifact_name}")
    return _canonical_json(manifest).decode("utf-8").strip()


def _regular_wheel_extra(name: str, content: bytes) -> tuple[str, bytes, int, int, int]:
    return name, content, 3, stat.S_IFREG | 0o644, 0


@pytest.fixture(scope="session")
def repository_source_map() -> package_transport._PackageSourceMap:
    root = Path(__file__).resolve().parents[1]
    source_sha = _git(root, "rev-parse", "--verify", "HEAD")
    source_tree = _git(root, "rev-parse", "--verify", "HEAD^{tree}")
    return package_transport._source_map_from_git_objects(root, source_sha, source_tree)


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
    directory, manifest_json, source_sha, source_tree, repo_root = _payload(tmp_path / "payload")

    result = verify_payload(directory, manifest_json, source_sha, source_tree, repo_root)

    assert result["source"] == {"sha": source_sha, "tree": source_tree}
    assert {entry["name"] for entry in result["files"]} == {WHEEL_NAME, SDIST_NAME}


def test_package_transport_rejects_missing_artifact_directory(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, repo_root = _payload(tmp_path / "payload")

    with pytest.raises(PackageTransportError, match="ARTIFACT_DIRECTORY_MISSING"):
        verify_payload(directory / "missing", manifest_json, source_sha, source_tree, repo_root)


def test_package_transport_rejects_reparse_point_artifact_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, manifest_json, source_sha, source_tree, repo_root = _payload(tmp_path / "payload")
    _simulate_reparse_point(directory, monkeypatch)

    with pytest.raises(PackageTransportError, match="SOURCE_GENERATED_PATH_REPARSE_POINT"):
        verify_payload(directory, manifest_json, source_sha, source_tree, repo_root)


def test_package_transport_rejects_reparse_point_payload_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, _, _, _, _ = _payload(tmp_path / "payload")
    wheel_path = directory / WHEEL_NAME
    _simulate_reparse_point(wheel_path, monkeypatch)

    with pytest.raises(PackageTransportError, match="REPARSE_POINT_REJECTED"):
        package_transport._read_regular_file(wheel_path)


def test_package_transport_rejects_missing_file(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, repo_root = _payload(tmp_path / "payload")
    (directory / WHEEL_NAME).unlink()

    with pytest.raises(PackageTransportError, match="ARTIFACT_FILE_SET_MISMATCH"):
        verify_payload(directory, manifest_json, source_sha, source_tree, repo_root)


def test_package_transport_rejects_unexpected_file(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, repo_root = _payload(tmp_path / "payload")
    (directory / "unexpected.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(PackageTransportError, match="ARTIFACT_FILE_SET_MISMATCH"):
        verify_payload(directory, manifest_json, source_sha, source_tree, repo_root)


def test_package_transport_rejects_renamed_distribution(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, repo_root = _payload(tmp_path / "payload")
    (directory / WHEEL_NAME).rename(directory / "renamed.whl")

    with pytest.raises(PackageTransportError, match="ARTIFACT_FILE_SET_MISMATCH"):
        verify_payload(directory, manifest_json, source_sha, source_tree, repo_root)


def test_package_transport_rejects_hash_mismatch(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, repo_root = _payload(tmp_path / "payload")
    source_map = package_transport._source_map_from_git_objects(repo_root, source_sha, source_tree)
    _write_wheel(directory / WHEEL_NAME, source_map=source_map, comment=b"B")

    with pytest.raises(PackageTransportError, match=f"HASH_MISMATCH:{WHEEL_NAME}"):
        verify_payload(directory, manifest_json, source_sha, source_tree, repo_root)


def test_package_transport_rejects_truncated_distribution(tmp_path: Path) -> None:
    directory, manifest_json, source_sha, source_tree, repo_root = _payload(tmp_path / "payload")
    wheel = directory / WHEEL_NAME
    wheel.write_bytes(wheel.read_bytes()[:-8])

    with pytest.raises(PackageTransportError, match=f"SIZE_MISMATCH:{WHEEL_NAME}"):
        verify_payload(directory, manifest_json, source_sha, source_tree, repo_root)


@pytest.mark.parametrize("wrong_field", ("sha", "tree"))
def test_package_transport_rejects_source_identity_mismatch(
    tmp_path: Path, wrong_field: str
) -> None:
    directory, manifest_json, source_sha, source_tree, repo_root = _payload(tmp_path / "payload")
    if wrong_field == "sha":
        source_sha = "c" * 40
    else:
        source_tree = "d" * 40

    with pytest.raises(PackageTransportError, match="SOURCE_ID_MISMATCH"):
        verify_payload(directory, manifest_json, source_sha, source_tree, repo_root)


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
        source_map: package_transport._PackageSourceMap,
    ) -> None:
        nonlocal changed
        original_inspect(data, filename, source_map)
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
def test_wheel_inspector_rejects_unsafe_member_paths(
    tmp_path: Path, name: str, repository_source_map: package_transport._PackageSourceMap
) -> None:
    wheel_path = tmp_path / "unsafe.whl"
    _write_wheel(
        wheel_path,
        source_map=repository_source_map,
        extra_member=(name, b"payload", 3, stat.S_IFREG | 0o644, 0),
    )

    with pytest.raises(PackageTransportError, match="WHEEL_PATH_INVALID"):
        _inspect_wheel(wheel_path.read_bytes(), WHEEL_NAME, repository_source_map)


@pytest.mark.parametrize(
    "name",
    tuple(
        name
        for name in WINDOWS_STYLE_UNSAFE_NAMES
        if name and "\x00" not in name
    ),
)
def test_sdist_inspector_rejects_unsafe_member_paths(
    tmp_path: Path, name: str, repository_source_map: package_transport._PackageSourceMap
) -> None:
    archive_path = tmp_path / "unsafe.tar.gz"
    _write_sdist(archive_path, source_map=repository_source_map, extra_member=name)

    with pytest.raises(PackageTransportError, match="SDIST_PATH_INVALID"):
        _inspect_sdist(archive_path.read_bytes(), SDIST_NAME, repository_source_map)


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
    tmp_path: Path,
    create_system: int,
    unix_mode: int,
    dos_attributes: int,
    repository_source_map: package_transport._PackageSourceMap,
) -> None:
    wheel_path = tmp_path / "special.whl"
    _write_wheel(
        wheel_path,
        source_map=repository_source_map,
        extra_member=(
            f"{PACKAGE_NAME}/special-member",
            b"member data",
            create_system,
            unix_mode,
            dos_attributes,
        ),
    )

    with pytest.raises(PackageTransportError, match="WHEEL_MEMBER_TYPE_INVALID"):
        _inspect_wheel(wheel_path.read_bytes(), WHEEL_NAME, repository_source_map)


@pytest.mark.parametrize(
    "member_type",
    (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE),
    ids=("symlink", "hardlink", "fifo", "character-device", "block-device"),
)
def test_sdist_inspector_rejects_nonregular_members(
    tmp_path: Path,
    member_type: bytes,
    repository_source_map: package_transport._PackageSourceMap,
) -> None:
    archive_path = tmp_path / "special.tar.gz"
    _write_sdist(
        archive_path,
        source_map=repository_source_map,
        extra_member=f"{PACKAGE_NAME}-{PACKAGE_VERSION}/special-member",
        extra_type=member_type,
    )

    with pytest.raises(PackageTransportError, match="SDIST_MEMBER_TYPE_INVALID"):
        _inspect_sdist(archive_path.read_bytes(), SDIST_NAME, repository_source_map)


def test_sdist_inspector_rejects_casefold_member_collisions(
    tmp_path: Path, repository_source_map: package_transport._PackageSourceMap
) -> None:
    archive_path = tmp_path / "casefold-collision.tar.gz"
    _write_sdist(
        archive_path,
        source_map=repository_source_map,
        extra_member=f"{PACKAGE_NAME}-{PACKAGE_VERSION}/src/{PACKAGE_NAME}/__INIT__.PY",
    )

    with pytest.raises(PackageTransportError, match="SDIST_MEMBER_SET_INVALID"):
        _inspect_sdist(archive_path.read_bytes(), SDIST_NAME, repository_source_map)


def test_wheel_inspector_wraps_malformed_deflate_data(
    tmp_path: Path, repository_source_map: package_transport._PackageSourceMap
) -> None:
    wheel_path = tmp_path / "malformed-deflate.whl"
    _write_deflated_wheel(wheel_path, source_map=repository_source_map)
    payload = bytearray(wheel_path.read_bytes())
    metadata_name = f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA"
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        member = archive.getinfo(metadata_name)
    header_offset = member.header_offset
    header = struct.unpack_from("<IHHHHHIIIHH", payload, header_offset)
    data_offset = header_offset + 30 + header[9] + header[10]
    payload[data_offset] = 0x07  # Reserved DEFLATE block type.

    with pytest.raises(PackageTransportError, match="WHEEL_ARCHIVE_INVALID"):
        _inspect_wheel(bytes(payload), WHEEL_NAME, repository_source_map)


def test_package_transport_rejects_wheel_directory_members(
    tmp_path: Path, repository_source_map: package_transport._PackageSourceMap
) -> None:
    wheel_path = tmp_path / "directory.whl"
    _write_wheel(
        wheel_path,
        source_map=repository_source_map,
        extra_member=(
            f"{PACKAGE_NAME}/nested/",
            b"",
            3,
            stat.S_IFDIR | 0o755,
            0x10,
        ),
    )

    with pytest.raises(PackageTransportError, match="WHEEL_PATH_INVALID"):
        _inspect_wheel(wheel_path.read_bytes(), WHEEL_NAME, repository_source_map)


def test_sdist_inspector_accepts_expected_directory_entries(
    tmp_path: Path, repository_source_map: package_transport._PackageSourceMap
) -> None:
    archive_path = tmp_path / "directory.tar.gz"
    _write_sdist(archive_path, source_map=repository_source_map)
    _inspect_sdist(archive_path.read_bytes(), SDIST_NAME, repository_source_map)


def test_sdist_sources_manifest_is_order_independent_but_exact(
    tmp_path: Path, repository_source_map: package_transport._PackageSourceMap
) -> None:
    sources_path = f"src/{PACKAGE_NAME}.egg-info/SOURCES.txt"
    expected_entries = package_transport._sdist_sources_manifest_entries(
        repository_source_map
    )
    actual_order = sorted(expected_entries, reverse=True)
    reordered_manifest = "\n".join(actual_order).encode("utf-8")
    archive_path = tmp_path / "setuptools-order.tar.gz"
    _write_sdist(
        archive_path,
        source_map=repository_source_map,
        generated_overrides={sources_path: reordered_manifest},
    )

    _inspect_sdist(archive_path.read_bytes(), SDIST_NAME, repository_source_map)

    invalid_archive = tmp_path / "unexpected-source.tar.gz"
    _write_sdist(
        invalid_archive,
        source_map=repository_source_map,
        generated_overrides={sources_path: reordered_manifest + b"\nhidden.py"},
    )
    with pytest.raises(PackageTransportError, match="SDIST_SOURCES_MANIFEST_INVALID"):
        _inspect_sdist(invalid_archive.read_bytes(), SDIST_NAME, repository_source_map)


def test_sdist_inspector_rejects_unbound_trailing_archive_data(
    tmp_path: Path, repository_source_map: package_transport._PackageSourceMap
) -> None:
    archive_path = tmp_path / "valid.tar.gz"
    _write_sdist(archive_path, source_map=repository_source_map)
    valid_payload = archive_path.read_bytes()
    hidden_tar = io.BytesIO()
    hidden_content = b"unbound payload"
    with tarfile.open(fileobj=hidden_tar, mode="w") as archive:
        hidden_member = tarfile.TarInfo(
            f"{PACKAGE_NAME}-{PACKAGE_VERSION}/hidden.py"
        )
        hidden_member.size = len(hidden_content)
        archive.addfile(hidden_member, io.BytesIO(hidden_content))
    appended_tar = hidden_tar.getvalue()
    malicious_payloads = (
        valid_payload + gzip.compress(appended_tar, mtime=0),
        gzip.compress(gzip.decompress(valid_payload) + appended_tar, mtime=0),
    )

    for malicious_payload in malicious_payloads:
        with pytest.raises(PackageTransportError, match="SDIST_TRAILING_DATA"):
            _inspect_sdist(malicious_payload, SDIST_NAME, repository_source_map)


def test_wheel_inspector_rejects_unbound_trailing_archive_data(
    tmp_path: Path, repository_source_map: package_transport._PackageSourceMap
) -> None:
    wheel_path = tmp_path / WHEEL_NAME
    _write_wheel(wheel_path, source_map=repository_source_map)
    payload = wheel_path.read_bytes()

    with pytest.raises(PackageTransportError, match="WHEEL_TRAILING_DATA"):
        _inspect_wheel(payload + b"unbound payload", WHEEL_NAME, repository_source_map)

    commented_wheel = tmp_path / "commented.whl"
    _write_wheel(commented_wheel, source_map=repository_source_map, comment=b"hidden")
    with pytest.raises(PackageTransportError, match="WHEEL_TRAILING_DATA"):
        _inspect_wheel(
            commented_wheel.read_bytes(), WHEEL_NAME, repository_source_map
        )


def test_unknown_wheel_members_fail_producer_and_consumer_checks(tmp_path: Path) -> None:
    directory, baseline_manifest, source_sha, source_tree, repo_root = _payload(
        tmp_path / "payload"
    )
    source_map = package_transport._source_map_from_git_objects(
        repo_root, source_sha, source_tree
    )
    root = f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    cases = (
        ("startup-pth", (_regular_wheel_extra("greengap_startup.pth", b"import os\n"),)),
        ("other-pth", (_regular_wheel_extra("evil.pth", b"import os\n"),)),
        ("top-level-module", (_regular_wheel_extra("backdoor.py", b"payload = True\n"),)),
        (
            "other-package",
            (_regular_wheel_extra("another_package/__init__.py", b"payload = True\n"),),
        ),
        (
            "unknown-dist-info",
            (_regular_wheel_extra(f"{root}.dist-info/unknown", b"payload\n"),),
        ),
        (
            "unexpected-data",
            (_regular_wheel_extra(f"{root}.data/purelib/extra.py", b"payload\n"),),
        ),
        (
            "casefold-alias",
            (_regular_wheel_extra("GREENGAP/cli.py", b"payload = True\n"),),
        ),
        (
            "duplicate-logical-member",
            (_regular_wheel_extra("greengap/cli.py", b"payload = True\n"),),
        ),
    )

    for case_name, extras in cases:
        if case_name == "duplicate-logical-member":
            with pytest.warns(UserWarning, match="Duplicate name"):
                _write_wheel(
                    directory / WHEEL_NAME,
                    source_map=source_map,
                    extra_members=extras,
                )
        else:
            _write_wheel(
                directory / WHEEL_NAME,
                source_map=source_map,
                extra_members=extras,
            )

        with pytest.raises(PackageTransportError, match="WHEEL_MEMBER_SET_INVALID"):
            create_manifest(directory, repo_root, source_sha, source_tree)

        malicious_manifest = _manifest_with_updated_file(
            baseline_manifest, directory / WHEEL_NAME, WHEEL_NAME
        )
        (directory / MANIFEST_NAME).write_bytes(
            _canonical_json(json.loads(malicious_manifest))
        )
        with pytest.raises(PackageTransportError, match="WHEEL_MEMBER_SET_INVALID"):
            verify_payload(
                directory,
                malicious_manifest,
                source_sha,
                source_tree,
                repo_root,
            )


def test_unknown_sdist_members_fail_producer_and_consumer_checks(tmp_path: Path) -> None:
    directory, baseline_manifest, source_sha, source_tree, repo_root = _payload(
        tmp_path / "payload"
    )
    source_map = package_transport._source_map_from_git_objects(
        repo_root, source_sha, source_tree
    )
    root = f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    for extra in (f"{root}/extra.py", f"{root}/evil.pth", f"{root}/custom_setup.py"):
        _write_sdist(
            directory / SDIST_NAME,
            source_map=source_map,
            extra_member=extra,
        )

        with pytest.raises(PackageTransportError, match="SDIST_MEMBER_SET_INVALID"):
            create_manifest(directory, repo_root, source_sha, source_tree)

        malicious_manifest = _manifest_with_updated_file(
            baseline_manifest, directory / SDIST_NAME, SDIST_NAME
        )
        (directory / MANIFEST_NAME).write_bytes(
            _canonical_json(json.loads(malicious_manifest))
        )
        with pytest.raises(PackageTransportError, match="SDIST_MEMBER_SET_INVALID"):
            verify_payload(
                directory,
                malicious_manifest,
                source_sha,
                source_tree,
                repo_root,
            )


@pytest.mark.parametrize(
    ("member_name", "replacement", "error"),
    (
        (
            f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/WHEEL",
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n\n",
            "WHEEL_GENERATED_METADATA_INVALID",
        ),
        (
            f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/entry_points.txt",
            b"[console_scripts]\ngreengap = evil:main\n",
            "WHEEL_GENERATED_METADATA_INVALID",
        ),
        (
            f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/top_level.txt",
            b"another_package\n",
            "WHEEL_GENERATED_METADATA_INVALID",
        ),
        (
            f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/licenses/LICENSE",
            b"altered license\n",
            "WHEEL_GENERATED_METADATA_INVALID",
        ),
        (
            f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA",
            METADATA.replace("Metadata-Version: 2.4", "Metadata-Version: 2.5").encode(),
            "PACKAGE_METADATA_MISMATCH",
        ),
        (
            f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/RECORD",
            b"unknown.py,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1\n",
            "WHEEL_RECORD_INVALID",
        ),
    ),
)
def test_wheel_generated_members_have_exact_semantics(
    tmp_path: Path,
    member_name: str,
    replacement: bytes,
    error: str,
    repository_source_map: package_transport._PackageSourceMap,
) -> None:
    wheel_path = tmp_path / "generated-override.whl"
    _write_wheel(
        wheel_path,
        source_map=repository_source_map,
        generated_overrides={member_name: replacement},
    )

    with pytest.raises(PackageTransportError, match=error):
        _inspect_wheel(wheel_path.read_bytes(), WHEEL_NAME, repository_source_map)


def test_git_source_map_uses_committed_blob_when_worktree_changes(tmp_path: Path) -> None:
    repo_root, _, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    source_path = repo_root / "src" / PACKAGE_NAME / "__init__.py"
    committed_bytes = source_path.read_bytes()
    raced_bytes = b"__version__ = '0.2.0.dev1'\nmutable_race = True\n"
    source_path.write_bytes(raced_bytes)

    source_map = package_transport._source_map_from_git_objects(
        repo_root, source_sha, source_tree
    )

    assert source_path.read_bytes() == raced_bytes
    assert source_map.package_files[f"src/{PACKAGE_NAME}/__init__.py"] == committed_bytes


def test_wheel_source_blob_mismatch_fails_producer_and_consumer(tmp_path: Path) -> None:
    directory, baseline_manifest, source_sha, source_tree, repo_root = _payload(
        tmp_path / "payload"
    )
    source_map = package_transport._source_map_from_git_objects(
        repo_root, source_sha, source_tree
    )
    source_path = f"src/{PACKAGE_NAME}/__init__.py"
    stale_bytes = source_map.package_files[source_path] + b"mutable_race = True\n"
    _write_wheel(
        directory / WHEEL_NAME,
        source_map=source_map,
        source_overrides={source_path: stale_bytes},
    )

    with pytest.raises(PackageTransportError, match="WHEEL_SOURCE_FILES_MISMATCH"):
        create_manifest(directory, repo_root, source_sha, source_tree)

    malicious_manifest = _manifest_with_updated_file(
        baseline_manifest, directory / WHEEL_NAME, WHEEL_NAME
    )
    (directory / MANIFEST_NAME).write_bytes(_canonical_json(json.loads(malicious_manifest)))
    with pytest.raises(PackageTransportError, match="WHEEL_SOURCE_FILES_MISMATCH"):
        verify_payload(directory, malicious_manifest, source_sha, source_tree, repo_root)


def test_git_tree_enumeration_rejects_oversized_git_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root, _, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    monkeypatch.setattr(package_transport, "_GIT_TREE_OUTPUT_MAX_BYTES", 64)

    with pytest.raises(PackageTransportError, match="SOURCE_GIT_OUTPUT_LIMIT"):
        package_transport._git_tree_entries(repo_root, source_sha, source_tree)


def test_reverted_concurrent_source_mutation_cannot_change_provenance_map(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root, dist_dir, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    source_map = package_transport._source_map_from_git_objects(
        repo_root, source_sha, source_tree
    )
    source_path = repo_root / "src" / PACKAGE_NAME / "__init__.py"
    committed_bytes = source_path.read_bytes()
    raced_bytes = b"__version__ = '0.2.0.dev1'\nraced = True\n"
    _write_wheel(
        dist_dir / WHEEL_NAME,
        source_map=source_map,
        source_overrides={f"src/{PACKAGE_NAME}/__init__.py": raced_bytes},
    )
    original_inspector = package_transport._inspect_distribution

    def inspect_during_race(
        data: bytes,
        filename: str,
        observed_source_map: package_transport._PackageSourceMap,
    ) -> None:
        if filename != WHEEL_NAME:
            original_inspector(data, filename, observed_source_map)
            return
        source_path.write_bytes(raced_bytes)
        try:
            original_inspector(data, filename, observed_source_map)
        finally:
            source_path.write_bytes(committed_bytes)

    monkeypatch.setattr(package_transport, "_inspect_distribution", inspect_during_race)

    with pytest.raises(PackageTransportError, match="WHEEL_SOURCE_FILES_MISMATCH"):
        create_manifest(dist_dir, repo_root, source_sha, source_tree)

    assert source_path.read_bytes() == committed_bytes
    assert not (dist_dir / MANIFEST_NAME).exists()


def test_git_source_map_ignores_replacement_refs(tmp_path: Path) -> None:
    repo_root, _, source_sha, source_tree = _repository_with_payload(tmp_path / "repo")
    original_bytes = (repo_root / "src" / PACKAGE_NAME / "__init__.py").read_bytes()
    source_path = repo_root / "src" / PACKAGE_NAME / "__init__.py"
    source_path.write_bytes(b"__version__ = '0.2.0.dev1'\nreplacement = True\n")
    _git(repo_root, "add", "--", f"src/{PACKAGE_NAME}/__init__.py")
    _git(repo_root, "commit", "-qm", "replacement commit")
    replacement_sha = _git(repo_root, "rev-parse", "--verify", "HEAD")
    _git(repo_root, "replace", source_sha, replacement_sha)

    source_map = package_transport._source_map_from_git_objects(
        repo_root, source_sha, source_tree
    )

    assert source_map.package_files[f"src/{PACKAGE_NAME}/__init__.py"] == original_bytes
