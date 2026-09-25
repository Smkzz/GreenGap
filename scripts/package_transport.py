from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import zipfile
import zlib
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from typing import Any

PACKAGE_NAME = "greengap"
PACKAGE_VERSION = "0.2.0.dev1"
MANIFEST_NAME = "payload-manifest.json"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_METADATA_BYTES = 1024 * 1024
MAX_TAR_STREAM_BYTES = MAX_EXPANDED_BYTES + MAX_ARCHIVE_MEMBERS * 1024 + 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_ID_RE = re.compile(r"^[0-9a-f]{40}$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_WINDOWS_DEVICE_RE = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.IGNORECASE)
_GENERATED_PATH_ROOTS = ("build", "dist", f"src/{PACKAGE_NAME}.egg-info")
_REPARSE_POINT_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_GIT_TIMEOUT_SECONDS = 30


class PackageTransportError(ValueError):
    """A package payload cannot be bound to its manifest."""


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _expected_filenames() -> tuple[str, str]:
    return (
        f"{PACKAGE_NAME}-{PACKAGE_VERSION}-py3-none-any.whl",
        f"{PACKAGE_NAME}-{PACKAGE_VERSION}.tar.gz",
    )


def _read_regular_file(path: Path) -> bytes:
    try:
        if _is_reparse_point(path):
            raise PackageTransportError(f"REPARSE_POINT_REJECTED:{path.name}")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise PackageTransportError(f"FILE_OPEN_FAILED:{path.name}") from exc
    try:
        info = os.fstat(descriptor)
        if getattr(info, "st_file_attributes", 0) & _REPARSE_POINT_FLAG:
            raise PackageTransportError(f"REPARSE_POINT_REJECTED:{path.name}")
        if not stat.S_ISREG(info.st_mode):
            raise PackageTransportError(f"NON_REGULAR_FILE:{path.name}")
        if info.st_size < 0 or info.st_size > MAX_ARCHIVE_BYTES:
            raise PackageTransportError(f"ARCHIVE_SIZE_LIMIT:{path.name}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_ARCHIVE_BYTES + 1)
        if len(data) != info.st_size or len(data) > MAX_ARCHIVE_BYTES:
            raise PackageTransportError(f"FILE_SIZE_CHANGED:{path.name}")
        return data
    finally:
        os.close(descriptor)


def _safe_archive_name(name: str, *, allow_trailing_slash: bool = False) -> bool:
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
        or _WINDOWS_DRIVE_RE.match(name) is not None
    ):
        return False
    if allow_trailing_slash and name.endswith("/"):
        name = name[:-1]
    parts = name.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return False
    for part in parts:
        if (
            any(ord(character) < 32 or ord(character) == 127 for character in part)
            or any(character in '<>:\"|?*' for character in part)
            or part.endswith((" ", "."))
            or _WINDOWS_DEVICE_RE.fullmatch(part) is not None
        ):
            return False
    return True


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CEILING_DIRECTORIES",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_NOSYSTEM",
        } or name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            environment.pop(name, None)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return environment


def _run_git(repo_root: Path, *arguments: str) -> bytes:
    command = [
        "git",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-C",
        str(repo_root),
        *arguments,
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            env=_git_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PackageTransportError("SOURCE_GIT_CHECK_FAILED") from exc
    if result.returncode != 0:
        raise PackageTransportError("SOURCE_GIT_CHECK_FAILED")
    return result.stdout


def _is_reparse_point(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PackageTransportError("SOURCE_PATH_INSPECTION_FAILED") from exc
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT_FLAG
    )


def _generated_path_root(relative_path: str) -> str | None:
    if not relative_path or "\\" in relative_path or relative_path.startswith("/"):
        return None
    normalized = relative_path.rstrip("/")
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    for root in _GENERATED_PATH_ROOTS:
        if normalized == root or normalized.startswith(f"{root}/"):
            if any(part.casefold() in {".git", ".hg", ".svn"} for part in parts):
                return None
            return root
    return None


def _validate_generated_path(repo_root: Path, relative_path: str) -> None:
    if _generated_path_root(relative_path) is None:
        raise PackageTransportError("SOURCE_WORKTREE_NOT_EQUIVALENT")
    parts = relative_path.rstrip("/").split("/")
    current = repo_root
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise PackageTransportError("SOURCE_STATE_CHANGED_DURING_CHECK") from exc
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT_FLAG:
            raise PackageTransportError("SOURCE_GENERATED_PATH_REPARSE_POINT")
        is_directory = stat.S_ISDIR(info.st_mode)
        is_regular_file = stat.S_ISREG(info.st_mode)
        if index < len(parts) - 1 and not is_directory:
            raise PackageTransportError("SOURCE_GENERATED_PATH_INVALID")
        if index == len(parts) - 1 and not (is_directory or is_regular_file):
            raise PackageTransportError("SOURCE_GENERATED_PATH_INVALID")


def _repository_observation(
    repo_root: Path, expected_source_sha: str, expected_source_tree: str
) -> tuple[str, str, tuple[bytes, ...]]:
    if _is_reparse_point(repo_root) or not repo_root.is_dir():
        raise PackageTransportError("SOURCE_REPOSITORY_INVALID")
    try:
        resolved_root = repo_root.resolve(strict=True)
    except OSError as exc:
        raise PackageTransportError("SOURCE_REPOSITORY_INVALID") from exc
    top_level_bytes = _run_git(repo_root, "rev-parse", "--show-toplevel").rstrip(b"\r\n")
    try:
        top_level = Path(os.fsdecode(top_level_bytes)).resolve(strict=True)
    except OSError as exc:
        raise PackageTransportError("SOURCE_REPOSITORY_INVALID") from exc
    if os.path.normcase(os.path.abspath(top_level)) != os.path.normcase(os.path.abspath(resolved_root)):
        raise PackageTransportError("SOURCE_REPOSITORY_INVALID")

    source_sha = _run_git(repo_root, "rev-parse", "--verify", "HEAD").decode("ascii", "strict").strip()
    source_tree = (
        _run_git(repo_root, "rev-parse", "--verify", "HEAD^{tree}")
        .decode("ascii", "strict")
        .strip()
    )
    if (
        not GIT_ID_RE.fullmatch(source_sha)
        or not GIT_ID_RE.fullmatch(source_tree)
        or source_sha != expected_source_sha
        or source_tree != expected_source_tree
    ):
        raise PackageTransportError("SOURCE_ID_MISMATCH")

    index_entries = _run_git(repo_root, "ls-files", "-v", "-z")
    for record in index_entries.split(b"\x00"):
        if not record:
            continue
        if len(record) < 3 or record[1:2] != b" " or record[:1] != b"H":
            raise PackageTransportError("SOURCE_INDEX_FLAGS_INVALID")

    status = _run_git(
        repo_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
        "--ignore-submodules=none",
    )
    allowed_generated_entries: list[bytes] = []
    for record in status.split(b"\x00"):
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            raise PackageTransportError("SOURCE_GIT_STATUS_INVALID")
        state = record[:2]
        if state not in {b"??", b"!!"}:
            raise PackageTransportError("SOURCE_WORKTREE_MODIFIED")
        relative_path = os.fsdecode(record[3:])
        _validate_generated_path(repo_root, relative_path)
        allowed_generated_entries.append(record)
    return source_sha, source_tree, tuple(sorted(allowed_generated_entries))


def _tracked_repository_paths(repo_root: Path) -> set[str]:
    return {
        os.fsdecode(record)
        for record in _run_git(repo_root, "ls-files", "-z").split(b"\x00")
        if record
    }


def _tracked_package_sources(
    repo_root: Path, tracked_paths: set[str]
) -> dict[str, tuple[int, str]]:
    prefix = f"src/{PACKAGE_NAME}/"
    package_paths = {path for path in tracked_paths if path.startswith(prefix)}
    if not package_paths or any(
        not _safe_archive_name(path) for path in package_paths
    ):
        raise PackageTransportError("SOURCE_PACKAGE_FILES_INVALID")

    sources: dict[str, tuple[int, str]] = {}
    total_size = 0
    for relative_path in sorted(package_paths):
        data = _read_regular_file(repo_root.joinpath(*relative_path.split("/")))
        total_size += len(data)
        if total_size > MAX_EXPANDED_BYTES:
            raise PackageTransportError("SOURCE_PACKAGE_SIZE_LIMIT")
        sources[relative_path] = (len(data), hashlib.sha256(data).hexdigest())
    return sources


def _remove_stale_manifest(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PackageTransportError("MANIFEST_OUTPUT_INSPECTION_FAILED") from exc
    if stat.S_ISLNK(info.st_mode):
        try:
            path.unlink()
        except OSError as exc:
            raise PackageTransportError("MANIFEST_OUTPUT_CLEANUP_FAILED") from exc
        return
    if getattr(info, "st_file_attributes", 0) & _REPARSE_POINT_FLAG:
        raise PackageTransportError("MANIFEST_OUTPUT_REPARSE_POINT")
    if not stat.S_ISREG(info.st_mode):
        raise PackageTransportError("MANIFEST_OUTPUT_INVALID")
    try:
        path.unlink()
    except OSError as exc:
        raise PackageTransportError("MANIFEST_OUTPUT_CLEANUP_FAILED") from exc


def _metadata_identity(data: bytes, filename: str) -> None:
    if len(data) > MAX_METADATA_BYTES:
        raise PackageTransportError(f"PACKAGE_METADATA_LIMIT:{filename}")
    metadata = BytesParser(policy=default).parsebytes(data)
    name = re.sub(r"[-_.]+", "-", metadata.get("Name", "")).lower()
    version = metadata.get("Version", "")
    if name != PACKAGE_NAME or version != PACKAGE_VERSION:
        raise PackageTransportError(f"PACKAGE_METADATA_MISMATCH:{filename}")


def _inspect_wheel(
    data: bytes,
    filename: str,
    expected_source_files: dict[str, tuple[int, str]] | None = None,
) -> None:
    expected_metadata = f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA"
    found_source_files: set[str] = set()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if (
                len(members) > MAX_ARCHIVE_MEMBERS
                or len(set(names)) != len(names)
                or len({name.casefold() for name in names}) != len(names)
            ):
                raise PackageTransportError(f"WHEEL_MEMBER_SET_INVALID:{filename}")
            if sum(member.file_size for member in members) > MAX_EXPANDED_BYTES:
                raise PackageTransportError(f"WHEEL_EXPANDED_SIZE_LIMIT:{filename}")
            for member in members:
                if not _safe_archive_name(member.filename):
                    raise PackageTransportError(f"WHEEL_PATH_INVALID:{filename}")
                if (
                    member.is_dir()
                    or member.create_system != 3
                    or member.external_attr >> 16 != (stat.S_IFREG | 0o644)
                    or member.external_attr & 0xFFFF
                    or member.flag_bits & 0x1
                ):
                    raise PackageTransportError(f"WHEEL_MEMBER_TYPE_INVALID:{filename}")
                if expected_source_files is not None and member.filename.startswith(
                    f"{PACKAGE_NAME}/"
                ):
                    source_path = f"src/{member.filename}"
                    expected = expected_source_files.get(source_path)
                    if expected is None:
                        raise PackageTransportError(f"WHEEL_SOURCE_FILES_MISMATCH:{filename}")
                    content = archive.read(member)
                    if (len(content), hashlib.sha256(content).hexdigest()) != expected:
                        raise PackageTransportError(f"WHEEL_SOURCE_FILES_MISMATCH:{filename}")
                    found_source_files.add(source_path)
            metadata_members = [
                member for member in members if member.filename.endswith(".dist-info/METADATA")
            ]
            if len(metadata_members) != 1 or metadata_members[0].filename != expected_metadata:
                raise PackageTransportError(f"WHEEL_METADATA_MISSING:{filename}")
            if metadata_members[0].file_size > MAX_METADATA_BYTES:
                raise PackageTransportError(f"PACKAGE_METADATA_LIMIT:{filename}")
            metadata = archive.read(metadata_members[0])
            if archive.testzip() is not None:
                raise PackageTransportError(f"WHEEL_CRC_INVALID:{filename}")
    except (OSError, zipfile.BadZipFile, RuntimeError, zlib.error) as exc:
        raise PackageTransportError(f"WHEEL_ARCHIVE_INVALID:{filename}") from exc
    if expected_source_files is not None and found_source_files != set(expected_source_files):
        raise PackageTransportError(f"WHEEL_SOURCE_FILES_MISMATCH:{filename}")
    _metadata_identity(metadata, filename)


def _inspect_sdist(
    data: bytes,
    filename: str,
    expected_source_files: dict[str, tuple[int, str]] | None = None,
    source_repo_root: Path | None = None,
    tracked_paths: set[str] | None = None,
) -> None:
    expected_root = f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    expected_metadata = f"{expected_root}/PKG-INFO"
    metadata: bytes | None = None
    tar_data = _decompress_sdist(data, filename)
    tracked_paths_by_casefold: dict[str, str] | None = None
    if tracked_paths is not None:
        tracked_paths_by_casefold = {path.casefold(): path for path in tracked_paths}
        if len(tracked_paths_by_casefold) != len(tracked_paths):
            raise PackageTransportError(f"SDIST_SOURCE_FILES_INVALID:{filename}")
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as archive:
            names: set[str] = set()
            folded_names: set[str] = set()
            found_source_files: set[str] = set()
            member_count = 0
            expanded_size = 0
            while member := archive.next():
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise PackageTransportError(f"SDIST_MEMBER_SET_INVALID:{filename}")
                normalized_name = member.name.rstrip("/")
                if normalized_name in names or normalized_name.casefold() in folded_names:
                    raise PackageTransportError(f"SDIST_MEMBER_SET_INVALID:{filename}")
                names.add(normalized_name)
                folded_names.add(normalized_name.casefold())
                is_directory = member.type == tarfile.DIRTYPE
                if not _safe_archive_name(member.name, allow_trailing_slash=is_directory):
                    raise PackageTransportError(f"SDIST_PATH_INVALID:{filename}")
                if member.name.rstrip("/").split("/", 1)[0] != expected_root:
                    raise PackageTransportError(f"SDIST_PATH_INVALID:{filename}")
                if is_directory:
                    if member.size != 0 or member.linkname:
                        raise PackageTransportError(f"SDIST_MEMBER_TYPE_INVALID:{filename}")
                    relative_name = member.name[len(expected_root) :].lstrip("/")
                    if relative_name and tracked_paths is not None:
                        if tracked_paths_by_casefold is None:
                            raise PackageTransportError(f"SDIST_SOURCE_FILES_INVALID:{filename}")
                        if not (
                            any(
                                path.casefold().startswith(f"{relative_name.casefold()}/")
                                for path in tracked_paths
                            )
                            or _is_generated_sdist_path(relative_name, is_directory=True)
                        ):
                            raise PackageTransportError(f"SDIST_SOURCE_FILES_MISMATCH:{filename}")
                    continue
                if (
                    member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}
                    or not member.isfile()
                    or member.size < 0
                    or member.sparse is not None
                ):
                    raise PackageTransportError(f"SDIST_MEMBER_TYPE_INVALID:{filename}")
                if member.name == expected_metadata and member.size > MAX_METADATA_BYTES:
                    raise PackageTransportError(f"PACKAGE_METADATA_LIMIT:{filename}")
                expanded_size += member.size
                if expanded_size > MAX_EXPANDED_BYTES:
                    raise PackageTransportError(f"SDIST_EXPANDED_SIZE_LIMIT:{filename}")
                source = archive.extractfile(member)
                if source is None:
                    raise PackageTransportError(f"SDIST_MEMBER_UNREADABLE:{filename}")
                read_size = 0
                chunks: list[bytes] = []
                relative_name = member.name[len(expected_root) + 1 :]
                tracked_path = (
                    tracked_paths_by_casefold.get(relative_name.casefold())
                    if tracked_paths_by_casefold is not None
                    else None
                )
                if tracked_path is not None and tracked_path != relative_name:
                    raise PackageTransportError(f"SDIST_SOURCE_FILES_MISMATCH:{filename}")
                if (
                    tracked_paths_by_casefold is not None
                    and tracked_path is None
                    and not _is_generated_sdist_path(relative_name)
                ):
                    raise PackageTransportError(f"SDIST_SOURCE_FILES_MISMATCH:{filename}")
                if tracked_path is not None and source_repo_root is None:
                    raise PackageTransportError(f"SDIST_SOURCE_FILES_INVALID:{filename}")
                source_path = (
                    relative_name
                    if expected_source_files is not None and relative_name.startswith("src/greengap/")
                    else None
                )
                source_digest = hashlib.sha256() if source_path is not None else None
                tracked_digest = hashlib.sha256() if tracked_path is not None else None
                if source_path is not None and (
                    expected_source_files is None or source_path not in expected_source_files
                ):
                    raise PackageTransportError(f"SDIST_SOURCE_FILES_MISMATCH:{filename}")
                with source:
                    while chunk := source.read(64 * 1024):
                        read_size += len(chunk)
                        if member.name == expected_metadata:
                            chunks.append(chunk)
                        if source_digest is not None:
                            source_digest.update(chunk)
                        if tracked_digest is not None:
                            tracked_digest.update(chunk)
                if read_size != member.size:
                    raise PackageTransportError(f"SDIST_MEMBER_TRUNCATED:{filename}")
                if tracked_path is not None:
                    if source_repo_root is None or tracked_digest is None:
                        raise PackageTransportError(f"SDIST_SOURCE_FILES_INVALID:{filename}")
                    source_data = _read_regular_file(
                        source_repo_root.joinpath(*tracked_path.split("/"))
                    )
                    if (read_size, tracked_digest.hexdigest()) != (
                        len(source_data),
                        hashlib.sha256(source_data).hexdigest(),
                    ):
                        raise PackageTransportError(f"SDIST_SOURCE_FILES_MISMATCH:{filename}")
                if source_path is not None:
                    if expected_source_files is None or source_digest is None:
                        raise PackageTransportError(f"SDIST_SOURCE_FILES_INVALID:{filename}")
                    expected = expected_source_files[source_path]
                    if (read_size, source_digest.hexdigest()) != expected:
                        raise PackageTransportError(f"SDIST_SOURCE_FILES_MISMATCH:{filename}")
                    found_source_files.add(source_path)
                if member.name == expected_metadata:
                    metadata = b"".join(chunks)
    except (OSError, EOFError, tarfile.TarError, zlib.error) as exc:
        raise PackageTransportError(f"SDIST_ARCHIVE_INVALID:{filename}") from exc
    if metadata is None:
        raise PackageTransportError(f"SDIST_METADATA_MISSING:{filename}")
    if expected_source_files is not None and found_source_files != set(expected_source_files):
        raise PackageTransportError(f"SDIST_SOURCE_FILES_MISMATCH:{filename}")
    _metadata_identity(metadata, filename)


def _is_generated_sdist_path(relative_path: str, *, is_directory: bool = False) -> bool:
    egg_info_root = f"src/{PACKAGE_NAME}.egg-info"
    if is_directory:
        return relative_path == egg_info_root or relative_path.startswith(f"{egg_info_root}/")
    return relative_path in {"PKG-INFO", "setup.cfg"} or relative_path.startswith(
        f"{egg_info_root}/"
    )


def _decompress_sdist(data: bytes, filename: str) -> bytes:
    chunks: list[bytes] = []
    expanded_size = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as archive:
            while chunk := archive.read(64 * 1024):
                expanded_size += len(chunk)
                if expanded_size > MAX_TAR_STREAM_BYTES:
                    raise PackageTransportError(f"SDIST_EXPANDED_SIZE_LIMIT:{filename}")
                chunks.append(chunk)
    except PackageTransportError:
        raise
    except (OSError, EOFError, zlib.error) as exc:
        raise PackageTransportError(f"SDIST_ARCHIVE_INVALID:{filename}") from exc
    return b"".join(chunks)


def _inspect_distribution(
    data: bytes,
    filename: str,
    expected_source_files: dict[str, tuple[int, str]] | None = None,
    *,
    source_repo_root: Path | None = None,
    tracked_paths: set[str] | None = None,
) -> None:
    if filename.endswith(".whl"):
        _inspect_wheel(data, filename, expected_source_files)
    elif filename.endswith(".tar.gz"):
        _inspect_sdist(
            data,
            filename,
            expected_source_files,
            source_repo_root,
            tracked_paths,
        )
    else:
        raise PackageTransportError(f"DISTRIBUTION_FILENAME_INVALID:{filename}")


def _validated_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "source", "package", "files"}:
        raise PackageTransportError("MANIFEST_SCHEMA_INVALID")
    if value["schema_version"] != 1:
        raise PackageTransportError("MANIFEST_VERSION_INVALID")
    source = value["source"]
    package = value["package"]
    files = value["files"]
    if not isinstance(source, dict) or set(source) != {"sha", "tree"}:
        raise PackageTransportError("MANIFEST_SOURCE_INVALID")
    if not all(isinstance(source[key], str) and GIT_ID_RE.fullmatch(source[key]) for key in ("sha", "tree")):
        raise PackageTransportError("MANIFEST_SOURCE_INVALID")
    if package != {"name": PACKAGE_NAME, "version": PACKAGE_VERSION}:
        raise PackageTransportError("MANIFEST_PACKAGE_INVALID")
    if not isinstance(files, list) or len(files) != 2:
        raise PackageTransportError("MANIFEST_FILE_SET_INVALID")
    expected_names = set(_expected_filenames())
    actual_names: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"name", "size", "sha256"}:
            raise PackageTransportError("MANIFEST_FILE_ENTRY_INVALID")
        name, size, digest = entry["name"], entry["size"], entry["sha256"]
        if not isinstance(name, str) or name not in expected_names or name in actual_names:
            raise PackageTransportError("MANIFEST_FILENAME_INVALID")
        if not isinstance(size, int) or isinstance(size, bool) or size < 1 or size > MAX_ARCHIVE_BYTES:
            raise PackageTransportError(f"MANIFEST_SIZE_INVALID:{name}")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise PackageTransportError(f"MANIFEST_HASH_INVALID:{name}")
        actual_names.add(name)
    if actual_names != expected_names:
        raise PackageTransportError("MANIFEST_FILE_SET_INVALID")
    return value


def _resolve_create_directories(dist_dir: Path, repo_root: Path) -> tuple[Path, Path]:
    if _is_reparse_point(repo_root) or not repo_root.is_dir():
        raise PackageTransportError("SOURCE_REPOSITORY_INVALID")
    try:
        resolved_root = repo_root.resolve(strict=True)
    except OSError as exc:
        raise PackageTransportError("SOURCE_REPOSITORY_INVALID") from exc
    requested_dist = dist_dir if dist_dir.is_absolute() else resolved_root / dist_dir
    expected_dist = resolved_root / "dist"
    if os.path.normcase(os.path.abspath(requested_dist)) != os.path.normcase(
        os.path.abspath(expected_dist)
    ):
        raise PackageTransportError("DISTRIBUTION_DIRECTORY_INVALID")
    if _is_reparse_point(expected_dist) or not expected_dist.is_dir():
        raise PackageTransportError("DISTRIBUTION_DIRECTORY_INVALID")
    return expected_dist, resolved_root


def create_manifest(
    dist_dir: Path,
    repo_root: Path,
    expected_source_sha: str,
    expected_source_tree: str,
) -> dict[str, Any]:
    dist_dir, repo_root = _resolve_create_directories(dist_dir, repo_root)
    if not dist_dir.is_dir():
        raise PackageTransportError("DISTRIBUTION_DIRECTORY_INVALID")
    manifest_path = dist_dir / MANIFEST_NAME
    temporary_path = dist_dir / f".{MANIFEST_NAME}.tmp"
    _remove_stale_manifest(manifest_path)
    _remove_stale_manifest(temporary_path)
    if not GIT_ID_RE.fullmatch(expected_source_sha) or not GIT_ID_RE.fullmatch(
        expected_source_tree
    ):
        raise PackageTransportError("SOURCE_ID_INVALID")
    first_observation = _repository_observation(
        repo_root, expected_source_sha, expected_source_tree
    )
    tracked_paths = _tracked_repository_paths(repo_root)
    expected_source_files = _tracked_package_sources(repo_root, tracked_paths)
    expected_names = set(_expected_filenames())
    entries = list(dist_dir.iterdir())
    if {entry.name for entry in entries} != expected_names or len(entries) != 2:
        raise PackageTransportError("DISTRIBUTION_FILE_SET_INVALID")
    files: list[dict[str, Any]] = []
    for name in sorted(expected_names):
        data = _read_regular_file(dist_dir / name)
        _inspect_distribution(
            data,
            name,
            expected_source_files,
            source_repo_root=repo_root,
            tracked_paths=tracked_paths,
        )
        files.append({"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    second_observation = _repository_observation(
        repo_root, expected_source_sha, expected_source_tree
    )
    if first_observation != second_observation:
        raise PackageTransportError("SOURCE_CHANGED_DURING_PACKAGE_INSPECTION")
    source_sha, source_tree, _ = second_observation
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "source": {"sha": source_sha, "tree": source_tree},
        "package": {"name": PACKAGE_NAME, "version": PACKAGE_VERSION},
        "files": files,
    }
    try:
        with temporary_path.open("xb") as stream:
            stream.write(_canonical_json(manifest))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, manifest_path)
    except OSError as exc:
        raise PackageTransportError("MANIFEST_WRITE_FAILED") from exc
    finally:
        if temporary_path.is_symlink() or temporary_path.is_file():
            temporary_path.unlink()
    return manifest


def verify_payload(directory: Path, expected_manifest_json: str, source_sha: str, source_tree: str) -> dict[str, Any]:
    try:
        manifest = _validated_manifest(json.loads(expected_manifest_json))
    except (json.JSONDecodeError, TypeError) as exc:
        raise PackageTransportError("EXPECTED_MANIFEST_INVALID") from exc
    if manifest["source"] != {"sha": source_sha, "tree": source_tree}:
        raise PackageTransportError("SOURCE_ID_MISMATCH")
    try:
        directory_is_reparse_point = _is_reparse_point(directory)
    except PackageTransportError as exc:
        raise PackageTransportError("ARTIFACT_DIRECTORY_MISSING") from exc
    if directory_is_reparse_point or not directory.is_dir():
        raise PackageTransportError("ARTIFACT_DIRECTORY_MISSING")
    expected_names = {MANIFEST_NAME, *(entry["name"] for entry in manifest["files"])}
    entries = list(directory.iterdir())
    if len(entries) != len(expected_names) or {entry.name for entry in entries} != expected_names:
        raise PackageTransportError("ARTIFACT_FILE_SET_MISMATCH")
    manifest_bytes = _read_regular_file(directory / MANIFEST_NAME)
    if manifest_bytes != _canonical_json(manifest):
        raise PackageTransportError("DOWNLOADED_MANIFEST_MISMATCH")
    for entry in manifest["files"]:
        name = entry["name"]
        data = _read_regular_file(directory / name)
        if len(data) != entry["size"]:
            raise PackageTransportError(f"SIZE_MISMATCH:{name}")
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise PackageTransportError(f"HASH_MISMATCH:{name}")
        _inspect_distribution(data, name)
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create or verify a GreenGap package transport manifest.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--dist-dir", type=Path, required=True)
    create.add_argument("--repo-root", type=Path, required=True)
    create.add_argument("--expected-source-sha", required=True)
    create.add_argument("--expected-source-tree", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--artifact-dir", type=Path, required=True)
    verify.add_argument("--expected-manifest-json", required=True)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--source-tree", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "create":
            manifest = create_manifest(
                args.dist_dir,
                args.repo_root,
                args.expected_source_sha,
                args.expected_source_tree,
            )
        else:
            manifest = verify_payload(
                args.artifact_dir,
                args.expected_manifest_json,
                args.source_sha,
                args.source_tree,
            )
    except (OSError, PackageTransportError) as exc:
        print(f"PACKAGE_TRANSPORT_INVALID:{exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
