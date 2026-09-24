from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import zipfile
import zlib
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath
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
        if path.is_symlink():
            raise PackageTransportError(f"SYMLINK_REJECTED:{path.name}")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise PackageTransportError(f"FILE_OPEN_FAILED:{path.name}") from exc
    try:
        info = os.fstat(descriptor)
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


def _safe_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and bool(path.parts) and all(
        part not in {"", ".", ".."} for part in path.parts
    )


def _metadata_identity(data: bytes, filename: str) -> None:
    if len(data) > MAX_METADATA_BYTES:
        raise PackageTransportError(f"PACKAGE_METADATA_LIMIT:{filename}")
    metadata = BytesParser(policy=default).parsebytes(data)
    name = re.sub(r"[-_.]+", "-", metadata.get("Name", "")).lower()
    version = metadata.get("Version", "")
    if name != PACKAGE_NAME or version != PACKAGE_VERSION:
        raise PackageTransportError(f"PACKAGE_METADATA_MISMATCH:{filename}")


def _inspect_wheel(data: bytes, filename: str) -> None:
    expected_metadata = f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if len(members) > MAX_ARCHIVE_MEMBERS or len(set(names)) != len(names):
                raise PackageTransportError(f"WHEEL_MEMBER_SET_INVALID:{filename}")
            if sum(member.file_size for member in members) > MAX_EXPANDED_BYTES:
                raise PackageTransportError(f"WHEEL_EXPANDED_SIZE_LIMIT:{filename}")
            if any(not _safe_archive_name(name.rstrip("/")) for name in names):
                raise PackageTransportError(f"WHEEL_PATH_INVALID:{filename}")
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
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise PackageTransportError(f"WHEEL_ARCHIVE_INVALID:{filename}") from exc
    _metadata_identity(metadata, filename)


def _inspect_sdist(data: bytes, filename: str) -> None:
    expected_root = f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    expected_metadata = f"{expected_root}/PKG-INFO"
    metadata: bytes | None = None
    tar_data = _decompress_sdist(data, filename)
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as archive:
            names: set[str] = set()
            member_count = 0
            expanded_size = 0
            while member := archive.next():
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise PackageTransportError(f"SDIST_MEMBER_SET_INVALID:{filename}")
                if member.name in names:
                    raise PackageTransportError(f"SDIST_MEMBER_SET_INVALID:{filename}")
                names.add(member.name)
                if not _safe_archive_name(member.name) or PurePosixPath(member.name).parts[0] != expected_root:
                    raise PackageTransportError(f"SDIST_PATH_INVALID:{filename}")
                if member.isdir():
                    continue
                if not member.isfile() or member.size < 0:
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
                with source:
                    while chunk := source.read(64 * 1024):
                        read_size += len(chunk)
                        if member.name == expected_metadata:
                            chunks.append(chunk)
                if read_size != member.size:
                    raise PackageTransportError(f"SDIST_MEMBER_TRUNCATED:{filename}")
                if member.name == expected_metadata:
                    metadata = b"".join(chunks)
    except (OSError, EOFError, tarfile.TarError, zlib.error) as exc:
        raise PackageTransportError(f"SDIST_ARCHIVE_INVALID:{filename}") from exc
    if metadata is None:
        raise PackageTransportError(f"SDIST_METADATA_MISSING:{filename}")
    _metadata_identity(metadata, filename)


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


def _inspect_distribution(data: bytes, filename: str) -> None:
    if filename.endswith(".whl"):
        _inspect_wheel(data, filename)
    elif filename.endswith(".tar.gz"):
        _inspect_sdist(data, filename)
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


def create_manifest(dist_dir: Path, source_sha: str, source_tree: str) -> dict[str, Any]:
    if not GIT_ID_RE.fullmatch(source_sha) or not GIT_ID_RE.fullmatch(source_tree):
        raise PackageTransportError("SOURCE_ID_INVALID")
    if not dist_dir.is_dir() or dist_dir.is_symlink():
        raise PackageTransportError("DISTRIBUTION_DIRECTORY_INVALID")
    expected_names = set(_expected_filenames())
    entries = list(dist_dir.iterdir())
    if {entry.name for entry in entries} != expected_names or len(entries) != 2:
        raise PackageTransportError("DISTRIBUTION_FILE_SET_INVALID")
    files: list[dict[str, Any]] = []
    for name in sorted(expected_names):
        data = _read_regular_file(dist_dir / name)
        _inspect_distribution(data, name)
        files.append({"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "source": {"sha": source_sha, "tree": source_tree},
        "package": {"name": PACKAGE_NAME, "version": PACKAGE_VERSION},
        "files": files,
    }
    manifest_path = dist_dir / MANIFEST_NAME
    if manifest_path.exists() or manifest_path.is_symlink():
        raise PackageTransportError("MANIFEST_ALREADY_EXISTS")
    temporary_path = dist_dir / f".{MANIFEST_NAME}.tmp"
    if temporary_path.exists() or temporary_path.is_symlink():
        raise PackageTransportError("MANIFEST_TEMPORARY_ALREADY_EXISTS")
    temporary_path.write_bytes(_canonical_json(manifest))
    temporary_path.replace(manifest_path)
    return manifest


def verify_payload(directory: Path, expected_manifest_json: str, source_sha: str, source_tree: str) -> dict[str, Any]:
    try:
        manifest = _validated_manifest(json.loads(expected_manifest_json))
    except (json.JSONDecodeError, TypeError) as exc:
        raise PackageTransportError("EXPECTED_MANIFEST_INVALID") from exc
    if manifest["source"] != {"sha": source_sha, "tree": source_tree}:
        raise PackageTransportError("SOURCE_ID_MISMATCH")
    if not directory.is_dir() or directory.is_symlink():
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
    create.add_argument("--source-sha", required=True)
    create.add_argument("--source-tree", required=True)
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
            manifest = create_manifest(args.dist_dir, args.source_sha, args.source_tree)
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
