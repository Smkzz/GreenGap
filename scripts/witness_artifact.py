"""Stage and verify the exact Runtime Witness evidence uploaded by CI.

This helper is used by the Linux Runtime Witness job. It copies witness
fragments through no-follow file descriptors, records the analyzer input
bytes, and verifies the downloaded artifact against both the upload digest
and the analysis result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_ROOT = _REPO_ROOT / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from greengap.util import (  # noqa: E402
    MAX_RUNTIME_AGGREGATE_BYTES,
    MAX_RUNTIME_WITNESS_BYTES,
    MAX_RUNTIME_WITNESS_FRAGMENTS,
)

_FRAGMENT_PREFIX = "greengap-"
_FRAGMENT_SUFFIX = ".json"
_MAX_DIRECTORY_ENTRIES = MAX_RUNTIME_WITNESS_FRAGMENTS * 2
_MAX_ARTIFACT_BYTES = MAX_RUNTIME_AGGREGATE_BYTES + 6 * MAX_RUNTIME_WITNESS_BYTES
_MAX_ARCHIVE_BYTES = _MAX_ARTIFACT_BYTES + (MAX_RUNTIME_WITNESS_FRAGMENTS + 16) * 2048
_FRAGMENT_NAME_RE = re.compile(r"^greengap-[^/\\\x00-\x1f\x7f]{1,480}\.json$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_STAGE_RECEIPT = "stage.json"
_COMMAND_STATUS = "commands.json"
_INPUT_INVENTORY = "inputs.json"
_INTEGRITY_RECEIPT = "integrity.json"


class ArtifactIntegrityError(ValueError):
    """The staged or uploaded evidence cannot be verified completely."""


@dataclass(frozen=True)
class FileDigest:
    path: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


def _fail(code: str) -> None:
    raise ArtifactIntegrityError(code)


def _is_reparse_point(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def _file_signature(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
    )


def _read_at(directory_fd: int, name: str, limit: int) -> bytes:
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise ArtifactIntegrityError("STAGE_SOURCE_STAT_FAILED") from exc
    if not stat.S_ISREG(before.st_mode) or _is_reparse_point(before):
        _fail("STAGE_SOURCE_NOT_REGULAR")
    if before.st_size > limit:
        _fail("STAGE_FILE_SIZE_LIMIT_EXCEEDED")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise ArtifactIntegrityError("STAGE_SOURCE_OPEN_FAILED") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _file_signature(before) != _file_signature(opened):
            _fail("STAGE_SOURCE_CHANGED")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                _fail("STAGE_FILE_SIZE_LIMIT_EXCEEDED")
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            _file_signature(opened) != _file_signature(after)
            or _file_signature(before) != _file_signature(current)
            or total != before.st_size
        ):
            _fail("STAGE_SOURCE_CHANGED")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _open_directory(path: Path, *, parent_fd: int | None = None) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(path), flags) if parent_fd is None else os.open(
            path.name, flags, dir_fd=parent_fd
        )
    except OSError as exc:
        raise ArtifactIntegrityError("STAGE_DIRECTORY_OPEN_FAILED") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode) or _is_reparse_point(opened):
            _fail("STAGE_DIRECTORY_NOT_REGULAR")
        if parent_fd is None:
            current = path.lstat()
        else:
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if _file_signature(opened) != _file_signature(current):
            _fail("STAGE_DIRECTORY_CHANGED")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_new_at(directory_fd: int, name: str, data: bytes) -> None:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except OSError as exc:
        raise ArtifactIntegrityError("STAGE_DESTINATION_WRITE_FAILED") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse_point(opened) or opened.st_size != 0:
            _fail("STAGE_DESTINATION_NOT_REGULAR")
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _fail("STAGE_DESTINATION_WRITE_FAILED")
            view = view[written:]
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while total <= len(data):
            chunk = os.read(descriptor, min(64 * 1024, len(data) + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(after.st_mode)
            or _is_reparse_point(after)
            or _file_signature(after) != _file_signature(current)
            or after.st_size != len(data)
            or b"".join(chunks) != data
        ):
            _fail("STAGE_DESTINATION_CHANGED")
    except OSError as exc:
        raise ArtifactIntegrityError("STAGE_DESTINATION_WRITE_FAILED") from exc
    finally:
        os.close(descriptor)


def _write_new_file(path: Path, data: bytes) -> None:
    try:
        parent_fd = _open_directory(path.parent)
    except ArtifactIntegrityError as exc:
        raise ArtifactIntegrityError("STAGE_DESTINATION_PARENT_INVALID") from exc
    try:
        _write_new_at(parent_fd, path.name, data)
        if _file_signature(os.fstat(parent_fd)) != _file_signature(path.parent.lstat()):
            _fail("STAGE_DESTINATION_PARENT_CHANGED")
    finally:
        os.close(parent_fd)


def stage_fragments(
    source_root: Path,
    destination_root: Path,
    *,
    collection_outcome: str = "success",
    execution_outcome: str = "success",
) -> tuple[str, ...]:
    """Copy only bounded regular witness fragments into a fresh evidence root."""

    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        _fail("STAGE_REQUIRES_POSIX_NOFOLLOW")
    if destination_root.exists() or destination_root.is_symlink():
        _fail("STAGE_DESTINATION_EXISTS")
    allowed_outcomes = {"success", "failure", "cancelled", "skipped"}
    if collection_outcome not in allowed_outcomes or execution_outcome not in allowed_outcomes:
        _fail("STAGE_COMMAND_OUTCOME_INVALID")
    destination_root.mkdir(parents=False)
    for group in ("collection", "execution"):
        (destination_root / group).mkdir()

    try:
        source_info = source_root.lstat()
    except FileNotFoundError:
        _write_new_file(
            destination_root / _STAGE_RECEIPT,
            _canonical_json({"schema_version": 1, "files": []}),
        )
        _write_new_file(
            destination_root / _COMMAND_STATUS,
            _canonical_json(
                {
                    "schema_version": 1,
                    "collection": collection_outcome,
                    "execution": execution_outcome,
                }
            ),
        )
        return ()
    except OSError as exc:
        raise ArtifactIntegrityError("STAGE_SOURCE_ROOT_INVALID") from exc
    if (
        not stat.S_ISDIR(source_info.st_mode)
        or stat.S_ISLNK(source_info.st_mode)
        or _is_reparse_point(source_info)
    ):
        _fail("STAGE_SOURCE_ROOT_INVALID")

    copied: list[str] = []
    staged_files: list[FileDigest] = []
    aggregate_bytes = 0
    fragment_count = 0
    root_fd = _open_directory(source_root)
    destination_fd: int | None = None
    destination_group_fds: dict[str, int] = {}
    try:
        destination_fd = _open_directory(destination_root)
        for group in ("collection", "execution"):
            destination_group_fds[group] = _open_directory(Path(group), parent_fd=destination_fd)
        for group in ("collection", "execution"):
            try:
                group_fd = _open_directory(Path(group), parent_fd=root_fd)
            except ArtifactIntegrityError as exc:
                try:
                    os.stat(group, dir_fd=root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise exc
            try:
                entry_count = 0
                with os.scandir(group_fd) as entries:
                    for entry in entries:
                        entry_count += 1
                        if entry_count > _MAX_DIRECTORY_ENTRIES:
                            _fail("STAGE_DIRECTORY_ENTRY_LIMIT_EXCEEDED")
                        name = entry.name
                        if not name.startswith(_FRAGMENT_PREFIX) or not name.endswith(_FRAGMENT_SUFFIX):
                            continue
                        if _FRAGMENT_NAME_RE.fullmatch(name) is None:
                            _fail("STAGE_FRAGMENT_NAME_INVALID")
                        try:
                            metadata = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            raise ArtifactIntegrityError("STAGE_SOURCE_STAT_FAILED") from exc
                        if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
                            _fail("STAGE_SOURCE_NOT_REGULAR")
                        fragment_count += 1
                        if fragment_count > MAX_RUNTIME_WITNESS_FRAGMENTS:
                            _fail("STAGE_FRAGMENT_COUNT_LIMIT_EXCEEDED")
                        data = _read_at(group_fd, name, MAX_RUNTIME_WITNESS_BYTES)
                        aggregate_bytes += len(data)
                        if aggregate_bytes > MAX_RUNTIME_AGGREGATE_BYTES:
                            _fail("STAGE_AGGREGATE_SIZE_LIMIT_EXCEEDED")
                        relative = f"{group}/{name}"
                        _write_new_at(destination_group_fds[group], name, data)
                        copied.append(relative)
                        staged_files.append(
                            FileDigest(relative, len(data), hashlib.sha256(data).hexdigest())
                        )
                current = os.stat(group, dir_fd=root_fd, follow_symlinks=False)
                if _file_signature(os.fstat(group_fd)) != _file_signature(current):
                    _fail("STAGE_DIRECTORY_CHANGED")
            finally:
                os.close(group_fd)
        if _file_signature(os.fstat(root_fd)) != _file_signature(source_root.lstat()):
            _fail("STAGE_SOURCE_ROOT_CHANGED")
        for group, group_fd in destination_group_fds.items():
            assert destination_fd is not None
            current = os.stat(group, dir_fd=destination_fd, follow_symlinks=False)
            if _file_signature(os.fstat(group_fd)) != _file_signature(current):
                _fail("STAGE_DESTINATION_CHANGED")
        assert destination_fd is not None
        if _file_signature(os.fstat(destination_fd)) != _file_signature(destination_root.lstat()):
            _fail("STAGE_DESTINATION_CHANGED")
    finally:
        os.close(root_fd)
        for group_fd in destination_group_fds.values():
            os.close(group_fd)
        if destination_fd is not None:
            os.close(destination_fd)
    receipt = {
        "schema_version": 1,
        "files": [item.to_dict() for item in sorted(staged_files, key=lambda item: item.path)],
    }
    _write_new_file(destination_root / _STAGE_RECEIPT, _canonical_json(receipt))
    _write_new_file(
        destination_root / _COMMAND_STATUS,
        _canonical_json(
            {
                "schema_version": 1,
                "collection": collection_outcome,
                "execution": execution_outcome,
            }
        ),
    )
    return tuple(sorted(copied))


def _validate_relative_file(
    value: Any, *, allow_analysis: bool = True, allow_integrity: bool = False
) -> str:
    if not isinstance(value, str) or "\\" in value or "\x00" in value:
        _fail("ARTIFACT_PATH_INVALID")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        _fail("ARTIFACT_PATH_INVALID")
    root_files = {"manifest.json", _STAGE_RECEIPT, _COMMAND_STATUS, _INPUT_INVENTORY}
    if allow_analysis:
        root_files.add("analysis.json")
    if allow_integrity:
        root_files.add(_INTEGRITY_RECEIPT)
    if value in root_files:
        return value
    if len(path.parts) == 2 and path.parts[0] in {"collection", "execution"}:
        if _FRAGMENT_NAME_RE.fullmatch(path.parts[1]) is None:
            _fail("ARTIFACT_PATH_INVALID")
        return value
    _fail("ARTIFACT_PATH_INVALID")


def _safe_file_digest(path: Path, *, limit: int) -> FileDigest:
    data = _read_regular_path(path, limit)
    return FileDigest(path.as_posix(), len(data), hashlib.sha256(data).hexdigest())


def _read_regular_path(path: Path, limit: int) -> bytes:
    try:
        parent_fd = _open_directory(path.parent)
    except ArtifactIntegrityError as exc:
        raise ArtifactIntegrityError("ARTIFACT_FILE_PARENT_INVALID") from exc
    try:
        return _read_at(parent_fd, path.name, limit)
    finally:
        os.close(parent_fd)


def _scan_root(root: Path, *, include_analysis: bool, include_receipt: bool) -> tuple[FileDigest, ...]:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise ArtifactIntegrityError("ARTIFACT_ROOT_MISSING") from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or _is_reparse_point(root_info)
    ):
        _fail("ARTIFACT_ROOT_INVALID")

    files: list[FileDigest] = []
    total_entries = 0
    aggregate_bytes = 0
    fragment_count = 0
    allowed_root_files = {"manifest.json", _STAGE_RECEIPT, _COMMAND_STATUS, _INPUT_INVENTORY}
    if include_analysis:
        allowed_root_files.add("analysis.json")
    if include_receipt:
        allowed_root_files.add(_INTEGRITY_RECEIPT)
    try:
        root_fd = _open_directory(root)
        try:
            with os.scandir(root_fd) as entries:
                for entry in entries:
                    total_entries += 1
                    if total_entries > _MAX_DIRECTORY_ENTRIES + 8:
                        _fail("ARTIFACT_ENTRY_LIMIT_EXCEEDED")
                    if entry.name in {"collection", "execution"}:
                        group_fd = _open_directory(Path(entry.name), parent_fd=root_fd)
                        try:
                            child_count = 0
                            with os.scandir(group_fd) as children:
                                for child in children:
                                    child_count += 1
                                    total_entries += 1
                                    if (
                                        child_count > _MAX_DIRECTORY_ENTRIES
                                        or total_entries > _MAX_DIRECTORY_ENTRIES + 8
                                    ):
                                        _fail("ARTIFACT_ENTRY_LIMIT_EXCEEDED")
                                    name = child.name
                                    if not name.startswith(_FRAGMENT_PREFIX) or not name.endswith(
                                        _FRAGMENT_SUFFIX
                                    ):
                                        _fail("ARTIFACT_UNEXPECTED_FILE")
                                    if _FRAGMENT_NAME_RE.fullmatch(name) is None:
                                        _fail("ARTIFACT_PATH_INVALID")
                                    metadata = child.stat(follow_symlinks=False)
                                    if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
                                        _fail("ARTIFACT_FILE_NOT_REGULAR")
                                    data = _read_at(group_fd, name, MAX_RUNTIME_WITNESS_BYTES)
                                    relative = f"{entry.name}/{name}"
                                    files.append(
                                        FileDigest(relative, len(data), hashlib.sha256(data).hexdigest())
                                    )
                                    fragment_count += 1
                                    aggregate_bytes += len(data)
                                    if fragment_count > MAX_RUNTIME_WITNESS_FRAGMENTS:
                                        _fail("ARTIFACT_FILE_COUNT_LIMIT_EXCEEDED")
                                    if aggregate_bytes > _MAX_ARTIFACT_BYTES:
                                        _fail("ARTIFACT_AGGREGATE_SIZE_LIMIT_EXCEEDED")
                            current = os.stat(entry.name, dir_fd=root_fd, follow_symlinks=False)
                            if _file_signature(os.fstat(group_fd)) != _file_signature(current):
                                _fail("ARTIFACT_DIRECTORY_CHANGED")
                        finally:
                            os.close(group_fd)
                    elif entry.name in allowed_root_files:
                        metadata = entry.stat(follow_symlinks=False)
                        if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
                            _fail("ARTIFACT_FILE_NOT_REGULAR")
                        data = _read_at(root_fd, entry.name, MAX_RUNTIME_WITNESS_BYTES)
                        files.append(
                            FileDigest(entry.name, len(data), hashlib.sha256(data).hexdigest())
                        )
                        aggregate_bytes += len(data)
                        if aggregate_bytes > _MAX_ARTIFACT_BYTES:
                            _fail("ARTIFACT_AGGREGATE_SIZE_LIMIT_EXCEEDED")
                    else:
                        _fail("ARTIFACT_UNEXPECTED_FILE")
            if _file_signature(os.fstat(root_fd)) != _file_signature(root.lstat()):
                _fail("ARTIFACT_ROOT_CHANGED")
        finally:
            os.close(root_fd)
    except OSError as exc:
        raise ArtifactIntegrityError("ARTIFACT_ROOT_READ_FAILED") from exc

    if len(files) > MAX_RUNTIME_WITNESS_FRAGMENTS + 6:
        _fail("ARTIFACT_FILE_COUNT_LIMIT_EXCEEDED")
    return tuple(sorted(files, key=lambda item: item.path))


def _canonical_json(payload: Any) -> bytes:
    return (json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _read_json(path: Path) -> Any:
    try:
        return json.loads(_read_regular_path(path, MAX_RUNTIME_WITNESS_BYTES).decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ArtifactIntegrityError("ARTIFACT_JSON_INVALID") from exc


def create_input_inventory(root: Path) -> tuple[FileDigest, ...]:
    """Bind the manifest and fragments before the analysis step consumes them."""

    files = _scan_root(root, include_analysis=False, include_receipt=False)
    _validate_stage_receipt(root, files)
    _validate_command_status(root)
    data_files = tuple(file for file in files if file.path != _INPUT_INVENTORY)
    payload = {"schema_version": 1, "files": [file.to_dict() for file in data_files]}
    _write_new_file(root / _INPUT_INVENTORY, _canonical_json(payload))
    return data_files


def _validate_command_status(root: Path) -> None:
    payload = _read_json(root / _COMMAND_STATUS)
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "collection",
        "execution",
    }:
        _fail("ARTIFACT_COMMAND_STATUS_INVALID")
    if (
        not isinstance(payload["schema_version"], int)
        or isinstance(payload["schema_version"], bool)
        or payload["schema_version"] != 1
        or payload["collection"] not in {"success", "failure", "cancelled", "skipped"}
        or payload["execution"] not in {"success", "failure", "cancelled", "skipped"}
    ):
        _fail("ARTIFACT_COMMAND_STATUS_INVALID")
    if payload["collection"] != "success" or payload["execution"] != "success":
        _fail("ARTIFACT_COMMAND_OUTCOME_NOT_SUCCESS")


def _validate_stage_receipt(root: Path, current_files: tuple[FileDigest, ...]) -> None:
    """Bind staged fragments to the bytes copied before manifest generation."""

    payload = _read_json(root / _STAGE_RECEIPT)
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "files"}:
        _fail("ARTIFACT_STAGE_RECEIPT_INVALID")
    if (
        not isinstance(payload["schema_version"], int)
        or isinstance(payload["schema_version"], bool)
        or payload["schema_version"] != 1
        or not isinstance(payload["files"], list)
    ):
        _fail("ARTIFACT_STAGE_RECEIPT_INVALID")
    recorded: list[FileDigest] = []
    seen: set[str] = set()
    for item in payload["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            _fail("ARTIFACT_STAGE_RECEIPT_INVALID")
        relative = _validate_relative_file(item["path"], allow_analysis=False)
        size = item["size"]
        sha256 = item["sha256"]
        if (
            not relative.startswith(("collection/", "execution/"))
            or relative in seen
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(sha256, str)
            or _SHA256_RE.fullmatch(sha256) is None
        ):
            _fail("ARTIFACT_STAGE_RECEIPT_INVALID")
        seen.add(relative)
        recorded.append(FileDigest(relative, size, sha256))
    if recorded != sorted(recorded, key=lambda item: item.path):
        _fail("ARTIFACT_STAGE_RECEIPT_INVALID")
    current_fragments = tuple(
        file
        for file in current_files
        if file.path.startswith(("collection/", "execution/"))
    )
    if current_fragments != tuple(recorded):
        _fail("ARTIFACT_STAGED_FRAGMENTS_CHANGED")


def _validate_inventory(
    root: Path, *, include_receipt: bool = False
) -> tuple[FileDigest, ...]:
    payload = _read_json(root / _INPUT_INVENTORY)
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "files"}:
        _fail("ARTIFACT_INPUT_INVENTORY_INVALID")
    if (
        not isinstance(payload["schema_version"], int)
        or isinstance(payload["schema_version"], bool)
        or payload["schema_version"] != 1
        or not isinstance(payload["files"], list)
    ):
        _fail("ARTIFACT_INPUT_INVENTORY_INVALID")
    recorded: list[FileDigest] = []
    seen: set[str] = set()
    for item in payload["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            _fail("ARTIFACT_INPUT_INVENTORY_INVALID")
        relative = _validate_relative_file(item["path"], allow_analysis=False)
        size = item["size"]
        sha256 = item["sha256"]
        if (
            relative == _INPUT_INVENTORY
            or relative in seen
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(sha256, str)
            or _SHA256_RE.fullmatch(sha256) is None
        ):
            _fail("ARTIFACT_INPUT_INVENTORY_INVALID")
        seen.add(relative)
        recorded.append(FileDigest(relative, size, sha256))
    if recorded != sorted(recorded, key=lambda item: item.path):
        _fail("ARTIFACT_INPUT_INVENTORY_INVALID")
    current = _scan_root(root, include_analysis=True, include_receipt=include_receipt)
    _validate_stage_receipt(root, current)
    _validate_command_status(root)
    excluded = {"analysis.json", _INPUT_INVENTORY}
    if include_receipt:
        excluded.add(_INTEGRITY_RECEIPT)
    current_data = tuple(file for file in current if file.path not in excluded)
    if current_data != tuple(recorded):
        _fail("ARTIFACT_ANALYZED_INPUTS_CHANGED")
    return tuple(recorded)


def _run_analysis(root: Path, repository_root: Path) -> tuple[dict[str, Any], int]:
    command = [
        sys.executable,
        "-m",
        "greengap",
        "witness",
        "analyze",
        "--manifest",
        str(root / "manifest.json"),
        "--collection-witness",
        str(root / "collection"),
        "--execution-witness",
        str(root / "execution"),
        "--json",
    ]
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.casefold() in {"path", "systemroot", "windir", "temp", "tmp", "tmpdir", "lang", "lc_all"}
    }
    source_path = str(repository_root / "src")
    environment["PYTHONPATH"] = source_path
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONSAFEPATH"] = "1"
    environment["PYTHONUTF8"] = "1"
    command.insert(1, "-P")
    try:
        completed = subprocess.run(
            command,
            cwd=repository_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ArtifactIntegrityError("ARTIFACT_REANALYSIS_FAILED") from exc
    try:
        result = json.loads(completed.stdout)
    except (ValueError, TypeError) as exc:
        raise ArtifactIntegrityError("ARTIFACT_REANALYSIS_OUTPUT_INVALID") from exc
    expected_status = {
        "COMPLETE": 0,
        "BLOCKED": 1,
        "INCOMPLETE": 2,
    }.get(result.get("outcome") if isinstance(result, dict) else None)
    if expected_status is None or completed.returncode != expected_status:
        _fail("ARTIFACT_REANALYSIS_STATUS_MISMATCH")
    return result, completed.returncode


def _seal_payload(root: Path, repository_root: Path) -> tuple[dict[str, Any], str]:
    _validate_inventory(root)
    try:
        stored_analysis = _read_json(root / "analysis.json")
    except ArtifactIntegrityError as exc:
        raise ArtifactIntegrityError("ARTIFACT_ANALYSIS_MISSING_OR_INVALID") from exc
    actual_analysis, _ = _run_analysis(root, repository_root)
    if stored_analysis != actual_analysis:
        _fail("ARTIFACT_ANALYSIS_DOES_NOT_MATCH_INPUTS")
    files = _scan_root(root, include_analysis=True, include_receipt=False)
    payload = {"schema_version": 1, "files": [file.to_dict() for file in files]}
    encoded = _canonical_json(payload)
    return payload, hashlib.sha256(encoded).hexdigest()


def seal_artifact(root: Path, repository_root: Path) -> str:
    """Write the digest receipt after checking the staged analysis inputs."""

    payload, receipt_digest = _seal_payload(root, repository_root)
    encoded = _canonical_json(payload)
    _write_new_file(root / _INTEGRITY_RECEIPT, encoded)
    return receipt_digest


def _archive_file_names(archive: zipfile.ZipFile) -> tuple[set[str], list[zipfile.ZipInfo]]:
    names: set[str] = set()
    files: list[zipfile.ZipInfo] = []
    aggregate_size = 0
    fragment_count = 0
    infos = archive.infolist()
    if len(infos) > MAX_RUNTIME_WITNESS_FRAGMENTS + 8:
        _fail("ARTIFACT_ARCHIVE_ENTRY_LIMIT_EXCEEDED")
    for info in infos:
        name = info.filename
        if not name or "\\" in name or "\x00" in name:
            _fail("ARTIFACT_ARCHIVE_PATH_INVALID")
        path = PurePosixPath(name.rstrip("/"))
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            _fail("ARTIFACT_ARCHIVE_PATH_INVALID")
        mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if info.is_dir():
            if (
                file_type not in {0, stat.S_IFDIR}
                or name not in {"collection/", "execution/"}
                or name in names
            ):
                _fail("ARTIFACT_ARCHIVE_DIRECTORY_INVALID")
            names.add(name)
            continue
        relative = _validate_relative_file(name, allow_integrity=True)
        if relative in names:
            _fail("ARTIFACT_ARCHIVE_DUPLICATE_PATH")
        if file_type not in {0, stat.S_IFREG}:
            _fail("ARTIFACT_ARCHIVE_NONREGULAR_FILE")
        if info.flag_bits & 0x1:
            _fail("ARTIFACT_ARCHIVE_ENCRYPTED")
        if info.file_size > MAX_RUNTIME_WITNESS_BYTES:
            _fail("ARTIFACT_ARCHIVE_FILE_SIZE_LIMIT_EXCEEDED")
        aggregate_size += info.file_size
        if aggregate_size > _MAX_ARTIFACT_BYTES:
            _fail("ARTIFACT_ARCHIVE_SIZE_LIMIT_EXCEEDED")
        if relative.startswith(("collection/", "execution/")):
            fragment_count += 1
            if fragment_count > MAX_RUNTIME_WITNESS_FRAGMENTS:
                _fail("ARTIFACT_ARCHIVE_FRAGMENT_LIMIT_EXCEEDED")
        names.add(relative)
        files.append(info)
    return names, files


def _snapshot_archive(
    archive_path: Path, *, limit: int, temporary_parent: Path
) -> tuple[BinaryIO, str]:
    """Hash and snapshot one no-follow archive handle for later extraction."""

    try:
        parent_fd = _open_directory(archive_path.parent)
    except ArtifactIntegrityError as exc:
        raise ArtifactIntegrityError("ARTIFACT_ARCHIVE_PARENT_INVALID") from exc
    descriptor: int | None = None
    snapshot: BinaryIO | None = None
    try:
        before = os.stat(archive_path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or _is_reparse_point(before):
            _fail("ARTIFACT_ARCHIVE_NOT_REGULAR")
        if before.st_size > limit:
            _fail("ARTIFACT_ARCHIVE_SIZE_LIMIT_EXCEEDED")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(archive_path.name, flags, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _file_signature(before) != _file_signature(opened):
            _fail("ARTIFACT_ARCHIVE_CHANGED")
        snapshot = tempfile.TemporaryFile(mode="w+b", dir=temporary_parent)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                _fail("ARTIFACT_ARCHIVE_SIZE_LIMIT_EXCEEDED")
            digest.update(chunk)
            snapshot.write(chunk)
        after = os.fstat(descriptor)
        current = os.stat(archive_path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            _file_signature(opened) != _file_signature(after)
            or _file_signature(before) != _file_signature(current)
            or total != before.st_size
        ):
            _fail("ARTIFACT_ARCHIVE_CHANGED")
        snapshot.flush()
        snapshot.seek(0)
        return snapshot, digest.hexdigest()
    except OSError as exc:
        if snapshot is not None:
            snapshot.close()
        raise ArtifactIntegrityError("ARTIFACT_ARCHIVE_READ_FAILED") from exc
    except BaseException:
        if snapshot is not None:
            snapshot.close()
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def _extract_archive(archive_source: BinaryIO, destination: Path) -> set[str]:
    try:
        archive = zipfile.ZipFile(archive_source)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ArtifactIntegrityError("ARTIFACT_ARCHIVE_INVALID") from exc
    extracted: set[str] = set()
    with archive:
        names, files = _archive_file_names(archive)
        for directory in ("collection", "execution"):
            (destination / directory).mkdir()
        for info in files:
            relative = _validate_relative_file(info.filename, allow_integrity=True)
            target = destination / Path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                with archive.open(info, "r") as source, target.open("xb") as output:
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > info.file_size or written > MAX_RUNTIME_WITNESS_BYTES:
                            _fail("ARTIFACT_ARCHIVE_FILE_SIZE_MISMATCH")
                        output.write(chunk)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise ArtifactIntegrityError("ARTIFACT_ARCHIVE_READ_FAILED") from exc
            if written != info.file_size:
                _fail("ARTIFACT_ARCHIVE_FILE_SIZE_MISMATCH")
            extracted.add(relative)
    return extracted


def _validate_integrity_receipt(root: Path, expected_receipt_digest: str) -> None:
    expected = expected_receipt_digest.removeprefix("sha256:").lower()
    if _SHA256_RE.fullmatch(expected) is None:
        _fail("ARTIFACT_EXPECTED_RECEIPT_DIGEST_INVALID")
    receipt_digest = _safe_file_digest(
        root / _INTEGRITY_RECEIPT, limit=MAX_RUNTIME_WITNESS_BYTES
    ).sha256
    if receipt_digest != expected:
        _fail("ARTIFACT_INTEGRITY_RECEIPT_MISMATCH")
    payload = _read_json(root / _INTEGRITY_RECEIPT)
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "files"}:
        _fail("ARTIFACT_INTEGRITY_RECEIPT_INVALID")
    if (
        not isinstance(payload["schema_version"], int)
        or isinstance(payload["schema_version"], bool)
        or payload["schema_version"] != 1
        or not isinstance(payload["files"], list)
    ):
        _fail("ARTIFACT_INTEGRITY_RECEIPT_INVALID")
    recorded: list[FileDigest] = []
    seen: set[str] = set()
    for item in payload["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            _fail("ARTIFACT_INTEGRITY_RECEIPT_INVALID")
        relative = _validate_relative_file(item["path"], allow_integrity=True)
        size = item["size"]
        sha256 = item["sha256"]
        if (
            relative == _INTEGRITY_RECEIPT
            or relative in seen
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(sha256, str)
            or _SHA256_RE.fullmatch(sha256) is None
        ):
            _fail("ARTIFACT_INTEGRITY_RECEIPT_INVALID")
        seen.add(relative)
        recorded.append(FileDigest(relative, size, sha256))
    if recorded != sorted(recorded, key=lambda item: item.path):
        _fail("ARTIFACT_INTEGRITY_RECEIPT_INVALID")
    current = _scan_root(root, include_analysis=True, include_receipt=True)
    current_without_receipt = tuple(file for file in current if file.path != _INTEGRITY_RECEIPT)
    if current_without_receipt != tuple(recorded):
        _fail("ARTIFACT_UPLOADED_FILE_MISMATCH")


def verify_archive(
    archive_path: Path,
    *,
    expected_archive_digest: str,
    expected_receipt_digest: str,
    repository_root: Path,
    temporary_parent: Path,
) -> None:
    """Verify an artifact ZIP's upload digest, file inventory, and analysis."""

    expected_archive = expected_archive_digest.removeprefix("sha256:").lower()
    if _SHA256_RE.fullmatch(expected_archive) is None:
        _fail("ARTIFACT_EXPECTED_DIGEST_INVALID")
    archive_snapshot, actual_archive_digest = _snapshot_archive(
        archive_path, limit=_MAX_ARCHIVE_BYTES, temporary_parent=temporary_parent
    )
    if actual_archive_digest != expected_archive:
        archive_snapshot.close()
        _fail("ARTIFACT_UPLOAD_DIGEST_MISMATCH")

    try:
        with tempfile.TemporaryDirectory(prefix="greengap-artifact-readback-", dir=temporary_parent) as name:
            extracted_root = Path(name) / "evidence"
            extracted_root.mkdir()
            extracted_names = _extract_archive(archive_snapshot, extracted_root)
            _validate_integrity_receipt(extracted_root, expected_receipt_digest)
            expected_files = {
                file.path
                for file in _scan_root(
                    extracted_root, include_analysis=True, include_receipt=True
                )
            }
            archived_files = {name for name in extracted_names}
            if archived_files != expected_files:
                _fail("ARTIFACT_ARCHIVE_FILE_SET_MISMATCH")
            _validate_inventory(extracted_root, include_receipt=True)
            stored_analysis = _read_json(extracted_root / "analysis.json")
            actual_analysis, _ = _run_analysis(extracted_root, repository_root)
            if stored_analysis != actual_analysis:
                _fail("ARTIFACT_ANALYSIS_DOES_NOT_MATCH_UPLOADED_INPUTS")
    except OSError as exc:
        raise ArtifactIntegrityError("ARTIFACT_READBACK_FAILED") from exc
    finally:
        archive_snapshot.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage = subparsers.add_parser("stage", help="copy bounded witness fragments")
    stage.add_argument("--source-root", type=Path, required=True)
    stage.add_argument("--destination-root", type=Path, required=True)
    stage.add_argument("--collection-outcome", required=True)
    stage.add_argument("--execution-outcome", required=True)
    inventory = subparsers.add_parser("inventory", help="record the analyzer input bytes")
    inventory.add_argument("--artifact-root", type=Path, required=True)
    seal = subparsers.add_parser("seal", help="verify analysis and write integrity receipt")
    seal.add_argument("--artifact-root", type=Path, required=True)
    seal.add_argument("--repository-root", type=Path, default=_REPO_ROOT)
    verify = subparsers.add_parser("verify", help="verify downloaded upload bytes and analysis")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--artifact-digest", required=True)
    verify.add_argument("--integrity-digest", required=True)
    verify.add_argument("--repository-root", type=Path, default=_REPO_ROOT)
    verify.add_argument("--temporary-parent", type=Path, required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "stage":
            copied = stage_fragments(
                args.source_root,
                args.destination_root,
                collection_outcome=args.collection_outcome,
                execution_outcome=args.execution_outcome,
            )
            print(f"STAGED_WITNESS_FRAGMENTS={len(copied)}")
        elif args.command == "inventory":
            files = create_input_inventory(args.artifact_root)
            print(f"WITNESS_INPUTS={len(files)}")
        elif args.command == "seal":
            print(seal_artifact(args.artifact_root, args.repository_root))
        else:
            verify_archive(
                args.archive,
                expected_archive_digest=args.artifact_digest,
                expected_receipt_digest=args.integrity_digest,
                repository_root=args.repository_root,
                temporary_parent=args.temporary_parent,
            )
            print("RUNTIME_WITNESS_UPLOAD_READBACK=PASS")
        return 0
    except ArtifactIntegrityError as exc:
        print(f"RUNTIME_WITNESS_ARTIFACT_ERROR={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
