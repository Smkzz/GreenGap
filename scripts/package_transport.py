from __future__ import annotations

import argparse
import base64
import csv
import fnmatch
import hashlib
import io
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import threading
import tomllib
import zipfile
import zlib
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
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
_GIT_TREE_OUTPUT_MAX_BYTES = MAX_EXPANDED_BYTES
_GIT_OUTPUT_CHUNK_BYTES = 64 * 1024
_DIST_INFO_NAME = f"{PACKAGE_NAME}-{PACKAGE_VERSION}.dist-info"
_WHEEL_METADATA_FILES = frozenset(
    {
        f"{_DIST_INFO_NAME}/METADATA",
        f"{_DIST_INFO_NAME}/RECORD",
        f"{_DIST_INFO_NAME}/WHEEL",
        f"{_DIST_INFO_NAME}/entry_points.txt",
        f"{_DIST_INFO_NAME}/licenses/LICENSE",
        f"{_DIST_INFO_NAME}/top_level.txt",
    }
)
_SDIST_GENERATED_FILES = frozenset(
    {
        "PKG-INFO",
        "setup.cfg",
        f"src/{PACKAGE_NAME}.egg-info/PKG-INFO",
        f"src/{PACKAGE_NAME}.egg-info/SOURCES.txt",
        f"src/{PACKAGE_NAME}.egg-info/dependency_links.txt",
        f"src/{PACKAGE_NAME}.egg-info/entry_points.txt",
        f"src/{PACKAGE_NAME}.egg-info/requires.txt",
        f"src/{PACKAGE_NAME}.egg-info/top_level.txt",
    }
)
_SDIST_SETUP_CFG = b"[egg_info]\ntag_build = \ntag_date = 0\n\n"
_SOURCE_VERSION_RE = re.compile(rb"(?m)^__version__\s*=\s*(['\"])([0-9A-Za-z.+!-]+)\1\s*$")


class PackageTransportError(ValueError):
    """A package payload cannot be bound to its manifest."""


@dataclass(frozen=True)
class _GitTreeEntry:
    mode: str
    object_type: str
    object_id: str


@dataclass(frozen=True)
class _PackageSourceMap:
    package_files: dict[str, bytes]
    sdist_files: dict[str, bytes]
    metadata_headers: tuple[tuple[str, str], ...]
    readme: bytes
    license: bytes
    entry_points: bytes
    requires: bytes
    top_level: bytes
    setuptools_version: str


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
    try:
        name.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return False
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
            "GIT_REPLACE_REF_BASE",
        } or name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            environment.pop(name, None)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def _run_git(repo_root: Path, *arguments: str, input_data: bytes | None = None) -> bytes:
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
            input=input_data,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PackageTransportError("SOURCE_GIT_CHECK_FAILED") from exc
    if result.returncode != 0:
        raise PackageTransportError("SOURCE_GIT_CHECK_FAILED")
    return result.stdout


def _run_git_with_output_limit(
    repo_root: Path, *arguments: str, max_output_bytes: int
) -> bytes:
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
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
            bufsize=0,
        )
    except OSError as exc:
        raise PackageTransportError("SOURCE_GIT_CHECK_FAILED") from exc
    stdout = process.stdout
    if stdout is None:
        process.kill()
        process.wait()
        raise PackageTransportError("SOURCE_GIT_CHECK_FAILED")

    output = bytearray()
    output_limit_exceeded = threading.Event()
    reader_errors: list[OSError] = []

    def read_output() -> None:
        try:
            while chunk := stdout.read(_GIT_OUTPUT_CHUNK_BYTES):
                if len(output) + len(chunk) > max_output_bytes:
                    output_limit_exceeded.set()
                    with suppress(OSError):
                        process.kill()
                    return
                output.extend(chunk)
        except OSError as exc:
            reader_errors.append(exc)

    reader = threading.Thread(target=read_output, name="greengap-git-output", daemon=True)
    reader.start()
    try:
        process.wait(timeout=_GIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        with suppress(OSError):
            process.kill()
        process.wait()
        reader.join(timeout=_GIT_TIMEOUT_SECONDS)
        raise PackageTransportError("SOURCE_GIT_CHECK_FAILED") from exc
    reader.join(timeout=_GIT_TIMEOUT_SECONDS)
    if reader.is_alive():
        with suppress(OSError):
            process.kill()
        process.wait()
        raise PackageTransportError("SOURCE_GIT_CHECK_FAILED")
    if output_limit_exceeded.is_set():
        raise PackageTransportError("SOURCE_GIT_OUTPUT_LIMIT")
    if reader_errors or process.returncode != 0:
        raise PackageTransportError("SOURCE_GIT_CHECK_FAILED")
    return bytes(output)


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


def _git_tree_entries(repo_root: Path, source_sha: str, source_tree: str) -> dict[str, _GitTreeEntry]:
    try:
        actual_tree = (
            _run_git(repo_root, "rev-parse", "--verify", f"{source_sha}^{{tree}}")
            .decode("ascii", "strict")
            .strip()
        )
    except UnicodeError as exc:
        raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID") from exc
    if actual_tree != source_tree:
        raise PackageTransportError("SOURCE_ID_MISMATCH")
    raw_tree = _run_git_with_output_limit(
        repo_root,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        source_sha,
        max_output_bytes=_GIT_TREE_OUTPUT_MAX_BYTES,
    )
    records = [record for record in raw_tree.split(b"\x00") if record]
    if len(records) > MAX_ARCHIVE_MEMBERS:
        raise PackageTransportError("SOURCE_TREE_MEMBER_LIMIT")
    entries: dict[str, _GitTreeEntry] = {}
    for record in records:
        header, separator, raw_path = record.partition(b"\t")
        if not separator:
            raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID")
        try:
            mode, object_type, object_id = header.decode("ascii", "strict").split(" ")
            path = os.fsdecode(raw_path)
        except (UnicodeError, ValueError) as exc:
            raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID") from exc
        if not path or path in entries or not GIT_ID_RE.fullmatch(object_id):
            raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID")
        entries[path] = _GitTreeEntry(mode, object_type, object_id)
    return entries


def _git_blob_bytes(repo_root: Path, entries: dict[str, _GitTreeEntry]) -> dict[str, bytes]:
    if not entries:
        return {}
    object_ids = sorted({entry.object_id for entry in entries.values()})
    request = b"".join(object_id.encode("ascii") + b"\n" for object_id in object_ids)
    checks = _run_git(repo_root, "cat-file", "--batch-check", input_data=request).splitlines()
    if len(checks) != len(object_ids):
        raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID")
    sizes: dict[str, int] = {}
    total_size = 0
    for object_id, line in zip(object_ids, checks, strict=True):
        fields = line.decode("ascii", "strict").split(" ")
        if len(fields) != 3 or fields[0] != object_id or fields[1] != "blob":
            raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID")
        try:
            size = int(fields[2])
        except ValueError as exc:
            raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID") from exc
        if size < 0 or size > MAX_EXPANDED_BYTES:
            raise PackageTransportError("SOURCE_PACKAGE_SIZE_LIMIT")
        total_size += size
        if total_size > MAX_EXPANDED_BYTES:
            raise PackageTransportError("SOURCE_PACKAGE_SIZE_LIMIT")
        sizes[object_id] = size

    raw_blobs = _run_git(repo_root, "cat-file", "--batch", input_data=request)
    cursor = 0
    blobs: dict[str, bytes] = {}
    for object_id in object_ids:
        header_end = raw_blobs.find(b"\n", cursor)
        if header_end < 0:
            raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID")
        header = raw_blobs[cursor:header_end].decode("ascii", "strict").split(" ")
        if len(header) != 3 or header[0] != object_id or header[1] != "blob":
            raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID")
        try:
            size = int(header[2])
        except ValueError as exc:
            raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID") from exc
        if size != sizes[object_id]:
            raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID")
        start = header_end + 1
        end = start + size
        if end >= len(raw_blobs) or raw_blobs[end : end + 1] != b"\n":
            raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID")
        blobs[object_id] = raw_blobs[start:end]
        cursor = end + 1
    if cursor != len(raw_blobs):
        raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID")
    return {path: blobs[entry.object_id] for path, entry in entries.items()}


def _manifest_source_paths(
    tree_entries: dict[str, _GitTreeEntry], manifest_data: bytes
) -> set[str]:
    try:
        lines = manifest_data.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        raise PackageTransportError("SOURCE_MANIFEST_INVALID") from exc
    selected: set[str] = set()
    if "MANIFEST.in" in tree_entries:
        selected.add("MANIFEST.in")
    for line in lines:
        try:
            fields = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise PackageTransportError("SOURCE_MANIFEST_INVALID") from exc
        if not fields:
            continue
        directive, *arguments = fields
        if directive == "include" and arguments:
            for pattern in arguments:
                if (
                    not pattern
                    or "\\" in pattern
                    or pattern.startswith("/")
                    or any(part in {"", ".", ".."} for part in pattern.split("/"))
                ):
                    raise PackageTransportError("SOURCE_MANIFEST_INVALID")
                matches = {
                    path for path in tree_entries if fnmatch.fnmatchcase(path, pattern)
                }
                selected.update(matches)
        elif directive == "recursive-include" and len(arguments) >= 2:
            directory, *patterns = arguments
            if (
                not directory
                or "\\" in directory
                or directory.startswith("/")
                or any(part in {"", ".", ".."} for part in directory.split("/"))
                or any(character in "*?[]!" for character in directory)
            ):
                raise PackageTransportError("SOURCE_MANIFEST_INVALID")
            prefix = f"{directory.rstrip('/')}/"
            for pattern in patterns:
                if (
                    not pattern
                    or "/" in pattern
                    or "\\" in pattern
                    or any(character in pattern for character in ":<>|")
                ):
                    raise PackageTransportError("SOURCE_MANIFEST_INVALID")
                matches = {
                    path
                    for path in tree_entries
                    if path.startswith(prefix)
                    and fnmatch.fnmatchcase(path[len(prefix) :].rsplit("/", 1)[-1], pattern)
                }
                selected.update(matches)
        else:
            raise PackageTransportError("SOURCE_MANIFEST_DIRECTIVE_UNSUPPORTED")
    if not selected or any(not _safe_archive_name(path) for path in selected):
        raise PackageTransportError("SOURCE_MANIFEST_PATH_INVALID")
    folded = [path.casefold() for path in selected]
    if len(set(folded)) != len(folded):
        raise PackageTransportError("SOURCE_MANIFEST_COLLISION")
    for path in selected:
        entry = tree_entries.get(path)
        if entry is None or entry.mode not in {"100644", "100755"} or entry.object_type != "blob":
            raise PackageTransportError("SOURCE_MANIFEST_MEMBER_INVALID")
    return selected


def _metadata_from_project(
    project: dict[str, Any], *, setuptools_version: str, version: str
) -> tuple[tuple[tuple[str, str], ...], bytes, bytes, bytes]:
    name = project.get("name")
    description = project.get("description")
    readme_path = project.get("readme")
    license_expression = project.get("license")
    authors = project.get("authors", [])
    urls = project.get("urls", {})
    keywords = project.get("keywords", [])
    classifiers = project.get("classifiers", [])
    requires_python = project.get("requires-python")
    dependencies = project.get("dependencies", [])
    optional_dependencies = project.get("optional-dependencies", {})
    scripts = project.get("scripts", {})
    gui_scripts = project.get("gui-scripts", {})
    extra_entry_points = project.get("entry-points", {})
    license_files = project.get("license-files", [])
    dynamic = project.get("dynamic", [])
    if (
        name != PACKAGE_NAME
        or not isinstance(description, str)
        or not isinstance(readme_path, str)
        or not isinstance(license_expression, str)
        or not isinstance(authors, list)
        or not isinstance(urls, dict)
        or not isinstance(keywords, list)
        or not isinstance(classifiers, list)
        or not isinstance(requires_python, str)
        or not isinstance(dependencies, list)
        or not isinstance(optional_dependencies, dict)
        or not isinstance(scripts, dict)
        or not isinstance(gui_scripts, dict)
        or not isinstance(extra_entry_points, dict)
        or not isinstance(license_files, list)
        or "version" not in dynamic
    ):
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
    if (
        scripts != {PACKAGE_NAME: "greengap.cli:main"}
        or gui_scripts
        or extra_entry_points
        or license_files != ["LICENSE"]
    ):
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
    if Path(readme_path).suffix.lower() != ".md":
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
    if any(not isinstance(item, str) for item in [*keywords, *classifiers, *dependencies]):
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in urls.items()):
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
    if any(not isinstance(item, str) for item in license_files):
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")

    headers: list[tuple[str, str]] = [
        ("Metadata-Version", "2.4"),
        ("Name", PACKAGE_NAME),
        ("Version", version),
        ("Summary", description),
        ("License-Expression", license_expression),
        ("Requires-Python", requires_python),
        ("Description-Content-Type", "text/markdown"),
        ("Dynamic", "license-file"),
    ]
    for author in authors:
        if not isinstance(author, dict) or set(author) - {"name", "email"}:
            raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
        author_name = author.get("name")
        author_email = author.get("email")
        if not isinstance(author_name, str) or (author_email is not None and not isinstance(author_email, str)):
            raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
        if author_email:
            headers.append(("Author-email", f"{author_name} <{author_email}>"))
        else:
            headers.append(("Author", author_name))
    for label, url in urls.items():
        headers.append(("Project-URL", f"{label}, {url}"))
    if keywords:
        headers.append(("Keywords", ",".join(keywords)))
    headers.extend(("Classifier", classifier) for classifier in classifiers)
    headers.extend(("License-File", path) for path in license_files)
    headers.extend(("Requires-Dist", dependency) for dependency in dependencies)
    for extra, extra_dependencies in optional_dependencies.items():
        if (
            not isinstance(extra, str)
            or not isinstance(extra_dependencies, list)
            or any(not isinstance(item, str) for item in extra_dependencies)
        ):
            raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
        headers.append(("Provides-Extra", extra))
        headers.extend(
            ("Requires-Dist", f'{dependency}; extra == "{extra}"')
            for dependency in extra_dependencies
        )

    entry_point_groups: dict[str, dict[str, str]] = {}
    for group, mapping in (
        ("console_scripts", scripts),
        ("gui_scripts", gui_scripts),
        *extra_entry_points.items(),
    ):
        if not isinstance(group, str) or not isinstance(mapping, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in mapping.items()
        ):
            raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
        if mapping:
            entry_point_groups[group] = mapping
    entry_point_lines: list[str] = []
    for group in sorted(entry_point_groups):
        entry_point_lines.append(f"[{group}]")
        entry_point_lines.extend(
            f"{key} = {value}" for key, value in sorted(entry_point_groups[group].items())
        )
        entry_point_lines.append("")
    entry_points = "\n".join(entry_point_lines).encode("utf-8")

    requirement_lines = list(dependencies)
    for extra, extra_dependencies in optional_dependencies.items():
        if requirement_lines:
            requirement_lines.append("")
        requirement_lines.append(f"[{extra}]")
        requirement_lines.extend(extra_dependencies)
    requires = ("\n".join(requirement_lines) + ("\n" if requirement_lines else "")).encode("utf-8")
    build_requires = project.get("_build_requires", [])
    if (
        not isinstance(build_requires, list)
        or len(build_requires) != 1
        or not isinstance(build_requires[0], str)
        or not build_requires[0].startswith("setuptools==")
    ):
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
    expected_setuptools = build_requires[0].partition("==")[2]
    if expected_setuptools != setuptools_version:
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
    return tuple(headers), entry_points, requires, readme_path.encode("utf-8")


def _source_map_from_git_objects(
    repo_root: Path, expected_source_sha: str, expected_source_tree: str
) -> _PackageSourceMap:
    if not GIT_ID_RE.fullmatch(expected_source_sha) or not GIT_ID_RE.fullmatch(expected_source_tree):
        raise PackageTransportError("SOURCE_ID_INVALID")
    tree_entries = _git_tree_entries(repo_root, expected_source_sha, expected_source_tree)
    manifest_entry = tree_entries.get("MANIFEST.in")
    pyproject_entry = tree_entries.get("pyproject.toml")
    init_entry = tree_entries.get(f"src/{PACKAGE_NAME}/__init__.py")
    if manifest_entry is None or pyproject_entry is None or init_entry is None:
        raise PackageTransportError("SOURCE_PACKAGE_FILES_INVALID")
    required_config: dict[str, _GitTreeEntry] = {
        "MANIFEST.in": manifest_entry,
        "pyproject.toml": pyproject_entry,
    }
    config_bytes = _git_blob_bytes(repo_root, required_config)
    selected = _manifest_source_paths(tree_entries, config_bytes["MANIFEST.in"])
    sdist_entries = {path: tree_entries[path] for path in selected}
    for entry in sdist_entries.values():
        if entry.mode not in {"100644", "100755"} or entry.object_type != "blob":
            raise PackageTransportError("SOURCE_MANIFEST_MEMBER_INVALID")
    sdist_files = _git_blob_bytes(repo_root, sdist_entries)
    if len(sdist_files) != len(sdist_entries):
        raise PackageTransportError("SOURCE_GIT_OBJECT_INVALID")
    package_prefix = f"src/{PACKAGE_NAME}/"
    package_files = {path: data for path, data in sdist_files.items() if path.startswith(package_prefix)}
    if not package_files or f"{package_prefix}__init__.py" not in package_files:
        raise PackageTransportError("SOURCE_PACKAGE_FILES_INVALID")
    try:
        pyproject = tomllib.loads(sdist_files["pyproject.toml"].decode("utf-8", "strict"))
        project = pyproject["project"]
        build_system = pyproject["build-system"]
        build_requires = build_system["requires"]
        init_version_matches = _SOURCE_VERSION_RE.findall(package_files[f"{package_prefix}__init__.py"])
        if len(init_version_matches) != 1:
            raise ValueError("package version assignment is ambiguous")
        version = init_version_matches[0][1].decode("ascii", "strict")
    except (KeyError, UnicodeError, tomllib.TOMLDecodeError, TypeError, ValueError) as exc:
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID") from exc
    if version != PACKAGE_VERSION or not isinstance(build_requires, list):
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
    try:
        setuptools_version = next(
            requirement.partition("==")[2]
            for requirement in build_requires
            if isinstance(requirement, str) and requirement.startswith("setuptools==")
        )
    except StopIteration as exc:
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID") from exc
    project_with_build = dict(project)
    project_with_build["_build_requires"] = [requirement for requirement in build_requires if requirement.startswith("setuptools==")]
    headers, entry_points, requires, readme_path_bytes = _metadata_from_project(
        project_with_build, setuptools_version=setuptools_version, version=version
    )
    readme_path = readme_path_bytes.decode("utf-8", "strict")
    if readme_path not in sdist_files:
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
    license_files = project_with_build.get("license-files", [])
    if not license_files or any(path not in sdist_files for path in license_files):
        raise PackageTransportError("SOURCE_PROJECT_METADATA_INVALID")
    readme = sdist_files[readme_path]
    license_bytes = sdist_files[license_files[0]]
    top_level_names = sorted(
        {
            path[len("src/") :].split("/", 1)[0]
            for path in package_files
            if path.startswith("src/") and "/" in path[len("src/") :]
        }
    )
    if top_level_names != [PACKAGE_NAME]:
        raise PackageTransportError("SOURCE_PACKAGE_FILES_INVALID")
    return _PackageSourceMap(
        package_files=package_files,
        sdist_files=sdist_files,
        metadata_headers=headers,
        readme=readme,
        license=license_bytes,
        entry_points=entry_points,
        requires=requires,
        top_level=("\n".join(top_level_names) + "\n").encode("utf-8"),
        setuptools_version=setuptools_version,
    )


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


def _validate_metadata(data: bytes, filename: str, source_map: _PackageSourceMap) -> None:
    if len(data) > MAX_METADATA_BYTES:
        raise PackageTransportError(f"PACKAGE_METADATA_LIMIT:{filename}")
    metadata = BytesParser(policy=default).parsebytes(data)
    if metadata.defects:
        raise PackageTransportError(f"PACKAGE_METADATA_INVALID:{filename}")
    actual = Counter((key.lower(), value) for key, value in metadata.items())
    expected = Counter((key.lower(), value) for key, value in source_map.metadata_headers)
    payload = metadata.get_payload()
    if (
        actual != expected
        or not isinstance(payload, str)
        or payload.encode("utf-8") != source_map.readme
    ):
        raise PackageTransportError(f"PACKAGE_METADATA_MISMATCH:{filename}")


def _wheel_generated_files(source_map: _PackageSourceMap) -> dict[str, bytes]:
    generated = {
        f"{_DIST_INFO_NAME}/WHEEL": (
            "Wheel-Version: 1.0\n"
            f"Generator: setuptools ({source_map.setuptools_version})\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n\n"
        ).encode(),
        f"{_DIST_INFO_NAME}/entry_points.txt": source_map.entry_points,
        f"{_DIST_INFO_NAME}/licenses/LICENSE": source_map.license,
        f"{_DIST_INFO_NAME}/top_level.txt": source_map.top_level,
    }
    return generated


def _expected_wheel_members(source_map: _PackageSourceMap) -> dict[str, bytes]:
    members = {
        f"{PACKAGE_NAME}/{path[len(f'src/{PACKAGE_NAME}/') :]}": content
        for path, content in source_map.package_files.items()
    }
    for name, content in _wheel_generated_files(source_map).items():
        if name in members:
            raise PackageTransportError("SOURCE_PACKAGE_FILES_INVALID")
        members[name] = content
    members[f"{_DIST_INFO_NAME}/METADATA"] = b""
    members[f"{_DIST_INFO_NAME}/RECORD"] = b""
    return members


def _wheel_record(members: dict[str, bytes], record_path: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(members):
        digest = base64.urlsafe_b64encode(hashlib.sha256(members[name]).digest())
        writer.writerow(
            (name, f"sha256={digest.decode('ascii').rstrip('=')}", str(len(members[name])))
        )
    writer.writerow((record_path, "", ""))
    return output.getvalue().encode("utf-8")


def _sdist_sources_manifest_entries(source_map: _PackageSourceMap) -> set[str]:
    included_sources = set(source_map.sdist_files)
    included_sources.update(_SDIST_GENERATED_FILES - {"PKG-INFO", "setup.cfg"})
    return included_sources


def _sdist_generated_files(source_map: _PackageSourceMap) -> dict[str, bytes]:
    sources_path = f"src/{PACKAGE_NAME}.egg-info/SOURCES.txt"
    included_sources = _sdist_sources_manifest_entries(source_map)
    sources = ("\n".join(sorted(included_sources)) + "\n").encode("utf-8")
    return {
        "setup.cfg": _SDIST_SETUP_CFG,
        sources_path: sources,
        f"src/{PACKAGE_NAME}.egg-info/dependency_links.txt": b"\n",
        f"src/{PACKAGE_NAME}.egg-info/entry_points.txt": source_map.entry_points,
        f"src/{PACKAGE_NAME}.egg-info/requires.txt": source_map.requires,
        f"src/{PACKAGE_NAME}.egg-info/top_level.txt": source_map.top_level,
    }


def _sdist_expected_directories(file_paths: set[str]) -> set[str]:
    directories = {""}
    for path in file_paths:
        parts = path.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            directories.add("/".join(parts[:index]))
    return directories


def _validate_sdist_sources_manifest(
    data: bytes, source_map: _PackageSourceMap, filename: str
) -> None:
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise PackageTransportError(
            f"SDIST_SOURCES_MANIFEST_INVALID:{filename}"
        ) from exc
    normalized_text = text.replace("\r\n", "\n")
    lines = normalized_text.splitlines()
    expected_entries = _sdist_sources_manifest_entries(source_map)
    if (
        not lines
        or "\r" in normalized_text
        or any(not line or not _safe_archive_name(line) for line in lines)
        or len(lines) != len(set(lines))
        or set(lines) != expected_entries
    ):
        raise PackageTransportError(f"SDIST_SOURCES_MANIFEST_INVALID:{filename}")


def _inspect_wheel(
    data: bytes,
    filename: str,
    source_map: _PackageSourceMap,
) -> None:
    expected_members = _expected_wheel_members(source_map)
    metadata_path = f"{_DIST_INFO_NAME}/METADATA"
    record_path = f"{_DIST_INFO_NAME}/RECORD"
    end_record_signature = b"PK\x05\x06"
    end_record_search_start = max(0, len(data) - 22 - 0xFFFF)
    end_record_offset = data.rfind(end_record_signature, end_record_search_start)
    if end_record_offset >= 0 and end_record_offset + 22 <= len(data):
        comment_size = int.from_bytes(
            data[end_record_offset + 20 : end_record_offset + 22], "little"
        )
        if end_record_offset + 22 + comment_size != len(data) or comment_size:
            raise PackageTransportError(f"WHEEL_TRAILING_DATA:{filename}")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if archive.comment or (
                members and min(member.header_offset for member in members) != 0
            ):
                raise PackageTransportError(f"WHEEL_TRAILING_DATA:{filename}")
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
            if set(names) != set(expected_members) or len(names) != len(expected_members):
                raise PackageTransportError(f"WHEEL_MEMBER_SET_INVALID:{filename}")
            contents: dict[str, bytes] = {}
            for member in members:
                contents[member.filename] = archive.read(member)
            if len(contents[metadata_path]) > MAX_METADATA_BYTES:
                raise PackageTransportError(f"PACKAGE_METADATA_LIMIT:{filename}")
            metadata = contents[metadata_path]
    except (OSError, zipfile.BadZipFile, RuntimeError, zlib.error) as exc:
        raise PackageTransportError(f"WHEEL_ARCHIVE_INVALID:{filename}") from exc
    except KeyError as exc:
        raise PackageTransportError(f"WHEEL_MEMBER_SET_INVALID:{filename}") from exc
    for name, expected in expected_members.items():
        if name in {metadata_path, record_path}:
            continue
        if contents[name] != expected:
            code = "WHEEL_SOURCE_FILES_MISMATCH" if name.startswith(f"{PACKAGE_NAME}/") else "WHEEL_GENERATED_METADATA_INVALID"
            raise PackageTransportError(f"{code}:{filename}")
    record_members = {name: value for name, value in contents.items() if name != record_path}
    if contents[record_path] != _wheel_record(record_members, record_path):
        raise PackageTransportError(f"WHEEL_RECORD_INVALID:{filename}")
    _validate_metadata(metadata, filename, source_map)


def _inspect_sdist(
    data: bytes,
    filename: str,
    source_map: _PackageSourceMap,
) -> None:
    expected_root = f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    metadata_path = "PKG-INFO"
    egg_info_metadata_path = f"src/{PACKAGE_NAME}.egg-info/PKG-INFO"
    tar_data = _decompress_sdist(data, filename)
    expected_files = set(source_map.sdist_files) | set(_SDIST_GENERATED_FILES)
    expected_directories = _sdist_expected_directories(expected_files)
    expected_paths = {
        expected_root if not path else f"{expected_root}/{path}"
        for path in expected_directories | expected_files
    }
    generated_files = _sdist_generated_files(source_map)
    metadata: dict[str, bytes] = {}
    found_files: set[str] = set()
    found_directories: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as archive:
            folded_names: set[str] = set()
            member_count = 0
            expanded_size = 0
            full_names: set[str] = set()
            while member := archive.next():
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise PackageTransportError(f"SDIST_MEMBER_SET_INVALID:{filename}")
                normalized_name = member.name.rstrip("/")
                if normalized_name.casefold() in folded_names:
                    raise PackageTransportError(f"SDIST_MEMBER_SET_INVALID:{filename}")
                folded_names.add(normalized_name.casefold())
                is_directory = member.type == tarfile.DIRTYPE
                if not _safe_archive_name(member.name, allow_trailing_slash=is_directory):
                    raise PackageTransportError(f"SDIST_PATH_INVALID:{filename}")
                if normalized_name != expected_root and not normalized_name.startswith(
                    f"{expected_root}/"
                ):
                    raise PackageTransportError(f"SDIST_PATH_INVALID:{filename}")
                full_names.add(normalized_name)
                if is_directory:
                    if member.size != 0 or member.linkname:
                        raise PackageTransportError(f"SDIST_MEMBER_TYPE_INVALID:{filename}")
                    relative_name = normalized_name[len(expected_root) :].lstrip("/")
                    found_directories.add(relative_name)
                    continue
                if (
                    member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}
                    or not member.isfile()
                    or member.size < 0
                    or member.sparse is not None
                ):
                    raise PackageTransportError(f"SDIST_MEMBER_TYPE_INVALID:{filename}")
                relative_name = normalized_name[len(expected_root) + 1 :]
                if relative_name not in expected_files:
                    raise PackageTransportError(f"SDIST_MEMBER_SET_INVALID:{filename}")
                if relative_name in {metadata_path, egg_info_metadata_path} and member.size > MAX_METADATA_BYTES:
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
                        chunks.append(chunk)
                if read_size != member.size:
                    raise PackageTransportError(f"SDIST_MEMBER_TRUNCATED:{filename}")
                content = b"".join(chunks)
                if relative_name in source_map.sdist_files:
                    if content != source_map.sdist_files[relative_name]:
                        raise PackageTransportError(f"SDIST_SOURCE_FILES_MISMATCH:{filename}")
                elif relative_name == f"src/{PACKAGE_NAME}.egg-info/SOURCES.txt":
                    _validate_sdist_sources_manifest(content, source_map, filename)
                elif relative_name in generated_files and content != generated_files[relative_name]:
                    raise PackageTransportError(f"SDIST_GENERATED_METADATA_INVALID:{filename}")
                if relative_name in {metadata_path, egg_info_metadata_path}:
                    metadata[relative_name] = content
                found_files.add(relative_name)
            tar_stream = archive.fileobj
            if tar_stream is None or any(tar_data[tar_stream.tell() :]):
                raise PackageTransportError(f"SDIST_TRAILING_DATA:{filename}")
    except (OSError, EOFError, tarfile.TarError, zlib.error) as exc:
        raise PackageTransportError(f"SDIST_ARCHIVE_INVALID:{filename}") from exc
    if full_names != expected_paths or found_files != expected_files or found_directories != expected_directories:
        raise PackageTransportError(f"SDIST_MEMBER_SET_INVALID:{filename}")
    if set(metadata) != {metadata_path, egg_info_metadata_path}:
        raise PackageTransportError(f"SDIST_METADATA_MISSING:{filename}")
    if metadata[metadata_path] != metadata[egg_info_metadata_path]:
        raise PackageTransportError(f"SDIST_METADATA_MISMATCH:{filename}")
    for package_metadata in metadata.values():
        _validate_metadata(package_metadata, filename, source_map)


def _decompress_sdist(data: bytes, filename: str) -> bytes:
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        expanded = decompressor.decompress(data, MAX_TAR_STREAM_BYTES + 1)
        if len(expanded) > MAX_TAR_STREAM_BYTES or decompressor.unconsumed_tail:
            raise PackageTransportError(f"SDIST_EXPANDED_SIZE_LIMIT:{filename}")
        if decompressor.unused_data:
            raise PackageTransportError(f"SDIST_TRAILING_DATA:{filename}")
        if not decompressor.eof:
            raise PackageTransportError(f"SDIST_ARCHIVE_INVALID:{filename}")
        tail = decompressor.flush()
        if len(expanded) + len(tail) > MAX_TAR_STREAM_BYTES:
            raise PackageTransportError(f"SDIST_EXPANDED_SIZE_LIMIT:{filename}")
        expanded += tail
    except PackageTransportError:
        raise
    except (OSError, EOFError, zlib.error) as exc:
        raise PackageTransportError(f"SDIST_ARCHIVE_INVALID:{filename}") from exc
    return expanded


def _inspect_distribution(
    data: bytes,
    filename: str,
    source_map: _PackageSourceMap,
) -> None:
    if filename.endswith(".whl"):
        _inspect_wheel(data, filename, source_map)
    elif filename.endswith(".tar.gz"):
        _inspect_sdist(data, filename, source_map)
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
    source_map = _source_map_from_git_objects(
        repo_root, expected_source_sha, expected_source_tree
    )
    expected_names = set(_expected_filenames())
    entries = list(dist_dir.iterdir())
    if {entry.name for entry in entries} != expected_names or len(entries) != 2:
        raise PackageTransportError("DISTRIBUTION_FILE_SET_INVALID")
    files: list[dict[str, Any]] = []
    for name in sorted(expected_names):
        data = _read_regular_file(dist_dir / name)
        _inspect_distribution(data, name, source_map)
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


def verify_payload(
    directory: Path,
    expected_manifest_json: str,
    source_sha: str,
    source_tree: str,
    repo_root: Path,
) -> dict[str, Any]:
    try:
        manifest = _validated_manifest(json.loads(expected_manifest_json))
    except (json.JSONDecodeError, TypeError) as exc:
        raise PackageTransportError("EXPECTED_MANIFEST_INVALID") from exc
    if manifest["source"] != {"sha": source_sha, "tree": source_tree}:
        raise PackageTransportError("SOURCE_ID_MISMATCH")
    first_observation = _repository_observation(repo_root, source_sha, source_tree)
    source_map = _source_map_from_git_objects(repo_root, source_sha, source_tree)
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
        _inspect_distribution(data, name, source_map)
    second_observation = _repository_observation(repo_root, source_sha, source_tree)
    if first_observation != second_observation:
        raise PackageTransportError("SOURCE_CHANGED_DURING_PACKAGE_INSPECTION")
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
    verify.add_argument("--repo-root", type=Path, required=True)
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
                args.repo_root,
            )
    except (OSError, PackageTransportError) as exc:
        print(f"PACKAGE_TRANSPORT_INVALID:{exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
