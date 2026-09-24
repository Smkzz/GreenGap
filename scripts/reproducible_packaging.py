"""Cross-platform reproducible packaging hooks for GreenGap."""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import os
import re
import stat
import tarfile
import tempfile
import zipfile
import zlib
from contextlib import suppress
from datetime import UTC, datetime
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from tarfile import TarInfo

from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
from setuptools.command.egg_info import egg_info as _egg_info
from setuptools.command.sdist import sdist as _sdist

_EGG_INFO_METADATA_PATHS = ("PKG-INFO",)
_SDIST_METADATA_PATHS = (
    "PKG-INFO",
    "setup.cfg",
    "src/greengap.egg-info/PKG-INFO",
)
_MAX_WHEEL_ARCHIVE_BYTES = 256 * 1024 * 1024
_MAX_WHEEL_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_WHEEL_MEMBERS = 4096
_MAX_METADATA_BYTES = 16 * 1024 * 1024
_ZIP_EPOCH_MIN = 315532800  # 1980-01-01T00:00:00Z
_ZIP_EPOCH_MAX = 4354819198  # 2107-12-31T23:59:58Z


def _is_link_or_reparse_point(path: Path, file_stat: os.stat_result | None = None) -> bool:
    """Detect symlinks and Windows junctions/reparse points without following them."""
    current = file_stat if file_stat is not None else path.lstat()
    if stat.S_ISLNK(current.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(current, "st_file_attributes", 0) & reparse_point)


def normalize_generated_text(data: bytes, member: str) -> bytes:
    """Convert generated CRLF text to LF and reject ambiguous/binary metadata."""
    if b"\x00" in data:
        raise ValueError(f"generated metadata is binary: {member}")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"generated metadata is not UTF-8: {member}") from exc
    if b"\r" in data.replace(b"\r\n", b""):
        raise ValueError(f"generated metadata contains a bare CR: {member}")
    return data.replace(b"\r\n", b"\n")


def _safe_staged_file(root: Path, relative: str) -> Path | None:
    """Return a regular, non-symlink metadata target below a build staging root."""
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise ValueError(f"unsafe generated metadata path: {relative!r}")

    absolute_root = Path(os.path.abspath(root))
    current = Path(absolute_root.anchor)
    for part in absolute_root.parts[1:]:
        current = current / part
        if _is_link_or_reparse_point(current):
            raise ValueError(
                "metadata staging root must not contain symlink or reparse-point components"
            )
    root_path = absolute_root.resolve(strict=True)
    target = root_path
    parts = relative.split("/")
    for part in parts:
        target = target / part
        try:
            target_stat = target.lstat()
        except FileNotFoundError:
            return None
        if _is_link_or_reparse_point(target, target_stat):
            raise ValueError(
                f"generated metadata path contains a symlink or reparse point: {relative}"
            )

    if not stat.S_ISREG(target_stat.st_mode):
        raise ValueError(f"generated metadata target is not a regular file: {relative}")
    try:
        target.resolve(strict=True).relative_to(root_path)
    except ValueError as exc:
        raise ValueError(f"generated metadata path escapes staging root: {relative}") from exc
    return target


def _read_regular_file(path: Path, max_bytes: int) -> tuple[os.stat_result, bytes]:
    """Read a bounded regular file without following symlinks when the OS supports it."""
    original = path.lstat()
    if _is_link_or_reparse_point(path, original) or not stat.S_ISREG(original.st_mode):
        raise ValueError(f"expected a regular file: {path.name}")
    if original.st_size > max_bytes:
        raise ValueError(f"input exceeds the size limit: {path.name}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"could not safely open input: {path.name}") from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != original.st_dev
            or opened.st_ino != original.st_ino
            or opened.st_size != original.st_size
            or opened.st_mtime_ns != original.st_mtime_ns
        ):
            raise RuntimeError(f"input changed while opening: {path.name}")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            contents = handle.read(max_bytes + 1)
            after = os.fstat(handle.fileno())
        if len(contents) > max_bytes:
            raise ValueError(f"input exceeds the size limit: {path.name}")
        if after.st_size != opened.st_size or after.st_mtime_ns != opened.st_mtime_ns:
            raise RuntimeError(f"input changed while reading: {path.name}")
        return original, contents
    finally:
        if fd >= 0:
            os.close(fd)


def _atomic_replace_regular_file(path: Path, data: bytes, original: os.stat_result) -> None:
    """Atomically replace a checked build output using a private sibling temp file."""
    current = path.lstat()
    if (
        _is_link_or_reparse_point(path, current)
        or not stat.S_ISREG(current.st_mode)
        or current.st_dev != original.st_dev
        or current.st_ino != original.st_ino
        or current.st_mtime_ns != original.st_mtime_ns
        or current.st_size != original.st_size
    ):
        raise RuntimeError(f"generated output changed during normalization: {path.name}")

    fd, temp_name = tempfile.mkstemp(prefix=".greengap-repro-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, stat.S_IMODE(original.st_mode))
        os.replace(temp_name, path)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temp_name)


def _normalize_known_metadata(
    root: str | os.PathLike[str], paths: tuple[str, ...]
) -> tuple[str, ...]:
    staging_root = Path(root)
    changed: list[str] = []
    for relative in paths:
        target = _safe_staged_file(staging_root, relative)
        if target is None:
            continue
        original, contents = _read_regular_file(target, _MAX_METADATA_BYTES)
        normalized = normalize_generated_text(contents, relative)
        if normalized == contents:
            continue
        _atomic_replace_regular_file(target, normalized, original)
        changed.append(relative)
    return tuple(changed)


def normalize_egg_info_metadata(root: str | os.PathLike[str]) -> tuple[str, ...]:
    """Normalize PKG-INFO immediately after setuptools generates egg-info."""
    return _normalize_known_metadata(root, _EGG_INFO_METADATA_PATHS)


def normalize_sdist_metadata(root: str | os.PathLike[str]) -> tuple[str, ...]:
    """Normalize only known setuptools-generated metadata in an sdist staging tree."""
    return _normalize_known_metadata(root, _SDIST_METADATA_PATHS)


def _source_date_epoch() -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(value)
    except ValueError as exc:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer") from exc
    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must not be negative")
    return epoch


def _zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    bounded = min(max(epoch, _ZIP_EPOCH_MIN), _ZIP_EPOCH_MAX)
    moment = datetime.fromtimestamp(bounded, UTC)
    return (moment.year, moment.month, moment.day, moment.hour, moment.minute, moment.second & ~1)


def _validate_wheel_member(name: str) -> None:
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
        or re.match(r"^[A-Za-z]:", name)
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise ValueError(f"unsafe wheel member path: {name!r}")


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


def _read_wheel_member(source: zipfile.ZipFile, info: zipfile.ZipInfo, total_size: int) -> bytes:
    """Read one ZIP member in bounded chunks, even if its size header is dishonest."""
    chunks: list[bytes] = []
    size = 0
    with source.open(info, mode="r") as member:
        while True:
            member_remaining = _MAX_WHEEL_MEMBER_BYTES - size
            archive_remaining = _MAX_WHEEL_ARCHIVE_BYTES - total_size - size
            read_limit = min(1024 * 1024, member_remaining + 1, archive_remaining + 1)
            chunk = member.read(read_limit)
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_WHEEL_MEMBER_BYTES:
                raise ValueError(f"wheel member exceeds the size limit: {info.filename}")
            if total_size + size > _MAX_WHEEL_ARCHIVE_BYTES:
                raise ValueError("wheel archive exceeds the uncompressed size limit")
            chunks.append(chunk)
    if size != info.file_size:
        raise ValueError(f"wheel member size does not match its header: {info.filename}")
    return b"".join(chunks)


def _canonical_wheel_bytes(raw_archive: bytes, source_epoch: int) -> bytes:
    if len(raw_archive) > _MAX_WHEEL_ARCHIVE_BYTES:
        raise ValueError("wheel archive exceeds the reproducible packaging size limit")

    try:
        source = zipfile.ZipFile(io.BytesIO(raw_archive), mode="r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("invalid wheel archive") from exc

    with source:
        infos = source.infolist()
        if not infos or len(infos) > _MAX_WHEEL_MEMBERS:
            raise ValueError("wheel archive has an invalid member count")

        members: dict[str, bytes] = {}
        folded_names: set[str] = set()
        total_uncompressed = 0
        for info in infos:
            name = info.filename
            _validate_wheel_member(name)
            folded = name.casefold()
            if name in members or folded in folded_names:
                raise ValueError(f"duplicate wheel member path: {name}")
            folded_names.add(folded)
            if info.is_dir() or info.flag_bits & 0x1:
                raise ValueError(f"unsupported wheel member type: {name}")
            if info.file_size > _MAX_WHEEL_MEMBER_BYTES:
                raise ValueError(f"wheel member exceeds the size limit: {name}")
            total_uncompressed += info.file_size
            if total_uncompressed > _MAX_WHEEL_ARCHIVE_BYTES:
                raise ValueError("wheel archive exceeds the uncompressed size limit")
            unix_mode = info.external_attr >> 16
            if info.create_system == 3 and stat.S_ISLNK(unix_mode):
                raise ValueError(f"wheel symlink member is unsupported: {name}")
            try:
                contents = _read_wheel_member(source, info, total_uncompressed - info.file_size)
            except (
                EOFError,
                OSError,
                RuntimeError,
                zipfile.BadZipFile,
                zlib.error,
            ) as exc:
                raise ValueError(f"could not read wheel member: {name}") from exc
            members[name] = contents

    metadata_paths = [name for name in members if re.fullmatch(r"[^/]+\.dist-info/METADATA", name)]
    record_paths = [name for name in members if re.fullmatch(r"[^/]+\.dist-info/RECORD", name)]
    if len(metadata_paths) != 1 or len(record_paths) != 1:
        raise ValueError("wheel must contain exactly one dist-info METADATA and RECORD")
    metadata_path, record_path = metadata_paths[0], record_paths[0]
    if metadata_path.rsplit("/", 1)[0] != record_path.rsplit("/", 1)[0]:
        raise ValueError("wheel METADATA and RECORD must share one dist-info directory")
    if any(name in members for name in (record_path + ".jws", record_path + ".p7s")):
        raise ValueError("signed wheels cannot be rewritten reproducibly")

    metadata = normalize_generated_text(members[metadata_path], metadata_path)
    parsed_metadata = BytesParser(policy=default).parsebytes(metadata)
    if not parsed_metadata.get("Name") or not parsed_metadata.get("Version"):
        raise ValueError("wheel METADATA must declare Name and Version")
    members[metadata_path] = metadata
    members[record_path] = _wheel_record(
        {name: data for name, data in members.items() if name != record_path}, record_path
    )

    output = io.BytesIO()
    timestamp = _zip_datetime(source_epoch)
    with zipfile.ZipFile(
        output, mode="w", compression=zipfile.ZIP_STORED, allowZip64=True
    ) as target:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=timestamp)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.internal_attr = 0
            info.flag_bits = 0
            info.extra = b""
            info.comment = b""
            target.writestr(info, members[name], compress_type=zipfile.ZIP_STORED)
    canonical = output.getvalue()
    if len(canonical) > _MAX_WHEEL_ARCHIVE_BYTES:
        raise ValueError("canonical wheel archive exceeds the size limit")
    return canonical


def normalize_wheel_archive(path: str | os.PathLike[str]) -> bool:
    """Canonicalize generated wheel metadata and ZIP container fields in place."""
    wheel_path = Path(path)
    original_stat, original = _read_regular_file(wheel_path, _MAX_WHEEL_ARCHIVE_BYTES)
    canonical = _canonical_wheel_bytes(original, _source_date_epoch())
    if canonical == original:
        return False
    _atomic_replace_regular_file(wheel_path, canonical, original_stat)
    return True


class ReproducibleSdist(_sdist):
    """Normalize generated metadata and archive metadata for source distributions."""

    def make_release_tree(self, base_dir: str, files: list[str]) -> None:
        super().make_release_tree(base_dir, files)
        normalize_sdist_metadata(base_dir)

    def make_archive(
        self,
        base_name: str | os.PathLike[str],
        format: str,
        root_dir: str | os.PathLike[str] | None = None,
        base_dir: str | None = None,
        owner: str | None = None,
        group: str | None = None,
    ) -> str:
        if format != "gztar":
            return super().make_archive(base_name, format, root_dir, base_dir, owner, group)
        root = Path(root_dir) if root_dir is not None else Path.cwd()
        archive_base = base_dir or Path.cwd().name
        epoch = _source_date_epoch()
        archive_name = str(base_name) + ".tar.gz"
        source_root = root / archive_base
        archive_path = Path(archive_name)
        archive_path.parent.mkdir(parents=True, exist_ok=True)

        def normalize(info: TarInfo) -> TarInfo:
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = epoch
            info.mode = 0o755 if info.isdir() else 0o644
            return info

        with (
            archive_path.open("wb") as handle,
            gzip.GzipFile(fileobj=handle, mode="wb", mtime=epoch) as compressed,
            tarfile.open(fileobj=compressed, mode="w|") as archive,
        ):
            archive.add(source_root, arcname=archive_base, filter=normalize)
        return str(archive_path)


class ReproducibleEggInfo(_egg_info):
    """Canonicalize only generated PKG-INFO before downstream package commands."""

    def run(self) -> None:
        super().run()
        normalize_egg_info_metadata(self.egg_info)


class ReproducibleBdistWheel(_bdist_wheel):
    """Rewrite wheel output with stable member bytes, order and ZIP metadata."""

    def run(self) -> None:
        existing = getattr(self.distribution, "dist_files", None)
        previous_count = len(existing) if isinstance(existing, list) else 0
        super().run()

        outputs = getattr(self.distribution, "dist_files", None)
        new_records = outputs[previous_count:] if isinstance(outputs, list) else []
        wheel_records = [item for item in new_records if item and item[0] == "bdist_wheel"]
        if len(wheel_records) == 1:
            wheel_path = Path(wheel_records[0][2])
        else:
            impl_tag, abi_tag, plat_tag = self.get_tag()
            basename = f"{self.wheel_dist_name}-{impl_tag}-{abi_tag}-{plat_tag}.whl"
            wheel_path = Path(self.dist_dir) / basename
        if not wheel_path.is_file():
            raise RuntimeError("setuptools did not produce the expected wheel archive")
        normalize_wheel_archive(wheel_path)
