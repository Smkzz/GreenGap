from __future__ import annotations

import base64
import csv
import hashlib
import io
import stat
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path

import pytest
from scripts.reproducible_packaging import (
    normalize_egg_info_metadata,
    normalize_generated_text,
    normalize_sdist_metadata,
    normalize_wheel_archive,
)

_DIST_INFO = "greengap-0.2.0.dev1.dist-info"
_METADATA_PATH = f"{_DIST_INFO}/METADATA"
_RECORD_PATH = f"{_DIST_INFO}/RECORD"
_WHEEL_MEMBERS = {
    _METADATA_PATH: (b"Metadata-Version: 2.4\r\nName: greengap\r\nVersion: 0.2.0.dev1\r\n\r\n"),
    f"{_DIST_INFO}/WHEEL": (
        b"Wheel-Version: 1.0\nGenerator: setuptools (84.0.0)\n"
        b"Root-Is-Purelib: true\nTag: py3-none-any\n"
    ),
    "greengap/__init__.py": b"__version__ = '0.2.0.dev1'\n",
    _RECORD_PATH: b"stale record content\n",
}


def _write_input_wheel(
    path: Path,
    *,
    create_system: int,
    timestamp: tuple[int, int, int, int, int, int],
    order: tuple[str, ...],
    metadata: bytes,
) -> None:
    contents = dict(_WHEEL_MEMBERS)
    contents[_METADATA_PATH] = metadata
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in order:
            info = zipfile.ZipInfo(name, date_time=timestamp)
            info.create_system = create_system
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, contents.get(name, b"outside"))


def _assert_record_is_valid(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())
        record_path = next(name for name in names if name.endswith(".dist-info/RECORD"))
        rows = list(csv.reader(io.StringIO(archive.read(record_path).decode("utf-8"))))
        assert len(rows) == len(names)
        assert {row[0] for row in rows} == names
        for name, digest, size in rows:
            if name == record_path:
                assert digest == ""
                assert size == ""
                continue
            content = archive.read(name)
            expected = base64.urlsafe_b64encode(hashlib.sha256(content).digest())
            assert digest == f"sha256={expected.decode('ascii').rstrip('=')}"
            assert size == str(len(content))


def test_generated_text_normalizes_crlf_and_preserves_lf() -> None:
    assert normalize_generated_text(b"Name: GreenGap\r\n\r\n", "METADATA") == b"Name: GreenGap\n\n"
    already_lf = b"Name: GreenGap\n\n"
    assert normalize_generated_text(already_lf, "METADATA") == already_lf


def test_generated_text_rejects_bare_cr_and_binary_data() -> None:
    with pytest.raises(ValueError, match="bare CR"):
        normalize_generated_text(b"Name: Green\rGap\n", "METADATA")
    with pytest.raises(ValueError, match="binary"):
        normalize_generated_text(b"Name: GreenGap\x00\n", "METADATA")
    with pytest.raises(ValueError, match="UTF-8"):
        normalize_generated_text(b"Name: GreenGap\xff\n", "METADATA")


def test_sdist_normalization_is_whitelisted_and_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "stage"
    known = (
        "PKG-INFO",
        "setup.cfg",
        "src/greengap.egg-info/PKG-INFO",
    )
    for relative in known:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"Name: GreenGap\r\n\r\n")

    untouched = {
        "docs/PKG-INFO": b"unexpected\r\nmetadata\r\n",
        "src/other.egg-info/PKG-INFO": b"other\r\nmetadata\r\n",
        "src/greengap.egg-info/SOURCES.txt": b"binary\x00payload\r\n",
        "build/setup.cfg": b"unexpected\r\nconfig\r\n",
    }
    for relative, content in untouched.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    assert normalize_sdist_metadata(root) == known
    for relative in known:
        assert (root / relative).read_bytes() == b"Name: GreenGap\n\n"
    for relative, content in untouched.items():
        assert (root / relative).read_bytes() == content

    unchanged_target = root / known[0]
    unchanged_mtime = unchanged_target.stat().st_mtime_ns
    assert normalize_sdist_metadata(root) == ()
    assert unchanged_target.stat().st_mtime_ns == unchanged_mtime


def test_egg_info_normalizes_only_generated_pkg_info(tmp_path: Path) -> None:
    root = tmp_path / "greengap.egg-info"
    root.mkdir()
    pkg_info = root / "PKG-INFO"
    pkg_info.write_bytes(b"Name: GreenGap\r\n\r\n")
    sources = root / "SOURCES.txt"
    sources.write_bytes(b"keep\r\nbytes\x00unchanged")

    assert normalize_egg_info_metadata(root) == ("PKG-INFO",)
    assert pkg_info.read_bytes() == b"Name: GreenGap\n\n"
    assert sources.read_bytes() == b"keep\r\nbytes\x00unchanged"


def test_sdist_normalization_rejects_symlinked_metadata_path(tmp_path: Path) -> None:
    root = tmp_path / "stage"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "PKG-INFO").write_bytes(b"Name: Outside\r\n\r\n")
    root.mkdir()
    nested = root / "src" / "greengap.egg-info"
    nested.parent.mkdir()
    try:
        nested.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable on this host: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        normalize_sdist_metadata(root)
    assert (outside / "PKG-INFO").read_bytes() == b"Name: Outside\r\n\r\n"


def test_sdist_normalization_rejects_junctioned_metadata_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "stage"
    junction = root / "src"
    metadata = root / "src" / "greengap.egg-info" / "PKG-INFO"
    metadata.parent.mkdir(parents=True)
    metadata.write_bytes(b"Name: GreenGap\r\n\r\n")

    original_is_junction = getattr(Path, "is_junction", None)

    def simulated_junction(path: Path) -> bool:
        return path == junction or (callable(original_is_junction) and original_is_junction(path))

    monkeypatch.setattr(Path, "is_junction", simulated_junction, raising=False)
    with pytest.raises(ValueError, match="reparse point"):
        normalize_sdist_metadata(root)
    assert metadata.read_bytes() == b"Name: GreenGap\r\n\r\n"


def test_wheel_normalization_matches_across_input_platform_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1790244000")
    windows_wheel = tmp_path / "windows.whl"
    linux_wheel = tmp_path / "linux.whl"
    names = tuple(_WHEEL_MEMBERS)
    _write_input_wheel(
        windows_wheel,
        create_system=0,
        timestamp=(2026, 9, 24, 10, 7, 6),
        order=names,
        metadata=_WHEEL_MEMBERS[_METADATA_PATH],
    )
    _write_input_wheel(
        linux_wheel,
        create_system=3,
        timestamp=(2026, 9, 24, 10, 36, 34),
        order=tuple(reversed(names)),
        metadata=_WHEEL_MEMBERS[_METADATA_PATH].replace(b"\r\n", b"\n"),
    )

    assert normalize_wheel_archive(windows_wheel)
    assert normalize_wheel_archive(linux_wheel)
    assert windows_wheel.read_bytes() == linux_wheel.read_bytes()
    _assert_record_is_valid(windows_wheel)
    _assert_record_is_valid(linux_wheel)

    with zipfile.ZipFile(windows_wheel) as archive:
        metadata = archive.read(_METADATA_PATH)
        parsed = BytesParser(policy=default).parsebytes(metadata)
        assert parsed["Name"] == "greengap"
        assert parsed["Version"] == "0.2.0.dev1"
        assert all(info.date_time == (2026, 9, 24, 10, 0, 0) for info in archive.infolist())
        assert all(info.create_system == 3 for info in archive.infolist())
        assert all(info.compress_type == zipfile.ZIP_STORED for info in archive.infolist())
        assert all(
            info.external_attr >> 16 == (stat.S_IFREG | 0o644) for info in archive.infolist()
        )

    before = windows_wheel.read_bytes()
    before_mtime = windows_wheel.stat().st_mtime_ns
    assert not normalize_wheel_archive(windows_wheel)
    assert windows_wheel.read_bytes() == before
    assert windows_wheel.stat().st_mtime_ns == before_mtime


def test_wheel_members_are_read_with_a_bounded_chunk_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1790244000")
    wheel_path = tmp_path / "bounded.whl"
    names = tuple(_WHEEL_MEMBERS)
    _write_input_wheel(
        wheel_path,
        create_system=3,
        timestamp=(2026, 9, 24, 10, 0, 0),
        order=names,
        metadata=_WHEEL_MEMBERS[_METADATA_PATH],
    )

    read_sizes: list[int] = []
    original_read = zipfile.ZipExtFile.read

    def track_bounded_read(handle: zipfile.ZipExtFile, size: int = -1) -> bytes:
        read_sizes.append(size)
        return original_read(handle, size)

    monkeypatch.setattr(zipfile.ZipExtFile, "read", track_bounded_read)
    assert normalize_wheel_archive(wheel_path)
    assert read_sizes
    assert all(0 < size <= 1024 * 1024 + 1 for size in read_sizes)


def test_wheel_normalization_rejects_archive_path_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1790244000")
    wheel_path = tmp_path / "traversal.whl"
    names = tuple(_WHEEL_MEMBERS)
    _write_input_wheel(
        wheel_path,
        create_system=3,
        timestamp=(2026, 9, 24, 10, 0, 0),
        order=("../outside.txt", *names),
        metadata=_WHEEL_MEMBERS[_METADATA_PATH],
    )
    original = wheel_path.read_bytes()

    with pytest.raises(ValueError, match="unsafe wheel member path"):
        normalize_wheel_archive(wheel_path)
    assert wheel_path.read_bytes() == original
    assert not (tmp_path.parent / "outside.txt").exists()


def test_wheel_normalization_rejects_symlink_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1790244000")
    wheel_path = tmp_path / "symlink.whl"
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for name, content in _WHEEL_MEMBERS.items():
            if name == _RECORD_PATH:
                continue
            archive.writestr(name, content)
        info = zipfile.ZipInfo("greengap/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "target")
        archive.writestr(_RECORD_PATH, _WHEEL_MEMBERS[_RECORD_PATH])
    original = wheel_path.read_bytes()

    with pytest.raises(ValueError, match="symlink member"):
        normalize_wheel_archive(wheel_path)
    assert wheel_path.read_bytes() == original
