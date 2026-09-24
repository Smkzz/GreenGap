"""Setuptools command integration for reproducible GreenGap package builds."""

from __future__ import annotations

import gzip
import os
import tarfile
from pathlib import Path
from tarfile import TarInfo

from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
from setuptools.command.egg_info import egg_info as _egg_info
from setuptools.command.sdist import sdist as _sdist

from scripts.reproducible_packaging import (
    _source_date_epoch,
    normalize_egg_info_metadata,
    normalize_sdist_metadata,
    normalize_wheel_archive,
)


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
