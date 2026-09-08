"""Setuptools hook for deterministic source archives when an epoch is provided."""

from __future__ import annotations

import gzip
import os
import tarfile
from pathlib import Path

from setuptools import setup
from setuptools.command.sdist import sdist as _sdist


class ReproducibleSdist(_sdist):
    """Normalize archive metadata so repeated release builds compare cleanly."""

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
        try:
            epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
        except ValueError as exc:
            raise ValueError("SOURCE_DATE_EPOCH must be an integer") from exc
        archive_name = str(base_name) + ".tar.gz"
        source_root = root / archive_base
        archive_path = Path(archive_name)
        archive_path.parent.mkdir(parents=True, exist_ok=True)

        def normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
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


setup(cmdclass={"sdist": ReproducibleSdist})
