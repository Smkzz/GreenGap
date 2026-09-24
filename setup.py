"""Setuptools hooks for reproducible wheel and source archive generation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scripts.setuptools_reproducible_commands import (
    ReproducibleBdistWheel,
    ReproducibleEggInfo,
    ReproducibleSdist,
)
from setuptools import setup

setup(
    cmdclass={
        "bdist_wheel": ReproducibleBdistWheel,
        "egg_info": ReproducibleEggInfo,
        "sdist": ReproducibleSdist,
    }
)
