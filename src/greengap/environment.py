"""Explicit, non-secret environment construction for target collection."""

from __future__ import annotations

import os
from collections.abc import Mapping

_COLLECTION_ENVIRONMENT_NAMES = frozenset(
    {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    }
)


def collection_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a small environment suitable for intentional target collection.

    The caller may add deterministic, task-owned variables such as ``PYTHONPATH``
    or a disposable temporary directory. Ambient credentials, proxy settings,
    package indexes, and pytest selector variables are never inherited.
    """

    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in _COLLECTION_ENVIRONMENT_NAMES
    }
    if extra:
        environment.update({str(name): str(value) for name, value in extra.items()})
    return environment
