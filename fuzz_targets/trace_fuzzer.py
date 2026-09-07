"""Bounded Atheris target for GreenGap's deterministic trace parsers."""

from __future__ import annotations

import sys
from typing import Any

MAX_INPUT_BYTES = 4096
MAX_PATTERN_COUNT = 8
MAX_FIELD_BYTES = 512
_trace_module: Any | None = None


def _trace() -> Any:
    global _trace_module
    if _trace_module is None:
        from greengap import trace as trace_module

        _trace_module = trace_module
    return _trace_module


def exercise_input(data: bytes) -> None:
    """Exercise parsing surfaces with one bounded, side-effect-free input.

    NUL-separated fields let the engine mutate command text, a repository path,
    and several GitHub path patterns independently while keeping every target
    invocation deterministic and in memory. Exceptions from the product code
    deliberately propagate so Atheris records them as crashes.
    """

    text = data[:MAX_INPUT_BYTES].decode("utf-8", errors="replace")
    fields = text.split("\x00", MAX_PATTERN_COUNT)
    command = fields[0]
    path = (fields[1] if len(fields) > 1 else text)[:MAX_FIELD_BYTES]
    patterns = [
        field[:MAX_FIELD_BYTES]
        for field in fields[2:]
        if field[:MAX_FIELD_BYTES]
    ]
    if not patterns:
        patterns = ["**/*.py"]

    # Runner-neutral command tokenization and shell segmentation.
    trace_module = _trace()
    trace_module._neutral_tokens(command)
    trace_module._shell_segments(command)

    # GitHub path-glob translation and ordered include/negation matching.
    trace_module._github_path_pattern_regex(text[:MAX_FIELD_BYTES])
    trace_module._path_patterns_match(path, patterns)


def main() -> None:
    import atheris

    global _trace_module
    with atheris.instrument_imports():
        from greengap import trace as trace_module

        _trace_module = trace_module
    atheris.Setup(sys.argv, exercise_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
