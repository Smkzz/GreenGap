"""Conservative, deterministic GitHub Actions to pytest command tracing."""

from __future__ import annotations

import ast
import configparser
import itertools
import json
import os
import re
import shlex
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal, cast

import yaml

from .model import PytestInvocation, TraceIssue, TraceResult
from .util import (
    MAX_CONFIG_BYTES,
    MAX_MATRIX_ROWS,
    MAX_WORKFLOW_FILES,
    PathSafetyError,
    normalize_repo_path,
    read_limited_text,
    safe_resolve,
)

MAX_DEPTH = 12
MAX_YAML_DEPTH = 64
_NEUTRAL_SHELL = "neutral"
_EXPRESSION = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
_ASSIGNMENT = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|:=)\s*(.*)$")
_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_PYTEST_PLUGIN_ASSIGNMENT = re.compile(
    r"(?m)^\s*pytest_plugins(?:\s*:\s*[^=]+)?\s*\+?="
)
_PYTEST_PLUGIN_CONFIG = re.compile(
    r"(?im)^\s*(?:required_plugins|pytest_plugins)\s*="
)
_PYTEST_HOOK_DEFINITION = re.compile(r"(?m)^\s*(?:async\s+)?def\s+pytest_[A-Za-z0-9_]+\s*\(")
_STATIC_FILE_CONDITION = re.compile(
    r"(?ms)^(?P<prefix>.*?)^[ \t]*if[ \t]+\[[ \t]+-(?P<kind>[fd])"
    r"[ \t]+(?P<path>[A-Za-z0-9_./\\-]+)[ \t]*\][ \t]*;[ \t]*then[ \t]+"
    r"(?P<body>[^;]+?)[ \t]*;[ \t]*fi(?P<suffix>.*)$"
)
_KNOWN_EXTERNAL_ACTIONS = {
    "actions/checkout",
    "actions/setup-python",
    "actions/setup-node",
    "actions/setup-go",
    "actions/setup-java",
    "actions/cache",
    "actions/upload-artifact",
    "actions/download-artifact",
    "actions/dependency-review-action",
    "github/codeql-action/init",
    "github/codeql-action/autobuild",
    "github/codeql-action/analyze",
    "github/codeql-action/upload-sarif",
    "ossf/scorecard-action",
    "anchore/sbom-action",
    "actions/attest-build-provenance",
    "astral-sh/setup-uv",
    "deadsnakes/action",
    "docker/setup-qemu-action",
    "pypa/gh-action-pypi-publish",
    "softprops/action-gh-release",
    "hynek/build-and-inspect-python-package",
    "zizmorcore/zizmor-action",
}
# Only these external actions have a deliberately narrow, workspace-safe
# contract in the analyzer.  All other external actions remain UNKNOWN even
# when their names are familiar; a known action is not proof that its code or
# configurable outputs cannot affect the checkout.
_PROVEN_WORKSPACE_SAFE_ACTIONS = {
    "actions/setup-python",
    "actions/setup-node",
    "actions/setup-go",
    "actions/setup-java",
    "astral-sh/setup-uv",
    "deadsnakes/action",
    "docker/setup-qemu-action",
}
_WORKSPACE_RESTORING_ACTIONS = {
    "actions/cache",
    "actions/download-artifact",
}
_SAFE_SETUP_COMMANDS = {
    "[",
    "cat",
    "chmod",
    "cp",
    "cd",
    ".",
    "echo",
    "env",
    "exit",
    "export",
    "git",
    "grep",
    "ls",
    "mkdir",
    "mv",
    "pip",
    "pip3",
    "pip-audit",
    "printf",
    "pwd",
    "rm",
    "return",
    "set",
    "sha256sum",
    "sort",
    "test",
    "touch",
    "true",
    "uname",
    "which",
}
# Runner relevance and workspace safety are separate contracts.  This set is
# intentionally small: commands not listed here must be audited by their
# command-specific effect classifier rather than inheriting safety from the
# setup-command allowlist above.
_WORKSPACE_READ_ONLY_COMMANDS = {
    "[",
    "cat",
    "cd",
    "echo",
    "env",
    "export",
    "exit",
    "grep",
    "ls",
    "pwd",
    "printf",
    "return",
    "set",
    "sha256sum",
    "sort",
    "test",
    "true",
    "uname",
    "which",
}
_WORKSPACE_MODELED_COMMANDS = {
    "greengap",
    "mypy",
    "pip-audit",
    "pyright",
    "ruff",
    "twine",
}
_SAFE_PYTHON_MODULES = {
    "compileall",
    "coverage",
    "pip",
    "pip_audit",
    "pre-commit",
    "pytest",
    "venv",
    "mypy",
    "ruff",
    "twine",
}

WorkspaceState = Literal[
    "PROVEN_READ_ONLY",
    "MODELED_STATE_TRANSITION",
    "UNKNOWN_SIDE_EFFECT",
]
PROVEN_READ_ONLY: WorkspaceState = "PROVEN_READ_ONLY"
MODELED_STATE_TRANSITION: WorkspaceState = "MODELED_STATE_TRANSITION"
UNKNOWN_SIDE_EFFECT: WorkspaceState = "UNKNOWN_SIDE_EFFECT"

_PYTEST_CONFIG_NAMES = (
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
)
_PYTEST_CONFIG_IGNORED_PARTS = {".git", ".venv", ".tox", ".nox", "venv"}


def _merge_workspace_state(left: WorkspaceState, right: WorkspaceState) -> WorkspaceState:
    if UNKNOWN_SIDE_EFFECT in (left, right):
        return UNKNOWN_SIDE_EFFECT
    if MODELED_STATE_TRANSITION in (left, right):
        return MODELED_STATE_TRANSITION
    return PROVEN_READ_ONLY
@dataclass(frozen=True)
class _Context:
    cwd: Path
    env: dict[str, str]
    matrix: dict[str, Any]
    inputs: dict[str, Any]
    provenance: tuple[str, ...]
    event_context: str | None = None
    workspace_state: WorkspaceState = PROVEN_READ_ONLY
    workflow_event_context: str | None = None
    runner_os: str | None = None


def _scalar(value: Any) -> str | None:
    if value is None:
        return ""
    if isinstance(value, str | int | float | bool):
        return str(value).lower() if isinstance(value, bool) else str(value)
    return None


def _lookup(name: str, context: _Context) -> Any | None:
    pieces = name.strip().split(".")
    if len(pieces) != 2:
        return None
    scope, key = pieces
    if scope == "matrix":
        return context.matrix.get(key)
    if scope == "env":
        return context.env.get(key)
    if scope == "inputs":
        return context.inputs.get(key)
    if scope == "github" and key == "event_name":
        # GitHub Actions exposes the bound event name in every workflow run.
        return context.event_context
    return None


def _expression_value(expression: str, context: _Context) -> str | None:
    expression = expression.strip()
    for part in (part.strip() for part in expression.split("||")):
        if part.startswith("format(") and part.endswith(")"):
            inner = part[len("format(") : -1]
            match = re.match(r"\s*(['\"])(.*?)\1\s*,\s*(.*?)\s*$", inner)
            if not match:
                return None
            template, argument = match.group(2), match.group(3)
            value = _lookup(argument, context)
            if value is None:
                return None
            return template.replace("{0}", str(value))
        if len(part) >= 2 and part[0] == part[-1] and part[0] in "'\"":
            return part[1:-1]
        value = _lookup(part, context)
        if value is not None and str(value) != "":
            return str(value)
    return None


def _condition_value(value: Any, context: _Context | None = None) -> bool | None:
    """Evaluate only literal workflow conditions; all context is otherwise unknown."""

    if value is None:
        return True
    if isinstance(value, bool):
        return value
    text = _scalar(value)
    if text is None:
        return None
    stripped = text.strip()
    if stripped.startswith("${{") and stripped.endswith("}}"):
        stripped = stripped[3:-2].strip()
    lowered = stripped.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if context is not None:
        direct = _lookup(stripped, context)
        if direct is not None:
            return bool(direct)
        match = re.fullmatch(
            r"([A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*)\s*(==|!=)\s*(['\"])(.*?)\3",
            stripped,
        )
        if match:
            actual = _lookup(match.group(1), context)
            if actual is None:
                return None
            equal = str(actual) == match.group(4)
            return equal if match.group(2) == "==" else not equal
        function_match = re.fullmatch(
            r"(startsWith|endsWith)\(\s*([A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*)\s*,\s*(['\"])(.*?)\3\s*\)",
            stripped,
        )
        if function_match:
            actual = _lookup(function_match.group(2), context)
            if actual is None:
                return None
            text_actual = str(actual)
            suffix = function_match.group(4)
            if function_match.group(1) == "startsWith":
                return text_actual.startswith(suffix)
            return text_actual.endswith(suffix)
    return None


def _structure_too_deep(value: Any, limit: int = MAX_YAML_DEPTH) -> bool:
    pending: list[tuple[Any, int]] = [(value, 1)]
    seen: set[int] = set()
    while pending:
        item, depth = pending.pop()
        if isinstance(item, dict | list):
            identity = id(item)
            if identity in seen:
                continue
            seen.add(identity)
        if depth > limit:
            return True
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return False


def _event_signature(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return json.dumps(sorted(value))
    if isinstance(value, dict):
        try:
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            return None
    return None


def _event_kinds(value: Any) -> set[str] | None:
    """Return event kinds with the narrow branch/tag filters we can prove."""

    def one(name: str, config: Any = None) -> str:
        if name != "push" or not isinstance(config, dict):
            return f"{name}:any"
        has_tags = "tags" in config or "tags-ignore" in config
        has_branches = "branches" in config or "branches-ignore" in config
        if has_tags and not has_branches:
            return "push:tags"
        if has_branches and not has_tags:
            return "push:branches"
        return "push:any"

    if isinstance(value, str):
        return {one(value)}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return {one(item) for item in value}
    if isinstance(value, dict):
        if not value:
            return {"*:any"}
        if all(isinstance(key, str) for key in value):
            return {one(str(key), config) for key, config in value.items()}
    return None


def _event_kinds_overlap(left: str, right: str) -> bool:
    left_name, _, left_filter = left.partition(":")
    right_name, _, right_filter = right.partition(":")
    if "*" in {left_name, right_name} or left_name == right_name:
        return left_filter == right_filter or "any" in {left_filter, right_filter}
    return False


def _contains_runner_hint(value: str) -> bool:
    tokens = _tokens(value)
    if not tokens:
        return False
    # Environment/prefix wrappers are part of the command spelling, not the
    # executable identity.  Strip only the statically recognized wrappers so
    # a default-shell assignment such as ``PYTEST_ADDOPTS=... pytest`` still
    # counts as a relevant pytest boundary (and cannot hide behind the
    # neutral-parser rejection).
    tokens = _command_core_tokens(tokens)
    if not tokens:
        return False
    first = _basename(tokens[0])
    if first in {"pytest", "pytest.exe", "tox", "tox.exe", "nox", "invoke", "pre-commit", "pre_commit"}:
        return True
    if first.endswith("pytest") or first.endswith("pytest.exe"):
        return True
    if first.endswith("coverage") or first.endswith("coverage.exe"):
        return (
            len(tokens) > 2
            and tokens[1] == "run"
            and any(
                index + 1 < len(tokens)
                and token == "-m"
                and _basename(tokens[index + 1]) == "pytest"
                for index, token in enumerate(tokens[2:-1], start=2)
            )
        )
    if first in {"make", "gmake"}:
        return any(token.lower() in {"test", "tests", "check", "check-all"} for token in tokens[1:])
    if first == "coverage":
        return len(tokens) > 1 and tokens[1] == "run"
    if first.startswith("python") or first == "py":
        return any(
            index + 1 < len(tokens)
            and token == "-m"
            and _basename(tokens[index + 1]) in {"pytest", "pre-commit", "pre_commit"}
            for index, token in enumerate(tokens[:-1])
        )
    if first in {"npm", "pnpm", "yarn"}:
        arguments = tokens[1:]
        return "test" in arguments or (
            len(arguments) > 1 and arguments[0] == "run" and arguments[1] == "test"
        )
    if first == "just":
        return any(token.lower() in {"test", "tests", "check", "check-all"} for token in tokens[1:])
    return False


def _has_unquoted(command: str, needle: str) -> bool:
    in_single = False
    in_double = False
    escaped = False
    index = 0
    while index < len(command):
        character = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "\\" and not in_single:
            escaped = True
            index += 1
            continue
        if character == "'" and not in_double:
            in_single = not in_single
            index += 1
            continue
        if character == '"' and not in_single:
            in_double = not in_double
            index += 1
            continue
        if not in_single and not in_double and command.startswith(needle, index):
            return True
        index += 1
    return False


def _runner_segment_count(command: str) -> int:
    return sum(_contains_runner_hint(piece) for piece in _shell_segments(command))


def _has_unsafe_redirection(command: str) -> bool:
    return any(
        _contains_runner_hint(line)
        and (_has_unquoted(line, ">") or _has_unquoted(line, "<"))
        for line in command.splitlines()
    )


def _shell_control_flow_unknown(command: str) -> bool:
    """Reject branches/alternatives that can change whether a test command runs."""

    runner_present = any(_contains_runner_hint(piece) for piece in _shell_segments(command))
    if any(_has_unquoted(command, operator) for operator in ("&&", "||")) and runner_present:
        return True
    if _has_unsafe_redirection(command) and runner_present:
        return True
    if _runner_segment_count(command) > 1:
        return True
    # A setup-only pipeline such as ``env | sort`` does not affect whether a
    # test command is selected.  Pipelines that contain a runner remain
    # unknown because the pipe can change its arguments, output, or exit
    # status.  This keeps the subset fail-closed without rejecting harmless
    # diagnostics in otherwise analyzable scripts.
    if any(
        "|" in line and any(_contains_runner_hint(part) for part in line.split("|"))
        for line in command.splitlines()
    ):
        return True
    if re.search(r"(?m)(?:^|;)\s*cd\b[^;\n]*(?:;|$)", command) and runner_present:
        return True
    lines = command.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip().lower()
        if not re.match(r"^(?:if|elif|while|for|case)\b", stripped):
            continue
        body: list[str] = []
        if "then" in stripped:
            inline_body = stripped.split("then", 1)[1]
            if "fi" in inline_body:
                inline_body = inline_body.split("fi", 1)[0]
            body.append(inline_body)
            if _contains_runner_hint(inline_body):
                return True
        depth = 0
        for child in lines[index + 1 :]:
            child_stripped = child.strip().lower()
            if re.match(r"^(?:if|while|for|case)\b", child_stripped):
                depth += 1
            if child_stripped in {"fi", "done", "esac"}:
                if depth == 0:
                    break
                depth -= 1
            body.append(child)
        if _contains_runner_hint("\n".join(body)):
            return True
    return False


def _powershell_control_flow_unknown(command: str) -> bool:
    """Reject PowerShell syntax outside the direct-command subset."""

    if any(
        _has_unquoted(command, operator) for operator in ("&&", "||", ">", "<", "|")
    ):
        return True
    if _has_unquoted(command, ";"):
        return True
    return any(
        re.match(r"^(?:if|elseif|else|while|for|foreach|switch|try|catch|finally)\b", line.strip(), re.I)
        or re.search(r"\$\([^\n]*\)", line)
        or re.match(r"^\s*&\s*", line)
        for line in command.splitlines()
    )


def resolve_expressions(value: str, context: _Context) -> tuple[str, bool]:
    """Resolve only expressions whose value is statically known."""

    complete = True

    def replace(match: re.Match[str]) -> str:
        nonlocal complete
        resolved = _expression_value(match.group(1), context)
        if resolved is None:
            complete = False
            return match.group(0)
        return resolved

    return _EXPRESSION.sub(replace, value), complete


def _static_shell(value: Any, context: _Context) -> str | None:
    text = _scalar(value)
    if text is None:
        return "unknown"
    resolved, known = resolve_expressions(text, context)
    if not known:
        return "unknown"
    # GitHub's custom shell form is ``command [args...] {0}``.  Looking only
    # at the first word would treat a wrapper/template as the built-in shell,
    # even though its startup flags or executable can change command
    # semantics.  The explicitly enumerated Bash templates below invoke Bash
    # directly once with the generated script as its only script argument.
    # Their flags only control Bash startup/error handling; they cannot source
    # repository code ahead of the generated script.  Every other template,
    # including a wrapper around ``{0}``, remains unknown.
    normalized = resolved.strip().lower()
    if normalized in {
        "bash",
        "bash {0}",
        "bash --noprofile --norc -e -o pipefail {0}",
        "bash --noprofile --norc -eo pipefail {0}",
        "sh",
    }:
        return "bash"
    if normalized in {"pwsh", "powershell"}:
        return "powershell"
    return "unknown"


def _static_setup_python_runtime(value: Any, context: _Context) -> bool:
    """Accept only a directly resolved Python runtime selector.

    ``actions/setup-python`` changes the executable that a later ``python -m
    pytest`` or ``pytest`` can resolve to. A dynamic version file/range is
    therefore not merely setup metadata: it is an unmodeled runner-identity
    boundary. A static minor/patch (including a resolved matrix value) is
    enough for the v0.1 action subset; wildcards and version files are not.
    """

    if not isinstance(value, dict) or "python-version-file" in value:
        return False
    raw_version = _scalar(value.get("python-version"))
    if raw_version is None:
        return False
    version, known = resolve_expressions(raw_version, context)
    if not known or not version.strip():
        return False
    return not any(marker in version for marker in ("*", "<", ">", "=", "!", "~", "^")) and not (
        version.strip().lower().endswith((".x", "-x"))
    )


def _default_shell(
    defaults: Any, runs_on: Any, context: _Context, fallback: str | None = None
) -> str | None:
    """Resolve an explicit shell or return the runner-neutral default.

    ``runs-on`` is routing metadata, not an attestation of the physical
    runner.  In particular it cannot select Bash versus PowerShell.  Steps
    without an explicit shell therefore use the tiny neutral command grammar
    and reject shell-specific syntax later in the resolver.
    """

    del runs_on  # retained in the internal signature for call-site stability
    if defaults is not None:
        if not isinstance(defaults, dict):
            return "unknown"
        run_defaults = defaults.get("run")
        if run_defaults is not None:
            if not isinstance(run_defaults, dict):
                return "unknown"
            if "shell" in run_defaults:
                return _static_shell(run_defaults.get("shell"), context)
            if fallback is not None:
                return fallback
    if fallback is not None:
        return fallback
    return _NEUTRAL_SHELL


def _runner_platform(runs_on: Any, context: _Context) -> str:
    """Return no platform identity from workflow routing metadata.

    GitHub permits self-hosted runners to carry arbitrary labels (including
    hosted-looking labels) and to omit the ``self-hosted`` label.  A static
    workflow trace therefore has no sound way to derive OS, filesystem case,
    shell, or executable identity from ``runs-on``.  Keep this compatibility
    helper, but make its unbound result explicit and load-bearing code must not
    treat routing labels as platform evidence.
    """

    del runs_on, context
    return "unknown"


def _matrix_rows(spec: Any) -> tuple[list[dict[str, Any]] | None, str | None]:
    if spec is None:
        return [{}], None
    if not isinstance(spec, dict):
        return None, "matrix must be a statically shaped mapping"
    if any(not isinstance(key, str) for key in spec):
        return None, "matrix keys must be strings"
    axes = {key: value for key, value in spec.items() if key not in {"include", "exclude"}}
    values: dict[str, list[Any]] = {}
    for key, value in axes.items():
        if isinstance(value, list):
            if any(not isinstance(item, str | int | float | bool | type(None)) for item in value):
                return None, f"matrix axis {key!r} contains a non-scalar value"
            values[key] = value
        elif isinstance(value, str | int | float | bool):
            values[key] = [value]
        else:
            return None, f"matrix axis {key!r} is not statically enumerable"
    keys = tuple(values)
    combinations = 1
    for key in keys:
        combinations *= len(values[key])
        if combinations > MAX_MATRIX_ROWS:
            return None, f"limit: matrix expands beyond GitHub's {MAX_MATRIX_ROWS}-job limit"
    if not keys and "include" in spec:
        rows: list[dict[str, Any]] = []
    else:
        rows = [
            dict(zip(keys, combination, strict=False))
            for combination in itertools.product(*(values[key] for key in keys))
        ]
    excludes = spec.get("exclude", [])
    if excludes is not None:
        if not isinstance(excludes, list) or any(not isinstance(item, dict) for item in excludes):
            return None, "matrix.exclude is not a static list of mappings"
        if any(any(not isinstance(key, str) for key in item) for item in excludes):
            return None, "matrix.exclude keys must be strings"
        if any(
            any(
                not isinstance(value, str | int | float | bool | type(None))
                for value in item.values()
            )
            for item in excludes
        ):
            return None, "matrix.exclude contains a non-scalar value"
        rows = [
            row
            for row in rows
            if not any(all(row.get(k) == v for k, v in item.items()) for item in excludes)
        ]
    includes = spec.get("include", [])
    if includes is not None:
        if not isinstance(includes, list) or any(not isinstance(item, dict) for item in includes):
            return None, "matrix.include is not a static list of mappings"
        if any(any(not isinstance(key, str) for key in item) for item in includes):
            return None, "matrix.include keys must be strings"
        if any(
            any(
                not isinstance(value, str | int | float | bool | type(None))
                for value in item.values()
            )
            for item in includes
        ):
            return None, "matrix.include contains a non-scalar value"
        original_rows = [dict(row) for row in rows]
        for item in includes:
            merged = False
            for index, original in enumerate(original_rows):
                if all(key not in original or original[key] == value for key, value in item.items()):
                    rows[index].update(item)
                    merged = True
            if not merged:
                rows.append(dict(item))
            if len(rows) > MAX_MATRIX_ROWS:
                return None, f"limit: matrix expands beyond GitHub's {MAX_MATRIX_ROWS}-job limit"
    return rows, None


def _shell_segments(command: str) -> tuple[str, ...]:
    def split_operators(line: str) -> tuple[str, ...]:
        pieces: list[str] = []
        current: list[str] = []
        quote: str | None = None
        escaped = False
        index = 0
        while index < len(line):
            character = line[index]
            if escaped:
                current.append(character)
                escaped = False
                index += 1
                continue
            if character == "\\" and quote != "'":
                current.append(character)
                escaped = True
                index += 1
                continue
            if quote is not None:
                current.append(character)
                if character == quote:
                    quote = None
                index += 1
                continue
            if character in {"'", '"'}:
                quote = character
                current.append(character)
                index += 1
                continue
            if character == ";" or line.startswith("&&", index) or line.startswith("||", index):
                pieces.append("".join(current))
                current = []
                index += 2 if character != ";" else 1
                continue
            current.append(character)
            index += 1
        pieces.append("".join(current))
        return tuple(pieces)

    logical_lines: list[str] = []
    pending = ""
    heredoc: str | None = None
    for line in command.splitlines():
        stripped = line.strip()
        if heredoc is not None:
            if stripped == heredoc:
                heredoc = None
            continue
        heredoc_match = re.search(
            r"<<-?\s*(?:(['\"])(.*?)\1|([A-Za-z_][A-Za-z0-9_.-]*))", stripped
        )
        if heredoc_match:
            heredoc = heredoc_match.group(2) or heredoc_match.group(3)
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        logical_lines.append(pending + stripped)
        pending = ""
    if pending.strip():
        logical_lines.append(pending)
    segments: list[str] = []
    for line in logical_lines:
        if not line or line.startswith("#"):
            continue
        for piece in split_operators(line):
            piece = piece.strip()
            if not piece or piece in {"then", "fi", "else", "do", "done", "{", "}"}:
                continue
            if piece.startswith(("if ", "elif ", "while ", "for ", "case ")):
                continue
            segments.append(piece)
    return tuple(segments)


def _has_shell_command_substitution(command: str) -> bool:
    """Detect shell command substitution whose nested effects are not parsed."""

    quote: str | None = None
    escaped = False
    index = 0
    while index < len(command):
        character = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote == "'":
            if character == "'":
                quote = None
            index += 1
            continue
        if quote == '"':
            if character == '"':
                quote = None
            elif character == "`" or (
                character == "$" and index + 1 < len(command) and command[index + 1] == "("
            ) or (
                character in "<>"
                and index + 1 < len(command)
                and command[index + 1] == "("
            ):
                return True
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            continue
        if character == "`" or (
            character == "$" and index + 1 < len(command) and command[index + 1] == "("
        ) or (
            character in "<>"
            and index + 1 < len(command)
            and command[index + 1] == "("
        ):
            return True
        index += 1
    return False


def _assignment_only_command(command: str) -> bool:
    """Recognize assignments whose command-substitution output is not executed."""

    saw_assignment = False
    for segment in _shell_segments(command):
        tokens = _tokens(segment)
        if not tokens:
            continue
        if _basename(tokens[0]) == "export":
            tokens = tokens[1:]
        if tokens and all(
            re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token) is not None for token in tokens
        ):
            saw_assignment = True
            continue
        if not _safe_setup_command(tokens):
            return False
    return saw_assignment


def _safe_path_prefix(value: str) -> bool:
    return value == "" or (
        value.endswith(("/", "\\")) and bool(re.fullmatch(r"[A-Za-z0-9_./\\:-]+", value))
    )


def _safe_executable_name(value: str) -> bool:
    return value.lower() in {
        "coverage",
        "mkdocs",
        "mypy",
        "pip",
        "pip3",
        "python",
        "python3",
        "ruff",
        "twine",
    }


def _safe_command_prefix(value: str) -> bool:
    return _safe_path_prefix(value) or _safe_executable_name(value)


def _expand_safe_prefix(command: str, env: dict[str, str]) -> tuple[str | None, str | None]:
    """Expand only variables that are provable executable path prefixes."""

    output: list[str] = []
    cursor = 0
    for match in _VARIABLE.finditer(command):
        output.append(command[cursor : match.start()])
        variable = match.group(1) or match.group(2) or ""
        rest = command[match.end() :].lstrip()
        runner_like = bool(
            re.match(
                r"(?:coverage|mkdocs|mypy|pip(?:3)?|python(?:3(?:\.\d+)?)?|pytest|ruff|twine)(?:\s|/|\\|$)",
                rest,
            )
        ) or variable.upper() in {"PIP", "PIP3", "PREFIX", "PYTHON"}
        if not runner_like:
            output.append(match.group(0))
            cursor = match.end()
            continue
        if variable not in env:
            return None, f"variable prefix ${variable} is not statically known"
        value = env[variable]
        if not _safe_command_prefix(value):
            return None, f"variable prefix ${variable} has a dynamic or unsafe value"
        output.append(value)
        cursor = match.end()
    output.append(command[cursor:])
    return "".join(output), None


_NEUTRAL_FORBIDDEN = frozenset("\\'\"`$(){}*?[];|&<>#%!^~")


def _neutral_tokens(command: str) -> tuple[str, ...] | None:
    """Tokenize only shell-neutral whitespace-separated command arguments.

    A workflow step without an explicit ``shell`` inherits a runner-specific
    default that cannot be established from ``runs-on``.  The neutral subset
    therefore rejects quoting, escaping, substitutions, operators, globbing,
    and assignment prefixes instead of choosing Bash or PowerShell on behalf
    of the physical runner.
    """

    if any(character in command for character in _NEUTRAL_FORBIDDEN):
        return None
    # ``str.split`` accepts Unicode whitespace that is not a command
    # separator for the supported shells (for example, a non-breaking space),
    # and silently accepting control characters can change script parsing.
    # Keep the grammar to ordinary horizontal/line whitespace only.
    if any(
        (character.isspace() and character not in " \t\r\n")
        or (ord(character) < 0x20 and character not in "\t\r\n")
        for character in command
    ):
        return None
    tokens = tuple(command.split())
    if not tokens:
        return ()
    # A prefix assignment is shell syntax, even when its value is empty.  An
    # empty PATH/PYTHONPATH (or any other startup variable) can change whether
    # the following executable resolves at all, so never treat ``NAME=`` as a
    # portable command token.
    if any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token) for token in tokens):
        return None
    return tokens


def _neutral_command_is_portable(command: str) -> bool:
    """Return whether *command* uses only runner-neutral shell syntax.

    The neutral grammar deliberately does not try to identify which default
    shell GitHub selected on the physical runner.  It accepts independent
    whitespace-separated command lines and rejects every syntax whose meaning
    differs between Bash, PowerShell, and other runner defaults.  Validation is
    performed on the original command before ``_shell_segments`` can discard
    separators, so a hidden chain cannot become two apparently safe commands.
    """

    if any(character in command for character in _NEUTRAL_FORBIDDEN):
        return False
    return all(_neutral_tokens(segment) is not None for segment in _shell_segments(command))


def _tokens(command: str, shell: str = "bash") -> tuple[str, ...] | None:
    """Tokenize one supported shell command without changing path spelling.

    Bash uses POSIX escaping, while PowerShell treats ``\\`` as a literal
    Windows path separator.  ``shlex``'s POSIX mode silently removes those
    separators, so PowerShell gets a deliberately small non-POSIX tokenizer
    based on ``shlex.split(posix=False)``.  Complex quoting/escaping remains
    unknown rather than being reinterpreted as a different command.
    """

    if shell == _NEUTRAL_SHELL:
        return _neutral_tokens(command)
    if shell == "powershell":
        try:
            raw_tokens = shlex.split(command, posix=False)
        except ValueError:
            return None
        tokens: list[str] = []
        for token in raw_tokens:
            if (
                len(token) >= 2
                and token[0] == token[-1]
                and token[0] in {"'", '"'}
            ):
                token = token[1:-1]
            # PowerShell's backtick escapes and embedded quote forms are not
            # modeled by this bounded parser.  Reject them rather than
            # allowing a partially reconstructed argument to affect pytest.
            if any(character in token for character in ("`", "'", '"')):
                return None
            tokens.append(token)
        return tuple(tokens)
    try:
        lexer = shlex.shlex(command, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        return tuple(lexer)
    except ValueError:
        return None


def _lexical_repo_path(root: Path, value: str, base: Path | None = None) -> str | None:
    """Return a normalized repository-relative spelling without resolving it.

    ``Path.resolve`` follows the analyst host's case and separator rules.  A
    lexical spelling lets a known case-sensitive runner detect when a
    case-insensitive analyst host silently canonicalized a different target.
    Safety is still established separately by ``safe_resolve``.
    """

    root_absolute = Path(os.path.abspath(root))
    raw = Path(value)
    if not raw.is_absolute():
        raw = (base or root_absolute) / raw
    lexical = Path(os.path.normpath(os.fspath(raw)))
    try:
        relative = lexical.relative_to(root_absolute)
    except ValueError:
        return None
    value = relative.as_posix()
    return "" if value == "." else value


def _casefold_repo_matches(root: Path, relative: str) -> tuple[Path, ...] | None:
    """Find repository paths matching *relative* under case-folding.

    This is used only to detect a case-insensitive analyst host canonicalizing
    a target that a case-sensitive runner would spell differently.  Directory
    enumeration is deliberately bounded; inability to establish a unique
    match is handled as UNKNOWN by the caller.
    """

    current = [root]
    parts = Path(relative).parts if relative else ()
    for part in parts:
        next_paths: list[Path] = []
        for parent in current:
            try:
                entries = parent.iterdir()
                for inspected, entry in enumerate(entries, start=1):
                    if inspected > 4096:
                        return None
                    if entry.name.casefold() == part.casefold():
                        next_paths.append(entry)
                        if len(next_paths) > 1:
                            return tuple(next_paths)
            except OSError:
                return None
        current = next_paths
        if not current:
            return ()
    return tuple(current)


def _portable_path_case_error(root: Path, relative: str) -> str | None:
    """Check exact component spelling without inheriting analyst-host rules.

    A runner-neutral selector must spell every existing component exactly as
    it appears in the checkout.  Walking directory entries also lets us detect
    a case-fold collision when the checkout is on a case-sensitive host.  A
    missing final component is left alone for compatibility with workflows that
    generate selectors before pytest starts; any existing prefix is still
    checked strictly.
    """

    current: list[Path] = [root]
    for part in Path(relative).parts if relative else ():
        if part in {"", "."}:
            continue
        next_paths: list[Path] = []
        for parent in current:
            try:
                matches = [
                    entry
                    for entry in parent.iterdir()
                    if entry.name.casefold() == part.casefold()
                ]
            except OSError:
                return "pytest path component could not be inspected safely"
            if len(matches) > 1:
                return f"pytest path component {part!r} has a case-fold collision"
            if not matches:
                # The selector may refer to a generated path.  There is no
                # existing component whose case can contradict the spelling.
                return None
            match = matches[0]
            if match.name != part:
                return (
                    f"pytest path component {part!r} does not match repository spelling "
                    f"{match.name!r}"
                )
            next_paths.append(match)
        current = next_paths
    return None


def _portable_repo_path(
    root: Path, value: str, base: Path | None = None
) -> tuple[str | None, Path | None, str | None]:
    """Resolve a repository-relative path using portable spelling rules.

    GreenGap runs on an analyst machine that may have different separator and
    case semantics from CI.  Only forward-slash, relative, statically spelled
    paths are accepted.  ``safe_resolve`` still enforces symlink and repository
    boundaries; the lexical and directory-entry checks prevent it from
    silently canonicalizing a different spelling on the analyst host.
    """

    if "\\" in value:
        return None, None, "path uses a runner-specific backslash separator"
    if re.match(r"^[A-Za-z]:", value):
        return None, None, "path is drive-qualified"
    if ":" in value:
        return None, None, "path contains a non-portable drive or stream separator"
    try:
        raw = Path(value)
    except (OSError, ValueError):
        return None, None, "path could not be parsed safely"
    if raw.is_absolute():
        return None, None, "path is absolute rather than repository-relative"
    lexical = _lexical_repo_path(root, value, base)
    if lexical is None:
        return None, None, "path escapes the repository"
    case_error = _portable_path_case_error(root, lexical)
    if case_error is not None:
        return lexical, None, case_error
    try:
        resolved = safe_resolve(root, lexical)
    except PathSafetyError as exc:
        return lexical, None, f"path is unsafe: {exc}"
    try:
        normalized = normalize_repo_path(root, resolved)
    except PathSafetyError as exc:
        return lexical, None, f"path is unsafe: {exc}"
    if normalized == ".":
        normalized = ""
    # ``Path.resolve`` on a case-insensitive analyst host may canonicalize an
    # existing component.  A mismatch means the selector is not portable.
    if normalized != lexical:
        return lexical, None, "path spelling is not exact for the repository"
    return lexical, resolved, None


def _basename(token: str) -> str:
    return token.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _safe_python_code(tokens: tuple[str, ...]) -> bool:
    """Allow only a tiny read-only diagnostic subset of ``python -c``."""

    try:
        code_index = tokens.index("-c")
        tree = ast.parse(" ".join(tokens[code_index + 1 :]), mode="exec")
    except (ValueError, SyntaxError):
        return False
    imported: set[str] = set()
    allowed_modules = {"platform", "struct", "sys"}
    allowed_attributes = {
        "platform": {"platform", "python_version"},
        "struct": {"calcsize"},
        "sys": {"version", "version_info"},
    }
    allowed_functions = {"bool", "float", "int", "len", "print", "repr", "str", "tuple"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name not in allowed_modules for alias in node.names):
                return False
            imported.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module not in allowed_modules or any(alias.name == "*" for alias in node.names):
                return False
            imported.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load) and node.id not in imported | allowed_functions:
                return False
        elif isinstance(node, ast.Attribute):
            if not isinstance(node.value, ast.Name):
                return False
            if node.value.id not in imported:
                return False
            module = node.value.id
            if node.attr not in allowed_attributes.get(module, set()):
                return False
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id not in allowed_functions:
                    return False
            elif isinstance(node.func, ast.Attribute):
                if not isinstance(node.func.value, ast.Name):
                    return False
                module = node.func.value.id
                if node.func.attr not in allowed_attributes.get(module, set()):
                    return False
            else:
                return False
        elif isinstance(
            node,
            ast.Module
            | ast.Expr
            | ast.Constant
            | ast.JoinedStr
            | ast.FormattedValue
            | ast.BinOp
            | ast.UnaryOp
            | ast.BoolOp
            | ast.Compare
            | ast.IfExp
            | ast.Tuple
            | ast.List
            | ast.Set
            | ast.Dict
            | ast.alias
            | ast.keyword
            | ast.Load
            | ast.operator
            | ast.unaryop
            | ast.boolop
            | ast.cmpop,
        ):
            continue
        else:
            return False
    return True


def _known_read_only_python_script(tokens: tuple[str, ...]) -> bool:
    """Recognize the explicit check-only mode of the unasync helper."""

    if len(tokens) < 3 or not _basename(tokens[0]).startswith("python"):
        return False
    script = tokens[1].replace("\\", "/").lower()
    return (script == "scripts/unasync.py" or script.endswith("/scripts/unasync.py")) and tokens[2:] == ("--check",)


def _safe_setup_command(tokens: tuple[str, ...]) -> bool:
    """Recognize commands that cannot select or execute the test suite by themselves."""

    if not tokens:
        return True
    first = _basename(tokens[0])
    if first in {"mypy", "ruff", "twine"}:
        return True
    if first == "pyright":
        return _safe_pyright_workspace_command(tuple(tokens[1:]))
    if first == "git":
        return _safe_git_command(tokens)
    if first in _SAFE_SETUP_COMMANDS:
        return True
    if first == "gh":
        return _safe_gh_command(tokens)
    if first == "mkdocs":
        return len(tokens) > 1 and tokens[1] == "build"
    if first == "greengap":
        return set(tokens[1:]).issubset({"--version", "--help"})
    if first == "coverage":
        return len(tokens) > 1 and tokens[1] in {"erase", "combine", "xml", "report"}
    if first.startswith("python"):
        if len(tokens) == 1:
            return True
        if _known_read_only_python_script(tokens):
            return True
        if "-c" in tokens:
            return _safe_python_code(tokens)
        for index, token in enumerate(tokens[:-1]):
            if token == "-m":
                return _basename(tokens[index + 1]) in _SAFE_PYTHON_MODULES
        return False
    return False


def _safe_gh_command(tokens: tuple[str, ...]) -> bool:
    """Recognize only statically read-only GitHub CLI commands.

    ``gh`` has both read-only queries and commands that can materialize files
    in the current directory (for example ``gh release download --dir .``).
    The default is therefore unknown; only an explicit read-only subset is
    trusted here.
    """

    if len(tokens) < 2 or _basename(tokens[0]).lower() != "gh":
        return False
    subcommand = tuple(token.lower() for token in tokens[1:])
    if subcommand[:2] in {
        ("release", "view"),
        ("release", "list"),
        ("pr", "view"),
        ("pr", "list"),
        ("pr", "checks"),
        ("run", "view"),
        ("run", "list"),
        ("repo", "view"),
        ("workflow", "view"),
        ("workflow", "list"),
    }:
        return True
    if subcommand[0] == "api":
        for index, token in enumerate(subcommand[1:], start=1):
            if token in {"-x", "--method"} and index + 1 < len(subcommand):
                return subcommand[index + 1] == "get"
            if token.startswith("--method="):
                return token.partition("=")[2] == "get"
        return True
    return False


def _safe_git_command(tokens: tuple[str, ...]) -> bool:
    """Allow only Git subcommands proven not to write repository bytes.

    Git has a large command surface and several commands that look like
    inspection but can write through options such as ``--output``.  The
    soundness boundary is therefore an explicit read-only allowlist rather
    than a mutation denylist.
    """

    if len(tokens) < 2 or _basename(tokens[0]).lower() != "git":
        return False
    arguments = tuple(token.lower() for token in tokens[1:])
    if any(token in {"--ext-diff", "--textconv"} for token in arguments[1:]):
        return False
    if any(
        token == "-o" or token == "--output" or token.startswith("--output=")
        for token in arguments[1:]
    ):
        return False
    command = arguments[0]
    if command in {
        "--version",
        "rev-parse",
        "status",
        "show-ref",
        "ls-files",
        "log",
        "describe",
        "symbolic-ref",
        "for-each-ref",
        "cat-file",
        "rev-list",
        "merge-base",
        "name-rev",
        "check-ignore",
    }:
        return True
    if command == "branch":
        return all(
            token in {"-a", "--all", "-r", "--remotes", "-l", "--list", "--show-current"}
            for token in arguments[1:]
        )
    if command == "remote":
        return len(arguments) == 1 or arguments[1] in {"-v", "--verbose", "show"}
    if command == "config":
        return any(
            token in {"--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin"}
            for token in arguments[1:]
        ) and not any(
            token in {"--add", "--replace-all", "--unset", "--unset-all", "--rename-section"}
            for token in arguments[1:]
        )
    return command == "archive"


def _command_may_run_tests(command: str) -> bool:
    """Treat every non-allowlisted command as relevant under an unknown condition."""

    segments = _shell_segments(command)
    if not segments:
        return False
    for segment in segments:
        tokens = _tokens(segment)
        if tokens is None or not _safe_setup_command(tokens):
            return True
    return False


_PRETEST_MUTATION_COMMANDS = {
    "chmod",
    "chown",
    "cp",
    "install",
    "ln",
    "mkdir",
    "mv",
    "patch",
    "rm",
    "rsync",
    "sed",
    "tee",
    "touch",
    "truncate",
}
def _segment_mutates_files(segment: str, tokens: tuple[str, ...]) -> bool:
    if _has_unquoted(segment, ">"):
        return True
    raw_command = tokens[0] if tokens else ""
    command = _basename(raw_command)
    # A repository-relative helper such as ``scripts/install`` must be
    # resolved and inspected as a script.  Treating its basename as the
    # coreutils ``install`` command makes ordinary dependency setup poison
    # every later test step.  Absolute/system commands remain conservative.
    repository_relative = raw_command.startswith(("./", "../")) or (
        ("/" in raw_command or "\\" in raw_command)
        and not raw_command.startswith(("/", "\\"))
        and not re.match(r"^[A-Za-z]:[\\/]", raw_command)
    )
    if command in _PRETEST_MUTATION_COMMANDS and not repository_relative:
        return True
    if command == "sort" and any(
        token == "-o" or token == "--output" or token.startswith("--output=")
        for token in tokens[1:]
    ):
        return True
    if command == "coverage" and any(
        token in {"-o", "--output-file"}
        or token.startswith("--output-file=")
        for token in tokens[1:]
    ):
        return True
    if command == "git":
        return not _safe_git_command(tokens)
    return False


def _pretest_mutation_unknown(command: str) -> bool:
    """Detect file-changing commands that precede a statically visible runner."""

    segments = _shell_segments(command)
    runner_visible = any(_contains_runner_hint(segment) for segment in segments)
    if not runner_visible:
        return False
    for segment in segments:
        tokens = _tokens(segment)
        if not tokens:
            continue
        if _contains_runner_hint(segment):
            return False
        if _segment_mutates_files(segment, tokens):
            return True
    return False


def _pretest_script_unknown(command: str) -> bool:
    """Require lifecycle setup to be statically harmless or test-resolvable."""

    for segment in _shell_segments(command):
        tokens = _tokens(segment)
        if tokens is None or _segment_mutates_files(segment, tokens):
            return True
        if all(re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token) for token in tokens):
            continue
        if _contains_runner_hint(segment) or _safe_setup_command(tokens):
            continue
        return True
    return False


def _script_contains_file_mutation(command: str) -> bool:
    for segment in _shell_segments(command):
        tokens = _tokens(segment)
        if tokens and _segment_mutates_files(segment, tokens):
            return True
    return False


def _command_core_tokens(tokens: tuple[str, ...]) -> tuple[str, ...]:
    """Remove shell environment/prefix wrappers before classifying an effect."""

    remaining = list(tokens)
    while remaining and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", remaining[0]):
        remaining.pop(0)
    if remaining and _basename(remaining[0]) == "export":
        remaining.pop(0)
        while remaining and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", remaining[0]):
            remaining.pop(0)
    if remaining and _basename(remaining[0]) == "env":
        remaining.pop(0)
        while remaining and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", remaining[0]):
            remaining.pop(0)
    while remaining and _basename(remaining[0]) in {"command", "exec", "time"}:
        remaining.pop(0)
    if remaining and _basename(remaining[0]) == "cross-env":
        remaining.pop(0)
        while remaining and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", remaining[0]):
            remaining.pop(0)
    return tuple(remaining)


def _implicit_tool_config_present(tool: str, root: Path | None, cwd: Path | None) -> bool:
    """Reject auto-discovered tool configuration unless it is modeled explicitly."""

    if root is None or cwd is None:
        return True
    try:
        repository = root.resolve()
        current = cwd.resolve()
        current.relative_to(repository)
    except (OSError, RuntimeError, ValueError):
        return True
    config_names = {
        "ruff": ("ruff.toml", ".ruff.toml", "pyproject.toml"),
        "mypy": ("mypy.ini", ".mypy.ini", "pyproject.toml", "setup.cfg"),
        "coverage": (
            ".coveragerc",
            "coverage.ini",
            "pyproject.toml",
            "setup.cfg",
            "tox.ini",
        ),
    }.get(tool)
    if config_names is None:
        return True
    while True:
        for name in config_names:
            path = current / name
            if not path.is_file():
                continue
            if name in {"ruff.toml", ".ruff.toml", ".coveragerc", "coverage.ini"}:
                return True
            try:
                text = read_limited_text(path, MAX_CONFIG_BYTES)
            except (OSError, ValueError, UnicodeError):
                return True
            lowered = text.lower()
            if name == "pyproject.toml":
                section = {
                    "ruff": "[tool.ruff",
                    "mypy": "[tool.mypy",
                    "coverage": "[tool.coverage",
                }[tool]
                if section in lowered:
                    return True
            elif (
                tool == "mypy" and re.search(r"(?m)^\s*\[mypy(?:[-\]]|\])", lowered)
            ) or (tool == "coverage" and re.search(r"(?m)^\s*\[coverage:", lowered)):
                return True
        if current == repository:
            return False
        parent = current.parent
        if parent == current:
            return False
        try:
            parent.relative_to(repository)
        except ValueError:
            return False
        current = parent


def _pytest_config_addopts(path: Path) -> tuple[bool, Any]:
    """Return whether *path* is a pytest config and expose its implicit addopts."""

    name = path.name.lower()
    try:
        if name in {"pytest.toml", ".pytest.toml", "pyproject.toml"}:
            data = tomllib.loads(read_limited_text(path, MAX_CONFIG_BYTES))
            if name in {"pytest.toml", ".pytest.toml"}:
                options = data.get("pytest")
                if options is None:
                    return True, ""
                if not isinstance(options, dict):
                    return True, None
                return True, options.get("addopts", "")
            tool = data.get("tool")
            if not isinstance(tool, dict):
                return False, ""
            options = tool.get("pytest")
            if not isinstance(options, dict):
                return False, ""
            native_options = options.get("ini_options", options)
            if not isinstance(native_options, dict):
                return True, None
            return True, native_options.get("addopts", "")

        section = {
            "pytest.ini": "pytest",
            ".pytest.ini": "pytest",
            "tox.ini": "pytest",
            "setup.cfg": "tool:pytest",
        }.get(name)
        if section is None:
            return False, ""
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.read_string(read_limited_text(path, MAX_CONFIG_BYTES))
        if not parser.has_section(section):
            return name in {"pytest.ini", ".pytest.ini"}, ""
        return True, parser.get(section, "addopts", fallback="")
    except (OSError, ValueError, UnicodeError, configparser.Error, tomllib.TOMLDecodeError):
        return True, None


def _startup_environment_unknown(
    environment: dict[str, str], shell: str, tokens: tuple[str, ...]
) -> tuple[str, str] | None:
    """Return a taint reason for startup environment hooks we cannot execute."""

    core = _command_core_tokens(tokens)
    first = _basename(core[0]) if core else ""
    bash_shells = {"bash", "sh", "zsh", "dash"}
    if environment.get("BASH_ENV", "").strip() and (
        shell in bash_shells or shell == _NEUTRAL_SHELL or first in bash_shells
    ):
        return (
            "BASH_STARTUP_ENV_UNKNOWN",
            "BASH_ENV executes before the visible shell command and is not statically audited",
        )
    python_tools = {
        "coverage",
        "mypy",
        "pip",
        "pip3",
        "pre-commit",
        "pre_commit",
        "pytest",
        "ruff",
        "tox",
        "tox.exe",
        "uv",
    }
    if environment.get("PYTHONPATH", "").strip() and (
        first in python_tools or first.startswith("python") or first == "py"
    ):
        return (
            "PYTHON_MODULE_PATH_UNKNOWN",
            "PYTHONPATH can change Python module and plugin resolution before the command runs",
        )
    if environment.get("PYTHONHOME", "").strip() and (
        first in python_tools or first.startswith("python") or first == "py"
    ):
        return (
            "PYTHON_STARTUP_ENV_UNKNOWN",
            "PYTHONHOME can change the Python runtime and module resolution before the command runs",
        )
    coverage_command = first == "coverage" or (
        (first.startswith("python") or first == "py")
        and any(
            index + 1 < len(core)
            and token == "-m"
            and _basename(core[index + 1]) == "coverage"
            for index, token in enumerate(core[:-1])
        )
    )
    if coverage_command and any(
        environment.get(name, "").strip()
        for name in ("COVERAGE_FILE", "COVERAGE_RCFILE", "COVERAGE_PROCESS_START")
    ):
        return (
            "COVERAGE_STARTUP_ENV_UNKNOWN",
            "Coverage startup environment can select executable configuration or repository output paths",
        )
    node_tools = {"node", "npm", "npm.cmd", "npx", "pnpm", "yarn"}
    if environment.get("NODE_OPTIONS", "").strip() and first in node_tools:
        return (
            "NODE_STARTUP_OPTIONS_UNKNOWN",
            "NODE_OPTIONS can preload executable code before the Node command runs",
        )
    pip_command = first in {"pip", "pip3"} or (
        (first.startswith("python") or first == "py")
        and any(
            index + 1 < len(core)
            and token == "-m"
            and _basename(core[index + 1]).lower() == "pip"
            for index, token in enumerate(core[:-1])
        )
    )
    safe_pip_environment = {
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "PIP_NO_CACHE_DIR",
        "PIP_NO_INPUT",
        "PIP_PROGRESS_BAR",
        "PIP_QUIET",
        "PIP_RETRIES",
        "PIP_TIMEOUT",
        "PIP_DEFAULT_TIMEOUT",
        "PIP_ROOT_USER_ACTION",
        "PIP_USER_AGENT_USER_DATA",
    }
    if pip_command and any(
        name.startswith("PIP_") and name not in safe_pip_environment and value.strip()
        for name, value in environment.items()
    ):
        return (
            "PIP_STARTUP_ENV_UNKNOWN",
            "PIP environment can alter the resolved distribution or installation target before pytest",
        )
    return None


def _pytest_environment_unknown(environment: dict[str, str]) -> bool:
    """Reject pytest environment controls except an explicit autoload disable.

    ``PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`` narrows the runtime surface and is
    therefore safe to carry through the direct pytest subset.  Every other
    non-empty pytest control can add arguments, load plugins, or re-enable
    plugin discovery with semantics outside this resolver.
    """

    if any(environment.get(name, "").strip() for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS")):
        return True
    if "PYTEST_DISABLE_PLUGIN_AUTOLOAD" not in environment:
        return False
    return environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"].strip().lower() not in {
        "1",
        "true",
        "yes",
        "on",
    }


def _has_option(tokens: tuple[str, ...], *names: str) -> bool:
    return any(
        token == name or token.startswith(name + "=")
        for token in tokens
        for name in names
    )


def _pip_requirement_paths(arguments: tuple[str, ...]) -> tuple[str, ...] | None:
    """Extract static ``pip -r`` paths, rejecting ambiguous option forms."""

    paths: list[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in {"-r", "--requirement"}:
            if index + 1 >= len(arguments):
                return None
            paths.append(arguments[index + 1])
            index += 2
            continue
        if token.startswith("--requirement="):
            paths.append(token.partition("=")[2])
            index += 1
            continue
        if token.startswith("-r") and len(token) > 2:
            paths.append(token[2:])
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--") and "r" in token[1:]:
            option_tail = token[1:]
            requirement_index = option_tail.find("r")
            if requirement_index >= 0:
                suffix = option_tail[requirement_index + 1 :]
                if suffix:
                    paths.append(suffix)
                    index += 1
                    continue
                if index + 1 >= len(arguments):
                    return None
                paths.append(arguments[index + 1])
                index += 2
                continue
        index += 1
    return tuple(paths)


def _pip_install_has_local_project_input(arguments: tuple[str, ...]) -> bool:
    """Detect pip install inputs that can execute a local build backend."""

    local_markers = ("./", "../", ".\\", "..\\", "/", "\\")
    remote_prefixes = (
        "http://",
        "https://",
        "git+http://",
        "git+https://",
        "svn+http://",
        "svn+https://",
        "hg+http://",
        "hg+https://",
        "bzr+http://",
        "bzr+https://",
    )
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in {"-e", "--editable"}:
            # Editable installs always execute project/VCS setup code.  The
            # source may be remote, but the command is outside the byte-stable
            # static subset and must not be trusted before a later pytest.
            return True
        if token.startswith("--editable=") or token.startswith("-e="):
            return True
        if token in {"-r", "--requirement", "-c", "--constraint"}:
            index += 2
            continue
        if token.startswith(("--requirement=", "--constraint=")):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        lowered = token.lower()
        if lowered.startswith(remote_prefixes):
            index += 1
            continue
        if token in {".", ".."} or token.startswith(local_markers) or "/" in token or "\\" in token:
            return True
        index += 1
    return False


def _pip_command_preserves_pytest_runtime(arguments: tuple[str, ...]) -> bool:
    """Accept only explicit core-pytest installs before a later pytest run.

    Installing an arbitrary wheel can register a ``pytest11`` entry point or
    replace the test executable.  Requirement/constraint indirection and all
    non-core packages therefore stay outside the predecessor subset.  The
    small exception preserves the ordinary CI shape that bootstraps only pip
    and pytest itself.
    """

    if not arguments:
        return False
    command = arguments[0].lower()
    if command in {"--version", "--help", "help", "list", "show", "check", "freeze", "debug"}:
        return True
    if command not in {"install", "i"}:
        return False
    packages: list[str] = []
    safe_flags = {
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--no-deps",
        "--no-input",
        "--pre",
        "--quiet",
        "--upgrade",
        "-q",
        "-u",
    }
    for token in arguments[1:]:
        if token.startswith("-"):
            if token.lower() in safe_flags or re.fullmatch(r"-q+", token.lower()):
                continue
            return False
        packages.append(token)
    return bool(packages) and all(
        re.fullmatch(
            r"(?:pip|pytest)(?:(?:===|==|!=|<=|>=|<|>|~=)[a-z0-9.*+!_-]+)?",
            package.lower(),
        )
        is not None
        for package in packages
    )


def _requirements_include_local_project(
    root: Path, cwd: Path, paths: tuple[str, ...], seen: frozenset[Path] = frozenset(), depth: int = 0
) -> bool:
    """Find local project/editable requirements before trusting a pip install."""

    if depth > MAX_DEPTH:
        return True
    for raw_path in paths:
        if not raw_path or any(marker in raw_path for marker in ("$", "{", "}")):
            return True
        try:
            path = safe_resolve(root, raw_path, cwd)
        except PathSafetyError:
            return True
        if path in seen:
            return True
        if not path.is_file():
            # pip cannot install from a missing requirement file, so it cannot
            # reach a local build through this reference.
            continue
        try:
            lines = read_limited_text(path, MAX_CONFIG_BYTES).splitlines()
        except (OSError, ValueError, UnicodeError):
            return True
        nested: list[str] = []
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            line = line.split(" #", 1)[0].strip()
            if line in {"-e", "--editable", ".", "./", "..", "../"}:
                return True
            if line.startswith(("-e ", "--editable ")):
                return True
            if line.startswith("-e") and not line.startswith("--"):
                return True
            if line.startswith("--editable="):
                return True
            if line.startswith("file:"):
                return True
            if line.startswith("-r ") or line.startswith("--requirement "):
                nested.append(line.split(None, 1)[1])
                continue
            if line.startswith("--requirement="):
                nested.append(line.partition("=")[2])
                continue
            if not line.startswith("-") and (
                line.startswith((".", "/", "\\"))
                or "/" in line
                or "\\" in line
            ):
                return True
        if nested and _requirements_include_local_project(
            root, path.parent, tuple(nested), seen | {path}, depth + 1
        ):
            return True
    return False


def _safe_ruff_workspace_command(arguments: tuple[str, ...]) -> bool:
    return (
        bool(arguments)
        and arguments[0] == "check"
        and not _has_option(
            arguments,
            "--add-noqa",
            "--config",
            "--fix",
            "--fix-only",
            "--output-file",
        )
    )


def _safe_mypy_workspace_command(arguments: tuple[str, ...]) -> bool:
    return not _has_option(
        arguments,
        "--any-exprs-report",
        "--cobertura-xml-report",
        "--config-file",
        "--html-report",
        "--junit-xml",
        "--linecount-report",
        "--linecoverage-report",
        "--lineprecision-report",
        "--cache-dir",
        "--sqlite-cache",
        "--txt-report",
        "--xml-report",
        "--xslt-html-report",
        "--xslt-txt-report",
    )


def _safe_pip_audit_workspace_command(arguments: tuple[str, ...]) -> bool:
    return not _has_option(arguments, "-o", "--output")


def _safe_pyright_workspace_command(arguments: tuple[str, ...]) -> bool:
    """Allow diagnostics but reject Pyright's repository-writing stub mode."""

    return not any(
        token == "--createstub" or token.startswith("--createstub=")
        for token in arguments
    )


def _safe_coverage_workspace_command(arguments: tuple[str, ...]) -> bool:
    if not arguments:
        return False
    if arguments[0] != "run":
        return not _has_option(arguments, "--rcfile", "-o", "--output-file")
    if _has_option(arguments, "--rcfile"):
        return False
    return any(
        index + 1 < len(arguments)
        and token == "-m"
        and _basename(arguments[index + 1]) == "pytest"
        for index, token in enumerate(arguments[1:-1], start=1)
    )


def _workspace_effect_for_tokens(
    segment: str,
    tokens: tuple[str, ...],
    root: Path | None = None,
    cwd: Path | None = None,
) -> WorkspaceState:
    core = _command_core_tokens(tokens)
    if not core:
        return PROVEN_READ_ONLY
    first = _basename(core[0]).lower()
    runs_coverage_module = (
        (first.startswith("python") or first == "py")
        and any(
            index + 1 < len(core)
            and token == "-m"
            and _basename(core[index + 1]).lower() == "coverage"
            for index, token in enumerate(core[:-1])
        )
    )
    if _contains_runner_hint(shlex.join(core)) and first != "coverage" and not runs_coverage_module:
        return MODELED_STATE_TRANSITION
    if first in {
        "make",
        "gmake",
        "bash",
        "sh",
        "zsh",
        "dash",
        "tox",
        "tox.exe",
    }:
        # The class-level resolver composes their nested repository commands;
        # this token-level transition only prevents them from being mistaken
        # for proven read-only commands.
        return MODELED_STATE_TRANSITION
    if first in {".", "source"}:
        return UNKNOWN_SIDE_EFFECT
    if (
        core[0].startswith(("./", "../"))
        or "/" in core[0]
        or "\\" in core[0]
    ) and (core[0].lower().endswith(".sh") or "scripts/" in core[0].replace("\\", "/")):
        return MODELED_STATE_TRANSITION
    if _segment_mutates_files(segment, tokens):
        return UNKNOWN_SIDE_EFFECT
    arguments = tuple(token.lower() for token in core[1:])
    if first == "uv":
        # ``uv run`` can synchronize the active project, resolve extras, and
        # install arbitrary distribution entry points before it reaches the
        # apparent pytest command.  Its environment boundary is deliberately
        # not treated as a transparent wrapper in the v0.1 resolver.
        return UNKNOWN_SIDE_EFFECT
    if first in {"pip", "pip3"}:
        if not _pip_command_preserves_pytest_runtime(arguments):
            return UNKNOWN_SIDE_EFFECT
        if any(
            token == option or token.startswith(option + "=")
            for token in arguments
            for option in {"--target", "--prefix", "--root", "--src"}
        ):
            return UNKNOWN_SIDE_EFFECT
        if _pip_install_has_local_project_input(arguments):
            return UNKNOWN_SIDE_EFFECT
        requirement_paths = _pip_requirement_paths(arguments)
        if requirement_paths is None:
            return UNKNOWN_SIDE_EFFECT
        if requirement_paths and (
            root is None
            or cwd is None
            or _requirements_include_local_project(root, cwd, requirement_paths)
        ):
            return UNKNOWN_SIDE_EFFECT
        return MODELED_STATE_TRANSITION
    if first == "ruff":
        return (
            MODELED_STATE_TRANSITION
            if _safe_ruff_workspace_command(arguments)
            and not _implicit_tool_config_present("ruff", root, cwd)
            else UNKNOWN_SIDE_EFFECT
        )
    if first == "mypy":
        return (
            MODELED_STATE_TRANSITION
            if _safe_mypy_workspace_command(arguments)
            and not _implicit_tool_config_present("mypy", root, cwd)
            else UNKNOWN_SIDE_EFFECT
        )
    if first == "pip-audit":
        return MODELED_STATE_TRANSITION if _safe_pip_audit_workspace_command(arguments) else UNKNOWN_SIDE_EFFECT
    if first == "pyright":
        return (
            MODELED_STATE_TRANSITION
            if _safe_pyright_workspace_command(arguments)
            else UNKNOWN_SIDE_EFFECT
        )
    if first == "greengap":
        return (
            MODELED_STATE_TRANSITION
            if _safe_setup_command(core)
            else UNKNOWN_SIDE_EFFECT
        )
    if first == "coverage":
        return (
            MODELED_STATE_TRANSITION
            if _safe_coverage_workspace_command(arguments)
            and not _implicit_tool_config_present("coverage", root, cwd)
            else UNKNOWN_SIDE_EFFECT
        )
    if first.startswith("python") or first == "py":
        if "-c" in core:
            return MODELED_STATE_TRANSITION if _safe_python_code(core) else UNKNOWN_SIDE_EFFECT
        module_index = next(
            (index for index, token in enumerate(core[:-1]) if token == "-m"), None
        )
        if module_index is not None:
            module = _basename(core[module_index + 1]).lower()
            module_args = tuple(token.lower() for token in core[module_index + 2 :])
            if module == "compileall":
                return MODELED_STATE_TRANSITION
            if module == "build":
                return UNKNOWN_SIDE_EFFECT
            if module == "coverage" and any(
                token in {"-o", "--output-file"}
                or token.startswith("--output-file=")
                for token in module_args
            ):
                return UNKNOWN_SIDE_EFFECT
            if module == "coverage":
                return (
                    MODELED_STATE_TRANSITION
                    if _safe_coverage_workspace_command(module_args)
                    and not _implicit_tool_config_present("coverage", root, cwd)
                    else UNKNOWN_SIDE_EFFECT
                )
            if module == "ruff":
                return (
                    MODELED_STATE_TRANSITION
                    if _safe_ruff_workspace_command(module_args)
                    and not _implicit_tool_config_present("ruff", root, cwd)
                    else UNKNOWN_SIDE_EFFECT
                )
            if module == "mypy":
                return (
                    MODELED_STATE_TRANSITION
                    if _safe_mypy_workspace_command(module_args)
                    and not _implicit_tool_config_present("mypy", root, cwd)
                    else UNKNOWN_SIDE_EFFECT
                )
            if module == "pip_audit":
                return (
                    MODELED_STATE_TRANSITION
                    if _safe_pip_audit_workspace_command(module_args)
                    else UNKNOWN_SIDE_EFFECT
                )
            if module == "venv":
                return UNKNOWN_SIDE_EFFECT
            if module == "pip":
                if not _pip_command_preserves_pytest_runtime(module_args):
                    return UNKNOWN_SIDE_EFFECT
                if _pip_install_has_local_project_input(module_args):
                    return UNKNOWN_SIDE_EFFECT
                requirement_paths = _pip_requirement_paths(module_args)
                if requirement_paths is None:
                    return UNKNOWN_SIDE_EFFECT
                if requirement_paths and (
                    root is None
                    or cwd is None
                    or _requirements_include_local_project(root, cwd, requirement_paths)
                ):
                    return UNKNOWN_SIDE_EFFECT
                return MODELED_STATE_TRANSITION
            if module in _SAFE_PYTHON_MODULES:
                return MODELED_STATE_TRANSITION
            return UNKNOWN_SIDE_EFFECT
        if _known_read_only_python_script(core):
            return MODELED_STATE_TRANSITION
        # A Python script, stdin program, or dynamically selected executable
        # can rewrite any repository byte.  Only explicit read-only diagnostics
        # and the audited module allowlist are safe here.
        return PROVEN_READ_ONLY if len(core) == 1 else UNKNOWN_SIDE_EFFECT
    if first in {"npm", "pnpm", "yarn"}:
        if "exec" in arguments:
            return UNKNOWN_SIDE_EFFECT
        if any(token in {"install", "i", "ci", "link", "build"} for token in arguments):
            return UNKNOWN_SIDE_EFFECT
        return MODELED_STATE_TRANSITION
    if first == "mkdocs":
        return UNKNOWN_SIDE_EFFECT
    if first == "git":
        return MODELED_STATE_TRANSITION if _safe_git_command(core) else UNKNOWN_SIDE_EFFECT
    if first in _WORKSPACE_READ_ONLY_COMMANDS:
        return PROVEN_READ_ONLY
    if first in _WORKSPACE_MODELED_COMMANDS and _safe_setup_command(core):
        return MODELED_STATE_TRANSITION
    if first == "gh" and _safe_gh_command(core):
        return MODELED_STATE_TRANSITION
    return UNKNOWN_SIDE_EFFECT


def _make_workspace_effect(
    tokens: tuple[str, ...], root: Path, cwd: Path, seen: frozenset[tuple[Path, str]] = frozenset()
) -> WorkspaceState:
    """Resolve simple Make prerequisites/recipes for workspace effects."""

    make_cwd = cwd
    targets: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "-C" and index + 1 < len(tokens):
            try:
                make_cwd = safe_resolve(root, tokens[index + 1], make_cwd)
            except PathSafetyError:
                return UNKNOWN_SIDE_EFFECT
            index += 2
            continue
        if token.startswith("-C") and len(token) > 2:
            try:
                make_cwd = safe_resolve(root, token[2:], make_cwd)
            except PathSafetyError:
                return UNKNOWN_SIDE_EFFECT
            index += 1
            continue
        if token.startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
            index += 1
            continue
        targets.append(token)
        index += 1
    makefile = next(
        (candidate for candidate in (make_cwd / "Makefile", make_cwd / "makefile", make_cwd / "GNUmakefile") if candidate.is_file()),
        None,
    )
    if makefile is None:
        return UNKNOWN_SIDE_EFFECT
    try:
        lines = read_limited_text(makefile, MAX_CONFIG_BYTES).splitlines()
    except (OSError, ValueError, UnicodeError):
        return UNKNOWN_SIDE_EFFECT
    rules: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    current: list[str] = []
    for line in lines:
        if line.startswith((" ", "\t")) and current:
            for name in current:
                prerequisites, recipes = rules[name]
                rules[name] = (prerequisites, recipes + (line.strip(),))
            continue
        match = re.match(r"^([A-Za-z0-9_.%/-]+(?:\s+[A-Za-z0-9_.%/-]+)*)\s*:\s*(.*)$", line)
        if match:
            names = tuple(match.group(1).split())
            prerequisites = tuple(match.group(2).split())
            for name in names:
                rules[name] = (prerequisites, ())
            current = list(names)
            continue
        current = []
    selected = targets or [next((name for name in rules if not name.startswith(".")), "")]
    if not selected:
        return UNKNOWN_SIDE_EFFECT
    state: WorkspaceState = PROVEN_READ_ONLY
    visited = set(seen)
    def visit(target: str) -> WorkspaceState:
        key = (make_cwd, target)
        if key in visited:
            return UNKNOWN_SIDE_EFFECT
        rule = rules.get(target)
        if rule is None:
            return PROVEN_READ_ONLY
        visited.add(key)
        prerequisites, recipes = rule
        result: WorkspaceState = PROVEN_READ_ONLY
        for prerequisite in prerequisites:
            result = _merge_workspace_state(result, visit(prerequisite))
        for recipe in recipes:
            recipe = recipe.lstrip("@").strip()
            if not recipe or "$" in recipe:
                result = _merge_workspace_state(result, UNKNOWN_SIDE_EFFECT)
            else:
                result = _merge_workspace_state(
                    result, _workspace_effect_for_command(recipe, root, make_cwd)
                )
        return result
    for target in selected:
        state = _merge_workspace_state(state, visit(target))
    return state


def _workspace_effect_for_command(
    command: str,
    root: Path | None = None,
    cwd: Path | None = None,
    seen: frozenset[Path] = frozenset(),
) -> WorkspaceState:
    """Classify setup effects; unknown commands are never treated as read-only."""

    if _has_shell_command_substitution(command):
        return UNKNOWN_SIDE_EFFECT
    if _has_pipeline_token(command):
        components = _pipeline_commands(command)
        if not components:
            return UNKNOWN_SIDE_EFFECT
        pipeline_state: WorkspaceState = PROVEN_READ_ONLY
        for component in components:
            pipeline_state = _merge_workspace_state(
                pipeline_state, _workspace_effect_for_command(component, root, cwd)
            )
        return pipeline_state
    state: WorkspaceState = PROVEN_READ_ONLY
    for segment in _shell_segments(command):
        tokens = _tokens(segment)
        if tokens is None:
            return UNKNOWN_SIDE_EFFECT
        if not tokens:
            continue
        if segment.strip() in {"|", "||", "&&", ";"}:
            continue
        core = _command_core_tokens(tokens)
        if root is not None and cwd is not None and core:
            raw_path = core[0]
            script_hint = raw_path.startswith(("./", "../")) or "/" in raw_path or "\\" in raw_path
            if _basename(core[0]).lower() in {"make", "gmake"}:
                effect = _make_workspace_effect(core, root, cwd)
            elif script_hint and (raw_path.lower().endswith(".sh") or "scripts/" in raw_path.replace("\\", "/")):
                try:
                    script_path = safe_resolve(root, raw_path, cwd)
                except PathSafetyError:
                    return UNKNOWN_SIDE_EFFECT
                if script_path in seen:
                    return UNKNOWN_SIDE_EFFECT
                if script_path.is_file():
                    try:
                        content = read_limited_text(script_path, MAX_CONFIG_BYTES)
                    except (OSError, ValueError, UnicodeError):
                        return UNKNOWN_SIDE_EFFECT
                    effect = _workspace_effect_for_command(
                        content, root, script_path.parent, seen | {script_path}
                    )
                else:
                    effect = UNKNOWN_SIDE_EFFECT
            else:
                effect = _workspace_effect_for_tokens(segment, tokens, root, cwd)
        else:
            effect = _workspace_effect_for_tokens(segment, tokens, root, cwd)
        state = _merge_workspace_state(state, effect)
    return state


def _contains_arbitrary_python_code(command: str) -> bool:
    for segment in _shell_segments(command):
        tokens = _tokens(segment)
        if not tokens:
            continue
        if (
            (_basename(tokens[0]) in {"python", "py"} or _basename(tokens[0]).startswith("python"))
            and "-c" in tokens
            and not _safe_python_code(tokens)
        ):
            return True
    return False


def _pytest_output_mutates_workspace(tokens: tuple[str, ...]) -> bool:
    """Detect pytest options that can write bytes visible to later steps."""

    output_options = {
        "--junitxml",
        "--junit-xml",
        "--json-report-file",
        "--html",
        "--result-log",
    }
    selection_files = {
        "pytest.ini",
        ".pytest.ini",
        "pyproject.toml",
        "tox.ini",
        "setup.cfg",
        "setup.py",
        "conftest.py",
    }
    index = 0
    while index < len(tokens):
        token = tokens[index]
        name, separator, value = token.partition("=")
        if name not in output_options:
            index += 1
            continue
        if not separator:
            if index + 1 >= len(tokens):
                return True
            value = tokens[index + 1]
            index += 1
        normalized = value.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if "$" in value or "{" in value or normalized in selection_files:
            return True
        index += 1
    return False


def _command_has_nested_workspace_resolution(command: str) -> bool:
    nested = {
        "pre-commit",
        "pre_commit",
        "tox",
        "tox.exe",
        "make",
        "gmake",
        "npm",
        "pnpm",
        "yarn",
        "bash",
        "sh",
        "zsh",
        "dash",
        "uv",
    }
    for segment in _shell_segments(command):
        tokens = _tokens(segment)
        core = _command_core_tokens(tokens) if tokens else ()
        if core and _basename(core[0]).lower() in nested:
            return True
    return False


def _workflow_has_path_filters(events: Any) -> bool:
    if not isinstance(events, dict):
        return False
    return any(
        isinstance(config, dict) and any(key in config for key in ("paths", "paths-ignore"))
        for config in events.values()
    )


def _workflow_has_ref_filters(events: Any) -> bool:
    if not isinstance(events, dict):
        return False
    return any(
        isinstance(config, dict)
        and any(
            key in config
            for key in ("branches", "branches-ignore", "tags", "tags-ignore")
        )
        for config in events.values()
    )


def _workflow_has_activity_filters(events: Any) -> bool:
    if not isinstance(events, dict):
        return False
    return any(isinstance(config, dict) and "types" in config for config in events.values())


def _path_patterns_match(path: str, patterns: Any) -> bool | None:
    if not isinstance(patterns, list) or not patterns or not all(
        isinstance(pattern, str) and pattern for pattern in patterns
    ):
        return None
    matched = False
    for raw_pattern in patterns:
        negated = raw_pattern.startswith("!")
        pattern = raw_pattern[1:] if negated else raw_pattern
        if not pattern:
            return None
        regex = _github_path_pattern_regex(pattern)
        if regex is None:
            return None
        if re.fullmatch(regex, path.replace("\\", "/")) is None:
            continue
        matched = not negated
    return matched


def _github_path_pattern_regex(pattern: str) -> str | None:
    """Translate GitHub's path-filter wildcards to a whole-path regex.

    GitHub's single-star wildcard never crosses a slash; double-star is the
    recursive form. Unsupported glob syntax is reported as unknown by the
    caller rather than being treated as a literal or a broader match.
    """

    normalized = pattern.replace("\\", "/")
    pieces: list[str] = []
    index = 0
    while index < len(normalized):
        character = normalized[index]
        if character == "*":
            if index + 1 < len(normalized) and normalized[index + 1] == "*":
                index += 2
                if index < len(normalized) and normalized[index] == "/":
                    pieces.append("(?:.*/)?")
                    index += 1
                else:
                    pieces.append(".*")
                continue
            pieces.append("[^/]*")
        elif character in "?[]{}()+":
            return None
        else:
            pieces.append(re.escape(character))
        index += 1
    return "".join(pieces)


def _event_config(
    events: Any, event_name: str, activity: str | None = None
) -> tuple[bool, dict[str, Any]] | None:
    """Select one GitHub event configuration without unioning other events."""

    if isinstance(events, str):
        return (events == event_name, {})
    if isinstance(events, list) and all(isinstance(item, str) for item in events):
        return (event_name in events, {})
    if isinstance(events, dict) and all(isinstance(key, str) for key in events):
        if event_name not in events:
            return False, {}
        config = events[event_name]
        if config is None:
            return True, {}
        if isinstance(config, dict):
            if "types" in config:
                types = config["types"]
                if not isinstance(types, list) or not types or not all(
                    isinstance(item, str) and item for item in types
                ):
                    return None
                if activity is None:
                    return None
                return activity in types, config
            return True, config
    return None


def _path_filter_runs(config: dict[str, Any], changed_files: tuple[str, ...]) -> bool | None:
    has_paths = "paths" in config
    has_ignored = "paths-ignore" in config
    if has_paths and has_ignored:
        return None
    if not has_paths and not has_ignored:
        return True
    if has_paths:
        matches = [_path_patterns_match(path, config["paths"]) for path in changed_files]
        if any(value is None for value in matches):
            return None
        return any(matches)
    ignored = [_path_patterns_match(path, config["paths-ignore"]) for path in changed_files]
    if any(value is None for value in ignored):
        return None
    return any(not value for value in ignored)


def _ref_name(value: str, *, tag: bool = False) -> str:
    normalized = value.strip().replace("\\", "/")
    prefixes = ("refs/tags/",) if tag else ("refs/heads/", "refs/tags/")
    for prefix in prefixes:
        if normalized.startswith(prefix):
            return normalized[len(prefix) :]
    return normalized


def _ref_filter_runs(
    config: dict[str, Any], event_context: str, ref: str | None, base_ref: str | None
) -> bool | None:
    """Evaluate branch/tag filters only when the triggering ref is bound."""

    branch_keys = ("branches", "branches-ignore")
    tag_keys = ("tags", "tags-ignore")
    has_branches = any(key in config for key in branch_keys)
    has_tags = any(key in config for key in tag_keys)
    if not has_branches and not has_tags:
        return True
    if has_branches and all(key in config for key in branch_keys):
        return None
    if has_tags and all(key in config for key in tag_keys):
        return None

    if event_context == "pull_request":
        if has_tags:
            return None
        value = base_ref
        is_tag = False
    elif event_context == "push":
        if ref is None:
            return None
        is_tag = ref.replace("\\", "/").startswith("refs/tags/")
        value = _ref_name(ref, tag=is_tag)
    else:
        return None
    if value is None:
        return None

    if is_tag:
        patterns = config.get("tags")
        ignored = config.get("tags-ignore")
    else:
        patterns = config.get("branches")
        ignored = config.get("branches-ignore")
    if patterns is not None:
        return _path_patterns_match(value, patterns)
    if ignored is not None:
        ignored_match = _path_patterns_match(value, ignored)
        return None if ignored_match is None else not ignored_match
    return None


def _workflow_filter_runs(
    config: dict[str, Any],
    event_context: str,
    changed_files: tuple[str, ...] | None,
    ref: str | None,
    base_ref: str | None,
    change_set_complete: bool,
    commit_count: int | None,
    changed_file_count: int | None,
    diff_timed_out: bool,
) -> bool | None:
    ref_result = _ref_filter_runs(config, event_context, ref, base_ref)
    if ref_result is False or ref_result is None:
        return ref_result
    if "paths" in config or "paths-ignore" in config:
        if event_context == "push" and ref is None:
            return None
        if event_context == "push" and ref is not None and ref.replace("\\", "/").startswith(
            "refs/tags/"
        ):
            # GitHub does not apply path filters to tag pushes.
            return True
        if changed_files is None:
            return None
        if (
            not change_set_complete
            or commit_count is None
            or changed_file_count is None
            or commit_count < 0
            or changed_file_count < 0
            or changed_file_count != len(changed_files)
            or diff_timed_out
            or commit_count > 1000
            or changed_file_count > 3000
        ):
            return None
        return _path_filter_runs(config, changed_files)
    return True


def _workflow_runs_for_changes(
    events: Any,
    changed_files: tuple[str, ...],
    event_context: str | None = None,
    change_set_complete: bool = False,
    commit_count: int | None = None,
    changed_file_count: int | None = None,
    diff_timed_out: bool = False,
) -> bool | None:
    """Evaluate path filters only for one explicitly bound event context."""

    if event_context is not None:
        selected = _event_config(events, event_context)
        if selected is None:
            return None
        present, config = selected
        return False if not present else _workflow_filter_runs(
            config,
            event_context,
            changed_files,
            None,
            None,
            change_set_complete,
            commit_count,
            changed_file_count,
            diff_timed_out,
        )
    if isinstance(events, dict):
        event_names = tuple(key for key in events if isinstance(key, str))
        if len(event_names) != 1:
            return None
        selected = _event_config(events, event_names[0])
        if selected is None:
            return None
        return _workflow_filter_runs(
            events[event_names[0]] or {},
            event_names[0],
            changed_files,
            None,
            None,
            change_set_complete,
            commit_count,
            changed_file_count,
            diff_timed_out,
        )
    return None


def _path_is_within(root: Path, cwd: Path, raw_path: str) -> bool | None:
    """Classify a static action path as inside the analyzed repository."""

    text = raw_path.strip()
    if not text or "${{" in text or "*" in text:
        return None
    if text.startswith("~"):
        return False
    try:
        candidate = (cwd / text).resolve() if not Path(text).is_absolute() else Path(text).resolve()
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _workspace_restore_effect(
    action_name: str, raw_with: Any, root: Path, cwd: Path
) -> bool | None:
    """Return whether a file-producing action can affect repository bytes."""

    if action_name == "actions/download-artifact":
        if raw_with is None:
            return True
        if not isinstance(raw_with, dict):
            return None
        raw_path = raw_with.get("path")
        if raw_path is None:
            return True
        path = _scalar(raw_path)
        return None if path is None else _path_is_within(root, cwd, path)
    if not isinstance(raw_with, dict):
        return None
    if "path" not in raw_with:
        return None
    raw_paths = _scalar(raw_with["path"])
    if raw_paths is None or not raw_paths.strip():
        return None
    for raw_path in raw_paths.splitlines():
        path = raw_path.strip()
        if not path:
            continue
        inside = _path_is_within(root, cwd, path)
        if inside is None:
            return None
        if inside:
            normalized = path.replace("\\", "/")
            while normalized.startswith("./"):
                normalized = normalized[2:]
            if not (
                normalized == ".mypy_cache"
                or normalized.startswith(".mypy_cache/")
                or normalized == ".ruff_cache"
                or normalized.startswith(".ruff_cache/")
                or normalized == "__pycache__"
                or normalized.startswith("__pycache__/")
            ):
                return True
    return False


def _pipeline_commands(command: str) -> tuple[str, ...] | None:
    """Split raw pipeline components without turning shell operators into data."""

    commands: list[str] = []
    found_pipeline = False
    for line in command.splitlines():
        current: list[str] = []
        pieces: list[str] = []
        quote: str | None = None
        escaped = False
        index = 0
        while index < len(line):
            character = line[index]
            if escaped:
                current.append(character)
                escaped = False
                index += 1
                continue
            if character == "\\" and quote != "'":
                current.append(character)
                escaped = True
                index += 1
                continue
            if quote is not None:
                current.append(character)
                if character == quote:
                    quote = None
                index += 1
                continue
            if character in {"'", '"'}:
                quote = character
                current.append(character)
                index += 1
                continue
            if character == "|":
                if index + 1 < len(line) and line[index + 1] == "|":
                    current.extend(("|", "|"))
                    index += 2
                    continue
                piece = "".join(current).strip()
                if not piece:
                    return None
                pieces.append(piece)
                current = []
                found_pipeline = True
                index += 2 if index + 1 < len(line) and line[index + 1] == "&" else 1
                continue
            current.append(character)
            index += 1
        if quote is not None:
            return None
        tail = "".join(current).strip()
        if found_pipeline and pieces:
            if not tail:
                return None
            pieces.append(tail)
            commands.extend(pieces)
        elif line.strip():
            commands.append(line.strip())
    if not found_pipeline:
        return ()
    return tuple(commands)


def _has_pipeline_token(command: str) -> bool:
    components = _pipeline_commands(command)
    return components is None or bool(components)


def _relevant_text(value: str) -> bool:
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in (
            "pytest",
            " tox",
            "tox ",
            "make test",
            "npm test",
            "pnpm test",
            "yarn test",
            "nox -",
            "invoke test",
            "just test",
            "run_tests",
            "run-tests",
            "scripts/test",
            "make ci",
            "./ci",
            ".sh",
            "coverage run",
        )
    )


def _env_mapping(value: Any, context: _Context) -> tuple[dict[str, str], bool]:
    if value is None:
        return {}, True
    if not isinstance(value, dict):
        return {}, False
    result: dict[str, str] = {}
    complete = True
    for key, raw in value.items():
        text = _scalar(raw)
        if text is None:
            complete = False
            continue
        resolved, known = resolve_expressions(text, context)
        result[str(key)] = resolved
        complete = complete and known
    return result, complete


def _relative_matrix(row: dict[str, Any]) -> str:
    if not row:
        return "default"
    return ",".join(f"{key}={row[key]}" for key in sorted(row))


class _Resolver:
    def __init__(
        self,
        root: Path,
        changed_files: Sequence[str] | None = None,
        event_context: str | None = None,
        ref: str | None = None,
        base_ref: str | None = None,
        activity: str | None = None,
        change_set_complete: bool = False,
        commit_count: int | None = None,
        changed_file_count: int | None = None,
        diff_timed_out: bool = False,
    ) -> None:
        self.root = root.resolve()
        self.event_context = event_context
        self.ref = ref
        self.base_ref = base_ref
        self.activity = activity
        self.change_set_complete = change_set_complete
        self.commit_count = commit_count
        self.changed_file_count = changed_file_count
        self.diff_timed_out = diff_timed_out
        self.invocations: list[PytestInvocation] = []
        self.issues: list[TraceIssue] = []
        self.workflows: list[str] = []
        if changed_files is None:
            self.changed_files: tuple[str, ...] | None = None
        else:
            normalized: list[str] = []
            for changed_file in changed_files:
                try:
                    normalized.append(normalize_repo_path(self.root, changed_file))
                except PathSafetyError as exc:
                    self.issue(
                        "CHANGED_FILE_UNKNOWN",
                        f"changed file is outside the repository or unsafe: {exc}",
                        (str(changed_file),),
                    )
            self.changed_files = tuple(dict.fromkeys(normalized))
        self._workflow_stack: set[Path] = set()
        self._script_stack: set[Path] = set()
        self._make_stack: set[tuple[Path, str]] = set()
        self._package_stack: set[tuple[Path, str]] = set()
        self._tox_stack: set[Path] = set()
        self._workflow_events: dict[str, set[str]] = {}
        self._workflow_event_kinds: dict[str, set[str]] = {}
        self._workflow_path_filters: set[str] = set()
        self._pytest_plugin_declaration_checked = False
        self._pytest_plugin_declaration_error: str | None = None
        self._pytest_context_config_checked = False
        self._pytest_context_config_paths: tuple[Path, ...] = ()
        self._pytest_context_config_error: str | None = None
        self._pytest_portable_paths_checked = False
        self._pytest_portable_paths_issue: str | None = None

    def issue(
        self, code: str, message: str, provenance: tuple[str, ...], relevant: bool = True
    ) -> None:
        item = TraceIssue(code, message, provenance, relevant)
        if item not in self.issues:
            self.issues.append(item)

    def invocation(self, item: PytestInvocation) -> None:
        if item not in self.invocations:
            self.invocations.append(item)

    def _trace_result(
        self,
        invocations: tuple[PytestInvocation, ...],
        issues: tuple[TraceIssue, ...],
        workflows: tuple[str, ...],
    ) -> TraceResult:
        return TraceResult(
            invocations,
            issues,
            workflows,
            self.changed_files,
            self.event_context,
            self.activity,
            self.ref,
            self.base_ref,
            self.change_set_complete,
            self.commit_count,
            self.changed_file_count,
            self.diff_timed_out,
        )

    def _precommit_config_is_non_test(self) -> bool:
        """Prove that the local pre-commit hooks are not test runners."""

        path = next(
            (
                candidate
                for candidate in (
                    self.root / ".pre-commit-config.yaml",
                    self.root / ".pre-commit-config.yml",
                )
                if candidate.is_file()
            ),
            None,
        )
        if path is None:
            return False
        try:
            data = yaml.safe_load(read_limited_text(path, MAX_CONFIG_BYTES))
        except (OSError, ValueError, UnicodeError, yaml.YAMLError, RecursionError, MemoryError):
            return False
        if not isinstance(data, dict) or not isinstance(data.get("repos"), list):
            return False
        known_repositories = ("ruff-pre-commit", "uv-pre-commit", "pre-commit-hooks")
        for raw_repo in data["repos"]:
            if not isinstance(raw_repo, dict):
                return False
            repository = str(raw_repo.get("repo", "")).lower()
            hooks = raw_repo.get("hooks", [])
            if not isinstance(hooks, list):
                return False
            if not any(marker in repository for marker in known_repositories):
                for raw_hook in hooks:
                    if not isinstance(raw_hook, dict):
                        return False
                    entry = _scalar(raw_hook.get("entry"))
                    if entry is None or _relevant_text(entry):
                        return False
                    tokens = _tokens(entry)
                    if tokens is None or not _safe_setup_command(tokens):
                        return False
        return True

    def _precommit_entries(self) -> tuple[tuple[str, str, tuple[str, ...]], ...] | None:
        """Return statically declared hook ids, entries, and stages."""

        path = next(
            (
                candidate
                for candidate in (
                    self.root / ".pre-commit-config.yaml",
                    self.root / ".pre-commit-config.yml",
                )
                if candidate.is_file()
            ),
            None,
        )
        if path is None:
            return None
        try:
            data = yaml.safe_load(read_limited_text(path, MAX_CONFIG_BYTES))
        except (OSError, ValueError, UnicodeError, yaml.YAMLError, RecursionError, MemoryError):
            return None
        if not isinstance(data, dict) or not isinstance(data.get("repos"), list):
            return None
        entries: list[tuple[str, str, tuple[str, ...]]] = []
        for raw_repo in data["repos"]:
            if not isinstance(raw_repo, dict) or not isinstance(raw_repo.get("hooks"), list):
                return None
            for raw_hook in raw_repo["hooks"]:
                if not isinstance(raw_hook, dict):
                    return None
                hook_id = _scalar(raw_hook.get("id"))
                entry = _scalar(raw_hook.get("entry"))
                if not hook_id or "entry" not in raw_hook or entry is None or not entry:
                    return None
                raw_stages = raw_hook.get("stages")
                stages: tuple[str, ...]
                if isinstance(raw_stages, str):
                    stages = (raw_stages,)
                elif isinstance(raw_stages, list) and all(isinstance(stage, str) for stage in raw_stages):
                    stages = tuple(raw_stages)
                elif raw_stages in (None, []):
                    stages = ()
                else:
                    return None
                entries.append((hook_id, entry, stages))
        return tuple(entries)

    def _resolve_precommit_selection(
        self, tokens: tuple[str, ...]
    ) -> tuple[frozenset[str] | None, str | None] | None:
        try:
            run_index = tokens.index("run")
        except ValueError:
            return None
        selected: set[str] = set()
        stage: str | None = None
        value_options = {"--config", "--hook-stage", "--from-ref", "--to-ref", "--source"}
        index = run_index + 1
        while index < len(tokens):
            token = tokens[index]
            if token == "--":
                selected.update(tokens[index + 1 :])
                break
            if token in {"--hook-stage", "--stage"}:
                if index + 1 >= len(tokens):
                    return None
                stage = tokens[index + 1]
                index += 2
                continue
            if token.startswith("--hook-stage=") or token.startswith("--stage="):
                stage = token.split("=", 1)[1]
                index += 1
                continue
            if token in value_options:
                if index + 1 >= len(tokens):
                    return None
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            selected.add(token)
            index += 1
        return (frozenset(selected) if selected else None), stage

    def _resolve_precommit(
        self,
        context: _Context,
        depth: int,
        selected_hooks: frozenset[str] | None = None,
        selected_stage: str | None = None,
        shell: str = _NEUTRAL_SHELL,
    ) -> WorkspaceState:
        runner_relevance_proven = self._precommit_config_is_non_test()
        entries = self._precommit_entries()
        if entries is None:
            self.issue(
                "PRE_COMMIT_HOOKS_UNKNOWN",
                "pre-commit hooks could not be statically enumerated",
                context.provenance,
                relevant=not runner_relevance_proven,
            )
            return UNKNOWN_SIDE_EFFECT
        if not entries:
            self.issue(
                "PRE_COMMIT_HOOKS_UNKNOWN",
                "pre-commit configuration declares no statically visible hooks",
                context.provenance,
                relevant=not runner_relevance_proven,
            )
            return UNKNOWN_SIDE_EFFECT
        selected_entries = tuple(
            (hook_id, entry)
            for hook_id, entry, stages in entries
            if (selected_hooks is None or hook_id in selected_hooks)
            and (selected_stage is None or not stages or selected_stage in stages)
        )
        if selected_hooks is not None and not any(hook_id in selected_hooks for hook_id, _, _ in entries):
            self.issue(
                "PRE_COMMIT_HOOK_UNKNOWN",
                "selected pre-commit hook id is not declared in the repository configuration",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        state: WorkspaceState = context.workspace_state
        for hook_id, entry in selected_entries:
            hook_context = replace(
                context,
                provenance=context.provenance + (f"pre-commit:{hook_id}",),
                workspace_state=state,
            )
            state = _merge_workspace_state(
                state,
                self._resolve_command(
                    entry,
                    hook_context,
                    depth + 1,
                    shell=shell,
                ),
            )
        return state

    def _job_may_run_tests(self, job: dict[str, Any]) -> bool:
        """Use only statically visible test-bearing steps for condition relevance."""

        if "uses" in job:
            return True
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            return True
        for raw_step in steps:
            if not isinstance(raw_step, dict):
                return True
            command = _scalar(raw_step.get("run"))
            if command is not None and _command_may_run_tests(command):
                return True
            uses = raw_step.get("uses")
            if isinstance(uses, str):
                action_name = uses.split("@", 1)[0].lower()
                if action_name == "pre-commit-ci/lite-action" and self._precommit_config_is_non_test():
                    continue
                if action_name.startswith("./") or action_name not in _KNOWN_EXTERNAL_ACTIONS:
                    return True
        return False

    def _context(self, cwd: Path | None = None, **changes: Any) -> _Context:
        return _Context(cwd or self.root, {}, {}, {}, ()).__class__(
            cwd=cwd or self.root,
            env=changes.get("env", {}),
            matrix=changes.get("matrix", {}),
            inputs=changes.get("inputs", {}),
            provenance=changes.get("provenance", ()),
            event_context=changes.get("event_context"),
            workspace_state=changes.get("workspace_state", PROVEN_READ_ONLY),
            workflow_event_context=changes.get("workflow_event_context"),
            runner_os=changes.get("runner_os"),
        )

    def trace(self) -> TraceResult:
        _, workflow_dir, workflow_error = _portable_repo_path(self.root, ".github/workflows")
        if workflow_error is not None or workflow_dir is None:
            code = (
                "PATH_OUTSIDE_REPOSITORY"
                if workflow_error
                and any(marker in workflow_error for marker in ("escape", "absolute", "unsafe"))
                else "PATH_PORTABILITY_UNKNOWN"
            )
            self.issue(
                code,
                workflow_error or "workflow directory could not be resolved safely",
                (".github/workflows",),
            )
            return self._trace_result((), tuple(self.issues), ())
        if not workflow_dir.is_dir():
            return self._trace_result((), (), ())
        try:
            paths = tuple(
                sorted(
                    path
                    for path in workflow_dir.iterdir()
                    if path.suffix.lower() in {".yml", ".yaml"}
                )
            )
        except OSError as exc:
            self.issue(
                "WORKFLOW_ENUMERATION_ERROR",
                f"could not enumerate workflow files: {exc}",
                (".github/workflows",),
            )
            return self._trace_result((), tuple(self.issues), ())
        if len(paths) > MAX_WORKFLOW_FILES:
            self.issue(
                "WORKFLOW_COUNT_LIMIT",
                f"workflow directory contains {len(paths)} files; limit is {MAX_WORKFLOW_FILES}",
                (".github/workflows",),
            )
            paths = paths[:MAX_WORKFLOW_FILES]
        for path in paths:
            try:
                relative = normalize_repo_path(self.root, path)
            except PathSafetyError as exc:
                self.issue(
                    "PATH_OUTSIDE_REPOSITORY",
                    f"workflow path is unsafe: {exc}",
                    (f"workflow:{path}",),
                )
                continue
            self._resolve_workflow(
                path,
                _Context(
                    self.root,
                    {},
                    {},
                    {},
                    (relative,),
                    self.event_context,
                ),
            )
        invocation_workflows = {
            invocation.provenance[0]
            for invocation in self.invocations
            if invocation.provenance
        }
        for workflow in sorted(invocation_workflows & self._workflow_path_filters):
            self.issue(
                "WORKFLOW_PATH_FILTER_UNKNOWN",
                "workflow path filters require an actual changed-file set before CI scope can be proven",
                (workflow,),
            )
        event_signatures = {
            event
            for workflow, events in self._workflow_events.items()
            if workflow in invocation_workflows
            for event in events
        }
        if len(event_signatures) > 1:
            provenance = tuple(
                f"workflow:{path}" for path in sorted(invocation_workflows)
            )
            self.issue(
                "WORKFLOW_CONTEXT_AMBIGUOUS",
                "workflow files have distinct trigger contexts; their pytest scopes cannot be merged safely",
                provenance,
            )
        invocation_kinds = {
            kind
            for workflow in invocation_workflows
            for kind in self._workflow_event_kinds.get(workflow, {"unknown"})
        }
        final_issues: list[TraceIssue] = []
        for issue in self.issues:
            workflow_name: str | None = (
                issue.provenance[0] if issue.provenance else None
            )
            issue_kinds = self._workflow_event_kinds.get(workflow_name or "")
            if (
                issue.relevant
                and invocation_workflows
                and workflow_name not in invocation_workflows
                and issue_kinds
                and invocation_kinds
                and not any(
                    _event_kinds_overlap(issue_kind, invocation_kind)
                    for issue_kind in issue_kinds
                    for invocation_kind in invocation_kinds
                )
            ):
                issue = replace(issue, relevant=False)
            if issue not in final_issues:
                final_issues.append(issue)
        return self._trace_result(
            tuple(self.invocations),
            tuple(final_issues),
            tuple(self.workflows),
        )

    def _load_yaml(self, path: Path, provenance: tuple[str, ...]) -> dict[str, Any] | None:
        try:
            data = yaml.safe_load(read_limited_text(path, MAX_CONFIG_BYTES))
        except ValueError as exc:
            code = "WORKFLOW_SIZE_LIMIT" if "size limit" in str(exc) else "WORKFLOW_PARSE_ERROR"
            self.issue(code, f"could not parse {path}: {exc}", provenance)
            return None
        except (OSError, yaml.YAMLError, RecursionError, MemoryError) as exc:
            self.issue("WORKFLOW_PARSE_ERROR", f"could not parse {path}: {exc}", provenance)
            return None
        if _structure_too_deep(data):
            self.issue(
                "WORKFLOW_PARSE_ERROR",
                f"workflow {path} exceeds the supported YAML nesting depth",
                provenance,
            )
            return None
        if not isinstance(data, dict):
            self.issue("WORKFLOW_SHAPE_UNKNOWN", f"workflow {path} is not a mapping", provenance)
            return None
        return data

    def _resolve_workflow(self, path: Path, context: _Context) -> None:
        try:
            relative_path = path.relative_to(self.root).as_posix()
        except ValueError:
            self.issue(
                "PATH_OUTSIDE_REPOSITORY",
                f"workflow path is outside the repository: {path}",
                context.provenance,
            )
            return
        _, portable_path, path_error = _portable_repo_path(self.root, relative_path)
        if path_error is not None or portable_path is None:
            code = (
                "PATH_OUTSIDE_REPOSITORY"
                if path_error
                and any(marker in path_error for marker in ("escape", "absolute", "unsafe"))
                else "PATH_PORTABILITY_UNKNOWN"
            )
            self.issue(
                code,
                path_error or "workflow path could not be resolved safely",
                context.provenance,
            )
            return
        path = portable_path
        if len(context.provenance) > MAX_DEPTH:
            self.issue(
                "RESOLUTION_DEPTH_EXCEEDED",
                "workflow resolution depth exceeded",
                context.provenance,
            )
            return
        if path in self._workflow_stack:
            self.issue("RESOLUTION_CYCLE", f"workflow cycle detected at {path}", context.provenance)
            return
        data = self._load_yaml(path, context.provenance)
        if data is None:
            return
        self._workflow_stack.add(path)
        relative = normalize_repo_path(self.root, path)
        if relative not in self.workflows:
            self.workflows.append(relative)
        yaml_data = cast(dict[Any, Any], data)
        events_present = "on" in yaml_data or True in yaml_data
        raw_events = yaml_data["on"] if "on" in yaml_data else yaml_data.get(True)
        event_signature = _event_signature(raw_events)
        if events_present and event_signature is None:
            self.issue(
                "WORKFLOW_EVENT_UNKNOWN",
                f"trigger declaration in {relative} is not statically representable",
                context.provenance,
            )
        selected_event: tuple[bool, dict[str, Any]] | None = None
        trigger_event = context.workflow_event_context or self.event_context
        if trigger_event is not None and events_present:
            selected_event = _event_config(raw_events, trigger_event, self.activity)
            if selected_event is None:
                self.issue(
                    "WORKFLOW_EVENT_FILTER_UNKNOWN"
                    if _workflow_has_activity_filters(raw_events)
                    else "WORKFLOW_EVENT_UNKNOWN",
                    "workflow trigger declaration cannot be matched to the bound event and activity",
                    context.provenance,
                )
                self._workflow_stack.remove(path)
                return
            present, _ = selected_event
            if not present:
                # A workflow declared for another event is not part of this plan.
                self._workflow_stack.remove(path)
                return
        declared_event = event_signature or ("unknown" if events_present else "implicit")
        effective_event = context.event_context or declared_event
        self._workflow_events.setdefault(relative, set()).add(effective_event)
        event_kinds = _event_kinds(raw_events) if events_present else {"implicit"}
        self._workflow_event_kinds.setdefault(relative, set()).update(event_kinds or {"unknown"})
        selected_config = selected_event[1] if selected_event is not None else None
        if trigger_event is not None and selected_config is not None:
            filter_result = _workflow_filter_runs(
                selected_config,
                trigger_event,
                self.changed_files,
                self.ref,
                self.base_ref,
                self.change_set_complete,
                self.commit_count,
                self.changed_file_count,
                self.diff_timed_out,
            )
            has_filters = any(
                key in selected_config
                for key in ("paths", "paths-ignore", "branches", "branches-ignore", "tags", "tags-ignore")
            )
            if has_filters and filter_result is None:
                filter_code = (
                    "WORKFLOW_PATH_FILTER_UNKNOWN"
                    if any(key in selected_config for key in ("paths", "paths-ignore"))
                    else "WORKFLOW_EVENT_FILTER_UNKNOWN"
                )
                self.issue(
                    filter_code,
                    "workflow branch, tag, or path filters require bound event context",
                    context.provenance,
                )
                self._workflow_stack.remove(path)
                return
            if has_filters and not filter_result:
                self._workflow_stack.remove(path)
                return
        elif trigger_event is None and _workflow_has_activity_filters(raw_events):
            self.issue(
                "WORKFLOW_EVENT_FILTER_UNKNOWN",
                "workflow activity types require a bound event activity",
                context.provenance,
            )
            self._workflow_stack.remove(path)
            return
        elif trigger_event is None and _workflow_has_ref_filters(raw_events):
            single_event: tuple[str, dict[str, Any]] | None = None
            if isinstance(raw_events, str):
                single_event = (raw_events, {})
            elif isinstance(raw_events, dict) and len(raw_events) == 1:
                name, config = next(iter(raw_events.items()))
                if isinstance(name, str) and (config is None or isinstance(config, dict)):
                    single_event = (name, config or {})
            if single_event is None:
                self.issue(
                    "WORKFLOW_EVENT_FILTER_UNKNOWN",
                    "workflow branch or tag filters require one bound event and ref",
                    context.provenance,
                )
                self._workflow_stack.remove(path)
                return
            filter_result = _workflow_filter_runs(
                single_event[1],
                single_event[0],
                self.changed_files,
                self.ref,
                self.base_ref,
                self.change_set_complete,
                self.commit_count,
                self.changed_file_count,
                self.diff_timed_out,
            )
            if filter_result is None:
                filter_code = (
                    "WORKFLOW_PATH_FILTER_UNKNOWN"
                    if any(key in single_event[1] for key in ("paths", "paths-ignore"))
                    else "WORKFLOW_EVENT_FILTER_UNKNOWN"
                )
                self.issue(
                    filter_code,
                    "workflow branch, tag, or path filters require bound context",
                    context.provenance,
                )
                self._workflow_stack.remove(path)
                return
            if not filter_result:
                self._workflow_stack.remove(path)
                return
        elif _workflow_has_path_filters(raw_events):
            if self.changed_files is None:
                self._workflow_path_filters.add(relative)
            else:
                runs_for_changes = _workflow_runs_for_changes(
                    raw_events,
                    self.changed_files,
                    trigger_event,
                    self.change_set_complete,
                    self.commit_count,
                    self.changed_file_count,
                    self.diff_timed_out,
                )
                if runs_for_changes is None:
                    self.issue(
                        "WORKFLOW_PATH_FILTER_UNKNOWN",
                        "workflow path filters could not be evaluated for the bound change set",
                        context.provenance,
                    )
                    self._workflow_stack.remove(path)
                    return
                elif not runs_for_changes:
                    self._workflow_stack.remove(path)
                    return
        workflow_shell = _default_shell(data.get("defaults"), None, context)
        root_env, _ = _env_mapping(data.get("env"), context)
        merged_root = {**context.env, **root_env}
        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            self.issue(
                "WORKFLOW_JOBS_UNKNOWN",
                f"jobs in {relative} are not statically enumerable",
                context.provenance,
            )
            self._workflow_stack.remove(path)
            return
        for job_id, raw_job in jobs.items():
            if not isinstance(raw_job, dict):
                self.issue(
                    "JOB_SHAPE_UNKNOWN", f"job {job_id!r} is not a mapping", context.provenance
                )
                continue
            job_condition = _condition_value(raw_job.get("if"))
            if job_condition is False:
                continue
            raw_job_condition = _scalar(raw_job.get("if"))
            defer_job_condition = (
                job_condition is None
                and raw_job_condition is not None
                and "matrix." in raw_job_condition
            )
            if job_condition is None and not defer_job_condition:
                self.issue(
                    "CONDITION_UNKNOWN",
                    f"job {job_id!r} has a condition that is not statically decidable",
                    context.provenance + (f"job:{job_id}",),
                    relevant=self._job_may_run_tests(raw_job),
                )
                continue
            strategy = raw_job.get("strategy")
            if strategy is not None and not isinstance(strategy, dict):
                self.issue(
                    "MATRIX_UNRESOLVED",
                    f"matrix strategy for job {job_id!r} is not statically enumerable",
                    context.provenance,
                )
                continue
            rows, matrix_error = _matrix_rows(
                strategy.get("matrix") if isinstance(strategy, dict) else None
            )
            if matrix_error is not None or rows is None:
                code = "MATRIX_LIMIT_EXCEEDED" if (matrix_error or "").startswith("limit:") else "MATRIX_UNRESOLVED"
                self.issue(
                    code,
                    matrix_error or f"matrix for job {job_id} is unknown",
                    context.provenance,
                )
                continue
            for row in rows:
                provenance = context.provenance + (
                    f"job:{job_id}",
                    f"matrix:{_relative_matrix(row)}",
                )
                row_base = _Context(
                    self.root,
                    merged_root,
                    row,
                    context.inputs,
                    provenance,
                    effective_event,
                    context.workspace_state,
                    context.workflow_event_context,
                    context.runner_os,
                )
                if defer_job_condition:
                    row_condition = _condition_value(raw_job.get("if"), row_base)
                    if row_condition is False:
                        continue
                    if row_condition is None:
                        self.issue(
                            "CONDITION_UNKNOWN",
                            f"job {job_id!r} has a matrix condition that is not statically decidable",
                            provenance,
                        )
                        continue
                job_env, job_env_complete = _env_mapping(raw_job.get("env"), row_base)
                if not job_env_complete:
                    self.issue(
                        "JOB_ENV_UNRESOLVED",
                        f"environment for job {job_id} contains unresolved values",
                        provenance,
                        False,
                    )
                job_context = _Context(
                    self.root,
                    {**merged_root, **job_env},
                    row,
                    context.inputs,
                    provenance,
                    effective_event,
                    context.workspace_state,
                    context.workflow_event_context,
                    _runner_platform(raw_job.get("runs-on"), row_base),
                )
                workflow_cwd = self._default_working_directory(
                    data.get("defaults"),
                    replace(row_base, runner_os=job_context.runner_os),
                    self.root,
                    provenance,
                )
                job_cwd = self._default_working_directory(
                    raw_job.get("defaults"), job_context, workflow_cwd, provenance
                )
                if "uses" in raw_job:
                    self._resolve_reusable(raw_job.get("uses"), job_context, raw_job)
                else:
                    job_shell = _default_shell(
                        raw_job.get("defaults"), raw_job.get("runs-on"), job_context, workflow_shell
                    )
                    self._resolve_steps(
                        raw_job.get("steps", []),
                        replace(job_context, cwd=job_cwd or self.root),
                        job_shell,
                        job_cwd,
                    )
        self._workflow_stack.remove(path)

    def _resolve_reusable(self, uses: Any, context: _Context, job: dict[str, Any]) -> None:
        if not isinstance(uses, str):
            self.issue(
                "REUSABLE_WORKFLOW_UNKNOWN",
                "reusable workflow uses value is not static",
                context.provenance,
            )
            return
        if not uses.startswith("./"):
            self.issue(
                "EXTERNAL_WORKFLOW_UNRESOLVED",
                f"external reusable workflow {uses!r} was not fetched",
                context.provenance,
            )
            return
        _, target, target_error = _portable_repo_path(self.root, uses[2:])
        if target_error is not None or target is None:
            code = (
                "PATH_OUTSIDE_REPOSITORY"
                if target_error
                and any(marker in target_error for marker in ("escape", "absolute", "unsafe"))
                else "PATH_PORTABILITY_UNKNOWN"
            )
            self.issue(
                code,
                target_error or "reusable workflow path could not be resolved safely",
                context.provenance,
            )
            return
        inputs: dict[str, Any] = {}
        raw_with = job.get("with", {})
        if isinstance(raw_with, dict):
            for key, raw in raw_with.items():
                text = _scalar(raw)
                if text is not None:
                    resolved, known = resolve_expressions(text, context)
                    if not known:
                        self.issue(
                            "REUSABLE_INPUT_UNRESOLVED",
                            f"input {key!r} is dynamic",
                            context.provenance,
                        )
                    inputs[str(key)] = resolved
        self._resolve_workflow(
            target,
            replace(
                context,
                inputs=inputs,
                cwd=self.root,
                event_context=context.event_context,
                workflow_event_context="workflow_call",
                provenance=context.provenance + (f"uses:{normalize_repo_path(self.root, target)}",),
            ),
        )

    def _resolve_steps(
        self,
        steps: Any,
        context: _Context,
        default_shell: str | None = _NEUTRAL_SHELL,
        default_cwd: Path | None = None,
    ) -> WorkspaceState:
        if not isinstance(steps, list):
            self.issue(
                "STEPS_UNKNOWN", "workflow steps are not statically enumerable", context.provenance
            )
            return UNKNOWN_SIDE_EFFECT
        workspace_state = context.workspace_state
        for index, raw_step in enumerate(steps):
            if not isinstance(raw_step, dict):
                self.issue(
                    "STEP_SHAPE_UNKNOWN", f"step {index} is not a mapping", context.provenance
                )
                # A malformed step may still be accepted differently by the
                # runner or a future workflow parser.  It cannot preserve the
                # byte-stable state required by a later inferred pytest step.
                workspace_state = UNKNOWN_SIDE_EFFECT
                continue
            label = str(raw_step.get("name") or raw_step.get("id") or index)
            provenance = context.provenance + (f"step:{label}",)
            step_condition = _condition_value(raw_step.get("if"), context)
            if step_condition is False:
                continue
            if step_condition is None:
                condition_relevant = False
                if "run" in raw_step:
                    raw_run = _scalar(raw_step.get("run"))
                    condition_relevant = raw_run is None or _command_may_run_tests(raw_run)
                elif "uses" in raw_step:
                    raw_uses = raw_step.get("uses")
                    action_name = (
                        raw_uses.split("@", 1)[0].lower()
                        if isinstance(raw_uses, str)
                        else ""
                    )
                    condition_relevant = action_name not in _KNOWN_EXTERNAL_ACTIONS and not (
                        action_name == "pre-commit-ci/lite-action"
                        and self._precommit_config_is_non_test()
                    )
                self.issue(
                    "CONDITION_UNKNOWN",
                    f"step {label} has a condition that is not statically decidable",
                    provenance,
                    relevant=condition_relevant,
                )
                raw_run = _scalar(raw_step.get("run")) if "run" in raw_step else None
                if raw_run is not None:
                    effect = _workspace_effect_for_command(
                        raw_run, self.root, context.cwd
                    )
                    # Either branch of a conditional test command can execute
                    # arbitrary test, fixture, plugin, or collection code.
                    # The branch that runs must taint later workspace state.
                    if _command_may_run_tests(raw_run):
                        effect = UNKNOWN_SIDE_EFFECT
                    if _command_has_nested_workspace_resolution(raw_run):
                        effect = UNKNOWN_SIDE_EFFECT
                    if any(
                        _pytest_output_mutates_workspace(tokens)
                        for segment in _shell_segments(raw_run)
                        for tokens in [_tokens(segment)]
                        if tokens
                    ):
                        effect = UNKNOWN_SIDE_EFFECT
                    workspace_state = _merge_workspace_state(
                        workspace_state, effect
                    )
                elif "uses" in raw_step:
                    workspace_state = _merge_workspace_state(
                        workspace_state,
                        self._conditional_action_workspace_effect(
                            raw_step.get("uses"),
                            raw_step.get("with"),
                            context,
                            provenance,
                        ),
                    )
                continue
            step_env, step_env_complete = _env_mapping(raw_step.get("env"), context)
            step_context = replace(
                context,
                env={**context.env, **step_env},
                provenance=provenance,
                workspace_state=workspace_state,
            )
            if not step_env_complete:
                self.issue(
                    "STEP_ENV_UNRESOLVED",
                    f"environment for step {label} is dynamic",
                    provenance,
                    False,
                )
            if "run" in raw_step:
                command = _scalar(raw_step.get("run"))
                if command is None:
                    self.issue(
                        "RUN_COMMAND_UNKNOWN",
                        f"run command in step {label} is not static",
                        provenance,
                    )
                    workspace_state = UNKNOWN_SIDE_EFFECT
                    continue
                shell = (
                    _static_shell(raw_step.get("shell"), step_context)
                    if "shell" in raw_step
                    else default_shell
                )
                if shell not in {_NEUTRAL_SHELL, "bash", "powershell"}:
                    self.issue(
                        "SHELL_UNKNOWN",
                        f"step {label} uses an unsupported or unresolved shell",
                        provenance,
                    )
                    if shell == "unknown":
                        self.issue(
                            "PYTEST_INVOCATION_CONTEXT_UNKNOWN",
                            "pytest shell semantics are not statically known",
                            provenance,
                        )
                    # A custom shell template can wrap, replace, or skip the
                    # generated script.  Treat it as an execution boundary,
                    # not merely an unsupported parser choice.
                    workspace_state = UNKNOWN_SIDE_EFFECT
                    continue
                command, known = resolve_expressions(command, step_context)
                if not known:
                    if _relevant_text(command):
                        self.issue(
                            "RUN_COMMAND_DYNAMIC",
                            "relevant run command contains an unresolved expression",
                            provenance,
                        )
                    # Even an apparently unrelated dynamic run step can
                    # execute a repository-controlled writer before a later
                    # test step.  The absence of a recognizable runner token
                    # is not proof of a harmless effect.
                    workspace_state = UNKNOWN_SIDE_EFFECT
                    continue
                cwd: Path | None = default_cwd
                raw_cwd = (
                    _scalar(raw_step.get("working-directory"))
                    if "working-directory" in raw_step
                    else None
                )
                if raw_cwd is not None:
                    raw_cwd, cwd_known = resolve_expressions(raw_cwd, step_context)
                    if cwd_known:
                        # GitHub resolves a step's explicit working-directory
                        # from GITHUB_WORKSPACE; it replaces, rather than
                        # appends to, workflow/job defaults.
                        _, cwd, cwd_error = _portable_repo_path(self.root, raw_cwd)
                        if cwd_error is not None or cwd is None:
                            code = (
                                "PATH_OUTSIDE_REPOSITORY"
                                if cwd_error
                                and any(
                                    marker in cwd_error
                                    for marker in ("escape", "absolute", "unsafe")
                                )
                                else "WORKING_DIRECTORY_UNKNOWN"
                            )
                            self.issue(
                                code,
                                cwd_error or "working directory could not be resolved safely",
                                provenance,
                            )
                            workspace_state = UNKNOWN_SIDE_EFFECT
                            continue
                    elif _relevant_text(command):
                        self.issue(
                            "WORKING_DIRECTORY_UNKNOWN",
                            "pytest command has an unresolved working directory",
                            provenance,
                        )
                        workspace_state = UNKNOWN_SIDE_EFFECT
                        continue
                if cwd is None:
                    self.issue(
                        "WORKING_DIRECTORY_UNKNOWN",
                        f"working directory for step {label} is not statically known",
                        provenance,
                    )
                    workspace_state = UNKNOWN_SIDE_EFFECT
                    continue
                command_context = replace(step_context, cwd=cwd)
                command_effect = _workspace_effect_for_command(command, self.root, cwd)
                command_has_runner = any(
                    _contains_runner_hint(segment) for segment in _shell_segments(command)
                )
                if workspace_state == UNKNOWN_SIDE_EFFECT and _command_may_run_tests(command):
                    self.issue(
                        "WORKSPACE_MUTATION_UNKNOWN",
                        "a previous workflow step may have changed workspace bytes before this test command",
                        provenance,
                        relevant=command_has_runner or _relevant_text(command),
                    )
                else:
                    command_effect = self._resolve_command(
                        command, command_context, 0, shell=shell
                    )
                workspace_state = _merge_workspace_state(workspace_state, command_effect)
            elif "uses" in raw_step:
                uses = raw_step.get("uses")
                if isinstance(uses, str) and uses.startswith("./"):
                    action_dir = self._resolve_path(uses[2:], self.root, provenance)
                    if action_dir is not None:
                        nested_state = self._resolve_composite(
                            action_dir, replace(step_context, workspace_state=workspace_state), default_shell
                        )
                        workspace_state = _merge_workspace_state(workspace_state, nested_state)
                    else:
                        workspace_state = UNKNOWN_SIDE_EFFECT
                elif isinstance(uses, str):
                    action_name = uses.split("@", 1)[0].lower()
                    if action_name == "actions/setup-python" and not _static_setup_python_runtime(
                        raw_step.get("with"), step_context
                    ):
                        self.issue(
                            "PYTHON_RUNTIME_UNKNOWN",
                            "actions/setup-python has an unresolved runtime selector",
                            provenance,
                        )
                        workspace_state = UNKNOWN_SIDE_EFFECT
                    if action_name == "actions/checkout":
                        raw_with = raw_step.get("with", {})
                        if not isinstance(raw_with, dict):
                            self.issue(
                                "CHECKOUT_WORKSPACE_UNKNOWN",
                                "actions/checkout inputs are not statically enumerable",
                                provenance,
                            )
                            workspace_state = UNKNOWN_SIDE_EFFECT
                        else:
                            workspace_inputs = {
                                "repository",
                                "ref",
                                "path",
                                "filter",
                                "sparse-checkout",
                                "sparse-checkout-cone-mode",
                                "submodules",
                                "lfs",
                                "clean",
                            }
                            configured = workspace_inputs.intersection(raw_with)
                            for input_name in sorted(configured):
                                if input_name == "sparse-checkout":
                                    code = "CHECKOUT_SPARSE_UNKNOWN"
                                    message = (
                                        "actions/checkout sparse inputs change the analyzed workspace surface"
                                    )
                                else:
                                    code = "CHECKOUT_WORKSPACE_UNKNOWN"
                                    message = (
                                        f"actions/checkout input {input_name!r} changes the analyzed workspace surface"
                                    )
                                self.issue(code, message, provenance)
                            if configured:
                                workspace_state = UNKNOWN_SIDE_EFFECT
                    if action_name in _WORKSPACE_RESTORING_ACTIONS:
                        raw_with = raw_step.get("with")
                        restore_effect = _workspace_restore_effect(
                            action_name,
                            raw_with,
                            self.root,
                            step_context.cwd,
                        )
                        if restore_effect is None or restore_effect:
                            self.issue(
                                "WORKSPACE_RESTORE_UNKNOWN",
                                f"{action_name} may restore files into the analyzed workspace",
                                provenance,
                            )
                            workspace_state = UNKNOWN_SIDE_EFFECT
                        else:
                            workspace_state = _merge_workspace_state(
                                workspace_state, MODELED_STATE_TRANSITION
                            )
                    if action_name == "ossf/scorecard-action":
                        self.issue(
                            "EXTERNAL_ACTION_WORKSPACE_UNKNOWN",
                            "ossf/scorecard-action may write its results file into the workspace",
                            provenance,
                            relevant=False,
                        )
                        workspace_state = UNKNOWN_SIDE_EFFECT
                    if action_name == "pre-commit-ci/lite-action":
                        workspace_state = _merge_workspace_state(
                            workspace_state,
                            self._resolve_precommit(
                                replace(step_context, workspace_state=workspace_state), 0
                            ),
                        )
                        continue
                    if (
                        action_name not in _PROVEN_WORKSPACE_SAFE_ACTIONS
                        and action_name != "actions/checkout"
                        and action_name not in _WORKSPACE_RESTORING_ACTIONS
                        and action_name != "ossf/scorecard-action"
                    ):
                        known_action = action_name in _KNOWN_EXTERNAL_ACTIONS
                        self.issue(
                            "EXTERNAL_ACTION_WORKSPACE_UNKNOWN"
                            if known_action
                            else "EXTERNAL_ACTION_UNKNOWN",
                            (
                                f"known external action {uses!r} may execute or write workspace bytes"
                                if known_action
                                else f"external action {uses!r} is not modeled as a setup-only action"
                            ),
                            provenance,
                            relevant=not known_action,
                        )
                        workspace_state = UNKNOWN_SIDE_EFFECT
                else:
                    self.issue(
                        "EXTERNAL_ACTION_UNKNOWN",
                        f"action in step {label} is not statically known",
                        provenance,
                    )
                    workspace_state = UNKNOWN_SIDE_EFFECT
        return workspace_state

    def _conditional_action_workspace_effect(
        self,
        raw_uses: Any,
        raw_with: Any,
        context: _Context,
        provenance: tuple[str, ...],
    ) -> WorkspaceState:
        """Propagate workspace effects for a step whose condition is unknown.

        An unresolved condition can skip an action entirely.  We must still
        model the effect of the branch that does run, otherwise a later test
        command can be treated as byte-stable when the conditional action may
        have restored or replaced repository files.
        """

        if not isinstance(raw_uses, str):
            self.issue(
                "EXTERNAL_ACTION_UNKNOWN",
                "conditional action is not statically known",
                provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if raw_uses.startswith("./"):
            self.issue(
                "COMPOSITE_CONDITION_UNKNOWN",
                "conditional local composite action may change workspace bytes",
                provenance,
            )
            return UNKNOWN_SIDE_EFFECT

        action_name = raw_uses.split("@", 1)[0].lower()
        if action_name == "pre-commit-ci/lite-action":
            return self._resolve_precommit(replace(context, workspace_state=PROVEN_READ_ONLY), 0)
        if action_name == "actions/checkout":
            self.issue(
                "CHECKOUT_CONDITION_UNKNOWN",
                "conditional actions/checkout may replace the analyzed workspace",
                provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if action_name in _WORKSPACE_RESTORING_ACTIONS:
            effect = _workspace_restore_effect(
                action_name,
                raw_with,
                self.root,
                context.cwd,
            )
            if effect is None or effect:
                self.issue(
                    "WORKSPACE_RESTORE_UNKNOWN",
                    f"conditional {action_name} may restore files into the analyzed workspace",
                    provenance,
                )
                return UNKNOWN_SIDE_EFFECT
            return MODELED_STATE_TRANSITION
        if action_name == "ossf/scorecard-action":
            self.issue(
                "EXTERNAL_ACTION_WORKSPACE_UNKNOWN",
                "conditional ossf/scorecard-action may write its results file into the workspace",
                provenance,
                relevant=False,
            )
            return UNKNOWN_SIDE_EFFECT
        if action_name not in _PROVEN_WORKSPACE_SAFE_ACTIONS:
            known_action = action_name in _KNOWN_EXTERNAL_ACTIONS
            self.issue(
                "EXTERNAL_ACTION_WORKSPACE_UNKNOWN"
                if known_action
                else "EXTERNAL_ACTION_UNKNOWN",
                (
                    f"known conditional external action {raw_uses!r} may execute or write workspace bytes"
                    if known_action
                    else f"conditional external action {raw_uses!r} is not modeled as setup-only"
                ),
                provenance,
                relevant=not known_action,
            )
            return UNKNOWN_SIDE_EFFECT
        return MODELED_STATE_TRANSITION

    def _resolve_composite(
        self, action_dir: Path, context: _Context, default_shell: str | None
    ) -> WorkspaceState:
        action_relative = normalize_repo_path(self.root, action_dir)
        action_file: Path | None = None
        for name in ("action.yml", "action.yaml"):
            _, candidate, candidate_error = _portable_repo_path(
                self.root,
                f"{action_relative}/{name}" if action_relative else name,
            )
            if candidate_error is not None:
                self.issue(
                    "PATH_PORTABILITY_UNKNOWN",
                    candidate_error,
                    context.provenance,
                )
                return UNKNOWN_SIDE_EFFECT
            if candidate is not None and candidate.is_file():
                action_file = candidate
                break
        if action_file is None:
            self.issue(
                "COMPOSITE_ACTION_UNRESOLVED",
                f"local composite action {action_dir} is missing action.yml",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        try:
            data = yaml.safe_load(read_limited_text(action_file, MAX_CONFIG_BYTES))
        except ValueError as exc:
            self.issue(
                "COMPOSITE_ACTION_PARSE_ERROR",
                f"could not parse {action_file}: {exc}",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        except (OSError, yaml.YAMLError, RecursionError, MemoryError) as exc:
            self.issue(
                "COMPOSITE_ACTION_PARSE_ERROR",
                f"could not parse {action_file}: {exc}",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        runs = data.get("runs") if isinstance(data, dict) else None
        if not isinstance(runs, dict) or runs.get("using") != "composite":
            self.issue(
                "COMPOSITE_ACTION_SHAPE_UNKNOWN",
                f"{action_file} is not a static composite action",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        return self._resolve_steps(
            runs.get("steps", []),
            replace(
                context,
                provenance=context.provenance
                + (f"composite:{normalize_repo_path(self.root, action_dir)}",),
            ),
            default_shell,
            context.cwd,
        )

    def _default_working_directory(
        self,
        defaults: Any,
        context: _Context,
        fallback: Path | None,
        provenance: tuple[str, ...],
    ) -> Path | None:
        if defaults is None:
            return fallback
        if not isinstance(defaults, dict):
            self.issue(
                "WORKING_DIRECTORY_UNKNOWN",
                "run defaults are not statically enumerable",
                provenance,
            )
            return None
        run_defaults = defaults.get("run")
        if run_defaults is None:
            return fallback
        if not isinstance(run_defaults, dict):
            self.issue(
                "WORKING_DIRECTORY_UNKNOWN",
                "run defaults are not statically enumerable",
                provenance,
            )
            return None
        if "working-directory" not in run_defaults:
            return fallback
        raw = _scalar(run_defaults.get("working-directory"))
        if raw is None:
            self.issue(
                "WORKING_DIRECTORY_UNKNOWN",
                "run default working-directory is not static",
                provenance,
            )
            return None
        resolved, known = resolve_expressions(raw, context)
        if not known:
            self.issue(
                "WORKING_DIRECTORY_UNKNOWN",
                "run default working-directory contains an unresolved expression",
                provenance,
            )
            return None
        _, path, path_error = _portable_repo_path(self.root, resolved)
        if path_error is not None or path is None:
            code = (
                "PATH_OUTSIDE_REPOSITORY"
                if path_error
                and any(marker in path_error for marker in ("escape", "absolute", "unsafe"))
                else "WORKING_DIRECTORY_UNKNOWN"
            )
            self.issue(
                code,
                path_error or "run default working-directory could not be resolved safely",
                provenance,
            )
            return None
        return path

    def _resolve_path(
        self, value: str, base: Path, provenance: tuple[str, ...] = ()
    ) -> Path | None:
        _, path, path_error = _portable_repo_path(self.root, value, base)
        if path_error is None and path is not None:
            return path
        code = (
            "PATH_OUTSIDE_REPOSITORY"
            if path_error
            and any(marker in path_error for marker in ("escape", "absolute", "unsafe"))
            else "PATH_PORTABILITY_UNKNOWN"
        )
        self.issue(
            code,
            path_error or f"path {value!r} could not be resolved safely",
            provenance,
        )
        return None

    def _runner_identity_unknown(self, tokens: tuple[str, ...], context: _Context) -> bool:
        """Reject bare executables whose shell resolution is repository-controlled."""

        if not tokens:
            return False
        core = _command_core_tokens(tokens)
        if not core:
            return False
        first_raw = core[0]
        first = _basename(first_raw)
        if "/" not in first_raw and "\\" not in first_raw:
            path_value = context.env.get("PATH")
            if path_value:
                separator = ";" if ";" in path_value else ":"
                for raw_entry in path_value.split(separator):
                    entry = raw_entry.strip().strip("'\"")
                    if not entry or entry in {"$PATH", "${PATH}"}:
                        continue
                    if "$PATH" in entry or "${PATH}" in entry:
                        entry = entry.replace("${PATH}", "").replace("$PATH", "").strip(separator)
                        if not entry:
                            continue
                    if "${{" in entry or "$GITHUB_WORKSPACE" in entry:
                        return True
                    try:
                        resolved = safe_resolve(self.root, entry, context.cwd)
                        resolved.relative_to(self.root)
                    except (PathSafetyError, ValueError):
                        continue
                    return True
        runner_names = {
            "pytest",
            "py.test",
            "tox",
            "nox",
            "invoke",
            "pre-commit",
            "pre_commit",
            "coverage",
        }
        is_runner = first in runner_names or (
            first.startswith("python")
            and any(
                index + 1 < len(core)
                and token == "-m"
                and _basename(core[index + 1]) in {"pytest", "pre-commit", "pre_commit"}
                for index, token in enumerate(core[:-1])
            )
        )
        if not is_runner:
            return False
        if "/" in first_raw or "\\" in first_raw:
            try:
                resolved = safe_resolve(self.root, first_raw, context.cwd)
            except PathSafetyError:
                return True
            try:
                resolved.relative_to(self.root)
            except ValueError:
                return False
            return True
        path_value = context.env.get("PATH")
        if not path_value:
            return False
        separator = ";" if ";" in path_value else ":"
        for raw_entry in path_value.split(separator):
            entry = raw_entry.strip().strip("'\"")
            if not entry or entry in {"$PATH", "${PATH}"}:
                continue
            if "$PATH" in entry or "${PATH}" in entry:
                entry = entry.replace("${PATH}", "").replace("$PATH", "").strip(separator)
                if not entry:
                    continue
            if "${{" in entry or "$GITHUB_WORKSPACE" in entry:
                return True
            try:
                resolved = safe_resolve(self.root, entry, context.cwd)
                resolved.relative_to(self.root)
            except (PathSafetyError, ValueError):
                continue
            return True
        return False

    def _resolve_static_file_condition(
        self, command: str, context: _Context, depth: int, shell: str
    ) -> WorkspaceState | None:
        """Resolve one exact ``if [ -f/-d path ]; then command; fi`` boundary.

        GitHub workflows often use this form to install an optional static
        requirements file.  It is safe to model only when the condition path
        is repository-relative and the entire branch syntax is exact.  Any
        dynamic expression, ``else`` branch, chaining, or unsupported shell
        construct falls through to the ordinary fail-closed control-flow path.
        """

        match = _STATIC_FILE_CONDITION.match(command.strip())
        if match is None:
            return None
        # The expression is deliberately a tiny Bash-only boundary.  The
        # bracket/then/fi grammar is not PowerShell syntax, and the neutral
        # default shell must not infer a shell from the command text.
        if shell != "bash":
            return None
        prefix = match.group("prefix").strip()
        branch = match.group("body").strip()
        suffix = match.group("suffix").strip()
        if not branch or "else" in branch.split():
            return None
        _, target, target_error = _portable_repo_path(
            self.root, match.group("path"), context.cwd
        )
        if target_error is not None or target is None:
            self.issue(
                "PATH_PORTABILITY_UNKNOWN",
                target_error or "static file condition path could not be resolved safely",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        prefix_state = context.workspace_state
        if prefix:
            prefix_state = self._resolve_command(
                prefix,
                replace(context, workspace_state=prefix_state),
                depth + 1,
                shell=shell,
            )
        if prefix_state == UNKNOWN_SIDE_EFFECT:
            return UNKNOWN_SIDE_EFFECT
        try:
            condition = target.is_file() if match.group("kind") == "f" else target.is_dir()
        except OSError:
            return UNKNOWN_SIDE_EFFECT
        state = prefix_state
        if condition:
            state = _merge_workspace_state(
                state,
                self._resolve_command(
                    branch,
                    replace(context, workspace_state=state),
                    depth + 1,
                    shell=shell,
                ),
            )
        if suffix:
            state = _merge_workspace_state(
                state,
                self._resolve_command(
                    suffix,
                    replace(context, workspace_state=state),
                    depth + 1,
                    shell=shell,
                ),
            )
        return state

    def _resolve_command(
        self, command: str, context: _Context, depth: int, shell: str = _NEUTRAL_SHELL
    ) -> WorkspaceState:
        state: WorkspaceState = context.workspace_state
        if depth > MAX_DEPTH:
            self.issue(
                "RESOLUTION_DEPTH_EXCEEDED", "command resolution depth exceeded", context.provenance
            )
            return UNKNOWN_SIDE_EFFECT
        neutral_unportable = shell == _NEUTRAL_SHELL and not _neutral_command_is_portable(command)
        # Do not model shell-specific static conditions under the neutral
        # grammar, but continue through the existing checks below so callers
        # retain precise diagnostics for substitutions, pipelines, and control
        # flow instead of receiving a generic parse error.
        static_condition = (
            None
            if neutral_unportable
            else self._resolve_static_file_condition(command, context, depth, shell)
        )
        if static_condition is not None:
            return static_condition
        if shell == "powershell" and _powershell_control_flow_unknown(command):
            self.issue(
                "SHELL_CONTROL_FLOW_UNKNOWN",
                "PowerShell control flow or command chaining is outside the supported static subset",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if _has_shell_command_substitution(command):
            if not _assignment_only_command(command):
                self.issue(
                    "SHELL_COMMAND_SUBSTITUTION_UNKNOWN",
                    "shell command substitution hides nested workspace effects",
                    context.provenance,
                    relevant=_relevant_text(command),
                )
            return UNKNOWN_SIDE_EFFECT
        if _contains_arbitrary_python_code(command):
            self.issue(
                "PYTHON_CODE_UNKNOWN",
                "arbitrary python -c code is outside the statically auditable command graph",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if _pretest_mutation_unknown(command):
            self.issue(
                "PRETEST_MUTATION_UNKNOWN",
                "file-changing setup precedes a test runner, so the CI test surface is not byte-stable",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if _has_pipeline_token(command):
            components = _pipeline_commands(command)
            if not components or any(_contains_runner_hint(component) for component in components):
                self.issue(
                    "SHELL_PIPE_UNKNOWN",
                    "shell pipelines are outside the supported static command subset",
                    context.provenance,
                )
                return UNKNOWN_SIDE_EFFECT
            state = context.workspace_state
            for component in components:
                component_state = self._resolve_command(
                    component,
                    replace(context, workspace_state=state),
                    depth + 1,
                    shell=shell,
                )
                if component_state == UNKNOWN_SIDE_EFFECT:
                    self.issue(
                        "SHELL_PIPE_UNKNOWN",
                        "a pipeline component has an unresolved workspace effect",
                        context.provenance,
                    )
                state = _merge_workspace_state(state, component_state)
            return state
        if _shell_control_flow_unknown(command):
            self.issue(
                "SHELL_CONTROL_FLOW_UNKNOWN",
                "shell control flow or command chaining can change whether a test command runs",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if neutral_unportable:
            # For a malformed neutral command, use the established pytest
            # option classifier only to preserve a useful selector/config
            # diagnostic.  Never retain the probe's invocation: its POSIX
            # tokenization is not evidence about the runner's default shell.
            probe_tokens = _tokens(command, shell="bash")
            if probe_tokens:
                probe_scope, probe_index, probe_error = self._pytest_scope(
                    probe_tokens, context.cwd, "unknown", "bash"
                )
                del probe_scope
                if probe_index is not None and probe_error:
                    if probe_error.startswith("context:"):
                        code = "PYTEST_INVOCATION_CONTEXT_UNKNOWN"
                    elif probe_error.startswith("configuration:"):
                        code = "PYTEST_CONFIGURATION_UNKNOWN"
                    else:
                        code = "PYTEST_SELECTOR_UNKNOWN"
                    self.issue(code, probe_error, context.provenance)
                elif probe_index is not None:
                    self.issue(
                        "PYTEST_INVOCATION_CONTEXT_UNKNOWN",
                        "default runner shell syntax is not in the portable command subset",
                        context.provenance,
                    )
                elif any(
                    re.search(rf"(?:^|\s){re.escape(name)}=", command)
                    for name in (
                        "PYTEST_ADDOPTS",
                        "PYTEST_PLUGINS",
                        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
                    )
                ) and _contains_runner_hint(command):
                    self.issue(
                        "PYTEST_CONFIGURATION_UNKNOWN",
                        "pytest configuration is assigned through runner-specific shell syntax",
                        context.provenance,
                    )
                elif _contains_runner_hint(command):
                    self.issue(
                        "PYTEST_INVOCATION_CONTEXT_UNKNOWN",
                        "default runner shell syntax is not in the portable command subset",
                        context.provenance,
                    )
            elif _relevant_text(command):
                self.issue(
                    "COMMAND_PARSE_UNKNOWN",
                    "default runner shell syntax is not in the portable command subset",
                    context.provenance,
                )
            # Even a non-test command with shell-specific syntax may execute
            # repository code or alter the working tree before a later pytest
            # step.  Preserve the taint while avoiding a noisy non-relevant
            # issue when no test plan depends on this command.
            return UNKNOWN_SIDE_EFFECT
        shell_env = dict(context.env)
        for segment in _shell_segments(command):
            expanded, prefix_error = _expand_safe_prefix(segment, context.env)
            if prefix_error is not None:
                if _relevant_text(segment):
                    self.issue("DYNAMIC_EXECUTABLE_PREFIX", prefix_error, context.provenance)
                # A dynamically selected executable can run arbitrary setup
                # code even when this segment contains no literal pytest
                # token.  It cannot leave later test inference byte-stable.
                state = UNKNOWN_SIDE_EFFECT
                continue
            if expanded is None:
                state = UNKNOWN_SIDE_EFFECT
                continue
            # A shell declaration identifies parsing syntax, not the physical
            # runner's filesystem.  Backslash pytest selectors therefore remain
            # unknown even under an explicit PowerShell shell; only portable
            # forward-slash selectors can be reconciled with the denominator.
            if _contains_runner_hint(segment) and "\\" in expanded:
                self.issue(
                    "PYTEST_INVOCATION_CONTEXT_UNKNOWN",
                    "pytest path separators are not modeled for this runner and shell combination",
                    context.provenance,
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            tokens = _tokens(expanded, shell=shell)
            if tokens is None:
                if _relevant_text(segment):
                    self.issue(
                        "COMMAND_PARSE_UNKNOWN",
                        "shell command could not be tokenized safely",
                        context.provenance,
                    )
                # A shell syntax/parser failure can short-circuit the job or
                # hide a side effect.  In either case a following pytest is
                # not proven to execute against the analyzed state.
                state = UNKNOWN_SIDE_EFFECT
                continue
            if not tokens:
                continue
            if expanded.strip() in {"|", "||", "&&", ";"}:
                continue
            state = _merge_workspace_state(
                state, _workspace_effect_for_tokens(expanded, tokens, self.root, context.cwd)
            )
            local_env = dict(shell_env)
            had_assignments = False
            while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
                key, value = tokens[0].split("=", 1)
                local_env[key] = value
                had_assignments = True
                tokens = tokens[1:]
            if not tokens:
                if had_assignments:
                    shell_env.update(local_env)
                continue
            if _basename(tokens[0]) == "env":
                tokens = tokens[1:]
                while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
                    key, value = tokens[0].split("=", 1)
                    local_env[key] = value
                    tokens = tokens[1:]
            if not tokens:
                continue
            nested_context = replace(context, env=local_env)
            if _basename(tokens[0]) in {"command", "exec", "time"}:
                tokens = tokens[1:]
                if not tokens:
                    continue
            if _basename(tokens[0]) == "cross-env":
                tokens = tokens[1:]
                while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
                    key, value = tokens[0].split("=", 1)
                    local_env[key] = value
                    tokens = tokens[1:]
                nested_context = replace(nested_context, env=local_env)
            if not tokens:
                continue
            startup_unknown = _startup_environment_unknown(local_env, shell, tokens)
            if startup_unknown is not None:
                code, message = startup_unknown
                self.issue(
                    code,
                    message,
                    context.provenance,
                    relevant=_command_may_run_tests(expanded),
                )
                state = UNKNOWN_SIDE_EFFECT
            first = _basename(tokens[0])
            if self._runner_identity_unknown(tokens, nested_context):
                self.issue(
                    "EXECUTABLE_IDENTITY_UNKNOWN",
                    "repository-controlled PATH or executable path can shadow the recognized test runner",
                    context.provenance,
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            if first in {"cd", "chdir"}:
                # A shell directory change affects every later command in the
                # generated script.  The resolver deliberately does not try
                # to carry mutable shell cwd across segments; doing so would
                # let a nested pytest reuse the repository-root denominator
                # after ``cd tests``.  Fail closed for the whole segment.
                self.issue(
                    "WORKING_DIRECTORY_UNKNOWN",
                    "shell directory changes are not modeled before a later command",
                    context.provenance,
                    relevant=_command_may_run_tests(command),
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            if first == "export":
                for token in tokens[1:]:
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
                        key, value = token.split("=", 1)
                        shell_env[key] = value
                continue
            if first in {"pre-commit", "pre_commit"}:
                selection = self._resolve_precommit_selection(tokens)
                if selection is None:
                    self.issue(
                        "PRE_COMMIT_COMMAND_UNKNOWN",
                        "only an explicit pre-commit run command has auditable hook selection",
                        context.provenance,
                    )
                    state = UNKNOWN_SIDE_EFFECT
                else:
                    state = _merge_workspace_state(
                        state, self._resolve_precommit(nested_context, depth, *selection, shell=shell)
                    )
                continue
            if first.startswith("python") and "-m" in tokens:
                module_indexes = [index for index, token in enumerate(tokens[:-1]) if token == "-m"]
                if any(_basename(tokens[index + 1]) in {"pre-commit", "pre_commit"} for index in module_indexes):
                    selection = self._resolve_precommit_selection(tokens)
                    if selection is None:
                        self.issue(
                            "PRE_COMMIT_COMMAND_UNKNOWN",
                            "only an explicit pre-commit run command has auditable hook selection",
                            context.provenance,
                        )
                        state = UNKNOWN_SIDE_EFFECT
                    else:
                        state = _merge_workspace_state(
                            state, self._resolve_precommit(nested_context, depth, *selection, shell=shell)
                        )
                    continue
            if (first.startswith("python") or first == "py") and "-c" in tokens:
                if not _safe_python_code(tokens):
                    self.issue(
                        "PYTHON_CODE_UNKNOWN",
                        "arbitrary python -c code is outside the statically auditable command graph",
                        context.provenance,
                    )
                    state = UNKNOWN_SIDE_EFFECT
                continue
            if first.startswith("python") or first == "py":
                module_indexes = [index for index, token in enumerate(tokens[:-1]) if token == "-m"]
                if module_indexes:
                    modules = {
                        _basename(tokens[index + 1]).lower()
                        for index in module_indexes
                    }
                    if any(module not in _SAFE_PYTHON_MODULES for module in modules):
                        self.issue(
                            "PYTHON_EXECUTION_UNKNOWN",
                            "python module execution is not in the audited read-only/module resolver subset",
                            context.provenance,
                        )
                        state = UNKNOWN_SIDE_EFFECT
                        continue
                elif len(tokens) > 1:
                    if _known_read_only_python_script(tokens):
                        continue
                    self.issue(
                        "PYTHON_EXECUTION_UNKNOWN",
                        "python script or stdin execution can rewrite repository bytes",
                        context.provenance,
                    )
                    if _relevant_text(" ".join(tokens)):
                        self.issue(
                            "UNKNOWN_TEST_RUNNER",
                            "python script execution is outside the statically supported test command subset",
                            context.provenance,
                        )
                    state = UNKNOWN_SIDE_EFFECT
                    continue
            if first == "git":
                if not _safe_git_command(tokens):
                    self.issue(
                        "GIT_COMMAND_UNKNOWN",
                        "git command is not in the explicit read-only allowlist",
                        context.provenance,
                        relevant=False,
                    )
                    state = UNKNOWN_SIDE_EFFECT
                continue
            if first == "uv":
                unwrapped, error = self._unwrap_uv(tokens)
                if error:
                    if len(tokens) > 1 and tokens[1] == "run":
                        self.issue("UV_COMMAND_UNKNOWN", error, context.provenance)
                        state = UNKNOWN_SIDE_EFFECT
                elif unwrapped:
                    state = _merge_workspace_state(
                        state,
                        self._resolve_command(
                            " ".join(shlex.quote(token) for token in unwrapped),
                            replace(nested_context, workspace_state=state),
                            depth + 1,
                            shell=shell,
                        ),
                    )
                continue
            try:
                scope, runner_index, scope_error = self._pytest_scope(
                    tokens,
                    nested_context.cwd,
                    nested_context.runner_os or "unknown",
                    shell,
                )
            except PathSafetyError as exc:
                self.issue(
                    "PATH_OUTSIDE_REPOSITORY",
                    f"pytest path selector is unsafe: {exc}",
                    context.provenance,
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            if runner_index is not None:
                if state == UNKNOWN_SIDE_EFFECT:
                    self.issue(
                        "WORKSPACE_MUTATION_UNKNOWN",
                        "an earlier command in this shell segment may have changed workspace bytes before pytest",
                        context.provenance,
                    )
                    continue
                if _pytest_environment_unknown(nested_context.env):
                    self.issue(
                        "PYTEST_CONFIGURATION_UNKNOWN",
                        "pytest selection can be changed by an environment configuration variable",
                        context.provenance,
                    )
                    # The unknown invocation may still execute test or plugin
                    # code.  It must therefore poison successor analysis just
                    # like an ordinary resolved pytest invocation does.
                    state = UNKNOWN_SIDE_EFFECT
                elif scope_error:
                    if scope_error.startswith("context:"):
                        code = "PYTEST_INVOCATION_CONTEXT_UNKNOWN"
                    elif scope_error.startswith("configuration:"):
                        code = "PYTEST_CONFIGURATION_UNKNOWN"
                    else:
                        code = "PYTEST_SELECTOR_UNKNOWN"
                    self.issue(code, scope_error, context.provenance)
                    # An unmodeled pytest option is not safe to carry across
                    # the selection graph: it may select a different suite or
                    # invoke a plugin/output path that changes later state.
                    state = UNKNOWN_SIDE_EFFECT
                elif scope is not None:
                    self.invocation(replace(scope, provenance=context.provenance))
                    # A pytest process executes repository-controlled
                    # collection, fixture, plugin, and test code. Its effects
                    # are not byte-proven, so a later pytest in the same job
                    # must not be analyzed against the old tree.
                    state = UNKNOWN_SIDE_EFFECT
                    if _pytest_output_mutates_workspace(tokens):
                        self.issue(
                            "PYTEST_WORKSPACE_OUTPUT_UNKNOWN",
                            "pytest output options may write into repository or selection-configuration bytes",
                            context.provenance,
                        )
                        state = UNKNOWN_SIDE_EFFECT
                continue
            if first in {"tox", "tox.exe"}:
                state = _merge_workspace_state(
                    state, self._resolve_tox(tokens, nested_context, depth + 1, shell=shell)
                )
                continue
            if first in {"make", "gmake"}:
                state = _merge_workspace_state(
                    state, self._resolve_make(tokens, nested_context, depth + 1, shell=shell)
                )
                continue
            if first in {"npm", "pnpm", "yarn"}:
                state = _merge_workspace_state(
                    state, self._resolve_package(tokens, nested_context, depth + 1, shell=shell)
                )
                continue
            if first in {"bash", "sh", "zsh", "dash"}:
                state = _merge_workspace_state(
                    state, self._resolve_shell(tokens, nested_context, depth + 1)
                )
                continue
            if first in {".", "source"}:
                if len(tokens) != 2:
                    self.issue(
                        "SHELL_SCRIPT_UNKNOWN",
                        "source command does not have one statically known script path",
                        context.provenance,
                    )
                    state = UNKNOWN_SIDE_EFFECT
                    continue
                script_path = self._resolve_path(tokens[1], nested_context.cwd, context.provenance)
                if script_path is None or not script_path.is_file():
                    self.issue(
                        "SHELL_SCRIPT_UNKNOWN",
                        "source command script path is unavailable or unsafe",
                        context.provenance,
                    )
                    state = UNKNOWN_SIDE_EFFECT
                    continue
                state = _merge_workspace_state(
                    state, self._resolve_script(script_path, nested_context, depth + 1, shell=shell)
                )
                continue
            token_text = tokens[0].replace("\\", "/")
            shell_script_hint = token_text.lower().endswith(".sh") or token_text.startswith(
                "scripts/"
            )
            if tokens[0].startswith("./") or "/" in tokens[0] or "\\" in tokens[0]:
                token_path = self._resolve_path(tokens[0], nested_context.cwd, context.provenance)
                if shell_script_hint and token_path is not None and token_path.is_file():
                    state = _merge_workspace_state(
                        state, self._resolve_script(token_path, nested_context, depth + 1, shell=shell)
                    )
                    continue
            elif shell_script_hint:
                token_path = self._resolve_path(tokens[0], nested_context.cwd, context.provenance)
                if token_path is not None and token_path.is_file():
                    state = _merge_workspace_state(
                        state, self._resolve_script(token_path, nested_context, depth + 1, shell=shell)
                    )
                    continue
            if _safe_setup_command(tokens):
                continue
            if _relevant_text(segment) and (
                "${" in segment or "$" in segment or "pytest" in segment.lower()
            ):
                self.issue(
                    "COMMAND_SELECTION_UNKNOWN",
                    "runner-like command contains unresolved shell semantics",
                    context.provenance,
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            self.issue(
                "UNKNOWN_TEST_RUNNER",
                f"command {_basename(tokens[0])!r} is outside the statically supported command subset",
                context.provenance,
                relevant=_relevant_text(segment),
            )
            state = UNKNOWN_SIDE_EFFECT
        return state

    def _unwrap_uv(self, tokens: tuple[str, ...]) -> tuple[tuple[str, ...] | None, str | None]:
        if len(tokens) < 2 or tokens[1] != "run":
            return None, "only uv run is supported"
        return None, "uv run may synchronize project-controlled code before the command"

    def _pytest_project_plugin_error(self) -> str | None:
        """Find repository-declared plugin surfaces that change pytest execution.

        A direct pytest command cannot be a proof when the checkout itself
        declares a plugin in a conftest/test module or advertises a pytest11
        entry point.  We deliberately do not emulate that code; presence is
        enough to make selection UNKNOWN.  The scan is bounded so a very large
        or unreadable checkout fails closed rather than silently skipping a
        declaration.
        """

        if self._pytest_plugin_declaration_checked:
            return self._pytest_plugin_declaration_error
        self._pytest_plugin_declaration_checked = True
        ignored_parts = {
            ".git",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".tox",
            ".venv",
            "build",
            "dist",
            "node_modules",
            "venv",
        }
        for name in (
            "pytest.toml",
            ".pytest.toml",
            "pytest.ini",
            ".pytest.ini",
            "pyproject.toml",
            "tox.ini",
            "setup.cfg",
            "setup.py",
        ):
            path = self.root / name
            try:
                if path.is_symlink():
                    self._pytest_plugin_declaration_error = (
                        f"pytest plugin configuration {name!r} is a symlink"
                    )
                    return self._pytest_plugin_declaration_error
                if not path.is_file():
                    continue
                text = read_limited_text(path, MAX_CONFIG_BYTES)
            except (OSError, ValueError, UnicodeError):
                self._pytest_plugin_declaration_error = (
                    f"pytest plugin configuration {name!r} could not be read safely"
                )
                return self._pytest_plugin_declaration_error
            lowered = text.lower()
            if _PYTEST_PLUGIN_CONFIG.search(text) or "pytest11" in lowered:
                self._pytest_plugin_declaration_error = (
                    f"pytest plugin configuration is declared by {name!r}"
                )
                return self._pytest_plugin_declaration_error

        # A static target can make a nested pytest configuration become the
        # active root configuration.  Inspect every tracked-looking config
        # location rather than assuming the shell cwd is the only discovery
        # starting point.
        config_names = {
            "pytest.toml",
            ".pytest.toml",
            "pytest.ini",
            ".pytest.ini",
            "pyproject.toml",
            "tox.ini",
            "setup.cfg",
            "setup.py",
        }
        inspected_configs = 0
        try:
            for path in self.root.rglob("*"):
                if path.name.lower() not in config_names:
                    continue
                if path.is_symlink():
                    self._pytest_plugin_declaration_error = (
                        "pytest plugin configuration discovery encountered a symlink"
                    )
                    return self._pytest_plugin_declaration_error
                if not path.is_file():
                    continue
                relative = path.relative_to(self.root)
                if len(relative.parts) == 1 or ignored_parts.intersection(relative.parts):
                    continue
                inspected_configs += 1
                if inspected_configs > 4096:
                    self._pytest_plugin_declaration_error = (
                        "pytest plugin configuration discovery is not safely bounded"
                    )
                    return self._pytest_plugin_declaration_error
                try:
                    text = read_limited_text(path, MAX_CONFIG_BYTES)
                except (OSError, ValueError, UnicodeError):
                    self._pytest_plugin_declaration_error = (
                        f"pytest plugin configuration {relative.as_posix()!r} could not be read safely"
                    )
                    return self._pytest_plugin_declaration_error
                if _PYTEST_PLUGIN_CONFIG.search(text) or "pytest11" in text.lower():
                    self._pytest_plugin_declaration_error = (
                        f"pytest plugin configuration is declared by {relative.as_posix()!r}"
                    )
                    return self._pytest_plugin_declaration_error
        except OSError:
            self._pytest_plugin_declaration_error = (
                "pytest plugin configuration discovery could not be completed safely"
            )
            return self._pytest_plugin_declaration_error

        inspected = 0
        try:
            for path in self.root.rglob("*.py"):
                try:
                    relative = path.relative_to(self.root)
                except ValueError:
                    self._pytest_plugin_declaration_error = (
                        "pytest plugin source discovery escaped the repository"
                    )
                    return self._pytest_plugin_declaration_error
                if ignored_parts.intersection(relative.parts):
                    continue
                if path.is_symlink():
                    self._pytest_plugin_declaration_error = (
                        f"pytest plugin source {relative.as_posix()!r} is a symlink"
                    )
                    return self._pytest_plugin_declaration_error
                inspected += 1
                if inspected > 4096:
                    self._pytest_plugin_declaration_error = (
                        "pytest plugin source discovery exceeded the bounded file limit"
                    )
                    return self._pytest_plugin_declaration_error
                try:
                    text = read_limited_text(path, MAX_CONFIG_BYTES)
                except (OSError, ValueError, UnicodeError):
                    self._pytest_plugin_declaration_error = (
                        f"pytest plugin source {relative.as_posix()!r} could not be read safely"
                    )
                    return self._pytest_plugin_declaration_error
                # Pytest imports every applicable conftest module before it
                # determines the final runnable item set.  Even without a
                # named hook, import-time code can register hooks/plugins,
                # rewrite configuration, or deselect items.  Its semantics
                # are repository-controlled Python, so the direct subset
                # cannot treat a non-empty conftest as irrelevant.
                # Windows resolves ``Conftest.py`` (and other case variants)
                # when pytest asks for ``conftest.py``.  The resolver may be
                # running on a case-sensitive host while modeling a Windows
                # runner, so this must be an explicit case-insensitive check
                # rather than relying on the host filesystem's behavior.
                if path.name.casefold() == "conftest.py" and text.strip():
                    self._pytest_plugin_declaration_error = (
                        f"pytest startup module {relative.as_posix()!r} is project-controlled code"
                    )
                    return self._pytest_plugin_declaration_error
                if _PYTEST_PLUGIN_ASSIGNMENT.search(text):
                    self._pytest_plugin_declaration_error = (
                        f"pytest_plugins is declared by {relative.as_posix()!r}"
                    )
                    return self._pytest_plugin_declaration_error
                if path.name.casefold() == "conftest.py" and _PYTEST_HOOK_DEFINITION.search(text):
                    self._pytest_plugin_declaration_error = (
                        f"pytest hook is declared by {relative.as_posix()!r}"
                    )
                    return self._pytest_plugin_declaration_error
        except OSError:
            self._pytest_plugin_declaration_error = (
                "pytest plugin source discovery could not be completed safely"
            )
            return self._pytest_plugin_declaration_error
        return None

    def _pytest_context_config_candidates(self) -> tuple[Path, ...] | None:
        """Cache recognized pytest configs that can change invocation root/context."""

        if self._pytest_context_config_checked:
            if self._pytest_context_config_error is not None:
                return None
            return self._pytest_context_config_paths

        self._pytest_context_config_checked = True
        candidates: list[Path] = []
        inspected = 0
        try:
            for path in self.root.rglob("*"):
                if path.name.casefold() not in _PYTEST_CONFIG_NAMES:
                    continue
                if path.name not in _PYTEST_CONFIG_NAMES:
                    try:
                        relative_name = path.relative_to(self.root).as_posix()
                    except ValueError:
                        relative_name = path.name
                    self._pytest_context_config_error = (
                        f"pytest configuration {relative_name!r} has platform-dependent case semantics"
                    )
                    return None
                try:
                    relative = path.relative_to(self.root)
                except ValueError:
                    self._pytest_context_config_error = (
                        "pytest configuration discovery escaped the repository"
                    )
                    return None
                if _PYTEST_CONFIG_IGNORED_PARTS.intersection(relative.parts):
                    continue
                if path.is_symlink():
                    self._pytest_context_config_error = (
                        f"pytest configuration {relative.as_posix()!r} is a symlink"
                    )
                    return None
                if not path.is_file():
                    continue
                inspected += 1
                if inspected > 4096:
                    self._pytest_context_config_error = (
                        "pytest configuration discovery is not safely bounded"
                    )
                    return None
                recognized, _ = _pytest_config_addopts(path)
                if recognized:
                    candidates.append(path.resolve())
        except OSError:
            self._pytest_context_config_error = (
                "pytest configuration discovery could not be completed safely"
            )
            return None

        self._pytest_context_config_paths = tuple(sorted(set(candidates)))
        return self._pytest_context_config_paths

    def _pytest_portable_paths_error(self) -> str | None:
        """Detect repository-wide path collisions before reusing a denominator.

        A repository-root pytest collection can be replayed on a different
        runner only when the relevant path namespace has one unambiguous,
        portable spelling.  Case-fold collisions are especially important:
        they can coexist on a case-sensitive analyst checkout but alias on a
        different runner (or vice versa).  The scan is bounded and ignores
        transient tool directories that are outside the denominator.
        """

        if self._pytest_portable_paths_checked:
            return self._pytest_portable_paths_issue
        self._pytest_portable_paths_checked = True
        seen: dict[str, str] = {}
        inspected = 0
        try:
            for path in self.root.rglob("*"):
                try:
                    relative = path.relative_to(self.root)
                except ValueError:
                    self._pytest_portable_paths_issue = (
                        "pytest path discovery escaped the repository"
                    )
                    return self._pytest_portable_paths_issue
                if any(part.casefold() in _PYTEST_CONFIG_IGNORED_PARTS for part in relative.parts):
                    continue
                inspected += 1
                if inspected > 8192:
                    self._pytest_portable_paths_issue = (
                        "pytest path discovery is not safely bounded"
                    )
                    return self._pytest_portable_paths_issue
                spelling = relative.as_posix()
                folded = spelling.casefold()
                previous = seen.get(folded)
                if previous is not None and previous != spelling:
                    self._pytest_portable_paths_issue = (
                        f"repository paths {previous!r} and {spelling!r} have a case-fold collision"
                    )
                    return self._pytest_portable_paths_issue
                seen[folded] = spelling
        except OSError:
            self._pytest_portable_paths_issue = (
                "pytest path discovery could not be completed safely"
            )
            return self._pytest_portable_paths_issue
        return None

    def _pytest_target_path(
        self,
        token: str,
        cwd: Path,
        runner_os: str,
        shell: str,
    ) -> tuple[str, str | None]:
        """Normalize one static pytest target using runner-neutral spelling.

        ``runs-on`` and the explicit shell are intentionally ignored here:
        neither proves the physical filesystem's case or separator semantics.
        The only accepted target is a repository-relative forward-slash path
        whose existing components have exact checkout spelling and no
        case-fold collision.
        """

        del runner_os, shell
        normalized, _, error = _portable_repo_path(self.root, token, cwd)
        return normalized or token, error

    def _pytest_invocation_context_error(
        self,
        cwd: Path,
        targets: tuple[str, ...],
        runner_os: str,
    ) -> str | None:
        """Prove that a traced pytest command can reuse the root denominator.

        GreenGap deliberately collects one repository-wide denominator from
        ``root`` with an explicit ``--rootdir``.  It must not use that result
        for an invocation whose working directory or target can select a
        different root/configuration context.  This bounded v0.1 rule permits
        only the repository-root context and static single targets that have
        no related nested pytest configuration.
        """

        try:
            repository = self.root.resolve()
            current = cwd.resolve()
            current.relative_to(repository)
        except (OSError, RuntimeError, ValueError):
            return "pytest invocation working directory is outside the repository"

        if current != repository:
            try:
                relative_cwd = current.relative_to(repository).as_posix()
            except ValueError:
                relative_cwd = str(current)
            return (
                f"pytest runs from non-root working directory {relative_cwd!r}; "
                "its root/import/configuration context is not congruent with the repository denominator"
            )

        del runner_os
        portable_error = self._pytest_portable_paths_error()
        if portable_error is not None:
            return portable_error
        if len(targets) > 1:
            return (
                "pytest has multiple explicit targets; their common root/configuration context "
                "is not modeled"
            )
        target: Path | None = None
        is_file = False
        is_dir = False
        if targets:
            try:
                target = safe_resolve(repository, targets[0])
                target_relative = target.relative_to(repository)
                is_file = target.is_file()
                is_dir = target.is_dir()
            except (OSError, PathSafetyError, ValueError):
                return "pytest target could not be inspected safely for configuration discovery"
            if _PYTEST_CONFIG_IGNORED_PARTS.intersection(
                part.casefold() for part in target_relative.parts
            ):
                return (
                    f"pytest target {targets[0]!r} is inside a transient directory whose "
                    "configuration context is not modeled"
                )
            if not is_file and not is_dir:
                # Static CI selectors are legitimately traced before their target
                # is generated or checked out in lightweight fixtures.  Their
                # spelling still lets us conservatively decide which config
                # locations could affect them without pretending the path exists.
                is_file = target.suffix.casefold() in {".py", ".pyw"}
                is_dir = not is_file

        def runner_path_within(child: Path, parent: Path) -> bool:
            try:
                child.relative_to(parent)
                return True
            except ValueError:
                return False

        candidates = self._pytest_context_config_candidates()
        if candidates is None:
            return self._pytest_context_config_error or "pytest configuration discovery failed"

        for config in candidates:
            try:
                relative = config.relative_to(repository)
            except ValueError:
                return "pytest configuration discovery escaped the repository"
            if len(relative.parts) != 1:
                continue
            # Configuration identity is part of the collection context.  A
            # case variant is not interchangeable with the denominator config
            # when the eventual runner's case semantics are unknown.
            if config.name not in _PYTEST_CONFIG_NAMES:
                return (
                    f"pytest configuration {relative.as_posix()!r} has platform-dependent case semantics"
                )

        if target is None:
            return None

        for config in candidates:
            try:
                config_dir = config.parent.resolve()
                config_relative = config.relative_to(repository).as_posix()
            except (OSError, RuntimeError, ValueError):
                return "pytest configuration discovery escaped the repository"
            if config_dir == repository:
                continue
            if is_file:
                selection_root = target.parent
                related = runner_path_within(selection_root, config_dir)
            else:
                related = runner_path_within(config_dir, target) or runner_path_within(
                    target, config_dir
                )
            if related:
                return (
                    f"pytest target {targets[0]!r} may select nested configuration "
                    f"{config_relative!r} instead of the repository denominator configuration"
                )
        return None

    def _pytest_scope(
        self,
        tokens: tuple[str, ...],
        cwd: Path,
        runner_os: str = "unknown",
        shell: str = _NEUTRAL_SHELL,
    ) -> tuple[PytestInvocation | None, int | None, str | None]:
        marker: int | None = None
        first = _basename(tokens[0])
        if first in {"pytest", "py.test"}:
            marker = 0
        elif first.startswith("python"):
            for index in range(1, len(tokens) - 1):
                if tokens[index] == "-m" and _basename(tokens[index + 1]) == "pytest":
                    marker = index + 1
                    break
                if tokens[index] == "-m" and _basename(tokens[index + 1]) == "coverage":
                    for inner in range(index + 2, len(tokens) - 1):
                        if tokens[inner] == "-m" and _basename(tokens[inner + 1]) == "pytest":
                            marker = inner + 1
                            break
        elif first == "coverage" and len(tokens) > 2 and tokens[1] == "run":
            for index in range(2, len(tokens) - 1):
                if tokens[index] == "-m" and _basename(tokens[index + 1]) == "pytest":
                    marker = index + 1
                    break
        if marker is None:
            return None, None, None

        implicit_args, implicit_error = self._pytest_implicit_addopts(cwd)
        if implicit_error is not None:
            return None, marker, f"configuration: {implicit_error}"
        plugin_error = self._pytest_project_plugin_error()
        if plugin_error is not None:
            return None, marker, f"configuration: {plugin_error}"

        unsupported = {
            "-k",
            "--keyword",
            "-m",
            "--markers",
            "--ignore",
            "--ignore-glob",
            "--deselect",
            "--lf",
            "--last-failed",
            "--failed-first",
            "--ff",
            "--stepwise",
            "--pyargs",
            "--maxfail",
            "-x",
            "--exitfirst",
            "--pdb",
            "--pdbcls",
            "--trace",
            "--runxfail",
            "--collect-in-virtualenv",
            "--import-mode",
            "--doctest-modules",
            "--doctest-glob",
            "--keep-duplicates",
            "--continue-on-collection-errors",
        }
        value_options = {
            "--junitxml",
            "--tb",
            "--color",
            "--capture",
            "--rootdir",
            "-o",
            "-c",
            "--confcutdir",
            "--basetemp",
            "--override-ini",
            "--filterwarnings",
            "--parallel-threads",
            "-W",
        }
        configuration_options = {
            "-o",
            "--override-ini",
            "-c",
            "--rootdir",
            "--confcutdir",
            "--basetemp",
            "-p",
        }
        flag_options = {
            "-q",
            "-v",
            "-vv",
            "-ra",
            "-s",
            "--quiet",
            "--verbose",
            "--disable-warnings",
            "--strict-config",
            "--strict-markers",
            "--no-header",
            "--no-summary",
        }
        paths: list[str] = []
        selectors: list[str] = []
        arguments = implicit_args + tokens[marker + 1 :]
        index = 0
        end_options = False
        while index < len(arguments):
            token = arguments[index]
            if token == "--":
                end_options = True
                index += 1
                continue
            if not end_options and token.startswith("-"):
                name, _, attached = token.partition("=")
                if name in {"--collect-only", "--co", "--setup-only", "--setup-plan"}:
                    return (
                        None,
                        marker,
                        f"configuration: pytest option {name} does not execute test functions",
                    )
                if name == "-p" or (token.startswith("-p") and not token.startswith("--")):
                    return None, marker, "configuration: pytest plugin loading can change collection"
                if name in {
                    "-n",
                    "--numprocesses",
                    "--dist",
                    "--tx",
                    "--cov",
                    "--cov-report",
                    "--cov-config",
                    "--cov-fail-under",
                    "--json-report",
                    "--json-report-file",
                    "--html",
                    "--self-contained-html",
                } or (token.startswith("-n") and not token.startswith("--")):
                    return None, marker, "configuration: pytest plugin options are not modeled"
                if name in unsupported or any(token.startswith(item + "=") for item in unsupported):
                    selectors.append(token)
                    return None, marker, f"pytest selector {name} is not modeled at file level"
                if name in configuration_options or any(
                    token.startswith(item + "=") for item in configuration_options
                ):
                    if name == "--basetemp":
                        value = attached
                        if not value:
                            if index + 1 >= len(arguments):
                                return None, marker, "configuration: pytest option --basetemp is missing its value"
                            value = arguments[index + 1]
                        if not self._pytest_basetemp_is_safe(value, cwd):
                            return None, marker, "configuration: pytest --basetemp can remove repository test bytes"
                        if not attached:
                            index += 1
                        index += 1
                        continue
                    return None, marker, f"configuration: pytest option {name} can change collection"
                if name in value_options:
                    if not attached:
                        if index + 1 >= len(arguments):
                            return None, marker, f"pytest option {name} is missing its value"
                        if index + 1 < len(arguments):
                            index += 1
                    index += 1
                    continue
                if name in flag_options or (
                    name.startswith("-") and set(name[1:]).issubset(set("qvras"))
                ):
                    index += 1
                    continue
                return None, marker, f"pytest option {name} has unmodeled selection semantics"
            if token.startswith("@"):
                return None, marker, "pytest argument files are not modeled"
            if "::" in token:
                return None, marker, "pytest node-id selectors are not modeled"
            if any(
                character in token
                for character in ("$", "{", "}", "*", "?", "[", "]", "~")
            ):
                return None, marker, "pytest path selector is dynamic or shell-expanded"
            normalized, target_error = self._pytest_target_path(token, cwd, runner_os, shell)
            if target_error is not None:
                return None, marker, f"context: {target_error}"
            paths.append(normalized)
            index += 1
        context_error = self._pytest_invocation_context_error(cwd, tuple(paths), runner_os)
        if context_error is not None:
            return None, marker, f"context: {context_error}"
        if not paths:
            return PytestInvocation("broad"), marker, None
        return (
            PytestInvocation(
                "paths",
                tuple(sorted(set(paths))),
                # Invocation paths are proven portable, so reconciliation must
                # never case-fold them based on the analyst or routing label.
                path_case_sensitive=True,
            ),
            marker,
            None,
        )

    def _pytest_implicit_addopts(self, cwd: Path) -> tuple[tuple[str, ...], str | None]:
        """Read one deterministically discovered pytest ``addopts`` value.

        The supported subset shares the ordinary argv parser below.  This lets
        harmless display flags remain usable while retaining fail-closed
        handling for collection-only, plugin, selector, and configuration
        options injected through pytest configuration.
        """

        try:
            repository = self.root.resolve()
            current = cwd.resolve()
            current.relative_to(repository)
        except (OSError, RuntimeError, ValueError):
            return (), "pytest configuration discovery is outside the repository"

        config_names = _PYTEST_CONFIG_NAMES
        checked: set[Path] = set()
        while True:
            for name in config_names:
                path = current / name
                checked.add(path)
                try:
                    if path.is_symlink():
                        return (), f"pytest configuration {name!r} is a symlink"
                    if not path.is_file():
                        continue
                    recognized, addopts = _pytest_config_addopts(path)
                except OSError:
                    return (), f"pytest configuration {name!r} could not be read safely"
                if not recognized:
                    continue
                if addopts is None:
                    return (), f"pytest configuration {name!r} could not be read safely"
                if isinstance(addopts, str):
                    if not addopts.strip():
                        return (), None
                    parsed = _neutral_tokens(addopts)
                    if parsed is None:
                        return (), f"pytest configuration {name!r} has malformed addopts"
                    return parsed, None
                if isinstance(addopts, list | tuple) and all(
                    isinstance(item, str) for item in addopts
                ):
                    for item in addopts:
                        parsed_item = _neutral_tokens(item)
                        if parsed_item is None or len(parsed_item) != 1:
                            return (), f"pytest configuration {name!r} has malformed addopts"
                    return tuple(addopts), None
                return (), f"pytest configuration {name!r} has non-string addopts"
            if current == repository:
                break
            parent = current.parent
            if parent == current:
                return (), "pytest configuration discovery escaped the repository"
            try:
                parent.relative_to(repository)
            except ValueError:
                return (), "pytest configuration discovery escaped the repository"
            current = parent

        # Pytest can choose its root/configuration from a static test target,
        # not only from the shell working directory.  If no ancestor config
        # was decisive, any nested config with non-empty addopts might become
        # active for a selected target.  Refuse that ambiguity rather than
        # silently reconstructing argv from the wrong rootdir.
        inspected = 0
        try:
            for path in self.root.rglob("*"):
                if path.name.lower() not in config_names:
                    continue
                if path.is_symlink():
                    return (), "pytest configuration discovery encountered a symlink"
                if not path.is_file():
                    continue
                if path in checked:
                    continue
                inspected += 1
                if inspected > 4096:
                    return (), "pytest configuration discovery is not safely bounded"
                recognized, addopts = _pytest_config_addopts(path)
                if not recognized:
                    continue
                try:
                    relative = path.relative_to(repository).as_posix()
                except ValueError:
                    return (), "pytest configuration discovery escaped the repository"
                if addopts is None:
                    return (), f"pytest configuration {relative!r} could not be read safely"
                if isinstance(addopts, str) and addopts.strip():
                    return (), (
                        f"pytest configuration {relative!r} may be selected by a test target"
                    )
                if isinstance(addopts, list | tuple) and addopts:
                    return (), (
                        f"pytest configuration {relative!r} may be selected by a test target"
                    )
                if not isinstance(addopts, str | list | tuple):
                    return (), f"pytest configuration {relative!r} has non-string addopts"
        except OSError:
            return (), "pytest configuration discovery could not be completed safely"
        return (), None

    def _pytest_basetemp_is_safe(self, value: str, cwd: Path) -> bool:
        """Allow only disposable tox/nox temp paths for pytest's destructive option."""

        if any(character in value for character in ("$", "{", "}", "*", "?", "[", "]")):
            return False
        try:
            candidate = Path(value)
            if not candidate.is_absolute():
                candidate = cwd / candidate
            candidate = candidate.resolve(strict=False)
            repository = self.root.resolve()
            relative = candidate.relative_to(repository)
        except ValueError:
            # A statically known path outside the checkout cannot remove test
            # or pytest-configuration bytes that GreenGap is analyzing.
            return True
        except OSError:
            return False
        return bool(relative.parts) and relative.parts[0].lower() in {".tox", ".nox"}

    def _resolve_shell(
        self, tokens: tuple[str, ...], context: _Context, depth: int
    ) -> WorkspaceState:
        shell_name = _basename(tokens[0]).lower()
        if shell_name not in {"bash", "sh"}:
            self.issue(
                "SHELL_SCRIPT_UNKNOWN",
                "shell interpreter is outside the exact script-wrapper subset",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if len(tokens) != 2 or tokens[1].startswith("-"):
            self.issue(
                "SHELL_SCRIPT_UNKNOWN",
                "shell wrapper must have exactly one statically known script path",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        script = tokens[1]
        if script.startswith("<("):
            self.issue(
                "DYNAMIC_SHELL_SETUP",
                "process-substitution shell setup is outside the selection graph",
                context.provenance,
                False,
            )
            return UNKNOWN_SIDE_EFFECT
        script_path = self._resolve_path(script, context.cwd, context.provenance)
        if script_path is not None:
            return self._resolve_script(script_path, context, depth, shell="bash")
        return UNKNOWN_SIDE_EFFECT

    def _script_assignments(self, content: str) -> dict[str, str | None]:
        values: dict[str, str | None] = {}
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("export "):
                stripped = stripped[len("export ") :].lstrip()
            match = _ASSIGNMENT.match(stripped)
            if not match:
                continue
            raw = match.group(2).strip()
            if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
                raw = raw[1:-1]
            values[match.group(1)] = raw if _safe_command_prefix(raw) else None
        return values

    def _filter_known_shell_branches(
        self, content: str, env: dict[str, str]
    ) -> str:
        """Select only the simple GitHub Actions branch we can prove."""

        lines = content.splitlines()
        output: list[str] = []
        index = 0
        while index < len(lines):
            line = lines[index]
            stripped = line.strip()
            match = re.match(
                r"^if\s+\[\s+(-z|-n)\s+(['\"]?)\$GITHUB_ACTIONS\2\s+\];?\s+then\s*$",
                stripped,
                re.IGNORECASE,
            )
            if not match:
                output.append(line)
                index += 1
                continue
            condition_empty = match.group(1) == "-z"
            actual_empty = not env.get("GITHUB_ACTIONS", "")
            take_then = condition_empty == actual_empty
            then_lines: list[str] = []
            else_lines: list[str] = []
            branch = then_lines
            index += 1
            while index < len(lines):
                branch_line = lines[index]
                branch_stripped = branch_line.strip()
                if branch_stripped == "else":
                    branch = else_lines
                    index += 1
                    continue
                if branch_stripped == "fi":
                    index += 1
                    break
                branch.append(branch_line)
                index += 1
            output.extend(then_lines if take_then else else_lines)
        return "\n".join(output)

    def _resolve_script(
        self, path: Path, context: _Context, depth: int, shell: str = _NEUTRAL_SHELL
    ) -> WorkspaceState:
        if depth > MAX_DEPTH:
            self.issue(
                "RESOLUTION_DEPTH_EXCEEDED", "script resolution depth exceeded", context.provenance
            )
            return UNKNOWN_SIDE_EFFECT
        if path in self._script_stack:
            self.issue("RESOLUTION_CYCLE", f"script cycle detected at {path}", context.provenance)
            return UNKNOWN_SIDE_EFFECT
        try:
            content = read_limited_text(path, MAX_CONFIG_BYTES)
        except (OSError, ValueError, UnicodeError) as exc:
            self.issue("SCRIPT_UNRESOLVED", f"could not read {path}: {exc}", context.provenance)
            return UNKNOWN_SIDE_EFFECT
        if _script_contains_file_mutation(content):
            self.issue(
                "PRETEST_MUTATION_UNKNOWN",
                "shell script changes the workspace before or during pytest selection",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if _shell_control_flow_unknown(content):
            self.issue(
                "SHELL_CONTROL_FLOW_UNKNOWN",
                "shell control flow or command chaining can change whether a test command runs",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        self._script_stack.add(path)
        env = {"GITHUB_ACTIONS": "true", **context.env}
        content = self._filter_known_shell_branches(content, env)
        assignments = self._script_assignments(content)
        for key, value in assignments.items():
            if value is not None:
                env[key] = value
        script_provenance = context.provenance + (f"script:{normalize_repo_path(self.root, path)}",)
        state: WorkspaceState = context.workspace_state
        for segment in _shell_segments(content):
            dynamic_prefix = any(
                value is None
                and re.search(rf"\$(?:\{{{re.escape(key)}\}}|{re.escape(key)})", segment)
                for key, value in assignments.items()
            )
            if dynamic_prefix and _relevant_text(segment):
                self.issue(
                    "DYNAMIC_EXECUTABLE_PREFIX",
                    "shell executable prefix is not a static path prefix",
                    script_provenance,
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            state = _merge_workspace_state(
                state,
                self._resolve_command(
                    segment,
                    replace(
                        context,
                        env=env,
                        provenance=script_provenance,
                        workspace_state=state,
                    ),
                    depth,
                    shell=shell,
                ),
            )
        self._script_stack.remove(path)
        return state

    def _load_makefile(
        self, cwd: Path
    ) -> tuple[dict[str, tuple[tuple[str, ...], tuple[str, ...]]], dict[str, str]] | None:
        file: Path | None = None
        for name in ("Makefile", "makefile", "GNUmakefile"):
            _, candidate, path_error = _portable_repo_path(self.root, name, cwd)
            if path_error is not None:
                # A case-variant or otherwise non-portable makefile must not
                # be selected using the analyst host's filesystem behavior.
                # Continue probing the other canonical GNU Make names: an
                # exact lowercase ``makefile`` is valid even when the first
                # (capitalized) spelling has a case-fold collision.
                continue
            if candidate is not None and candidate.is_file():
                file = candidate
                break
        if file is None:
            return None
        try:
            lines = read_limited_text(file, MAX_CONFIG_BYTES).splitlines()
        except (OSError, ValueError, UnicodeError):
            return None
        targets: dict[str, list[list[str]]] = {}
        variables: dict[str, str] = {}
        current: list[str] = []
        for line in lines:
            if line.startswith((" ", "\t")) and current:
                for name in current:
                    targets[name][1].append(line.strip())
                continue
            variable = re.match(
                r"^(?:export\s+)?([A-Za-z_.][A-Za-z0-9_.]*)\s*(?::=|\+=|\?=|=)\s*(.*)$",
                line,
            )
            if variable:
                variables[variable.group(1)] = variable.group(2).strip()
                current = []
                continue
            match = re.match(
                r"^([A-Za-z0-9_.%/-]+(?:\s+[A-Za-z0-9_.%/-]+)*)\s*:\s*(.*)$", line
            )
            if match:
                names = match.group(1).split()
                prerequisites = tuple(match.group(2).split())
                for name in names:
                    targets[name] = [list(prerequisites), []]
                current = names
                continue
            if re.match(r"^(?:-?include|sinclude)\s+", line):
                variables["__GREENGAP_MAKEFILE_INCLUDE_UNKNOWN__"] = "1"
                current = []
                continue
            current = []
        return {
            key: (tuple(value[0]), tuple(value[1])) for key, value in targets.items()
        }, variables

    def _resolve_make(
        self, tokens: tuple[str, ...], context: _Context, depth: int, shell: str = _NEUTRAL_SHELL
    ) -> WorkspaceState:
        cwd: Path | None = context.cwd
        index = 1
        assignments: dict[str, str] = {}
        targets: list[str] = []
        while index < len(tokens):
            token = tokens[index]
            if token == "-C" and index + 1 < len(tokens):
                if cwd is None:
                    return UNKNOWN_SIDE_EFFECT
                cwd = self._resolve_path(tokens[index + 1], cwd, context.provenance)
                if cwd is None:
                    return UNKNOWN_SIDE_EFFECT
                index += 2
                continue
            if token.startswith("-C") and len(token) > 2:
                if cwd is None:
                    return UNKNOWN_SIDE_EFFECT
                cwd = self._resolve_path(token[2:], cwd, context.provenance)
                if cwd is None:
                    return UNKNOWN_SIDE_EFFECT
                index += 1
                continue
            if token.startswith("-"):
                self.issue(
                    "MAKE_COMMAND_UNKNOWN",
                    f"Make option {token!r} is outside the statically supported subset",
                    context.provenance,
                )
                return UNKNOWN_SIDE_EFFECT
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
                key, value = token.split("=", 1)
                assignments[key] = value
            else:
                targets.append(token)
            index += 1
        if cwd is None:
            return UNKNOWN_SIDE_EFFECT
        data = self._load_makefile(cwd)
        if data is None:
            self.issue(
                "MAKEFILE_UNRESOLVED", f"no readable Makefile found in {cwd}", context.provenance
            )
            return UNKNOWN_SIDE_EFFECT
        rules, variables = data
        variables.update(context.env)
        variables.update(assignments)
        if variables.get("__GREENGAP_MAKEFILE_INCLUDE_UNKNOWN__"):
            self.issue(
                "MAKEFILE_INCLUDE_UNKNOWN",
                "Makefile include directives can change shell and recipe semantics",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if any(variables.get(name, "").strip() for name in ("SHELL", ".SHELLFLAGS", "SHELLFLAGS")):
            self.issue(
                "MAKE_SHELL_UNKNOWN",
                "Make shell configuration can wrap or replace recipe execution",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        selected = targets or (
            next((name for name in rules if not name.startswith(".")), ""),
        )
        if not selected or not selected[0]:
            self.issue(
                "MAKE_TARGET_UNKNOWN",
                "Makefile has no statically selected target",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        state: WorkspaceState = context.workspace_state
        for target in selected:
            state = _merge_workspace_state(
                state,
                self._resolve_make_target(
                    target,
                    rules,
                    variables,
                    replace(context, cwd=cwd, workspace_state=state),
                    depth,
                    shell,
                ),
            )
        return state

    def _resolve_make_target(
        self,
        target: str,
        rules: dict[str, tuple[tuple[str, ...], tuple[str, ...]]],
        variables: dict[str, str],
        context: _Context,
        depth: int,
        shell: str = _NEUTRAL_SHELL,
    ) -> WorkspaceState:
        key = (context.cwd, target)
        if key in self._make_stack:
            self.issue(
                "RESOLUTION_CYCLE", f"Make target cycle detected at {target}", context.provenance
            )
            return UNKNOWN_SIDE_EFFECT
        rule = rules.get(target)
        if rule is None:
            self.issue(
                "MAKE_TARGET_UNKNOWN",
                f"Make prerequisite or target {target!r} is not statically declared",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        self._make_stack.add(key)
        prerequisites, recipes = rule
        if _pretest_mutation_unknown("\n".join(recipes)):
            self.issue(
                "PRETEST_MUTATION_UNKNOWN",
                "file-changing Make setup precedes a test runner",
                context.provenance + (f"make:{target}",),
            )
            self._make_stack.remove(key)
            return UNKNOWN_SIDE_EFFECT
        state: WorkspaceState = context.workspace_state
        for prerequisite in prerequisites:
            if prerequisite in rules:
                state = _merge_workspace_state(
                    state,
                    self._resolve_make_target(
                        prerequisite,
                        rules,
                        variables,
                        replace(context, workspace_state=state),
                        depth + 1,
                        shell,
                    ),
                )
            else:
                self.issue(
                    "MAKE_TARGET_UNKNOWN",
                    f"Make prerequisite {prerequisite!r} is not statically declared",
                    context.provenance + (f"make:{target}",),
                )
                state = UNKNOWN_SIDE_EFFECT
        for recipe in recipes:
            if recipe.startswith("@"):  # make's display suppression is not shell semantics
                recipe = recipe[1:].lstrip()

            def replace_variable(match: re.Match[str]) -> str:
                name = match.group(1) or match.group(2) or ""
                return variables.get(name, match.group(0))

            if "$(shell" in recipe or "$(eval" in recipe or "$(call" in recipe:
                self.issue(
                    "MAKE_RECIPE_UNKNOWN", "Make recipe uses dynamic expansion", context.provenance
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            expanded = re.sub(r"\$\(([^()]+)\)|\$\{([^{}]+)\}", replace_variable, recipe)
            state = _merge_workspace_state(
                state,
                self._resolve_command(
                    expanded,
                    replace(
                        context,
                        provenance=context.provenance + (f"make:{target}",),
                        workspace_state=state,
                    ),
                    depth,
                    shell=shell,
                ),
            )
        self._make_stack.remove(key)
        return state

    def _tox_config(
        self, cwd: Path
    ) -> tuple[list[str], dict[str, dict[str, Any]], dict[str, Any] | None] | None:
        pyproject = cwd / "pyproject.toml"
        if pyproject.exists():
            try:
                data = tomllib.loads(read_limited_text(pyproject, MAX_CONFIG_BYTES))
            except (OSError, ValueError, UnicodeError, tomllib.TOMLDecodeError):
                data = {}
            tox = data.get("tool", {}).get("tox", {})
            if isinstance(tox, dict):
                env_list = tox.get("env_list", tox.get("envlist", []))
                names = (
                    [str(item) for item in env_list]
                    if isinstance(env_list, list)
                    else str(env_list).split()
                )
                envs = tox.get("envs", tox.get("env", {}))
                return names, envs if isinstance(envs, dict) else {}, tox
        tox_ini = cwd / "tox.ini"
        if not tox_ini.exists():
            return None
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(read_limited_text(tox_ini, MAX_CONFIG_BYTES))
        except (OSError, ValueError, UnicodeError, configparser.Error):
            return None
        envlist = parser.get("tox", "envlist", fallback="")
        names = [item.strip() for item in re.split(r"[\s,]+", envlist) if item.strip()]
        ini_envs: dict[str, dict[str, Any]] = {}
        if parser.has_section("testenv"):
            ini_envs["__base__"] = dict(parser.items("testenv"))
        for section in parser.sections():
            if section.startswith("testenv:"):
                ini_envs[section.split(":", 1)[1]] = dict(parser.items(section))
        return names, ini_envs, None

    def _tox_commands(
        self,
        config: tuple[list[str], dict[str, dict[str, Any]], dict[str, Any] | None],
        name: str,
        posargs: tuple[str, ...],
    ) -> tuple[list[str], bool]:
        env_names, envs, tox = config
        if tox is not None:
            base = tox.get("env_run_base", {})
            selected = envs.get(name, {})
            if not isinstance(base, dict) or not isinstance(selected, dict):
                return [], False
            commands: Any = selected.get("commands", base.get("commands", []))
            if isinstance(selected.get("base"), list):
                for parent in selected["base"]:
                    parent_data = envs.get(parent, {})
                    if (
                        isinstance(parent_data, dict)
                        and "commands" in parent_data
                        and "commands" not in selected
                    ):
                        commands = parent_data["commands"]
            if isinstance(commands, str):
                commands = [commands]
            if not isinstance(commands, list):
                return [], False
            values = []
            for item in commands:
                if isinstance(item, str):
                    values.append(item)
                    continue
                if not isinstance(item, list):
                    return [], False
                argv: list[str] = []
                for raw_token in item:
                    if isinstance(raw_token, str | int | float | bool):
                        argv.append(str(raw_token))
                        continue
                    if isinstance(raw_token, dict) and raw_token.get("replace") == "posargs":
                        default = raw_token.get("default", [])
                        if not isinstance(default, list):
                            return [], False
                        argv.extend(list(posargs) or [str(value) for value in default])
                        continue
                    return [], False
                values.append(shlex.join(argv))
        else:
            base = envs.get("__base__", {})
            selected = envs.get(name, {})
            raw = selected.get("commands", base.get("commands", ""))
            values = [line.strip() for line in str(raw).splitlines() if line.strip()]
        result: list[str] = []
        posarg_text = " ".join(shlex.quote(arg) for arg in posargs)
        for command in values:
            command = command.replace("{posargs}", posarg_text)
            command = re.sub(
                r"\{posargs:([^{}]*)\}", lambda match: posarg_text or match.group(1), command
            )
            command = command.replace("{envpython}", "python")
            command = command.replace("{toxinidir}", str(self.root))
            command = command.replace("{toxworkdir}", ".tox")
            command = command.replace("{env_tmp_dir}", f".tox/{name}")
            command = command.replace("{envlogdir}", f".tox/{name}/log")
            if re.search(r"\{[^{}]+\}", command):
                return [], False
            result.append(command)
        return result, True

    def _tox_pytest_environment_unknown(
        self,
        config: tuple[list[str], dict[str, dict[str, Any]], dict[str, Any] | None],
        name: str,
    ) -> bool:
        """Detect tox environment variables that can narrow pytest collection."""

        _, envs, tox = config
        if tox is not None:
            base = tox.get("env_run_base", {})
            selected = envs.get(name, {})
            if not isinstance(base, dict) or not isinstance(selected, dict):
                return True
            raw = selected.get("set_env", selected.get("setenv", base.get("set_env", base.get("setenv"))))
        else:
            base = envs.get("__base__", {})
            selected = envs.get(name, {})
            raw = selected.get("setenv", base.get("setenv"))
        if raw is None:
            return False
        if isinstance(raw, dict):
            return any(str(key).upper() in {
                "PYTEST_ADDOPTS",
                "PYTEST_PLUGINS",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
            } for key in raw)
        return any(
            line.split("=", 1)[0].strip().upper()
            in {"PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTEST_DISABLE_PLUGIN_AUTOLOAD"}
            for line in str(raw).splitlines()
            if "=" in line
        )

    def _tox_execution_context_unknown(
        self,
        config: tuple[list[str], dict[str, dict[str, Any]], dict[str, Any] | None],
        name: str,
    ) -> bool:
        """Reject tox lanes whose lifecycle commands are not fully modeled."""

        _, envs, tox = config
        if tox is not None:
            base = tox.get("env_run_base", {})
            selected = envs.get(name, {})
        else:
            base = envs.get("__base__", {})
            selected = envs.get(name, {})
        if not isinstance(base, dict) or not isinstance(selected, dict):
            return True
        for mapping in (base, selected):
            for key in ("changedir", "change_dir"):
                if key in mapping and mapping[key] not in (None, ""):
                    return True
            for lifecycle in ("commands_pre", "commands_post"):
                if mapping.get(lifecycle) not in (None, "", [], ()):
                    return True
        return False

    def _tox_packaging_unknown(
        self,
        config: tuple[list[str], dict[str, dict[str, Any]], dict[str, Any] | None],
        name: str,
    ) -> bool:
        """Require tox packaging to be explicitly disabled before tracing tests.

        Tox normally builds an sdist or wheel through the project's packaging
        backend before running commands.  Those hooks are executable project
        code, so only an explicit ``skip_install``/``package = skip`` contract
        is safe for byte-stable pytest inference.
        """

        _, envs, tox = config
        if tox is not None:
            base = tox.get("env_run_base", {})
            selected = envs.get(name, {})
            if not isinstance(base, dict) or not isinstance(selected, dict):
                return True
            skip_install = selected.get("skip_install", base.get("skip_install"))
            package = selected.get("package", base.get("package", tox.get("package")))
        else:
            base = envs.get("__base__", {})
            selected = envs.get(name, {})
            if not isinstance(base, dict) or not isinstance(selected, dict):
                return True
            skip_install = selected.get("skip_install", base.get("skip_install"))
            package = selected.get("package", base.get("package"))
        if str(skip_install).strip().lower() in {"1", "true", "yes", "on"}:
            return False
        package_name = str(package).strip().lower() if package is not None else ""
        return package_name not in {"skip", "none"}

    def _resolve_tox(
        self, tokens: tuple[str, ...], context: _Context, depth: int, shell: str = _NEUTRAL_SHELL
    ) -> WorkspaceState:
        config = self._tox_config(context.cwd)
        if config is None:
            self.issue(
                "TOX_CONFIG_UNRESOLVED",
                f"no readable tox configuration found in {context.cwd}",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        env_names, _, _ = config
        selected: list[str] = []
        posargs: tuple[str, ...] = ()
        index = 1
        if index < len(tokens) and tokens[index] == "run":
            index += 1
        while index < len(tokens):
            token = tokens[index]
            if token in {"-e", "--env"} and index + 1 < len(tokens):
                selected.extend(part for part in tokens[index + 1].split(",") if part)
                index += 2
                continue
            if token.startswith("-e") and len(token) > 2:
                selected.extend(part for part in token[2:].split(",") if part)
                index += 1
                continue
            if token == "--":
                posargs = tokens[index + 1 :]
                break
            if token.startswith("-"):
                self.issue(
                    "TOX_COMMAND_UNKNOWN",
                    f"tox option {token!r} is outside the statically supported subset",
                    context.provenance,
                )
                return UNKNOWN_SIDE_EFFECT
            index += 1
        if not selected:
            raw_env = context.env.get("TOX_ENV") or context.env.get("TOXENV")
            if raw_env:
                selected = [part for part in re.split(r"[\s,]+", raw_env) if part]
            else:
                selected = env_names
        if not selected or any("{" in name or "$" in name for name in selected):
            self.issue(
                "TOX_ENV_UNRESOLVED",
                "selected tox environments are not statically known",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        state: WorkspaceState = context.workspace_state
        for name in selected:
            if self._tox_execution_context_unknown(config, name):
                self.issue(
                    "TOX_EXECUTION_CONTEXT_UNKNOWN",
                    f"tox environment {name!r} changes directory or has unresolved lifecycle commands",
                    context.provenance + (f"tox:{name}",),
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            if self._tox_packaging_unknown(config, name):
                self.issue(
                    "TOX_PACKAGING_UNKNOWN",
                    f"tox environment {name!r} may execute the project packaging backend before tests",
                    context.provenance + (f"tox:{name}",),
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            if self._tox_pytest_environment_unknown(config, name):
                self.issue(
                    "PYTEST_CONFIGURATION_UNKNOWN",
                    f"tox environment {name!r} sets pytest selection or plugin configuration",
                    context.provenance + (f"tox:{name}",),
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            commands, complete = self._tox_commands(config, name, posargs)
            if not complete:
                self.issue(
                    "TOX_COMMANDS_UNRESOLVED",
                    f"commands for tox environment {name!r} are dynamic",
                    context.provenance,
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            for command in commands:
                state = _merge_workspace_state(
                    state,
                    self._resolve_command(
                        command,
                        replace(
                            context,
                            provenance=context.provenance + (f"tox:{name}",),
                            workspace_state=state,
                        ),
                        depth,
                        shell=shell,
                    ),
                )
        return state

    def _package_json(self, cwd: Path) -> tuple[Path, dict[str, str]] | None:
        _, path, path_error = _portable_repo_path(self.root, "package.json", cwd)
        if path_error is not None or path is None or not path.is_file():
            # npm-family discovery is case-sensitive on some CI runners;
            # never let the analyst host canonicalize Package.json into the
            # manifest that controls a test script.
            return None
        try:
            data = json.loads(read_limited_text(path, MAX_CONFIG_BYTES))
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
            return None
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if not isinstance(scripts, dict):
            return None
        return path, {str(key): str(value) for key, value in scripts.items()}

    def _package_execution_context_error(
        self, manager: str, cwd: Path, environment: dict[str, str]
    ) -> str | None:
        """Reject package-manager config that can wrap lifecycle execution.

        npm/pnpm/Yarn discover configuration above the package directory, and
        that configuration can choose a script shell or load project-owned
        hooks.  The resolver models only the plain package.json script graph.
        """

        try:
            repository = self.root.resolve()
            current = cwd.resolve()
            current.relative_to(repository)
        except (OSError, RuntimeError, ValueError):
            return "package-manager configuration discovery is outside the repository"
        config_names = {".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs"}
        while True:
            for name in config_names:
                path = current / name
                if path.exists():
                    return f"{manager} execution configuration {name!r} is project-controlled"
            if current == repository:
                break
            parent = current.parent
            if parent == current:
                return "package-manager configuration discovery escaped the repository"
            current = parent
        prefixes = ("NPM_CONFIG_", "YARN_", "PNPM_")
        if any(
            key.upper().startswith(prefixes) and value.strip()
            for key, value in environment.items()
        ):
            return f"{manager} execution configuration is injected through the environment"
        return None

    def _resolve_package(
        self, tokens: tuple[str, ...], context: _Context, depth: int, shell: str = _NEUTRAL_SHELL
    ) -> WorkspaceState:
        manager = _basename(tokens[0])
        cwd: Path | None = context.cwd
        index = 1
        if index + 1 < len(tokens) and tokens[index] in {"--prefix", "-C"}:
            if cwd is None:
                return UNKNOWN_SIDE_EFFECT
            cwd = self._resolve_path(tokens[index + 1], cwd, context.provenance)
            if cwd is None:
                return UNKNOWN_SIDE_EFFECT
            index += 2
        command = tokens[index] if index < len(tokens) else "test"
        if manager == "npm" and command == "run" and index + 1 < len(tokens):
            name = tokens[index + 1]
            posargs = tokens[index + 2 :]
        elif command in {"test", "run"}:
            name = (
                "test"
                if command == "test"
                else (tokens[index + 1] if index + 1 < len(tokens) else "")
            )
            posargs = tokens[index + 2 :] if command == "run" else tokens[index + 1 :]
        else:
            self.issue(
                "PACKAGE_COMMAND_UNKNOWN",
                f"package-manager command {command!r} is outside the audited test/run subset",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if cwd is None:
            return UNKNOWN_SIDE_EFFECT
        context_error = self._package_execution_context_error(manager, cwd, context.env)
        if context_error is not None:
            self.issue("PACKAGE_EXECUTION_CONTEXT_UNKNOWN", context_error, context.provenance)
            return UNKNOWN_SIDE_EFFECT
        package = self._package_json(cwd)
        if package is None or name not in package[1]:
            self.issue(
                "PACKAGE_SCRIPT_UNRESOLVED",
                f"package script {name!r} is not statically available in {cwd}",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        scripts = package[1]
        lifecycle_names = [name]
        if manager == "npm" and command in {"test", "run"}:
            lifecycle_names = [f"pre{name}", name, f"post{name}"]
        elif manager != "npm" and any(
            lifecycle in scripts for lifecycle in (f"pre{name}", f"post{name}")
        ):
            self.issue(
                "PACKAGE_LIFECYCLE_UNKNOWN",
                f"{manager} lifecycle hooks are not assumed to run implicitly",
                context.provenance,
            )
        selected_scripts = [lifecycle for lifecycle in lifecycle_names if lifecycle in scripts]
        pre_lifecycle = f"pre{name}"
        if (
            manager == "npm"
            and pre_lifecycle in scripts
            and _pretest_script_unknown(scripts[pre_lifecycle])
        ):
            self.issue(
                "NPM_PRETEST_UNKNOWN",
                "npm pre-test lifecycle script is not statically harmless or test-resolvable",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        state: WorkspaceState = context.workspace_state
        for lifecycle in selected_scripts:
            key = (cwd, lifecycle)
            if key in self._package_stack:
                self.issue(
                    "RESOLUTION_CYCLE",
                    f"package script cycle detected at {lifecycle}",
                    context.provenance,
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            self._package_stack.add(key)
            script = scripts[lifecycle]
            if posargs and lifecycle == name:
                script = f"{script} {' '.join(shlex.quote(arg) for arg in posargs)}"
            state = _merge_workspace_state(
                state,
                self._resolve_command(
                    script,
                    replace(
                        context,
                        cwd=cwd,
                        provenance=context.provenance + (f"npm:{lifecycle}",),
                        workspace_state=state,
                    ),
                    depth,
                    shell=shell,
                ),
            )
            self._package_stack.remove(key)
        return state


def trace_github_actions(
    root: Path,
    changed_files: Sequence[str] | None = None,
    event: str | None = None,
    ref: str | None = None,
    base_ref: str | None = None,
    activity: str | None = None,
    change_set_complete: bool = False,
    commit_count: int | None = None,
    changed_file_count: int | None = None,
    diff_timed_out: bool = False,
) -> TraceResult:
    return _Resolver(
        root,
        changed_files,
        event,
        ref,
        base_ref,
        activity,
        change_set_complete,
        commit_count,
        changed_file_count,
        diff_timed_out,
    ).trace()
