"""Conservative, deterministic GitHub Actions to pytest command tracing."""

from __future__ import annotations

import ast
import configparser
import fnmatch
import itertools
import json
import re
import shlex
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

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
_EXPRESSION = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
_ASSIGNMENT = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|:=)\s*(.*)$")
_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_KNOWN_SETUP_ACTIONS = {
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
_SAFE_SETUP_COMMANDS = {
    "cat",
    "chmod",
    "cp",
    "cd",
    ".",
    "echo",
    "env",
    "export",
    "git",
    "grep",
    "gh",
    "greengap",
    "ls",
    "mkdir",
    "mv",
    "pip",
    "pip3",
    "pip-audit",
    "pyright",
    "printf",
    "pwd",
    "rm",
    "set",
    "sha256sum",
    "sort",
    "touch",
    "true",
    "uname",
    "which",
}
_SAFE_PYTHON_MODULES = {
    "build",
    "compileall",
    "coverage",
    "pip",
    "pip_audit",
    "pre-commit",
    "venv",
    "mypy",
    "ruff",
    "twine",
    "zipfile",
}
@dataclass(frozen=True)
class _Context:
    cwd: Path
    env: dict[str, str]
    matrix: dict[str, Any]
    inputs: dict[str, Any]
    provenance: tuple[str, ...]
    event_context: str | None = None


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
    first = _basename(tokens[0])
    if first in {"pytest", "pytest.exe", "tox", "tox.exe", "nox", "invoke", "pre-commit", "pre_commit"}:
        return True
    if first.endswith("pytest") or first.endswith("pytest.exe"):
        return True
    if first.endswith("coverage") or first.endswith("coverage.exe"):
        return len(tokens) > 1 and tokens[1] == "run"
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
    first = resolved.strip().lower().split(maxsplit=1)[0] if resolved.strip() else ""
    if first in {"bash", "sh"}:
        return "bash"
    if first in {"pwsh", "powershell"}:
        return "powershell"
    return "unknown"


def _default_shell(
    defaults: Any, runs_on: Any, context: _Context, fallback: str | None = None
) -> str | None:
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
    runs_on_text = _scalar(runs_on) if runs_on is not None else None
    if runs_on_text is not None:
        resolved, known = resolve_expressions(runs_on_text, context)
        if not known:
            return "unknown"
        return "powershell" if "windows" in resolved.lower() else "bash"
    return fallback


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


def _safe_path_prefix(value: str) -> bool:
    return value == "" or (
        value.endswith(("/", "\\")) and bool(re.fullmatch(r"[A-Za-z0-9_./\\:-]+", value))
    )


def _expand_safe_prefix(command: str, env: dict[str, str]) -> tuple[str | None, str | None]:
    """Expand only variables that are provable executable path prefixes."""

    output: list[str] = []
    cursor = 0
    for match in _VARIABLE.finditer(command):
        output.append(command[cursor : match.start()])
        variable = match.group(1) or match.group(2) or ""
        rest = command[match.end() :].lstrip()
        runner_like = bool(
            re.match(r"(?:coverage|python(?:3(?:\.\d+)?)?|pytest)(?:\s|/|\\|$)", rest)
        )
        if not runner_like:
            output.append(match.group(0))
            cursor = match.end()
            continue
        if variable not in env:
            return None, f"variable prefix ${variable} is not statically known"
        value = env[variable]
        if not _safe_path_prefix(value):
            return None, f"variable prefix ${variable} has a dynamic or unsafe value"
        output.append(value)
        cursor = match.end()
    output.append(command[cursor:])
    return "".join(output), None


def _tokens(command: str) -> tuple[str, ...] | None:
    try:
        lexer = shlex.shlex(command, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        return tuple(lexer)
    except ValueError:
        return None


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


def _safe_setup_command(tokens: tuple[str, ...]) -> bool:
    """Recognize commands that cannot select or execute the test suite by themselves."""

    if not tokens:
        return True
    first = _basename(tokens[0])
    if first in {"mypy", "ruff", "twine"}:
        return True
    if first in _SAFE_SETUP_COMMANDS:
        return True
    if first == "greengap":
        return set(tokens[1:]).issubset({"--version", "--help"})
    if first == "coverage":
        return len(tokens) > 1 and tokens[1] in {"erase", "combine", "xml", "report"}
    if first.startswith("python"):
        if len(tokens) == 1:
            return True
        if "-c" in tokens:
            return _safe_python_code(tokens)
        for index, token in enumerate(tokens[:-1]):
            if token == "-m":
                return _basename(tokens[index + 1]) in _SAFE_PYTHON_MODULES
        return False
    return False


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
_PRETEST_MUTATING_GIT_COMMANDS = {
    "apply",
    "checkout",
    "clean",
    "merge",
    "restore",
    "reset",
    "switch",
}


def _segment_mutates_files(segment: str, tokens: tuple[str, ...]) -> bool:
    if _has_unquoted(segment, ">"):
        return True
    command = _basename(tokens[0]) if tokens else ""
    if command in _PRETEST_MUTATION_COMMANDS:
        return True
    if command == "git" and len(tokens) > 1:
        return _basename(tokens[1]) in _PRETEST_MUTATING_GIT_COMMANDS
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


def _workflow_has_path_filters(events: Any) -> bool:
    if not isinstance(events, dict):
        return False
    return any(
        isinstance(config, dict) and any(key in config for key in ("paths", "paths-ignore"))
        for config in events.values()
    )


def _path_patterns_match(path: str, patterns: Any) -> bool | None:
    if not isinstance(patterns, list) or not patterns or not all(
        isinstance(pattern, str) and pattern for pattern in patterns
    ):
        return None
    matched = False
    for raw_pattern in patterns:
        negated = raw_pattern.startswith("!")
        pattern = raw_pattern[1:] if negated else raw_pattern
        if not pattern or not fnmatch.fnmatchcase(path, pattern):
            continue
        matched = not negated
    return matched


def _workflow_runs_for_changes(events: Any, changed_files: tuple[str, ...]) -> bool | None:
    """Evaluate path filters only when an explicit changed-file set is bound."""

    if not isinstance(events, dict):
        return True
    filtered_event_seen = False
    for config in events.values():
        if not isinstance(config, dict):
            return True
        has_paths = "paths" in config
        has_ignored = "paths-ignore" in config
        if has_paths and has_ignored:
            return None
        if not has_paths and not has_ignored:
            return True
        filtered_event_seen = True
        if has_paths:
            matches = [_path_patterns_match(path, config["paths"]) for path in changed_files]
            if any(value is None for value in matches):
                return None
            if any(matches):
                return True
        else:
            ignored = [
                _path_patterns_match(path, config["paths-ignore"]) for path in changed_files
            ]
            if any(value is None for value in ignored):
                return None
            if any(not value for value in ignored):
                return True
    return not filtered_event_seen


def _pipeline_is_safe(command: str) -> bool:
    """Return true only for pipelines made entirely from setup allowlist commands."""

    found = False
    for line in command.splitlines():
        tokens = _tokens(line)
        if tokens is None or "|" not in tokens:
            continue
        found = True
        component: list[str] = []
        for token in (*tokens, "|"):
            if token == "|":
                if not component or not _safe_setup_command(tuple(component)):
                    return False
                component = []
            else:
                component.append(token)
    return found


def _has_pipeline_token(command: str) -> bool:
    return any(
        tokens is not None and "|" in tokens
        for tokens in (_tokens(line) for line in command.splitlines())
    )


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
    def __init__(self, root: Path, changed_files: Sequence[str] | None = None) -> None:
        self.root = root.resolve()
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

    def issue(
        self, code: str, message: str, provenance: tuple[str, ...], relevant: bool = True
    ) -> None:
        item = TraceIssue(code, message, provenance, relevant)
        if item not in self.issues:
            self.issues.append(item)

    def invocation(self, item: PytestInvocation) -> None:
        if item not in self.invocations:
            self.invocations.append(item)

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

    def _precommit_entries(self) -> tuple[str, ...] | None:
        """Return statically declared hook entries, or None if unsafe."""

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
        entries: list[str] = []
        for raw_repo in data["repos"]:
            if not isinstance(raw_repo, dict) or not isinstance(raw_repo.get("hooks"), list):
                return None
            for raw_hook in raw_repo["hooks"]:
                if not isinstance(raw_hook, dict):
                    return None
                entry = _scalar(raw_hook.get("entry"))
                if entry is None:
                    return None
                entries.append(entry)
        return tuple(entries)

    def _resolve_precommit(self, context: _Context, depth: int) -> None:
        if self._precommit_config_is_non_test():
            return
        entries = self._precommit_entries()
        if entries is None:
            self.issue(
                "PRE_COMMIT_HOOKS_UNKNOWN",
                "pre-commit hooks could not be statically enumerated",
                context.provenance,
            )
            return
        if not entries:
            self.issue(
                "PRE_COMMIT_HOOKS_UNKNOWN",
                "pre-commit configuration declares no statically visible hooks",
                context.provenance,
            )
            return
        for entry in entries:
            self._resolve_command(
                entry,
                replace(context, provenance=context.provenance + ("pre-commit:hook",)),
                depth + 1,
            )

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
                if action_name.startswith("./") or action_name not in _KNOWN_SETUP_ACTIONS:
                    return True
        return False

    def _context(self, cwd: Path | None = None, **changes: Any) -> _Context:
        return _Context(cwd or self.root, {}, {}, {}, ()).__class__(
            cwd=cwd or self.root,
            env=changes.get("env", {}),
            matrix=changes.get("matrix", {}),
            inputs=changes.get("inputs", {}),
            provenance=changes.get("provenance", ()),
        )

    def trace(self) -> TraceResult:
        try:
            workflow_dir = safe_resolve(self.root, ".github/workflows")
        except PathSafetyError as exc:
            self.issue(
                "PATH_OUTSIDE_REPOSITORY",
                f"workflow directory is unsafe: {exc}",
                (".github/workflows",),
            )
            return TraceResult((), tuple(self.issues), (), self.changed_files)
        if not workflow_dir.is_dir():
            return TraceResult((), (), (), self.changed_files)
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
            return TraceResult((), tuple(self.issues), (), self.changed_files)
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
            self._resolve_workflow(path, _Context(self.root, {}, {}, {}, (relative,)))
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
        return TraceResult(
            tuple(self.invocations),
            tuple(final_issues),
            tuple(self.workflows),
            self.changed_files,
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
            path = safe_resolve(self.root, path)
        except PathSafetyError as exc:
            self.issue("PATH_OUTSIDE_REPOSITORY", f"workflow path is unsafe: {exc}", context.provenance)
            return
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
        declared_event = event_signature or ("unknown" if events_present else "implicit")
        effective_event = context.event_context or declared_event
        self._workflow_events.setdefault(relative, set()).add(effective_event)
        event_kinds = _event_kinds(raw_events) if events_present else {"implicit"}
        self._workflow_event_kinds.setdefault(relative, set()).update(event_kinds or {"unknown"})
        if _workflow_has_path_filters(raw_events):
            if self.changed_files is None:
                self._workflow_path_filters.add(relative)
            else:
                runs_for_changes = _workflow_runs_for_changes(raw_events, self.changed_files)
                if runs_for_changes is None:
                    self.issue(
                        "WORKFLOW_PATH_FILTER_UNKNOWN",
                        "workflow path filters could not be evaluated for the bound change set",
                        context.provenance,
                    )
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
                )
                workflow_cwd = self._default_working_directory(
                    data.get("defaults"), row_base, self.root, provenance
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
        try:
            target = safe_resolve(self.root, uses[2:])
        except PathSafetyError as exc:
            self.issue("PATH_OUTSIDE_REPOSITORY", f"reusable workflow path is unsafe: {exc}", context.provenance)
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
                provenance=context.provenance + (f"uses:{normalize_repo_path(self.root, target)}",),
            ),
        )

    def _resolve_steps(
        self,
        steps: Any,
        context: _Context,
        default_shell: str | None = "bash",
        default_cwd: Path | None = None,
    ) -> None:
        if not isinstance(steps, list):
            self.issue(
                "STEPS_UNKNOWN", "workflow steps are not statically enumerable", context.provenance
            )
            return
        for index, raw_step in enumerate(steps):
            if not isinstance(raw_step, dict):
                self.issue(
                    "STEP_SHAPE_UNKNOWN", f"step {index} is not a mapping", context.provenance
                )
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
                    condition_relevant = action_name not in _KNOWN_SETUP_ACTIONS and not (
                        action_name == "pre-commit-ci/lite-action"
                        and self._precommit_config_is_non_test()
                    )
                self.issue(
                    "CONDITION_UNKNOWN",
                    f"step {label} has a condition that is not statically decidable",
                    provenance,
                    relevant=condition_relevant,
                )
                continue
            step_env, step_env_complete = _env_mapping(raw_step.get("env"), context)
            step_context = replace(context, env={**context.env, **step_env}, provenance=provenance)
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
                    continue
                shell = (
                    _static_shell(raw_step.get("shell"), step_context)
                    if "shell" in raw_step
                    else default_shell
                )
                if shell not in {"bash", "powershell"}:
                    self.issue(
                        "SHELL_UNKNOWN",
                        f"step {label} uses an unsupported or unresolved shell",
                        provenance,
                    )
                    continue
                command, known = resolve_expressions(command, step_context)
                if not known and _relevant_text(command):
                    self.issue(
                        "RUN_COMMAND_DYNAMIC",
                        "relevant run command contains an unresolved expression",
                        provenance,
                    )
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
                        cwd = self._resolve_path(raw_cwd, self.root, provenance)
                        if cwd is None:
                            continue
                    elif _relevant_text(command):
                        self.issue(
                            "WORKING_DIRECTORY_UNKNOWN",
                            "pytest command has an unresolved working directory",
                            provenance,
                        )
                        continue
                if cwd is None:
                    self.issue(
                        "WORKING_DIRECTORY_UNKNOWN",
                        f"working directory for step {label} is not statically known",
                        provenance,
                    )
                    continue
                self._resolve_command(
                    command, replace(step_context, cwd=cwd), 0, shell=shell
                )
            elif "uses" in raw_step:
                uses = raw_step.get("uses")
                if isinstance(uses, str) and uses.startswith("./"):
                    action_dir = self._resolve_path(uses[2:], self.root, provenance)
                    if action_dir is not None:
                        self._resolve_composite(action_dir, step_context, default_shell)
                elif isinstance(uses, str):
                    action_name = uses.split("@", 1)[0].lower()
                    if action_name == "actions/checkout":
                        raw_with = raw_step.get("with", {})
                        sparse_value = (
                            raw_with.get("sparse-checkout") if isinstance(raw_with, dict) else None
                        )
                        sparse_enabled = sparse_value not in (None, "", False, [])
                        if isinstance(raw_with, dict) and sparse_enabled:
                            self.issue(
                                "CHECKOUT_SPARSE_UNKNOWN",
                                "actions/checkout sparse inputs change the analyzed workspace surface",
                                provenance,
                            )
                    if action_name == "pre-commit-ci/lite-action" and self._precommit_config_is_non_test():
                        continue
                    if action_name not in _KNOWN_SETUP_ACTIONS:
                        self.issue(
                            "EXTERNAL_ACTION_UNKNOWN",
                            f"external action {uses!r} is not modeled as a setup-only action",
                            provenance,
                        )
                else:
                    self.issue(
                        "EXTERNAL_ACTION_UNKNOWN",
                        f"action in step {label} is not statically known",
                        provenance,
                    )

    def _resolve_composite(
        self, action_dir: Path, context: _Context, default_shell: str | None
    ) -> None:
        action_file = next(
            (
                candidate
                for candidate in (action_dir / "action.yml", action_dir / "action.yaml")
                if candidate.exists()
            ),
            None,
        )
        if action_file is None:
            self.issue(
                "COMPOSITE_ACTION_UNRESOLVED",
                f"local composite action {action_dir} is missing action.yml",
                context.provenance,
            )
            return
        try:
            data = yaml.safe_load(read_limited_text(action_file, MAX_CONFIG_BYTES))
        except ValueError as exc:
            self.issue(
                "COMPOSITE_ACTION_PARSE_ERROR",
                f"could not parse {action_file}: {exc}",
                context.provenance,
            )
            return
        except (OSError, yaml.YAMLError, RecursionError, MemoryError) as exc:
            self.issue(
                "COMPOSITE_ACTION_PARSE_ERROR",
                f"could not parse {action_file}: {exc}",
                context.provenance,
            )
            return
        runs = data.get("runs") if isinstance(data, dict) else None
        if not isinstance(runs, dict) or runs.get("using") != "composite":
            self.issue(
                "COMPOSITE_ACTION_SHAPE_UNKNOWN",
                f"{action_file} is not a static composite action",
                context.provenance,
            )
            return
        self._resolve_steps(
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
        return self._resolve_path(resolved, self.root, provenance)

    def _resolve_path(
        self, value: str, base: Path, provenance: tuple[str, ...] = ()
    ) -> Path | None:
        try:
            return safe_resolve(self.root, value, base)
        except PathSafetyError as exc:
            self.issue(
                "PATH_OUTSIDE_REPOSITORY",
                f"path {value!r} is outside the repository or crosses a symlink: {exc}",
                provenance,
            )
            return None

    def _resolve_command(
        self, command: str, context: _Context, depth: int, shell: str = "bash"
    ) -> None:
        if depth > MAX_DEPTH:
            self.issue(
                "RESOLUTION_DEPTH_EXCEEDED", "command resolution depth exceeded", context.provenance
            )
            return
        if shell == "powershell" and _powershell_control_flow_unknown(command):
            self.issue(
                "SHELL_CONTROL_FLOW_UNKNOWN",
                "PowerShell control flow or command chaining is outside the supported static subset",
                context.provenance,
            )
            return
        if _contains_arbitrary_python_code(command):
            self.issue(
                "PYTHON_CODE_UNKNOWN",
                "arbitrary python -c code is outside the statically auditable command graph",
                context.provenance,
            )
            return
        if _pretest_mutation_unknown(command):
            self.issue(
                "PRETEST_MUTATION_UNKNOWN",
                "file-changing setup precedes a test runner, so the CI test surface is not byte-stable",
                context.provenance,
            )
            return
        if _has_pipeline_token(command) and not _pipeline_is_safe(command):
            self.issue(
                "SHELL_PIPE_UNKNOWN",
                "shell pipelines are outside the supported static command subset",
                context.provenance,
            )
            return
        if _shell_control_flow_unknown(command):
            self.issue(
                "SHELL_CONTROL_FLOW_UNKNOWN",
                "shell control flow or command chaining can change whether a test command runs",
                context.provenance,
            )
            return
        shell_env = dict(context.env)
        for segment in _shell_segments(command):
            expanded, prefix_error = _expand_safe_prefix(segment, context.env)
            if prefix_error is not None:
                if _relevant_text(segment):
                    self.issue("DYNAMIC_EXECUTABLE_PREFIX", prefix_error, context.provenance)
                continue
            if expanded is None:
                continue
            tokens = _tokens(expanded)
            if tokens is None:
                if _relevant_text(segment):
                    self.issue(
                        "COMMAND_PARSE_UNKNOWN",
                        "shell command could not be tokenized safely",
                        context.provenance,
                    )
                continue
            if not tokens:
                continue
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
            first = _basename(tokens[0])
            if first == "export":
                for token in tokens[1:]:
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
                        key, value = token.split("=", 1)
                        shell_env[key] = value
                continue
            if first in {"pre-commit", "pre_commit"}:
                self._resolve_precommit(nested_context, depth)
                continue
            if first.startswith("python") and "-m" in tokens:
                module_indexes = [index for index, token in enumerate(tokens[:-1]) if token == "-m"]
                if any(_basename(tokens[index + 1]) in {"pre-commit", "pre_commit"} for index in module_indexes):
                    self._resolve_precommit(nested_context, depth)
                    continue
            if (first.startswith("python") or first == "py") and "-c" in tokens:
                if not _safe_python_code(tokens):
                    self.issue(
                        "PYTHON_CODE_UNKNOWN",
                        "arbitrary python -c code is outside the statically auditable command graph",
                        context.provenance,
                    )
                continue
            if first == "uv":
                unwrapped, error = self._unwrap_uv(tokens)
                if error:
                    if len(tokens) > 1 and tokens[1] == "run":
                        self.issue("UV_COMMAND_UNKNOWN", error, context.provenance)
                elif unwrapped:
                    self._resolve_command(
                        " ".join(shlex.quote(token) for token in unwrapped),
                        nested_context,
                        depth + 1,
                        shell=shell,
                    )
                continue
            try:
                scope, runner_index, scope_error = self._pytest_scope(tokens, nested_context.cwd)
            except PathSafetyError as exc:
                self.issue(
                    "PATH_OUTSIDE_REPOSITORY",
                    f"pytest path selector is unsafe: {exc}",
                    context.provenance,
                )
                continue
            if runner_index is not None:
                if any(
                    nested_context.env.get(name, "").strip()
                    for name in (
                        "PYTEST_ADDOPTS",
                        "PYTEST_PLUGINS",
                        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
                    )
                ):
                    self.issue(
                        "PYTEST_CONFIGURATION_UNKNOWN",
                        "pytest selection can be changed by an environment configuration variable",
                        context.provenance,
                    )
                elif scope_error:
                    code = (
                        "PYTEST_CONFIGURATION_UNKNOWN"
                        if scope_error.startswith("configuration:")
                        else "PYTEST_SELECTOR_UNKNOWN"
                    )
                    self.issue(code, scope_error, context.provenance)
                elif scope is not None:
                    self.invocation(replace(scope, provenance=context.provenance))
                continue
            if first in {"tox", "tox.exe"}:
                self._resolve_tox(tokens, nested_context, depth + 1)
                continue
            if first in {"make", "gmake"}:
                self._resolve_make(tokens, nested_context, depth + 1)
                continue
            if first in {"npm", "pnpm", "yarn"}:
                self._resolve_package(tokens, nested_context, depth + 1)
                continue
            if first in {"bash", "sh", "zsh", "dash"}:
                self._resolve_shell(tokens, nested_context, depth + 1)
                continue
            token_text = tokens[0].replace("\\", "/")
            shell_script_hint = token_text.lower().endswith(".sh") or token_text.startswith(
                "scripts/"
            )
            if tokens[0].startswith("./") or "/" in tokens[0] or "\\" in tokens[0]:
                token_path = self._resolve_path(tokens[0], nested_context.cwd, context.provenance)
                if shell_script_hint and token_path is not None and token_path.is_file():
                    self._resolve_script(token_path, nested_context, depth + 1)
                    continue
            elif shell_script_hint:
                token_path = self._resolve_path(tokens[0], nested_context.cwd, context.provenance)
                if token_path is not None and token_path.is_file():
                    self._resolve_script(token_path, nested_context, depth + 1)
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
                continue
            self.issue(
                "UNKNOWN_TEST_RUNNER",
                f"command {_basename(tokens[0])!r} is outside the statically supported command subset",
                context.provenance,
                relevant=_relevant_text(segment),
            )

    def _unwrap_uv(self, tokens: tuple[str, ...]) -> tuple[tuple[str, ...] | None, str | None]:
        if len(tokens) < 2 or tokens[1] != "run":
            return None, "only uv run is supported"
        value_options = {
            "--with",
            "--with-editable",
            "--with-requirements",
            "--group",
            "--project",
            "--package",
            "--python",
            "--directory",
            "--env-file",
            "--extra",
            "--index",
            "--resolution",
            "-C",
            "-p",
        }
        flag_options = {
            "--locked",
            "--frozen",
            "--offline",
            "--no-default-groups",
            "--isolated",
            "--no-project",
            "--no-sync",
        }
        index = 2
        while index < len(tokens):
            token = tokens[index]
            if token == "--":
                index += 1
                break
            if token in value_options:
                if index + 1 >= len(tokens):
                    return None, f"uv option {token} is missing its value"
                index += 2
                continue
            if any(token.startswith(option + "=") for option in value_options):
                index += 1
                continue
            if token in flag_options:
                index += 1
                continue
            if token.startswith("-"):
                return None, f"unknown uv option {token} prevents a safe command boundary"
            break
        if index >= len(tokens):
            return None, "uv run has no statically known command"
        return tokens[index:], None

    def _pytest_scope(
        self, tokens: tuple[str, ...], cwd: Path
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
        }
        value_options = {
            "--junitxml",
            "--maxfail",
            "--tb",
            "--color",
            "--capture",
            "--rootdir",
            "-o",
            "-c",
            "--confcutdir",
            "--basetemp",
            "--override-ini",
            "--cov",
            "--cov-report",
            "--cov-config",
            "--cov-fail-under",
            "--filterwarnings",
            "--parallel-threads",
            "-W",
            "-n",
            "-p",
        }
        configuration_options = {
            "-o",
            "--override-ini",
            "-c",
            "--rootdir",
            "--confcutdir",
        }
        flag_options = {
            "-q",
            "-v",
            "-vv",
            "-ra",
            "-s",
            "-x",
            "--exitfirst",
            "--collect-only",
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
        index = marker + 1
        end_options = False
        while index < len(tokens):
            token = tokens[index]
            if token == "--":
                end_options = True
                index += 1
                continue
            if not end_options and token.startswith("-"):
                name, _, attached = token.partition("=")
                if name in unsupported or any(token.startswith(item + "=") for item in unsupported):
                    selectors.append(token)
                    return None, marker, f"pytest selector {name} is not modeled at file level"
                if name in configuration_options or any(
                    token.startswith(item + "=") for item in configuration_options
                ):
                    return None, marker, f"configuration: pytest option {name} can change collection"
                if name in value_options:
                    if not attached:
                        if index + 1 >= len(tokens) and name != "--cov":
                            return None, marker, f"pytest option {name} is missing its value"
                        if index + 1 < len(tokens) and not (
                            name == "--cov" and tokens[index + 1].startswith("-")
                        ):
                            index += 1
                    index += 1
                    continue
                if name in flag_options or (
                    name.startswith("-") and set(name[1:]).issubset(set("qvxs"))
                ):
                    index += 1
                    continue
                return None, marker, f"pytest option {name} has unmodeled selection semantics"
            if "$" in token or "{" in token or "}" in token:
                return None, marker, "pytest path selector is dynamic"
            paths.append(normalize_repo_path(self.root, token, cwd))
            index += 1
        if not paths:
            return PytestInvocation("broad"), marker, None
        return PytestInvocation("paths", tuple(sorted(set(paths)))), marker, None

    def _resolve_shell(self, tokens: tuple[str, ...], context: _Context, depth: int) -> None:
        if len(tokens) < 2:
            self.issue(
                "SHELL_SCRIPT_UNKNOWN",
                "shell wrapper has no statically known script",
                context.provenance,
            )
            return
        if "-c" in tokens[1:]:
            self.issue(
                "SHELL_COMMAND_UNKNOWN",
                "shell -c hides a dynamic command graph",
                context.provenance,
            )
            return
        script = next((token for token in tokens[1:] if not token.startswith("-")), None)
        if script is None:
            self.issue(
                "SHELL_SCRIPT_UNKNOWN", "shell wrapper has no script path", context.provenance
            )
            return
        if script.startswith("<("):
            self.issue(
                "DYNAMIC_SHELL_SETUP",
                "process-substitution shell setup is outside the selection graph",
                context.provenance,
                False,
            )
            return
        script_path = self._resolve_path(script, context.cwd, context.provenance)
        if script_path is not None:
            self._resolve_script(script_path, context, depth)

    def _script_assignments(self, content: str) -> dict[str, str | None]:
        values: dict[str, str | None] = {}
        for line in content.splitlines():
            match = _ASSIGNMENT.match(line.strip())
            if not match:
                continue
            raw = match.group(2).strip()
            if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
                raw = raw[1:-1]
            values[match.group(1)] = raw if _safe_path_prefix(raw) else None
        return values

    def _resolve_script(self, path: Path, context: _Context, depth: int) -> None:
        if depth > MAX_DEPTH:
            self.issue(
                "RESOLUTION_DEPTH_EXCEEDED", "script resolution depth exceeded", context.provenance
            )
            return
        if path in self._script_stack:
            self.issue("RESOLUTION_CYCLE", f"script cycle detected at {path}", context.provenance)
            return
        try:
            content = read_limited_text(path, MAX_CONFIG_BYTES)
        except (OSError, ValueError, UnicodeError) as exc:
            self.issue("SCRIPT_UNRESOLVED", f"could not read {path}: {exc}", context.provenance)
            return
        if _script_contains_file_mutation(content):
            self.issue(
                "PRETEST_MUTATION_UNKNOWN",
                "shell script changes the workspace before or during pytest selection",
                context.provenance,
            )
            return
        if _shell_control_flow_unknown(content):
            self.issue(
                "SHELL_CONTROL_FLOW_UNKNOWN",
                "shell control flow or command chaining can change whether a test command runs",
                context.provenance,
            )
            return
        self._script_stack.add(path)
        assignments = self._script_assignments(content)
        env = dict(context.env)
        for key, value in assignments.items():
            if value is not None:
                env[key] = value
        script_provenance = context.provenance + (f"script:{normalize_repo_path(self.root, path)}",)
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
                continue
            self._resolve_command(
                segment, replace(context, env=env, provenance=script_provenance), depth
            )
        self._script_stack.remove(path)

    def _load_makefile(
        self, cwd: Path
    ) -> tuple[dict[str, tuple[tuple[str, ...], tuple[str, ...]]], dict[str, str]] | None:
        file = next(
            (
                candidate
                for candidate in (cwd / "Makefile", cwd / "makefile", cwd / "GNUmakefile")
                if candidate.exists()
            ),
            None,
        )
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
            variable = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|\+=|\?=|=)\s*(.*)$", line)
            if variable:
                variables[variable.group(1)] = variable.group(2).strip()
            current = []
        return {
            key: (tuple(value[0]), tuple(value[1])) for key, value in targets.items()
        }, variables

    def _resolve_make(self, tokens: tuple[str, ...], context: _Context, depth: int) -> None:
        cwd: Path | None = context.cwd
        index = 1
        assignments: dict[str, str] = {}
        targets: list[str] = []
        while index < len(tokens):
            token = tokens[index]
            if token == "-C" and index + 1 < len(tokens):
                if cwd is None:
                    return
                cwd = self._resolve_path(tokens[index + 1], cwd, context.provenance)
                if cwd is None:
                    return
                index += 2
                continue
            if token.startswith("-C") and len(token) > 2:
                if cwd is None:
                    return
                cwd = self._resolve_path(token[2:], cwd, context.provenance)
                if cwd is None:
                    return
                index += 1
                continue
            if token.startswith("-"):
                index += 1
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
                key, value = token.split("=", 1)
                assignments[key] = value
            else:
                targets.append(token)
            index += 1
        if cwd is None:
            return
        data = self._load_makefile(cwd)
        if data is None:
            self.issue(
                "MAKEFILE_UNRESOLVED", f"no readable Makefile found in {cwd}", context.provenance
            )
            return
        rules, variables = data
        variables.update(context.env)
        variables.update(assignments)
        selected = targets or (next(iter(rules), ""),)
        if not selected or not selected[0]:
            self.issue(
                "MAKE_TARGET_UNKNOWN",
                "Makefile has no statically selected target",
                context.provenance,
            )
            return
        for target in selected:
            self._resolve_make_target(target, rules, variables, replace(context, cwd=cwd), depth)

    def _resolve_make_target(
        self,
        target: str,
        rules: dict[str, tuple[tuple[str, ...], tuple[str, ...]]],
        variables: dict[str, str],
        context: _Context,
        depth: int,
    ) -> None:
        key = (context.cwd, target)
        if key in self._make_stack:
            self.issue(
                "RESOLUTION_CYCLE", f"Make target cycle detected at {target}", context.provenance
            )
            return
        rule = rules.get(target)
        if rule is None:
            return
        self._make_stack.add(key)
        prerequisites, recipes = rule
        if _pretest_mutation_unknown("\n".join(recipes)):
            self.issue(
                "PRETEST_MUTATION_UNKNOWN",
                "file-changing Make setup precedes a test runner",
                context.provenance + (f"make:{target}",),
            )
            self._make_stack.remove(key)
            return
        for prerequisite in prerequisites:
            if prerequisite in rules:
                self._resolve_make_target(prerequisite, rules, variables, context, depth + 1)
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
                continue
            expanded = re.sub(r"\$\(([^()]+)\)|\$\{([^{}]+)\}", replace_variable, recipe)
            self._resolve_command(
                expanded,
                replace(context, provenance=context.provenance + (f"make:{target}",)),
                depth,
            )
        self._make_stack.remove(key)

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

    def _resolve_tox(self, tokens: tuple[str, ...], context: _Context, depth: int) -> None:
        config = self._tox_config(context.cwd)
        if config is None:
            self.issue(
                "TOX_CONFIG_UNRESOLVED",
                f"no readable tox configuration found in {context.cwd}",
                context.provenance,
            )
            return
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
                index += 1
                continue
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
            return
        for name in selected:
            if self._tox_pytest_environment_unknown(config, name):
                self.issue(
                    "PYTEST_CONFIGURATION_UNKNOWN",
                    f"tox environment {name!r} sets pytest selection or plugin configuration",
                    context.provenance + (f"tox:{name}",),
                )
                continue
            commands, complete = self._tox_commands(config, name, posargs)
            if not complete:
                self.issue(
                    "TOX_COMMANDS_UNRESOLVED",
                    f"commands for tox environment {name!r} are dynamic",
                    context.provenance,
                )
                continue
            for command in commands:
                self._resolve_command(
                    command,
                    replace(context, provenance=context.provenance + (f"tox:{name}",)),
                    depth,
                )

    def _package_json(self, cwd: Path) -> tuple[Path, dict[str, str]] | None:
        path = cwd / "package.json"
        if not path.exists():
            return None
        try:
            data = json.loads(read_limited_text(path, MAX_CONFIG_BYTES))
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
            return None
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if not isinstance(scripts, dict):
            return None
        return path, {str(key): str(value) for key, value in scripts.items()}

    def _resolve_package(self, tokens: tuple[str, ...], context: _Context, depth: int) -> None:
        manager = _basename(tokens[0])
        cwd: Path | None = context.cwd
        index = 1
        if index + 1 < len(tokens) and tokens[index] in {"--prefix", "-C"}:
            if cwd is None:
                return
            cwd = self._resolve_path(tokens[index + 1], cwd, context.provenance)
            if cwd is None:
                return
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
            return
        if cwd is None:
            return
        package = self._package_json(cwd)
        if package is None or name not in package[1]:
            self.issue(
                "PACKAGE_SCRIPT_UNRESOLVED",
                f"package script {name!r} is not statically available in {cwd}",
                context.provenance,
            )
            return
        scripts = package[1]
        lifecycle_names = [name]
        if command in {"test", "run"}:
            lifecycle_names = [f"pre{name}", name, f"post{name}"]
        selected_scripts = [lifecycle for lifecycle in lifecycle_names if lifecycle in scripts]
        pre_lifecycle = f"pre{name}"
        if pre_lifecycle in scripts and _pretest_script_unknown(scripts[pre_lifecycle]):
            self.issue(
                "NPM_PRETEST_UNKNOWN",
                "npm pre-test lifecycle script is not statically harmless or test-resolvable",
                context.provenance,
            )
            return
        for lifecycle in selected_scripts:
            key = (cwd, lifecycle)
            if key in self._package_stack:
                self.issue(
                    "RESOLUTION_CYCLE",
                    f"package script cycle detected at {lifecycle}",
                    context.provenance,
                )
                continue
            self._package_stack.add(key)
            script = scripts[lifecycle]
            if posargs and lifecycle == name:
                script = f"{script} {' '.join(shlex.quote(arg) for arg in posargs)}"
            self._resolve_command(
                script,
                replace(context, cwd=cwd, provenance=context.provenance + (f"npm:{lifecycle}",)),
                depth,
            )
            self._package_stack.remove(key)


def trace_github_actions(
    root: Path, changed_files: Sequence[str] | None = None
) -> TraceResult:
    return _Resolver(root, changed_files).trace()
