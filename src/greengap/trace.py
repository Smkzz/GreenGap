"""Conservative, deterministic GitHub Actions to pytest command tracing."""

from __future__ import annotations

import ast
import configparser
import itertools
import json
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
_WORKSPACE_RESTORING_ACTIONS = {
    "actions/cache",
    "actions/download-artifact",
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
    "test",
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
    if first == "git":
        return _safe_git_command(tokens)
    if first in _SAFE_SETUP_COMMANDS:
        return True
    if first == "gh":
        return _safe_gh_command(tokens)
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
        "diff",
        "show",
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
        return not any(
            token in {"-d", "-D", "--delete", "--move", "-m", "-M", "--copy", "-c"}
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


def _workspace_effect_for_tokens(segment: str, tokens: tuple[str, ...]) -> WorkspaceState:
    core = _command_core_tokens(tokens)
    if not core:
        return PROVEN_READ_ONLY
    if _contains_runner_hint(shlex.join(core)):
        return MODELED_STATE_TRANSITION
    first = _basename(core[0]).lower()
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
        return MODELED_STATE_TRANSITION
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
        # ``uv run`` may materialize an isolated environment, but its effect is
        # modeled and transient for the repository selection graph.  Other uv
        # commands can rewrite lock/configuration bytes and remain unknown.
        return MODELED_STATE_TRANSITION if len(core) > 1 and core[1] == "run" else UNKNOWN_SIDE_EFFECT
    if first in {"pip", "pip3"}:
        if any(
            token in {"install", "uninstall", "wheel", "download"}
            for token in arguments
        ) and any(
            token in {".", "./", "-e", "--editable"} or token.startswith(("./", ".\\"))
            for token in arguments
        ):
            return UNKNOWN_SIDE_EFFECT
        return MODELED_STATE_TRANSITION
    if first.startswith("python") or first == "py":
        if "-c" in core:
            return MODELED_STATE_TRANSITION if _safe_python_code(core) else UNKNOWN_SIDE_EFFECT
        module_index = next(
            (index for index, token in enumerate(core[:-1]) if token == "-m"), None
        )
        if module_index is not None:
            module = _basename(core[module_index + 1]).lower()
            module_args = tuple(token.lower() for token in core[module_index + 2 :])
            if module in {"build", "compileall", "venv"}:
                return UNKNOWN_SIDE_EFFECT
            if module in {"pip", "pip_audit"}:
                if module == "pip" and any(
                    token in {"install", "uninstall", "wheel", "download"}
                    for token in module_args
                ) and any(
                    token in {".", "./", "-e", "--editable"}
                    or token.startswith(("./", ".\\"))
                    for token in module_args
                ):
                    return UNKNOWN_SIDE_EFFECT
                return MODELED_STATE_TRANSITION
            if module in _SAFE_PYTHON_MODULES:
                return MODELED_STATE_TRANSITION
            return UNKNOWN_SIDE_EFFECT
        # A Python script, stdin program, or dynamically selected executable
        # can rewrite any repository byte.  Only explicit read-only diagnostics
        # and the audited module allowlist are safe here.
        return PROVEN_READ_ONLY if len(core) == 1 else UNKNOWN_SIDE_EFFECT
    if first in {"npm", "pnpm", "yarn"}:
        if any(token in {"install", "i", "ci", "link", "build"} for token in arguments):
            return UNKNOWN_SIDE_EFFECT
        return MODELED_STATE_TRANSITION
    if first == "git":
        return MODELED_STATE_TRANSITION if _safe_git_command(core) else UNKNOWN_SIDE_EFFECT
    if _safe_setup_command(core):
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
    selected = targets or ([next(iter(rules))] if rules else [])
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

    state: WorkspaceState = PROVEN_READ_ONLY
    for segment in _shell_segments(command):
        tokens = _tokens(segment)
        if tokens is None:
            return UNKNOWN_SIDE_EFFECT
        if not tokens:
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
                effect = _workspace_effect_for_tokens(segment, tokens)
        else:
            effect = _workspace_effect_for_tokens(segment, tokens)
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
        "--cov-report",
    }
    for token in tokens:
        name, _, _ = token.partition("=")
        if name in output_options:
            return True
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
                if not hook_id or entry is None:
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
    ) -> WorkspaceState:
        if self._precommit_config_is_non_test():
            return MODELED_STATE_TRANSITION
        entries = self._precommit_entries()
        if entries is None:
            self.issue(
                "PRE_COMMIT_HOOKS_UNKNOWN",
                "pre-commit hooks could not be statically enumerated",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if not entries:
            self.issue(
                "PRE_COMMIT_HOOKS_UNKNOWN",
                "pre-commit configuration declares no statically visible hooks",
                context.provenance,
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
            event_context=changes.get("event_context"),
            workspace_state=changes.get("workspace_state", PROVEN_READ_ONLY),
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
        selected_event: tuple[bool, dict[str, Any]] | None = None
        if self.event_context is not None and events_present:
            selected_event = _event_config(raw_events, self.event_context, self.activity)
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
        if self.event_context is not None and selected_config is not None:
            filter_result = _workflow_filter_runs(
                selected_config,
                self.event_context,
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
        elif self.event_context is None and _workflow_has_activity_filters(raw_events):
            self.issue(
                "WORKFLOW_EVENT_FILTER_UNKNOWN",
                "workflow activity types require a bound event activity",
                context.provenance,
            )
            self._workflow_stack.remove(path)
            return
        elif self.event_context is None and _workflow_has_ref_filters(raw_events):
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
                    self.event_context,
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
                raw_run = _scalar(raw_step.get("run")) if "run" in raw_step else None
                if raw_run is not None:
                    effect = _workspace_effect_for_command(
                        raw_run, self.root, context.cwd
                    )
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
                        effect = _workspace_restore_effect(
                            action_name,
                            raw_with,
                            self.root,
                            step_context.cwd,
                        )
                        if effect is None or effect:
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
                    if action_name == "pre-commit-ci/lite-action" and self._precommit_config_is_non_test():
                        continue
                    if action_name not in _KNOWN_SETUP_ACTIONS:
                        self.issue(
                            "EXTERNAL_ACTION_UNKNOWN",
                            f"external action {uses!r} is not modeled as a setup-only action",
                            provenance,
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
        if action_name == "pre-commit-ci/lite-action" and self._precommit_config_is_non_test():
            return MODELED_STATE_TRANSITION
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
        if action_name not in _KNOWN_SETUP_ACTIONS:
            self.issue(
                "EXTERNAL_ACTION_UNKNOWN",
                f"conditional external action {raw_uses!r} is not modeled as setup-only",
                provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        return MODELED_STATE_TRANSITION

    def _resolve_composite(
        self, action_dir: Path, context: _Context, default_shell: str | None
    ) -> WorkspaceState:
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
    ) -> WorkspaceState:
        state: WorkspaceState = context.workspace_state
        if depth > MAX_DEPTH:
            self.issue(
                "RESOLUTION_DEPTH_EXCEEDED", "command resolution depth exceeded", context.provenance
            )
            return UNKNOWN_SIDE_EFFECT
        if shell == "powershell" and _powershell_control_flow_unknown(command):
            self.issue(
                "SHELL_CONTROL_FLOW_UNKNOWN",
                "PowerShell control flow or command chaining is outside the supported static subset",
                context.provenance,
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
        if _has_pipeline_token(command) and not _pipeline_is_safe(command):
            self.issue(
                "SHELL_PIPE_UNKNOWN",
                "shell pipelines are outside the supported static command subset",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if _shell_control_flow_unknown(command):
            self.issue(
                "SHELL_CONTROL_FLOW_UNKNOWN",
                "shell control flow or command chaining can change whether a test command runs",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
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
            prior_state = state
            state = _merge_workspace_state(
                state, _workspace_effect_for_tokens(expanded, tokens)
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
            first = _basename(tokens[0])
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
                        state, self._resolve_precommit(nested_context, depth, *selection)
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
                            state, self._resolve_precommit(nested_context, depth, *selection)
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
                scope, runner_index, scope_error = self._pytest_scope(tokens, nested_context.cwd)
            except PathSafetyError as exc:
                self.issue(
                    "PATH_OUTSIDE_REPOSITORY",
                    f"pytest path selector is unsafe: {exc}",
                    context.provenance,
                )
                state = UNKNOWN_SIDE_EFFECT
                continue
            if runner_index is not None:
                if prior_state == UNKNOWN_SIDE_EFFECT:
                    self.issue(
                        "WORKSPACE_MUTATION_UNKNOWN",
                        "an earlier command in this shell segment may have changed workspace bytes before pytest",
                        context.provenance,
                    )
                    continue
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
                    state, self._resolve_tox(tokens, nested_context, depth + 1)
                )
                continue
            if first in {"make", "gmake"}:
                state = _merge_workspace_state(
                    state, self._resolve_make(tokens, nested_context, depth + 1)
                )
                continue
            if first in {"npm", "pnpm", "yarn"}:
                state = _merge_workspace_state(
                    state, self._resolve_package(tokens, nested_context, depth + 1)
                )
                continue
            if first in {"bash", "sh", "zsh", "dash"}:
                state = _merge_workspace_state(
                    state, self._resolve_shell(tokens, nested_context, depth + 1)
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
                        state, self._resolve_script(token_path, nested_context, depth + 1)
                    )
                    continue
            elif shell_script_hint:
                token_path = self._resolve_path(tokens[0], nested_context.cwd, context.provenance)
                if token_path is not None and token_path.is_file():
                    state = _merge_workspace_state(
                        state, self._resolve_script(token_path, nested_context, depth + 1)
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

    def _resolve_shell(
        self, tokens: tuple[str, ...], context: _Context, depth: int
    ) -> WorkspaceState:
        if len(tokens) < 2:
            self.issue(
                "SHELL_SCRIPT_UNKNOWN",
                "shell wrapper has no statically known script",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        if "-c" in tokens[1:]:
            self.issue(
                "SHELL_COMMAND_UNKNOWN",
                "shell -c hides a dynamic command graph",
                context.provenance,
            )
            return UNKNOWN_SIDE_EFFECT
        script = next((token for token in tokens[1:] if not token.startswith("-")), None)
        if script is None:
            self.issue(
                "SHELL_SCRIPT_UNKNOWN", "shell wrapper has no script path", context.provenance
            )
            return UNKNOWN_SIDE_EFFECT
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
            return self._resolve_script(script_path, context, depth)
        return UNKNOWN_SIDE_EFFECT

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

    def _resolve_script(
        self, path: Path, context: _Context, depth: int
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
        assignments = self._script_assignments(content)
        env = dict(context.env)
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
                ),
            )
        self._script_stack.remove(path)
        return state

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

    def _resolve_make(
        self, tokens: tuple[str, ...], context: _Context, depth: int
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
                index += 1
                continue
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
        selected = targets or (next(iter(rules), ""),)
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
        """Reject tox lanes whose setup changes cwd or runs pre-commands."""

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
            commands_pre = mapping.get("commands_pre")
            if commands_pre not in (None, "", [], ()):
                return True
        return False

    def _resolve_tox(
        self, tokens: tuple[str, ...], context: _Context, depth: int
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
            return UNKNOWN_SIDE_EFFECT
        state: WorkspaceState = context.workspace_state
        for name in selected:
            if self._tox_execution_context_unknown(config, name):
                self.issue(
                    "TOX_EXECUTION_CONTEXT_UNKNOWN",
                    f"tox environment {name!r} changes directory or runs commands_pre",
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
                    ),
                )
        return state

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

    def _resolve_package(
        self, tokens: tuple[str, ...], context: _Context, depth: int
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
            return MODELED_STATE_TRANSITION
        if cwd is None:
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
