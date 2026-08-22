"""Conservative, deterministic GitHub Actions to pytest command tracing."""

from __future__ import annotations

import configparser
import itertools
import json
import re
import shlex
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

from .model import PytestInvocation, TraceIssue, TraceResult
from .util import normalize_repo_path

MAX_DEPTH = 12
_EXPRESSION = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
_ASSIGNMENT = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|:=)\s*(.*)$")
_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


@dataclass(frozen=True)
class _Context:
    cwd: Path
    env: dict[str, str]
    matrix: dict[str, Any]
    inputs: dict[str, Any]
    provenance: tuple[str, ...]


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


def _matrix_rows(spec: Any) -> tuple[list[dict[str, Any]] | None, str | None]:
    if spec is None:
        return [{}], None
    if not isinstance(spec, dict):
        return None, "matrix must be a statically shaped mapping"
    axes = {key: value for key, value in spec.items() if key not in {"include", "exclude"}}
    values: dict[str, list[Any]] = {}
    for key, value in axes.items():
        if isinstance(value, list):
            values[key] = value
        elif isinstance(value, str | int | float | bool):
            values[key] = [value]
        else:
            return None, f"matrix axis {key!r} is not statically enumerable"
    keys = tuple(values)
    rows = [
        dict(zip(keys, combination, strict=False))
        for combination in itertools.product(*(values[key] for key in keys))
    ]
    excludes = spec.get("exclude", [])
    if excludes is not None:
        if not isinstance(excludes, list) or any(not isinstance(item, dict) for item in excludes):
            return None, "matrix.exclude is not a static list of mappings"
        rows = [
            row
            for row in rows
            if not any(all(row.get(k) == v for k, v in item.items()) for item in excludes)
        ]
    includes = spec.get("include", [])
    if includes is not None:
        if not isinstance(includes, list) or any(not isinstance(item, dict) for item in includes):
            return None, "matrix.include is not a static list of mappings"
        for item in includes:
            merged = False
            for row in rows:
                if all(key not in row or row[key] == value for key, value in item.items()):
                    row.update(item)
                    merged = True
                    break
            if not merged:
                rows.append(dict(item))
    return rows, None


def _shell_segments(command: str) -> tuple[str, ...]:
    logical_lines: list[str] = []
    pending = ""
    for line in command.splitlines():
        stripped = line.strip()
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
        for piece in re.split(r"\s*(?:&&|\|\||;)\s*", line):
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
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.invocations: list[PytestInvocation] = []
        self.issues: list[TraceIssue] = []
        self.workflows: list[str] = []
        self._workflow_stack: set[Path] = set()
        self._script_stack: set[Path] = set()
        self._make_stack: set[tuple[Path, str]] = set()
        self._package_stack: set[tuple[Path, str]] = set()
        self._tox_stack: set[Path] = set()

    def issue(
        self, code: str, message: str, provenance: tuple[str, ...], relevant: bool = True
    ) -> None:
        item = TraceIssue(code, message, provenance, relevant)
        if item not in self.issues:
            self.issues.append(item)

    def invocation(self, item: PytestInvocation) -> None:
        if item not in self.invocations:
            self.invocations.append(item)

    def _context(self, cwd: Path | None = None, **changes: Any) -> _Context:
        return _Context(cwd or self.root, {}, {}, {}, ()).__class__(
            cwd=cwd or self.root,
            env=changes.get("env", {}),
            matrix=changes.get("matrix", {}),
            inputs=changes.get("inputs", {}),
            provenance=changes.get("provenance", ()),
        )

    def trace(self) -> TraceResult:
        workflow_dir = self.root / ".github" / "workflows"
        if not workflow_dir.is_dir():
            return TraceResult((), (), ())
        paths = tuple(
            sorted(
                path for path in workflow_dir.iterdir() if path.suffix.lower() in {".yml", ".yaml"}
            )
        )
        for path in paths:
            self._resolve_workflow(
                path, _Context(self.root, {}, {}, {}, (normalize_repo_path(self.root, path),))
            )
        return TraceResult(tuple(self.invocations), tuple(self.issues), tuple(self.workflows))

    def _load_yaml(self, path: Path, provenance: tuple[str, ...]) -> dict[str, Any] | None:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            self.issue("WORKFLOW_PARSE_ERROR", f"could not parse {path}: {exc}", provenance)
            return None
        if not isinstance(data, dict):
            self.issue("WORKFLOW_SHAPE_UNKNOWN", f"workflow {path} is not a mapping", provenance)
            return None
        return data

    def _resolve_workflow(self, path: Path, context: _Context) -> None:
        path = path.resolve()
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
            rows, matrix_error = _matrix_rows(
                raw_job.get("strategy", {}).get("matrix")
                if isinstance(raw_job.get("strategy"), dict)
                else None
            )
            if matrix_error is not None or rows is None:
                self.issue(
                    "MATRIX_UNRESOLVED",
                    matrix_error or f"matrix for job {job_id} is unknown",
                    context.provenance,
                )
                continue
            for row in rows:
                provenance = context.provenance + (
                    f"job:{job_id}",
                    f"matrix:{_relative_matrix(row)}",
                )
                row_base = _Context(self.root, merged_root, row, context.inputs, provenance)
                job_env, job_env_complete = _env_mapping(raw_job.get("env"), row_base)
                if not job_env_complete:
                    self.issue(
                        "JOB_ENV_UNRESOLVED",
                        f"environment for job {job_id} contains unresolved values",
                        provenance,
                        False,
                    )
                job_context = _Context(
                    self.root, {**merged_root, **job_env}, row, context.inputs, provenance
                )
                if "uses" in raw_job:
                    self._resolve_reusable(raw_job.get("uses"), job_context, raw_job)
                else:
                    self._resolve_steps(raw_job.get("steps", []), job_context)
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
        target = (self.root / uses[2:]).resolve()
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
                provenance=context.provenance + (f"uses:{normalize_repo_path(self.root, target)}",),
            ),
        )

    def _resolve_steps(self, steps: Any, context: _Context) -> None:
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
                command, known = resolve_expressions(command, step_context)
                if not known and _relevant_text(command):
                    self.issue(
                        "RUN_COMMAND_DYNAMIC",
                        "relevant run command contains an unresolved expression",
                        provenance,
                    )
                    continue
                cwd = step_context.cwd
                raw_cwd = _scalar(raw_step.get("working-directory"))
                if raw_cwd is not None:
                    raw_cwd, cwd_known = resolve_expressions(raw_cwd, step_context)
                    if cwd_known:
                        cwd = self._resolve_path(raw_cwd, step_context.cwd)
                    elif _relevant_text(command):
                        self.issue(
                            "WORKING_DIRECTORY_UNKNOWN",
                            "pytest command has an unresolved working directory",
                            provenance,
                        )
                        continue
                self._resolve_command(command, replace(step_context, cwd=cwd), 0)
            elif "uses" in raw_step:
                uses = raw_step.get("uses")
                if isinstance(uses, str) and uses.startswith("./"):
                    self._resolve_composite((self.root / uses[2:]).resolve(), step_context)
                # Marketplace actions such as actions/checkout do not themselves select tests.

    def _resolve_composite(self, action_dir: Path, context: _Context) -> None:
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
            data = yaml.safe_load(action_file.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
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
        )

    def _resolve_path(self, value: str, base: Path) -> Path:
        path = Path(value)
        return path.resolve() if path.is_absolute() else (base / path).resolve()

    def _resolve_command(self, command: str, context: _Context, depth: int) -> None:
        if depth > MAX_DEPTH:
            self.issue(
                "RESOLUTION_DEPTH_EXCEEDED", "command resolution depth exceeded", context.provenance
            )
            return
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
            local_env = dict(context.env)
            while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
                key, value = tokens[0].split("=", 1)
                local_env[key] = value
                tokens = tokens[1:]
            if not tokens:
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
                    )
                continue
            scope, runner_index, scope_error = self._pytest_scope(tokens, nested_context.cwd)
            if runner_index is not None:
                if scope_error:
                    self.issue("PYTEST_SELECTOR_UNKNOWN", scope_error, context.provenance)
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
            token_path = self._resolve_path(tokens[0], nested_context.cwd)
            if (
                tokens[0].startswith("./") or "/" in tokens[0] or "\\" in tokens[0]
            ) and token_path.is_file():
                self._resolve_script(token_path, nested_context, depth + 1)
                continue
            if _relevant_text(segment) and (
                "${" in segment or "$" in segment or "pytest" in segment.lower()
            ):
                self.issue(
                    "COMMAND_SELECTION_UNKNOWN",
                    "runner-like command contains unresolved shell semantics",
                    context.provenance,
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
        self._resolve_script(self._resolve_path(script, context.cwd), context, depth)

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
        path = path.resolve()
        if depth > MAX_DEPTH:
            self.issue(
                "RESOLUTION_DEPTH_EXCEEDED", "script resolution depth exceeded", context.provenance
            )
            return
        if path in self._script_stack:
            self.issue("RESOLUTION_CYCLE", f"script cycle detected at {path}", context.provenance)
            return
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            self.issue("SCRIPT_UNRESOLVED", f"could not read {path}: {exc}", context.provenance)
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
            lines = file.read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        targets: dict[str, list[list[str]]] = {}
        variables: dict[str, str] = {}
        current: list[str] = []
        for line in lines:
            if line.startswith((" ", "\t")) and current:
                targets[current[-1]][1].append(line.strip())
                continue
            match = re.match(r"^([A-Za-z0-9_.%/-]+)\s*:\s*(.*)$", line)
            if match:
                names = [match.group(1)]
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
        cwd = context.cwd
        index = 1
        assignments: dict[str, str] = {}
        targets: list[str] = []
        while index < len(tokens):
            token = tokens[index]
            if token == "-C" and index + 1 < len(tokens):
                cwd = self._resolve_path(tokens[index + 1], cwd)
                index += 2
                continue
            if token.startswith("-C") and len(token) > 2:
                cwd = self._resolve_path(token[2:], cwd)
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
                data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError):
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
            parser.read(tox_ini, encoding="utf-8")
        except (OSError, configparser.Error):
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
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if not isinstance(scripts, dict):
            return None
        return path, {str(key): str(value) for key, value in scripts.items()}

    def _resolve_package(self, tokens: tuple[str, ...], context: _Context, depth: int) -> None:
        manager = _basename(tokens[0])
        cwd = context.cwd
        index = 1
        if index + 1 < len(tokens) and tokens[index] in {"--prefix", "-C"}:
            cwd = self._resolve_path(tokens[index + 1], cwd)
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
        package = self._package_json(cwd)
        if package is None or name not in package[1]:
            self.issue(
                "PACKAGE_SCRIPT_UNRESOLVED",
                f"package script {name!r} is not statically available in {cwd}",
                context.provenance,
            )
            return
        key = (cwd, name)
        if key in self._package_stack:
            self.issue(
                "RESOLUTION_CYCLE", f"package script cycle detected at {name}", context.provenance
            )
            return
        self._package_stack.add(key)
        script = package[1][name]
        if posargs:
            script = f"{script} {' '.join(shlex.quote(arg) for arg in posargs)}"
        self._resolve_command(
            script,
            replace(context, cwd=cwd, provenance=context.provenance + (f"npm:{name}",)),
            depth,
        )
        self._package_stack.remove(key)


def trace_github_actions(root: Path) -> TraceResult:
    return _Resolver(root).trace()
