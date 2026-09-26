"""Explicit pytest plugin for GreenGap file-level runtime witnesses.

The plugin records only repository-relative file identities.  In particular,
it does not serialize node IDs (which can contain parameter values), test
output, environment variables, fixture values, or arbitrary target objects.
It is inert until pytest loads it and a witness directory is supplied.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
from pathlib import Path
from typing import Any

from . import __version__
from .model import WorkspaceSnapshot
from .snapshot import source_snapshot, workspace_snapshot
from .util import (
    MAX_RUNTIME_WITNESS_BYTES,
    MAX_RUNTIME_WITNESS_FILES,
    MAX_RUNTIME_WITNESS_FRAGMENTS,
    normalize_repo_path,
)
from .witness import (
    WITNESS_ARTIFACT_TYPE,
    WITNESS_SCHEMA_VERSION,
    _atomic_write_fragment,
    _fragment_names,
    _has_link_component,
    _witness_output_lock,
    normalize_witness_path,
    resolve_witness_output_path,
)

_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_TREE_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,256}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}/[A-Za-z0-9_.-]{1,128}$")
_MAX_NODEID_BYTES = 8192


def _safe_identifier(value: Any, *, numeric: bool = False) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        return None
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized) or ".." in normalized.split("/"):
        return None
    if numeric and not value.isdigit():
        return None
    return value


def _option(config: Any, name: str, default: Any = None) -> Any:
    try:
        return config.getoption(name, default=default)
    except (AttributeError, ValueError, TypeError):
        return default


def _first_option(config: Any, *names: str) -> Any:
    """Return the first explicitly configured value, including legacy aliases."""

    for name in names:
        value = _option(config, name)
        if value not in (None, ""):
            return value
    return None


def pytest_addoption(parser: Any) -> None:
    group = parser.getgroup("greengap witness")
    group.addoption(
        "--greengap-witness-dir",
        action="store",
        default=os.environ.get("GREENGAP_WITNESS_DIR"),
        metavar="PATH",
        help="write one unique GreenGap runtime witness fragment per pytest session",
    )
    group.addoption(
        "--greengap-witness",
        action="store",
        default=os.environ.get("GREENGAP_WITNESS_FILE"),
        metavar="PATH",
        help="compatibility alias for a witness directory or output path",
    )
    group.addoption(
        "--greengap-source-commit",
        "--greengap-source-sha",
        dest="greengap_source_sha",
        action="store",
        default=os.environ.get("GREENGAP_SOURCE_SHA") or os.environ.get("GREENGAP_SOURCE_COMMIT"),
        metavar="SHA",
        help="exact source commit to bind to this witness (explicit GreenGap identity)",
    )
    group.addoption(
        "--greengap-repository",
        action="store",
        default=os.environ.get("GREENGAP_REPOSITORY"),
        metavar="OWNER/REPOSITORY",
        help="optional safe repository identity supplied by the caller",
    )
    group.addoption(
        "--greengap-config-sha256",
        dest="greengap_config_sha256",
        action="store",
        default=os.environ.get("GREENGAP_CONFIG_SHA256"),
        metavar="SHA256",
        help="SHA-256 of the exact explicit .greengap.yml bytes used for this run",
    )
    group.addoption(
        "--greengap-witness-role",
        dest="greengap_witness_role",
        action="store",
        choices=("collection", "execution", "both"),
        default=os.environ.get("GREENGAP_WITNESS_ROLE"),
        help="kind of surface represented by this pytest session",
    )
    group.addoption(
        "--greengap-surface-id",
        "--greengap-witness-id",
        dest="greengap_surface_id",
        action="store",
        default=os.environ.get("GREENGAP_SURFACE_ID") or os.environ.get("GREENGAP_WITNESS_ID"),
        metavar="ID",
        help="stable explicit GreenGap surface identity",
    )
    group.addoption(
        "--greengap-full-collection",
        action="store_true",
        default=os.environ.get("GREENGAP_FULL_COLLECTION", "") == "1",
        help="assert that collection has no selectors or node filters",
    )
    group.addoption(
        "--greengap-run-id",
        dest="greengap_run_id",
        action="store",
        default=os.environ.get("GREENGAP_RUN_ID"),
        metavar="ID",
        help="explicit run identity shared by collection and execution witnesses",
    )
    group.addoption(
        "--greengap-run-attempt",
        dest="greengap_run_attempt",
        action="store",
        default=os.environ.get("GREENGAP_RUN_ATTEMPT", "1"),
        metavar="ID",
        help="explicit attempt identity for this run",
    )
    group.addoption(
        "--greengap-job-id",
        dest="greengap_job_id",
        action="store",
        default=os.environ.get("GREENGAP_JOB_ID"),
        metavar="ID",
        help="optional bounded job identity; never inferred from provider variables",
    )
    group.addoption(
        "--greengap-provider",
        dest="greengap_provider",
        action="store",
        choices=("local", "ci", "github_actions"),
        default=os.environ.get("GREENGAP_PROVIDER", "local"),
        help="explicit evidence provider label",
    )


def _git_value(root: Path, expression: str, pattern: re.Pattern[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", expression],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = completed.stdout.strip()
    if completed.returncode != 0 or pattern.fullmatch(value) is None:
        return None
    return value.lower()


def _config_root(config: Any) -> Path:
    """Choose the repository root even during pytest's early bootstrap phase."""

    candidates: list[Path] = []
    for value in (
        getattr(config, "rootpath", None),
        getattr(getattr(config, "invocation_params", None), "dir", None),
        Path.cwd(),
    ):
        if value is None:
            continue
        try:
            candidate = Path(str(value)).resolve()
        except (OSError, TypeError, ValueError):
            continue
        if candidate not in candidates:
            candidates.append(candidate)
    for candidate in candidates:
        if _git_value(candidate, "HEAD", _SHA_RE) is not None:
            return candidate
    return candidates[0] if candidates else Path.cwd().resolve()


def _source_identity(config: Any, errors: list[str]) -> tuple[str | None, str | None]:
    root = _config_root(config)
    actual = _git_value(root, "HEAD", _SHA_RE)
    tree = _git_value(root, "HEAD^{tree}", _TREE_RE)
    claim = _first_option(config, "greengap_source_sha", "greengap_source_commit")
    if claim in (None, ""):
        errors.append("SOURCE_COMMIT_CLAIM_MISSING")
    if claim not in (None, ""):
        if not isinstance(claim, str) or _SHA_RE.fullmatch(claim) is None:
            errors.append("SOURCE_COMMIT_INVALID")
        elif actual is None:
            errors.append("SOURCE_COMMIT_MISSING")
        elif claim.lower() != actual:
            errors.append("SOURCE_COMMIT_MISMATCH")
    if actual is None:
        errors.append("SOURCE_COMMIT_MISSING")
    return (actual if not any(code.startswith("SOURCE_COMMIT_") for code in errors) else None), tree


def _repository_identity(config: Any, errors: list[str]) -> str | None:
    value = _option(config, "greengap_repository")
    if value in (None, ""):
        return None
    result = value if isinstance(value, str) and _REPOSITORY_RE.fullmatch(value) is not None else None
    if result is None:
        errors.append("REPOSITORY_INVALID")
    return result


def _collection_is_unfiltered(config: Any, errors: list[str]) -> bool:
    declared = bool(_option(config, "greengap_full_collection", False))
    if not declared:
        return False
    option = getattr(config, "option", None)
    selector_options = (
        "keyword",
        "markexpr",
        "deselect",
        "ignore",
        "ignore_glob",
        "last_failed",
        "failedfirst",
        "newfirst",
        "stepwise",
        "stepwise_skip",
        "cache_show",
        "confcutdir",
        "noconftest",
        "keepduplicates",
        "collect_in_virtualenv",
        "doctestglob",
        "pyargs",
    )
    if any(getattr(option, name, None) for name in selector_options):
        errors.append("COLLECTION_SELECTOR_PRESENT")
        return False
    args = tuple(str(value) for value in getattr(config, "args", ()))
    invocation_args = tuple(
        str(value)
        for value in getattr(getattr(config, "invocation_params", None), "args", ())
    )
    configured_addopts: tuple[str, ...]
    try:
        configured_addopts_value = config.getini("addopts")
    except (AttributeError, ValueError, TypeError):
        configured_addopts_value = ()
    if isinstance(configured_addopts_value, str):
        configured_addopts = (configured_addopts_value,)
    else:
        configured_addopts = tuple(str(value) for value in (configured_addopts_value or ()))
    if os.environ.get("PYTEST_ADDOPTS") or os.environ.get("PYTEST_PLUGINS"):
        errors.append("COLLECTION_HIDDEN_OPTIONS_PRESENT")
        return False
    # ``config.args`` also contains project-configured testpaths.  Only reject
    # a path that is present in the caller's actual argv; configured testpaths
    # are part of the project's declared pytest surface, not a hidden runtime
    # selector introduced by this integration.
    meaningful_args = tuple(
        value
        for value in args
        if value not in {"", ".", "./"} and value in invocation_args
    )
    if meaningful_args or any("::" in value or "[" in value for value in meaningful_args):
        errors.append("COLLECTION_SELECTOR_PRESENT")
        return False
    selector_tokens = {
        "-k",
        "--keyword",
        "-m",
        "--markexpr",
        "--deselect",
        "--ignore",
        "--ignore-glob",
        "--override-ini",
        "-o",
        "--confcutdir",
        "--doctest-glob",
        "--import-mode",
    }
    # pytest may populate ``option.override_ini`` while translating ordinary
    # strictness addopts such as ``--strict-config``.  The actual override
    # arguments are checked below, so the parsed value alone is not evidence
    # that collection was restricted.
    if any(
        token in selector_tokens
        or (token.startswith("-o") and not token.startswith("--"))
        or any(token.startswith(f"{prefix}=") for prefix in selector_tokens)
        for token in (*invocation_args, *configured_addopts)
    ):
        errors.append("COLLECTION_SELECTOR_PRESENT")
        return False
    if any(token == "-p" or token.startswith("-p") for token in configured_addopts):
        errors.append("COLLECTION_PLUGIN_ADDOPTS_PRESENT")
        return False
    explicit_plugin = any(
        token in {"greengap.pytest_witness", "-pgreengap.pytest_witness"}
        for token in invocation_args
    ) or any(
        invocation_args[index] == "-p"
        and index + 1 < len(invocation_args)
        and invocation_args[index + 1] == "greengap.pytest_witness"
        for index in range(len(invocation_args))
    )
    if not explicit_plugin:
        errors.append("COLLECTION_PLUGIN_ACTIVATION_NOT_EXPLICIT")
        return False
    if os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") != "1":
        errors.append("COLLECTION_PLUGIN_AUTOLOAD_ENABLED")
        return False
    return True


def _path_from_nodeid(root: Path, nodeid: str) -> str | None:
    if not nodeid or "::" not in nodeid:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in nodeid):
        return None
    if len(nodeid.encode("utf-8", errors="replace")) > _MAX_NODEID_BYTES:
        return None
    raw = nodeid.split("::", 1)[0]
    try:
        return normalize_witness_path(normalize_repo_path(root, raw))
    except (OSError, TypeError, ValueError):
        return None


class _Witness:
    def __init__(self, config: Any, output_dir: Path) -> None:
        self.config = config
        self.root = _config_root(config)
        self.output_dir = output_dir
        self.errors: list[str] = []
        configured_role = _first_option(config, "greengap_witness_role")
        self.role = str(configured_role or "execution")
        if self.role not in {"collection", "execution", "both"}:
            self.role = "execution"
            self.errors.append("WITNESS_ROLE_INVALID")
        if configured_role in (None, ""):
            self.errors.append("WITNESS_ROLE_MISSING")
        self.session_id = uuid.uuid4().hex
        self.worker_id = _safe_identifier(os.environ.get("GREENGAP_WORKER_ID"))
        self.shard = _safe_identifier(os.environ.get("GREENGAP_SURFACE_SHARD"))
        self.surface_id = _safe_identifier(
            _first_option(config, "greengap_surface_id", "greengap_witness_id")
        )
        if self.surface_id is None:
            self.surface_id = "unknown"
            self.errors.append("SURFACE_ID_MISSING")
        source, tree = _source_identity(config, self.errors)
        self.git_sha = source
        self.git_tree = tree
        self.repository = _repository_identity(config, self.errors)
        config_sha256 = _first_option(config, "greengap_config_sha256")
        if config_sha256 not in (None, "") and (
            not isinstance(config_sha256, str) or _FINGERPRINT_RE.fullmatch(config_sha256) is None
        ):
            self.errors.append("CONFIG_DIGEST_INVALID")
            config_sha256 = None
        self.config_sha256 = config_sha256.lower() if isinstance(config_sha256, str) else None
        invocation_args = tuple(
            str(value)
            for value in getattr(getattr(config, "invocation_params", None), "args", ())
        )
        explicit_plugin = any(
            token in {"greengap.pytest_witness", "-pgreengap.pytest_witness"}
            for token in invocation_args
        ) or any(
            invocation_args[index] == "-p"
            and index + 1 < len(invocation_args)
            and invocation_args[index + 1] == "greengap.pytest_witness"
            for index in range(len(invocation_args))
        )
        if not explicit_plugin:
            self.errors.append("PLUGIN_ACTIVATION_NOT_EXPLICIT")
        if os.environ.get("PYTEST_ADDOPTS") or os.environ.get("PYTEST_PLUGINS"):
            self.errors.append("PLUGIN_HIDDEN_OPTIONS_PRESENT")
        if os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") != "1":
            self.errors.append("PLUGIN_AUTOLOAD_ENABLED")
        self.collection: set[str] = set()
        self.attempted: set[str] = set()
        self.call_executed: set[str] = set()
        self.call_outcomes: dict[str, str] = {}
        self.completed: set[str] = set()
        self.collection_complete = False
        self.session_finalized = False
        self.exitstatus: int | None = None
        self.start_snapshot: WorkspaceSnapshot | None = None
        self.final_snapshot: WorkspaceSnapshot | None = None
        self.source_start_snapshot: WorkspaceSnapshot | None = None
        self.source_final_snapshot: WorkspaceSnapshot | None = None
        # The early pytest hook can run before command-line options have been
        # parsed.  Evaluate collection declarations at collection finish so
        # an explicit --collect-only/--greengap-full-collection command is
        # observed rather than mistaken for a missing declaration.
        self.collection_unfiltered = False
        self._take_start_snapshot()

    def _take_start_snapshot(self) -> None:
        self.start_snapshot = workspace_snapshot(self.root, timeout=10.0)
        self.source_start_snapshot = source_snapshot(self.root, timeout=10.0)
        if not self.source_start_snapshot.complete:
            self.errors.append("SOURCE_IDENTITY_INCOMPLETE")
        claimed = os.environ.get("GREENGAP_SOURCE_FINGERPRINT")
        if claimed is not None:
            if _FINGERPRINT_RE.fullmatch(claimed) is None:
                self.errors.append("SOURCE_IDENTITY_INVALID")
            elif (
                self.source_start_snapshot is None
                or self.source_start_snapshot.fingerprint != claimed.lower()
            ):
                self.errors.append("SOURCE_IDENTITY_MISMATCH")

    def _take_final_snapshots(self) -> None:
        self.final_snapshot = workspace_snapshot(self.root, timeout=10.0)
        self.source_final_snapshot = source_snapshot(self.root, timeout=10.0)
        if not self.source_final_snapshot.complete:
            self.errors.append("SOURCE_IDENTITY_INCOMPLETE")

    def _file_for(self, nodeid: Any, raw_path: Any = None) -> str | None:
        text = str(nodeid or "")
        if not text or "::" not in text:
            return None
        candidate = raw_path
        if candidate is not None:
            try:
                return normalize_witness_path(normalize_repo_path(self.root, candidate))
            except (OSError, TypeError, ValueError):
                pass
        return _path_from_nodeid(self.root, text)

    def collection_finish(self, session: Any) -> None:
        if self.role in {"collection", "both"}:
            self.collection_unfiltered = _collection_is_unfiltered(self.config, self.errors)
            if not self.collection_unfiltered:
                self.errors.append("FULL_COLLECTION_NOT_DECLARED")
            if not bool(getattr(getattr(self.config, "option", None), "collectonly", False)):
                self.errors.append("COLLECTION_ONLY_REQUIRED")
        for item in getattr(session, "items", ()):
            path = self._file_for(getattr(item, "nodeid", ""), getattr(item, "path", None))
            if path is None:
                self.errors.append("COLLECTION_FILE_INVALID")
                continue
            if path not in self.collection:
                if len(self.collection) >= MAX_RUNTIME_WITNESS_FILES:
                    self.errors.append("COLLECTION_FILE_LIMIT_EXCEEDED")
                else:
                    self.collection.add(path)
        self.collection_complete = self.collection_unfiltered and not any(
            code.startswith("COLLECTION_") or code == "WORKSPACE_FINGERPRINT_INCOMPLETE"
            for code in self.errors
        )

    def _mark(self, target: set[str], nodeid: Any, raw_path: Any = None, error: str = "EXECUTION_FILE_INVALID") -> str | None:
        path = self._file_for(nodeid, raw_path)
        if path is None:
            self.errors.append(error)
            return None
        if path not in target and len(target) >= MAX_RUNTIME_WITNESS_FILES:
            self.errors.append("EXECUTION_FILE_LIMIT_EXCEEDED")
            return None
        target.add(path)
        return path

    def log_start(self, nodeid: str, location: Any) -> None:
        raw_path = location[0] if isinstance(location, tuple | list) and location else None
        self._mark(self.attempted, nodeid, raw_path)

    def log_report(self, report: Any) -> None:
        nodeid = getattr(report, "nodeid", "")
        raw_path = getattr(report, "fspath", None)
        path = self._mark(self.attempted, nodeid, raw_path)
        if path is None:
            return
        if getattr(report, "when", None) == "call":
            if path not in self.call_executed and len(self.call_executed) >= MAX_RUNTIME_WITNESS_FILES:
                self.errors.append("EXECUTION_FILE_LIMIT_EXCEEDED")
            else:
                self.call_executed.add(path)
            outcome = getattr(report, "outcome", None)
            if outcome in {"passed", "failed", "skipped"}:
                prior = self.call_outcomes.get(path)
                priority = {"skipped": 1, "passed": 2, "failed": 3}
                if prior is None or priority[outcome] > priority[prior]:
                    self.call_outcomes[path] = outcome

    def log_finish(self, nodeid: str, location: Any) -> None:
        raw_path = location[0] if isinstance(location, tuple | list) and location else None
        self._mark(self.completed, nodeid, raw_path)

    def _context(self) -> dict[str, Any]:
        provider = _safe_identifier(
            _first_option(self.config, "greengap_provider")
            or os.environ.get("GREENGAP_PROVIDER")
            or "local"
        )
        if provider not in {"local", "github_actions", "ci"}:
            self.errors.append("WITNESS_PROVIDER_INVALID")
            provider = "local"
        run_id = _safe_identifier(
            _first_option(self.config, "greengap_run_id") or os.environ.get("GREENGAP_RUN_ID")
        )
        if run_id is None:
            self.errors.append("RUN_ID_MISSING")
            run_id = "unknown-run"
        run_attempt = _safe_identifier(
            _first_option(self.config, "greengap_run_attempt")
            or os.environ.get("GREENGAP_RUN_ATTEMPT")
            or "1"
        )
        if run_attempt is None:
            self.errors.append("RUN_ATTEMPT_INVALID")
            run_attempt = "unknown-attempt"
        job_id = _safe_identifier(
            _first_option(self.config, "greengap_job_id") or os.environ.get("GREENGAP_JOB_ID")
        )
        values: dict[str, Any] = {
            "provider": provider,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "job": job_id or self.surface_id,
            "matrix_identity": _safe_identifier(os.environ.get("GREENGAP_MATRIX_ID")),
            "event": None,
            "ref": None,
            "surface_id": self.surface_id,
            "shard": self.shard,
            "worker_id": self.worker_id,
            "pid": os.getpid(),
            "config_sha256": self.config_sha256,
        }
        return values

    def _payload(self, exitstatus: Any, *, existing_fragments: int | None = None) -> dict[str, Any]:
        runtime_start = self.start_snapshot.fingerprint if self.start_snapshot is not None else "0" * 64
        runtime_final = self.final_snapshot.fingerprint if self.final_snapshot is not None else "0" * 64
        runtime_stable = (
            self.start_snapshot is not None
            and self.final_snapshot is not None
            and self.start_snapshot.complete
            and self.final_snapshot.complete
            and runtime_start == runtime_final
        )
        source_start = (
            self.source_start_snapshot.fingerprint
            if self.source_start_snapshot is not None
            else "0" * 64
        )
        source_final = (
            self.source_final_snapshot.fingerprint
            if self.source_final_snapshot is not None
            else "0" * 64
        )
        source_complete = (
            self.source_start_snapshot is not None
            and self.source_final_snapshot is not None
            and self.source_start_snapshot.complete
            and self.source_final_snapshot.complete
        )
        source_stable = source_complete and source_start == source_final
        if source_complete and not source_stable:
            self.errors.append("SOURCE_IDENTITY_UNSTABLE")
        if self.attempted - self.completed:
            self.errors.append("EXECUTION_INCOMPLETE")
        try:
            status = int(exitstatus)
        except (TypeError, ValueError):
            status = -1
            self.errors.append("SESSION_STATUS_INVALID")
        if self.role in {"collection", "both"} and status != 0:
            self.errors.append("COLLECTION_EXIT_NONZERO")
        finalized = self.session_finalized
        if not finalized:
            self.errors.append("SESSION_NOT_FINALIZED")
        collection_complete = self.collection_complete
        if self.role in {"collection", "both"} and not collection_complete:
            self.errors.append("COLLECTION_INCOMPLETE")
        if existing_fragments is None:
            existing_fragments = len(_fragment_names(self.output_dir))
        if existing_fragments >= MAX_RUNTIME_WITNESS_FRAGMENTS:
            self.errors.append("WITNESS_FRAGMENT_LIMIT_EXCEEDED")
        diagnostics = sorted(set(self.errors))[:64]
        complete = (
            self.git_sha is not None
            and source_stable
            and finalized
            and not diagnostics
            and (self.role == "execution" or collection_complete)
        )
        try:
            import pytest

            pytest_version = str(pytest.__version__)
        except (ImportError, AttributeError):
            pytest_version = "unknown"
        return {
            "schema_version": WITNESS_SCHEMA_VERSION,
            "witness_version": WITNESS_SCHEMA_VERSION,
            "artifact_type": WITNESS_ARTIFACT_TYPE,
            "kind": "pytest_runtime",
            "role": self.role,
            "greengap_version": __version__,
            "repository_identity": {
                "git_sha": self.git_sha,
                "git_tree": self.git_tree,
                "repository": self.repository,
            },
            "source_identity": {
                "initial_fingerprint": source_start,
                "final_fingerprint": source_final,
                "stable": source_stable,
            },
            "runtime_workspace_state": {
                "initial_fingerprint": runtime_start,
                "final_fingerprint": runtime_final,
                "stable": runtime_stable,
            },
            "workspace_identity": {
                "initial_fingerprint": runtime_start,
                "final_fingerprint": runtime_final,
                "stable": runtime_stable,
            },
            "pytest": {
                "version": pytest_version,
                "rootpath": ".",
                "session_id": self.session_id,
            },
            "execution_context": self._context(),
            "collection": {
                "complete": collection_complete,
                "collected_files": sorted(self.collection)[:MAX_RUNTIME_WITNESS_FILES],
            },
            "execution": {
                "attempted_files": sorted(self.attempted)[:MAX_RUNTIME_WITNESS_FILES],
                "call_executed_files": sorted(self.call_executed)[:MAX_RUNTIME_WITNESS_FILES],
                "completed_files": sorted(self.completed)[:MAX_RUNTIME_WITNESS_FILES],
                "call_outcomes": [
                    {"file": path, "outcome": outcome}
                    for path, outcome in sorted(self.call_outcomes.items())
                ][:MAX_RUNTIME_WITNESS_FILES],
            },
            "session": {"pytest_exitstatus": status, "finalized": finalized},
            "complete": complete,
            "diagnostics": diagnostics,
        }

    def _fragment_path(self) -> Path:
        worker = self.worker_id or "controller"
        return self.output_dir / f"greengap-{self.session_id}-{os.getpid()}-{worker}.json"

    def session_finish(self, session: Any, exitstatus: Any) -> None:
        try:
            self.exitstatus = int(exitstatus)
        except (TypeError, ValueError):
            self.exitstatus = -1
        self._take_final_snapshots()
        self.session_finalized = True
        self._write(exitstatus)

    def _write(self, exitstatus: Any) -> None:
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            if _has_link_component(self.output_dir) or not self.output_dir.is_dir():
                return
            with _witness_output_lock(self.output_dir):
                payload = self._payload(
                    exitstatus,
                    existing_fragments=len(_fragment_names(self.output_dir)),
                )
                encoded = json.dumps(
                    payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                if len(encoded) > MAX_RUNTIME_WITNESS_BYTES:
                    payload["collection"] = {"complete": False, "collected_files": []}
                    payload["execution"] = {
                        "attempted_files": [],
                        "call_executed_files": [],
                        "completed_files": [],
                        "call_outcomes": [],
                    }
                    payload["complete"] = False
                    payload["diagnostics"] = ["WITNESS_SIZE_LIMIT_EXCEEDED"]
                    encoded = json.dumps(
                        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                _atomic_write_fragment(self.output_dir, self._fragment_path(), encoded)
        except OSError:
            return


def _output_dir(config: Any) -> Path | None:
    raw = _option(config, "greengap_witness_dir")
    if not raw:
        raw = _option(config, "greengap_witness")
    if not raw:
        return None
    try:
        path = Path(str(raw))
        if path.suffix.casefold() == ".json":
            path = path.parent
        return resolve_witness_output_path(str(path))
    except (OSError, TypeError, ValueError):
        return None


def _instance(config: Any) -> _Witness | None:
    return getattr(config, "_greengap_file_witness", None)


def _configure_witness(config: Any) -> None:
    if _instance(config) is not None:
        return
    output_dir = _output_dir(config)
    if output_dir is not None:
        config._greengap_file_witness = _Witness(config, output_dir)


def pytest_load_initial_conftests(early_config: Any, parser: Any, args: Any) -> None:
    """Initialize before target conftests can abort pytest configuration."""

    global _EARLY_CONFIG
    _EARLY_CONFIG = early_config
    _configure_witness(early_config)


def pytest_configure(config: Any) -> None:
    _configure_witness(config)


def pytest_collection_finish(session: Any) -> None:
    witness = _instance(session.config)
    if witness is not None:
        witness.collection_finish(session)


_RUNTIME_CONFIG: Any | None = None
_EARLY_CONFIG: Any | None = None


def pytest_sessionstart(session: Any) -> None:
    global _RUNTIME_CONFIG
    _RUNTIME_CONFIG = session.config


def pytest_runtest_logstart(nodeid: str, location: Any) -> None:
    witness = _instance(_RUNTIME_CONFIG) if _RUNTIME_CONFIG is not None else None
    if witness is not None:
        witness.log_start(nodeid, location)


def pytest_runtest_logreport(report: Any) -> None:
    config = getattr(report, "config", None) or _RUNTIME_CONFIG
    witness = _instance(config) if config is not None else None
    if witness is not None:
        witness.log_report(report)


def pytest_runtest_logfinish(nodeid: str, location: Any) -> None:
    witness = _instance(_RUNTIME_CONFIG) if _RUNTIME_CONFIG is not None else None
    if witness is not None:
        witness.log_finish(nodeid, location)


def pytest_sessionfinish(session: Any, exitstatus: Any) -> None:
    witness = _instance(session.config)
    if witness is not None:
        witness.session_finish(session, exitstatus)


def pytest_unconfigure(config: Any) -> None:
    """Finalize an early witness when pytest never reaches sessionfinish."""

    witness = _instance(config)
    if witness is None or witness.session_finalized:
        return
    witness._take_final_snapshots()
    witness.session_finalized = True
    witness._write(witness.exitstatus if witness.exitstatus is not None else 4)


def pytest_internalerror(excrepr: Any, excinfo: Any) -> None:
    """Preserve an incomplete fragment for pre-session configuration errors."""

    config = _RUNTIME_CONFIG or _EARLY_CONFIG
    witness = _instance(config) if config is not None else None
    if witness is None or witness.session_finalized:
        return
    witness._take_final_snapshots()
    witness.session_finalized = True
    witness._write(4)
