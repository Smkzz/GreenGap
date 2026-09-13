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
import tempfile
import uuid
from pathlib import Path
from typing import Any

from . import __version__
from .model import WorkspaceSnapshot
from .snapshot import workspace_snapshot
from .util import (
    MAX_RUNTIME_WITNESS_BYTES,
    MAX_RUNTIME_WITNESS_FILES,
    MAX_RUNTIME_WITNESS_FRAGMENTS,
    normalize_repo_path,
)
from .witness import (
    WITNESS_ARTIFACT_TYPE,
    WITNESS_SCHEMA_VERSION,
    normalize_witness_path,
    resolve_witness_output_path,
)

_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
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
        action="store",
        default=os.environ.get("GREENGAP_SOURCE_COMMIT") or os.environ.get("GITHUB_SHA"),
        metavar="SHA",
        help="exact source commit to bind to this witness",
    )
    group.addoption(
        "--greengap-repository",
        action="store",
        default=os.environ.get("GREENGAP_REPOSITORY") or os.environ.get("GITHUB_REPOSITORY"),
        metavar="OWNER/REPOSITORY",
        help="optional safe repository identity",
    )
    group.addoption(
        "--greengap-witness-role",
        action="store",
        choices=("collection", "execution", "both"),
        default=os.environ.get("GREENGAP_WITNESS_ROLE", "execution"),
        help="kind of surface represented by this pytest session",
    )
    group.addoption(
        "--greengap-witness-id",
        action="store",
        default=os.environ.get("GREENGAP_WITNESS_ID"),
        metavar="ID",
        help="bounded manifest surface identity",
    )
    group.addoption(
        "--greengap-full-collection",
        action="store_true",
        default=os.environ.get("GREENGAP_FULL_COLLECTION", "") == "1",
        help="assert that collection has no selectors or node filters",
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
    claim = _option(config, "greengap_source_commit")
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
    )
    if any(getattr(option, name, None) for name in selector_options):
        errors.append("COLLECTION_SELECTOR_PRESENT")
        return False
    args = tuple(getattr(config, "args", ()))
    if args or any("::" in str(value) or "[" in str(value) for value in args):
        errors.append("COLLECTION_SELECTOR_PRESENT")
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
        self.role = str(_option(config, "greengap_witness_role", "execution"))
        if self.role not in {"collection", "execution", "both"}:
            self.role = "execution"
            self.errors.append("WITNESS_ROLE_INVALID")
        self.session_id = uuid.uuid4().hex
        self.worker_id = _safe_identifier(os.environ.get("PYTEST_XDIST_WORKER"))
        self.shard = _safe_identifier(os.environ.get("GREENGAP_SHARD")) or self.worker_id
        self.surface_id = _safe_identifier(_option(config, "greengap_witness_id"))
        if self.surface_id is None:
            self.surface_id = "collection" if self.role == "collection" else "execution"
        source, tree = _source_identity(config, self.errors)
        self.git_sha = source
        self.git_tree = tree
        self.repository = _repository_identity(config, self.errors)
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
        self.collection_unfiltered = _collection_is_unfiltered(config, self.errors)
        if self.role in {"collection", "both"} and not self.collection_unfiltered:
            self.errors.append("FULL_COLLECTION_NOT_DECLARED")
        self._take_start_snapshot()

    def _take_start_snapshot(self) -> None:
        self.start_snapshot = workspace_snapshot(self.root, timeout=10.0)
        if not self.start_snapshot.complete:
            self.errors.append("WORKSPACE_FINGERPRINT_INCOMPLETE")

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
        raw_path = location[0] if isinstance(location, (tuple, list)) and location else None
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
        raw_path = location[0] if isinstance(location, (tuple, list)) and location else None
        self._mark(self.completed, nodeid, raw_path)

    def _context(self) -> dict[str, Any]:
        provider = "github_actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "local"
        run_id = _safe_identifier(os.environ.get("GREENGAP_RUN_ID"))
        if run_id is None:
            run_id = _safe_identifier(os.environ.get("GITHUB_RUN_ID"), numeric=True)
        if run_id is None:
            run_id = f"local-{self.session_id}"
        run_attempt = _safe_identifier(os.environ.get("GREENGAP_RUN_ATTEMPT"))
        if run_attempt is None:
            run_attempt = _safe_identifier(os.environ.get("GITHUB_RUN_ATTEMPT"), numeric=True)
        if run_attempt is None:
            run_attempt = "1"
        values: dict[str, Any] = {
            "provider": provider,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "job": _safe_identifier(os.environ.get("GITHUB_JOB")) or self.surface_id,
            "matrix_identity": _safe_identifier(os.environ.get("GREENGAP_MATRIX_ID")),
            "event": _safe_identifier(os.environ.get("GITHUB_EVENT_NAME")),
            "ref": _safe_identifier(os.environ.get("GITHUB_REF")),
            "surface_id": self.surface_id,
            "shard": self.shard,
            "worker_id": self.worker_id,
            "pid": os.getpid(),
        }
        return values

    def _payload(self, exitstatus: Any) -> dict[str, Any]:
        start = self.start_snapshot.fingerprint if self.start_snapshot is not None else "0" * 64
        final = self.final_snapshot.fingerprint if self.final_snapshot is not None else "0" * 64
        stable = (
            self.start_snapshot is not None
            and self.final_snapshot is not None
            and self.start_snapshot.complete
            and self.final_snapshot.complete
            and start == final
        )
        if not stable:
            self.errors.append("WORKSPACE_UNSTABLE")
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
        try:
            existing_fragments = sum(1 for item in self.output_dir.glob("*.json") if item.is_file())
        except OSError:
            existing_fragments = MAX_RUNTIME_WITNESS_FRAGMENTS
        if existing_fragments >= MAX_RUNTIME_WITNESS_FRAGMENTS:
            self.errors.append("WITNESS_FRAGMENT_LIMIT_EXCEEDED")
        diagnostics = sorted(set(self.errors))[:64]
        complete = (
            self.git_sha is not None
            and stable
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
            "workspace_identity": {
                "initial_fingerprint": start,
                "final_fingerprint": final,
                "stable": stable,
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
        self.final_snapshot = workspace_snapshot(self.root, timeout=10.0)
        if not self.final_snapshot.complete:
            self.errors.append("WORKSPACE_FINGERPRINT_INCOMPLETE")
        self.session_finalized = True
        self._write(exitstatus)

    def _write(self, exitstatus: Any) -> None:
        payload = self._payload(exitstatus)
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
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
            encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            if self.output_dir.is_symlink() or not self.output_dir.is_dir():
                return
            final = self._fragment_path()
            if final.exists():
                return
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.output_dir, prefix=f".{final.name}.", delete=False
            ) as handle:
                temporary = Path(handle.name)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            if final.exists():
                temporary.unlink(missing_ok=True)
                return
            temporary.replace(final)
            try:
                directory_fd = os.open(str(self.output_dir), os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
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
    witness.final_snapshot = workspace_snapshot(witness.root, timeout=10.0)
    if not witness.final_snapshot.complete:
        witness.errors.append("WORKSPACE_FINGERPRINT_INCOMPLETE")
    witness.session_finalized = True
    witness._write(witness.exitstatus if witness.exitstatus is not None else 4)


def pytest_internalerror(excrepr: Any, excinfo: Any) -> None:
    """Preserve an incomplete fragment for pre-session configuration errors."""

    config = _RUNTIME_CONFIG or _EARLY_CONFIG
    witness = _instance(config) if config is not None else None
    if witness is None or witness.session_finalized:
        return
    witness.final_snapshot = workspace_snapshot(witness.root, timeout=10.0)
    if not witness.final_snapshot.complete:
        witness.errors.append("WORKSPACE_FINGERPRINT_INCOMPLETE")
    witness.session_finalized = True
    witness._write(4)
