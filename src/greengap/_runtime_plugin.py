"""Opt-in native pytest hooks for GreenGap runtime witnesses.

The plugin is inert unless the caller explicitly loads it and supplies a
witness output path.  It records only bounded JSON identity data; it never
captures test output, environment dumps, fixtures, or arbitrary Python state.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .runtime import (
    RUNTIME_WITNESS_ARTIFACT_TYPE,
    RUNTIME_WITNESS_SCHEMA_VERSION,
)
from .snapshot import workspace_snapshot
from .util import MAX_RUNTIME_WITNESS_BYTES, MAX_RUNTIME_WITNESS_NODES, normalize_repo_path

_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,256}$")
_MAX_NODEID_BYTES = 8192


def pytest_addoption(parser: Any) -> None:
    group = parser.getgroup("greengap")
    group.addoption(
        "--greengap-witness",
        action="store",
        default=os.environ.get("GREENGAP_WITNESS_FILE"),
        metavar="PATH",
        help="write an opt-in GreenGap runtime witness as inert JSON",
    )
    group.addoption(
        "--greengap-source-commit",
        action="store",
        default=os.environ.get("GREENGAP_SOURCE_COMMIT") or os.environ.get("GITHUB_SHA"),
        metavar="SHA",
        help="source commit to bind into the runtime witness",
    )
    group.addoption(
        "--greengap-matrix-id",
        action="store",
        default=os.environ.get("GREENGAP_MATRIX_ID"),
        metavar="ID",
        help="optional safe matrix/shard identity for witness aggregation",
    )


def _safe_identifier(value: Any, *, numeric: bool = False) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        return None
    if numeric and not value.isdigit():
        return None
    return value


def _source_commit(config: Any, errors: list[str]) -> str | None:
    value = config.getoption("greengap_source_commit", default=None)
    if value:
        if not isinstance(value, str) or _HEX_SHA_RE.fullmatch(value) is None:
            errors.append("SOURCE_COMMIT_INVALID")
            return None
        return value.lower()
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(str(config.rootpath)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        errors.append("SOURCE_COMMIT_MISSING")
        return None
    candidate = completed.stdout.strip()
    if completed.returncode != 0 or _HEX_SHA_RE.fullmatch(candidate) is None:
        errors.append("SOURCE_COMMIT_MISSING")
        return None
    return candidate.lower()


def _relative_node_path(root: Path, value: Any) -> str | None:
    try:
        return normalize_repo_path(root, value)
    except (OSError, ValueError, TypeError):
        return None


def _node_path(nodeid: str) -> str | None:
    raw = nodeid.split("::", 1)[0]
    if not nodeid or any(ord(character) < 32 or ord(character) == 127 for character in nodeid):
        return None
    if len(nodeid.encode("utf-8", errors="replace")) > _MAX_NODEID_BYTES:
        return None
    return raw


def _github_identity(config: Any, errors: list[str]) -> dict[str, str | None]:
    matrix = config.getoption("greengap_matrix_id", default=None)
    if matrix not in (None, "") and _safe_identifier(matrix) is None:
        errors.append("MATRIX_ID_INVALID")
    values = {
        "run_id": _safe_identifier(os.environ.get("GITHUB_RUN_ID"), numeric=True),
        "run_attempt": _safe_identifier(os.environ.get("GITHUB_RUN_ATTEMPT"), numeric=True),
        "job": _safe_identifier(os.environ.get("GITHUB_JOB")),
        "matrix": _safe_identifier(matrix),
        "shard": _safe_identifier(os.environ.get("PYTEST_XDIST_WORKER")),
        "repository": _safe_identifier(os.environ.get("GITHUB_REPOSITORY")),
    }
    if values["run_id"] is None or values["run_attempt"] is None or values["job"] is None:
        errors.append("RUN_IDENTITY_MISSING")
    return values


class _Witness:
    def __init__(self, config: Any, output: Path) -> None:
        self.config = config
        self.output = output
        worker = _safe_identifier(os.environ.get("PYTEST_XDIST_WORKER"))
        if worker:
            suffix = self.output.suffix or ".json"
            stem = self.output.name[: -len(self.output.suffix)] if self.output.suffix else self.output.name
            self.output = self.output.with_name(f"{stem}.{worker}{suffix}")
        self.root = Path(str(config.rootpath)).resolve()
        self.errors: list[str] = []
        self.collection: dict[str, str] = {}
        self.executed: dict[str, dict[str, Any]] = {}
        self.collection_complete = False
        self.session_complete = False
        self.start_snapshot = None
        self.final_snapshot = None
        self.source_commit = _source_commit(config, self.errors)
        self.github = _github_identity(config, self.errors)
        self.pytest_root = "."
        self._take_start_snapshot()

    def _take_start_snapshot(self) -> None:
        snapshot = workspace_snapshot(self.root, timeout=10.0)
        self.start_snapshot = snapshot
        if not snapshot.complete:
            self.errors.append("WORKSPACE_FINGERPRINT_INCOMPLETE")

    def _path_for(self, nodeid: str, raw_path: Any = None) -> str | None:
        candidate = _relative_node_path(self.root, raw_path) if raw_path is not None else None
        if candidate:
            return candidate
        raw_node_path = _node_path(nodeid)
        if raw_node_path is None:
            return None
        return _relative_node_path(self.root, raw_node_path)

    def collection_finish(self, session: Any) -> None:
        items = getattr(session, "items", ())
        for item in items:
            nodeid = str(getattr(item, "nodeid", ""))
            path = self._path_for(nodeid, getattr(item, "path", None))
            if not nodeid or "::" not in nodeid or path is None:
                self.errors.append("COLLECTION_NODE_INVALID")
                continue
            prior = self.collection.get(nodeid)
            if prior is not None and prior != path:
                self.errors.append("COLLECTION_NODE_CONFLICT")
            elif prior is None and len(self.collection) >= MAX_RUNTIME_WITNESS_NODES:
                self.errors.append("COLLECTION_LIMIT_EXCEEDED")
            else:
                self.collection[nodeid] = path
        self.collection_complete = not any(
            error.startswith(("COLLECTION_", "WORKSPACE_FINGERPRINT")) for error in self.errors
        )

    def _ensure_executed(self, nodeid: str, raw_path: Any = None) -> dict[str, Any] | None:
        path = self._path_for(nodeid, raw_path)
        if not nodeid or "::" not in nodeid or path is None:
            self.errors.append("EXECUTION_NODE_INVALID")
            return None
        prior = self.executed.get(nodeid)
        if prior is None:
            if len(self.executed) >= MAX_RUNTIME_WITNESS_NODES:
                self.errors.append("EXECUTION_LIMIT_EXCEEDED")
                return None
            prior = {
                "nodeid": nodeid,
                "path": path,
                "started": False,
                "finished": False,
                "reports": [],
            }
            self.executed[nodeid] = prior
        elif prior["path"] != path:
            self.errors.append("EXECUTION_NODE_CONFLICT")
            return None
        return prior

    def log_start(self, nodeid: str, location: Any) -> None:
        raw_path = location[0] if isinstance(location, tuple | list) and location else None
        record = self._ensure_executed(nodeid, raw_path)
        if record is not None:
            record["started"] = True

    def log_finish(self, nodeid: str, location: Any) -> None:
        raw_path = location[0] if isinstance(location, tuple | list) and location else None
        record = self._ensure_executed(nodeid, raw_path)
        if record is not None:
            record["finished"] = True

    def log_report(self, report: Any) -> None:
        nodeid = str(getattr(report, "nodeid", ""))
        raw_path = getattr(report, "fspath", None)
        record = self._ensure_executed(nodeid, raw_path)
        if record is None:
            return
        when = getattr(report, "when", None)
        outcome = getattr(report, "outcome", None)
        if when not in {"setup", "call", "teardown"} or outcome not in {
            "passed",
            "failed",
            "skipped",
        }:
            self.errors.append("REPORT_INVALID")
            return
        report_record = {"when": when, "outcome": outcome}
        if report_record not in record["reports"]:
            if len(record["reports"]) >= 6:
                self.errors.append("REPORT_LIMIT_EXCEEDED")
            else:
                record["reports"].append(report_record)

    def session_finish(self, session: Any, exitstatus: Any) -> None:
        self.final_snapshot = workspace_snapshot(self.root, timeout=10.0)
        if not self.final_snapshot.complete:
            self.errors.append("WORKSPACE_FINGERPRINT_INCOMPLETE")
        self.session_complete = True
        self._write(exitstatus)

    def _payload(self, exitstatus: Any) -> dict[str, Any]:
        start_fingerprint = self.start_snapshot.fingerprint if self.start_snapshot is not None else "0" * 64
        final_fingerprint = self.final_snapshot.fingerprint if self.final_snapshot is not None else "0" * 64
        stable = (
            self.start_snapshot is not None
            and self.final_snapshot is not None
            and self.start_snapshot.complete
            and self.final_snapshot.complete
            and start_fingerprint == final_fingerprint
        )
        if not stable:
            self.errors.append("WORKSPACE_UNSTABLE")
        if any(not record["finished"] for record in self.executed.values()):
            self.errors.append("EXECUTION_INCOMPLETE")
        if any(not record["reports"] for record in self.executed.values()):
            self.errors.append("REPORT_MISSING")
        errors = sorted(set(self.errors))
        complete = (
            self.source_commit is not None
            and not errors
            and self.collection_complete
            and self.session_complete
            and stable
        )
        try:
            status = int(exitstatus)
        except (TypeError, ValueError):
            status = -1
            errors.append("SESSION_STATUS_INVALID")
            complete = False
        return {
            "schema_version": RUNTIME_WITNESS_SCHEMA_VERSION,
            "artifact_type": RUNTIME_WITNESS_ARTIFACT_TYPE,
            "greengap_version": __version__,
            "source_commit": self.source_commit,
            "repository": self.github["repository"],
            "workspace_fingerprint": start_fingerprint,
            "workspace_fingerprint_final": final_fingerprint,
            "workspace_stable": stable,
            "pytest_root": self.pytest_root,
            "github": self.github,
            "collection": [
                {"nodeid": nodeid, "path": path}
                for nodeid, path in sorted(self.collection.items())
            ][:MAX_RUNTIME_WITNESS_NODES],
            "executed": [
                self.executed[nodeid] for nodeid in sorted(self.executed)
            ][:MAX_RUNTIME_WITNESS_NODES],
            "session": {
                "exit_status": status,
                "collection_complete": self.collection_complete,
                "session_complete": self.session_complete,
            },
            "complete": complete,
            "errors": sorted(set(errors))[:64],
        }

    def _write(self, exitstatus: Any) -> None:
        payload = self._payload(exitstatus)
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        if len(encoded) > MAX_RUNTIME_WITNESS_BYTES:
            payload["collection"] = []
            payload["executed"] = []
            payload["complete"] = False
            payload["errors"] = ["WITNESS_SIZE_LIMIT_EXCEEDED"]
            encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        try:
            self.output.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.output.parent, prefix=f".{self.output.name}.", delete=False
            ) as handle:
                temporary = Path(handle.name)
                handle.write(encoded)
            temporary.replace(self.output)
        except OSError:
            # The pytest job's exit result remains the target project's result;
            # failure to write is represented by a missing witness and is
            # therefore incomplete at aggregation time.
            return


def _instance(config: Any) -> _Witness | None:
    return getattr(config, "_greengap_runtime_witness", None)


def pytest_configure(config: Any) -> None:
    raw_output = config.getoption("greengap_witness", default=None)
    if not raw_output:
        return
    try:
        output = Path(str(raw_output))
    except (TypeError, ValueError):
        return
    config._greengap_runtime_witness = _Witness(config, output)


def pytest_collection_finish(session: Any) -> None:
    witness = _instance(session.config)
    if witness is not None:
        witness.collection_finish(session)


def pytest_runtest_logstart(nodeid: str, location: Any) -> None:
    witness = _instance(_RUNTIME_CONFIG) if _RUNTIME_CONFIG is not None else None
    if witness is not None:
        witness.log_start(nodeid, location)


def pytest_runtest_logfinish(nodeid: str, location: Any) -> None:
    witness = _instance(_RUNTIME_CONFIG) if _RUNTIME_CONFIG is not None else None
    if witness is not None:
        witness.log_finish(nodeid, location)


def pytest_runtest_logreport(report: Any) -> None:
    config = getattr(report, "config", None)
    if config is None:
        # pytest TestReport does not promise a config attribute.  The
        # session-level hook installs a fallback for this process.
        config = _RUNTIME_CONFIG
    witness = _instance(config) if config is not None else None
    if witness is not None:
        witness.log_report(report)


_RUNTIME_CONFIG: Any | None = None


def pytest_sessionstart(session: Any) -> None:
    global _RUNTIME_CONFIG
    _RUNTIME_CONFIG = session.config


def pytest_sessionfinish(session: Any, exitstatus: Any) -> None:
    witness = _instance(session.config)
    if witness is not None:
        witness.session_finish(session, exitstatus)
