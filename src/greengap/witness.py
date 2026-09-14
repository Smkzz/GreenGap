"""File-level runtime witness contracts and command orchestration.

This module is the v1 public boundary for the opt-in pytest witness.  It is
deliberately independent of the older node-level runtime contract in
``greengap.runtime``: a file-level witness never serializes pytest node IDs,
parameter values, target output, or the target process environment.

The target process is caller-authorized code execution.  The witness is not a
cryptographic attestation against code running in that same process.  Its
purpose is narrower: after a complete, explicitly declared collection and a
complete set of source-bound execution fragments, reconcile the files pytest
collected with files whose ``call`` phase was observed.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import stat
import subprocess
import tempfile
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .snapshot import source_snapshot, workspace_snapshot
from .util import (
    MAX_RUNTIME_AGGREGATE_BYTES,
    MAX_RUNTIME_EXPECTED_IDENTITIES,
    MAX_RUNTIME_WITNESS_BYTES,
    MAX_RUNTIME_WITNESS_FILES,
    MAX_RUNTIME_WITNESS_FRAGMENTS,
    MAX_RUNTIME_WITNESS_MANIFEST_ENTRIES,
    read_limited_bytes,
    run_process_tree,
)

WITNESS_SCHEMA_VERSION = 1
WITNESS_ARTIFACT_TYPE = "greengap_pytest_runtime_witness"
WITNESS_MANIFEST_ARTIFACT_TYPE = "greengap_pytest_runtime_witness_manifest"
WITNESS_ANALYSIS_ARTIFACT_TYPE = "greengap_pytest_runtime_analysis"
WITNESS_PLUGIN_MODULE = "greengap.pytest_witness"
WITNESS_RULE_ID = "GGW001"

_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,256}$")
_SAFE_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,4096}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:/")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}/[A-Za-z0-9_.-]{1,128}$")


class WitnessError(ValueError):
    """An artifact cannot support a complete runtime conclusion."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _read_json(path: Path, limit: int = MAX_RUNTIME_WITNESS_BYTES) -> Any:
    try:
        return json.loads(read_limited_bytes(path, limit).decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError, MemoryError) as exc:
        raise WitnessError("WITNESS_MALFORMED") from exc


def _safe_text(value: Any, *, identifier: bool = False, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value or _SAFE_TEXT_RE.fullmatch(value) is None:
        raise WitnessError("WITNESS_FIELD_INVALID")
    normalized = value.replace("\\", "/")
    if identifier and (
        _SAFE_ID_RE.fullmatch(value) is None
        or normalized.startswith("/")
        or _DRIVE_RE.match(normalized) is not None
        or any(part == ".." for part in normalized.split("/"))
    ):
        raise WitnessError("WITNESS_IDENTITY_INVALID")
    return value


def _sha(value: Any, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SHA1_RE.fullmatch(value) is None:
        raise WitnessError("SOURCE_COMMIT_INVALID")
    return value.lower()


def _fingerprint(value: Any) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise WitnessError("WORKSPACE_FINGERPRINT_INVALID")
    return value.lower()


def normalize_witness_path(value: Any) -> str:
    """Validate and normalize a repository-relative public file identity."""

    raw = _safe_text(value)
    assert raw is not None
    if len(raw.encode("utf-8")) > 1024:
        raise WitnessError("WITNESS_PATH_TOO_LONG")
    raw = raw.replace("\\", "/")
    if raw.startswith("/") or _DRIVE_RE.match(raw) is not None:
        raise WitnessError("WITNESS_PATH_INVALID")
    parts = raw.split("/")
    if any(part == ".." for part in parts):
        raise WitnessError("WITNESS_PATH_INVALID")
    normalized = posixpath.normpath(raw)
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        raise WitnessError("WITNESS_PATH_INVALID")
    if normalized.startswith("/") or _DRIVE_RE.match(normalized) is not None:
        raise WitnessError("WITNESS_PATH_INVALID")
    return normalized


def _path_list(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_RUNTIME_WITNESS_FILES:
        raise WitnessError("WITNESS_FILE_LIST_INVALID")
    result: set[str] = set()
    for item in value:
        result.add(normalize_witness_path(item))
    return sorted(result)


def _optional_id(value: Any) -> str | None:
    return _safe_text(value, identifier=True, nullable=True)


def _optional_repository(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _REPOSITORY_RE.fullmatch(value) is None:
        raise WitnessError("WITNESS_REPOSITORY_IDENTITY_INVALID")
    return value


def _required_id(value: Any) -> str:
    result = _safe_text(value, identifier=True)
    assert result is not None
    return result


def _validate_repository_identity(value: Any) -> dict[str, str | None]:
    if not isinstance(value, dict) or set(value) != {"git_sha", "git_tree", "repository"}:
        raise WitnessError("WITNESS_REPOSITORY_IDENTITY_INVALID")
    return {
        "git_sha": _sha(value["git_sha"], nullable=True),
        "git_tree": _sha(value["git_tree"], nullable=True),
        "repository": _optional_repository(value["repository"]),
    }


def _validate_identity_state(value: Any, *, error_code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "initial_fingerprint",
        "final_fingerprint",
        "stable",
    }:
        raise WitnessError(error_code)
    if not isinstance(value["stable"], bool):
        raise WitnessError(error_code)
    return {
        "initial_fingerprint": _fingerprint(value["initial_fingerprint"]),
        "final_fingerprint": _fingerprint(value["final_fingerprint"]),
        "stable": value["stable"],
    }


def _validate_workspace_identity(value: Any) -> dict[str, Any]:
    return _validate_identity_state(value, error_code="WITNESS_WORKSPACE_IDENTITY_INVALID")


def _validate_pytest_identity(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"version", "rootpath", "session_id"}:
        raise WitnessError("WITNESS_PYTEST_IDENTITY_INVALID")
    version = _safe_text(value["version"])
    rootpath = normalize_witness_path(value["rootpath"]) if value["rootpath"] != "." else "."
    session_id = _required_id(value["session_id"])
    if _UUID_RE.fullmatch(session_id) is None:
        raise WitnessError("WITNESS_SESSION_ID_INVALID")
    assert version is not None
    return {"version": version, "rootpath": rootpath, "session_id": session_id.lower()}


def _validate_execution_context(value: Any) -> dict[str, Any]:
    required = {
        "provider",
        "run_id",
        "run_attempt",
        "job",
        "matrix_identity",
        "event",
        "ref",
        "surface_id",
        "shard",
        "worker_id",
        "pid",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise WitnessError("WITNESS_EXECUTION_CONTEXT_INVALID")
    provider = _required_id(value["provider"])
    if provider not in {"local", "github_actions", "ci"}:
        raise WitnessError("WITNESS_EXECUTION_CONTEXT_INVALID")
    optional = {
        key: _optional_id(value[key])
        for key in ("run_id", "run_attempt", "job", "matrix_identity", "event", "ref", "shard", "worker_id")
    }
    pid = value["pid"]
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 or pid > 2**31 - 1:
        raise WitnessError("WITNESS_PROCESS_ID_INVALID")
    return {"provider": provider, **optional, "surface_id": _required_id(value["surface_id"]), "pid": pid}


def _validate_session(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"pytest_exitstatus", "finalized"}:
        raise WitnessError("WITNESS_SESSION_INVALID")
    status = value["pytest_exitstatus"]
    if isinstance(status, bool) or not isinstance(status, int) or status < -1 or status > 255:
        raise WitnessError("WITNESS_SESSION_INVALID")
    if not isinstance(value["finalized"], bool):
        raise WitnessError("WITNESS_SESSION_INVALID")
    return {"pytest_exitstatus": status, "finalized": value["finalized"]}


def _validate_witness_payload(payload: Any) -> dict[str, Any]:
    required = {
        "schema_version",
        "witness_version",
        "artifact_type",
        "kind",
        "role",
        "greengap_version",
        "repository_identity",
        "workspace_identity",
        "pytest",
        "execution_context",
        "collection",
        "execution",
        "session",
        "complete",
        "diagnostics",
    }
    allowed = required | {"source_identity", "runtime_workspace_state"}
    if not isinstance(payload, dict) or not required.issubset(payload) or not set(payload) <= allowed:
        raise WitnessError("WITNESS_SCHEMA_INVALID")
    if payload["schema_version"] != WITNESS_SCHEMA_VERSION or payload["witness_version"] != WITNESS_SCHEMA_VERSION:
        raise WitnessError("WITNESS_SCHEMA_UNSUPPORTED")
    if payload["artifact_type"] != WITNESS_ARTIFACT_TYPE:
        raise WitnessError("WITNESS_ARTIFACT_TYPE_INVALID")
    kind = _required_id(payload["kind"])
    role = _required_id(payload["role"])
    if kind != "pytest_runtime" or role not in {"collection", "execution", "both"}:
        raise WitnessError("WITNESS_KIND_INVALID")
    version = _safe_text(payload["greengap_version"])
    assert version is not None
    repository = _validate_repository_identity(payload["repository_identity"])
    workspace = _validate_workspace_identity(payload["workspace_identity"])
    runtime_workspace = _validate_identity_state(
        payload.get("runtime_workspace_state", workspace),
        error_code="WITNESS_RUNTIME_WORKSPACE_STATE_INVALID",
    )
    if "runtime_workspace_state" in payload and runtime_workspace != workspace:
        raise WitnessError("WITNESS_WORKSPACE_IDENTITY_CONFLICT")
    source_identity = _validate_identity_state(
        payload.get("source_identity", workspace),
        error_code="WITNESS_SOURCE_IDENTITY_INVALID",
    )
    pytest_identity = _validate_pytest_identity(payload["pytest"])
    context = _validate_execution_context(payload["execution_context"])
    collection = payload["collection"]
    if not isinstance(collection, dict) or set(collection) != {"complete", "collected_files"}:
        raise WitnessError("WITNESS_COLLECTION_INVALID")
    if not isinstance(collection["complete"], bool):
        raise WitnessError("WITNESS_COLLECTION_INVALID")
    execution = payload["execution"]
    if not isinstance(execution, dict) or not set(execution).issubset({
        "attempted_files",
        "call_executed_files",
        "completed_files",
        "call_outcomes",
    }) or not {"attempted_files", "call_executed_files", "completed_files"}.issubset(execution):
        raise WitnessError("WITNESS_EXECUTION_INVALID")
    call_outcomes = execution.get("call_outcomes", [])
    if not isinstance(call_outcomes, list) or len(call_outcomes) > MAX_RUNTIME_WITNESS_FILES:
        raise WitnessError("WITNESS_EXECUTION_INVALID")
    normalized_outcomes: dict[str, str] = {}
    for item in call_outcomes:
        if not isinstance(item, dict) or set(item) != {"file", "outcome"}:
            raise WitnessError("WITNESS_EXECUTION_INVALID")
        path = normalize_witness_path(item["file"])
        outcome = _required_id(item["outcome"])
        if outcome not in {"passed", "failed", "skipped"}:
            raise WitnessError("WITNESS_EXECUTION_INVALID")
        prior_outcome = normalized_outcomes.get(path)
        if prior_outcome is not None and prior_outcome != outcome:
            priority = {"skipped": 1, "passed": 2, "failed": 3}
            if priority[outcome] < priority[prior_outcome]:
                outcome = prior_outcome
        normalized_outcomes[path] = outcome
    attempted_files = _path_list(execution["attempted_files"])
    call_executed_files = _path_list(execution["call_executed_files"])
    completed_files = _path_list(execution["completed_files"])
    if any(path not in call_executed_files for path in normalized_outcomes):
        raise WitnessError("WITNESS_EXECUTION_CONFLICT")
    if any(path not in attempted_files for path in call_executed_files + completed_files):
        raise WitnessError("WITNESS_EXECUTION_CONFLICT")
    diagnostics = payload["diagnostics"]
    if not isinstance(diagnostics, list) or len(diagnostics) > 64:
        raise WitnessError("WITNESS_DIAGNOSTICS_INVALID")
    normalized_diagnostics: list[str] = []
    for item in diagnostics:
        normalized_diagnostics.append(_required_id(item))
    session = _validate_session(payload["session"])
    if not isinstance(payload["complete"], bool):
        raise WitnessError("WITNESS_COMPLETENESS_INVALID")
    normalized = {
        "schema_version": 1,
        "witness_version": 1,
        "artifact_type": WITNESS_ARTIFACT_TYPE,
        "kind": kind,
        "role": role,
        "greengap_version": version,
        "repository_identity": repository,
        "source_identity": source_identity,
        "runtime_workspace_state": runtime_workspace,
        "workspace_identity": workspace,
        "pytest": pytest_identity,
        "execution_context": context,
        "collection": {
            "complete": collection["complete"],
            "collected_files": _path_list(collection["collected_files"]),
        },
        "execution": {
            "attempted_files": attempted_files,
            "call_executed_files": call_executed_files,
            "completed_files": completed_files,
            "call_outcomes": [
                {"file": path, "outcome": outcome}
                for path, outcome in sorted(normalized_outcomes.items())
            ],
        },
        "session": session,
        "complete": payload["complete"],
        "diagnostics": sorted(set(normalized_diagnostics)),
    }
    return normalized


def load_witness(path: Path) -> dict[str, Any]:
    """Read and validate one file-level witness fragment."""

    return _validate_witness_payload(_read_json(path))


def validate_witness(payload: Any) -> dict[str, Any]:
    """Validate an in-memory file-level witness payload."""

    return _validate_witness_payload(payload)


def _normalize_witness_id(value: Any) -> str:
    raw_value = _safe_text(value)
    assert raw_value is not None
    raw = raw_value
    parts = raw.split("|")
    if len(parts) == 1:
        return f"{raw}|-"
    if len(parts) != 2 or any(part == "" or part == "-" and index == 0 for index, part in enumerate(parts)):
        raise WitnessError("MANIFEST_WITNESS_ID_INVALID")
    for part in parts:
        if part != "-" and _SAFE_ID_RE.fullmatch(part) is None:
            raise WitnessError("MANIFEST_WITNESS_ID_INVALID")
    return raw


def _expected_id_list(value: Any, *, required: bool = True) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_RUNTIME_WITNESS_MANIFEST_ENTRIES:
        raise WitnessError("MANIFEST_WITNESS_SET_INVALID")
    result = sorted({_normalize_witness_id(item) for item in value})
    if required and not result:
        raise WitnessError("MANIFEST_WITNESS_SET_INVALID")
    return result


def _validate_manifest_payload(payload: Any) -> dict[str, Any]:
    required = {
        "schema_version",
        "manifest_version",
        "artifact_type",
        "repository_identity",
        "workspace_identity",
        "run_identity",
        "collection",
        "execution",
        "required_witness_ids",
    }
    allowed = required | {"source_identity"}
    if not isinstance(payload, dict) or not required.issubset(payload) or not set(payload) <= allowed:
        raise WitnessError("MANIFEST_SCHEMA_INVALID")
    if payload["schema_version"] != 1 or payload["manifest_version"] != 1:
        raise WitnessError("MANIFEST_SCHEMA_UNSUPPORTED")
    if payload["artifact_type"] != WITNESS_MANIFEST_ARTIFACT_TYPE:
        raise WitnessError("MANIFEST_ARTIFACT_TYPE_INVALID")
    repository = _validate_repository_identity(payload["repository_identity"])
    source = repository["git_sha"]
    if source is None:
        raise WitnessError("MANIFEST_SOURCE_COMMIT_MISSING")
    workspace = payload["workspace_identity"]
    if not isinstance(workspace, dict) or set(workspace) != {"fingerprint"}:
        raise WitnessError("MANIFEST_WORKSPACE_IDENTITY_INVALID")
    workspace_fingerprint = _fingerprint(workspace["fingerprint"])
    source_payload = payload.get("source_identity", workspace)
    if not isinstance(source_payload, dict) or set(source_payload) != {"fingerprint"}:
        raise WitnessError("MANIFEST_SOURCE_IDENTITY_INVALID")
    source_fingerprint = _fingerprint(source_payload["fingerprint"])
    run_identity = payload["run_identity"]
    if not isinstance(run_identity, dict) or set(run_identity) != {"run_id", "run_attempt"}:
        raise WitnessError("MANIFEST_RUN_IDENTITY_INVALID")
    run_id = _required_id(run_identity["run_id"])
    run_attempt = _required_id(run_identity["run_attempt"])
    collection = payload["collection"]
    execution = payload["execution"]
    if not isinstance(collection, dict) or set(collection) != {"expected_witness_ids"}:
        raise WitnessError("MANIFEST_COLLECTION_INVALID")
    if not isinstance(execution, dict) or set(execution) != {"expected_witness_ids"}:
        raise WitnessError("MANIFEST_EXECUTION_INVALID")
    collection_ids = _expected_id_list(collection["expected_witness_ids"])
    execution_ids = _expected_id_list(execution["expected_witness_ids"])
    required_ids = _expected_id_list(payload["required_witness_ids"])
    expected_union = sorted(set(collection_ids) | set(execution_ids))
    if required_ids != expected_union:
        raise WitnessError("MANIFEST_REQUIRED_SET_CONFLICT")
    if len(required_ids) > MAX_RUNTIME_EXPECTED_IDENTITIES:
        raise WitnessError("MANIFEST_WITNESS_SET_LIMIT_EXCEEDED")
    return {
        "schema_version": 1,
        "manifest_version": 1,
        "artifact_type": WITNESS_MANIFEST_ARTIFACT_TYPE,
        "repository_identity": repository,
        "source_identity": {"fingerprint": source_fingerprint},
        "workspace_identity": {"fingerprint": workspace_fingerprint},
        "run_identity": {"run_id": run_id, "run_attempt": run_attempt},
        "collection": {"expected_witness_ids": collection_ids},
        "execution": {"expected_witness_ids": execution_ids},
        "required_witness_ids": required_ids,
    }


def load_manifest(path: Path) -> dict[str, Any]:
    """Read and validate a manifest without reading any target repository code."""

    return _validate_manifest_payload(_read_json(path))


def validate_manifest(payload: Any) -> dict[str, Any]:
    return _validate_manifest_payload(payload)


def witness_id(payload: Mapping[str, Any]) -> str:
    context = payload["execution_context"]
    surface = _required_id(context["surface_id"])
    shard = context.get("shard") or "-"
    return _normalize_witness_id(f"{surface}|{shard}")


def _same_json(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return json.dumps(left, sort_keys=True, separators=(",", ":")) == json.dumps(
        right, sort_keys=True, separators=(",", ":")
    )


def _has_link_component(path: Path) -> bool:
    """Reject symlink/junction components before resolving an output path."""

    try:
        absolute = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    except (OSError, TypeError, ValueError):
        return True
    current = Path(absolute.anchor) if absolute.anchor else Path()
    for part in absolute.parts:
        if part == absolute.anchor:
            continue
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            break
        except OSError:
            return True
        if stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400):
            return True
    return False


def resolve_witness_output_path(value: str) -> Path:
    """Return a lexical absolute output path with link boundaries rejected."""

    try:
        path = Path(os.path.abspath(os.path.expanduser(value)))
    except (OSError, TypeError, ValueError) as exc:
        raise WitnessError("WITNESS_OUTPUT_DIRECTORY_INVALID") from exc
    if _has_link_component(path):
        raise WitnessError("WITNESS_OUTPUT_DIRECTORY_INVALID")
    return path


@dataclass(frozen=True)
class WitnessAnalysis:
    """File-level witness reconciliation result."""

    complete: bool
    source_commit: str | None
    repository: str | None
    run_id: str | None
    run_attempt: str | None
    expected_witness_count: int
    received_witness_count: int
    fragment_count: int
    collected_files: tuple[str, ...]
    executed_files: tuple[str, ...]
    not_run_files: tuple[str, ...]
    findings: tuple[dict[str, Any], ...]
    errors: tuple[str, ...] = ()
    collection_witness_ids: tuple[str, ...] = ()
    execution_witness_ids: tuple[str, ...] = ()

    @property
    def outcome(self) -> str:
        if not self.complete:
            return "INCOMPLETE"
        return "BLOCKED" if self.not_run_files else "COMPLETE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": WITNESS_SCHEMA_VERSION,
            "artifact_type": WITNESS_ANALYSIS_ARTIFACT_TYPE,
            "mode": "witness",
            "complete": self.complete,
            "outcome": self.outcome,
            "runtime_execution_identity": "CERTIFIED" if self.complete else "NOT_CERTIFIED",
            "source_commit": self.source_commit,
            "repository": self.repository,
            "run_identity": {"run_id": self.run_id, "run_attempt": self.run_attempt},
            "expected_witness_count": self.expected_witness_count,
            "received_witness_count": self.received_witness_count,
            "fragment_count": self.fragment_count,
            "collection_file_count": len(self.collected_files),
            "executed_file_count": len(self.executed_files),
            "not_run_file_count": len(self.not_run_files),
            "collected_files": list(self.collected_files),
            "executed_files": list(self.executed_files),
            "not_run_files": list(self.not_run_files),
            "collection_witness_ids": list(self.collection_witness_ids),
            "execution_witness_ids": list(self.execution_witness_ids),
            "errors": list(self.errors),
            "findings": list(self.findings),
        }


def _empty_analysis(errors: Iterable[str], manifest: Mapping[str, Any] | None = None) -> WitnessAnalysis:
    identity = manifest.get("repository_identity", {}) if manifest else {}
    run = manifest.get("run_identity", {}) if manifest else {}
    source = identity.get("git_sha") if isinstance(identity, Mapping) else None
    repository = identity.get("repository") if isinstance(identity, Mapping) else None
    return WitnessAnalysis(
        complete=False,
        source_commit=source if isinstance(source, str) else None,
        repository=repository if isinstance(repository, str) else None,
        run_id=run.get("run_id") if isinstance(run, Mapping) else None,
        run_attempt=run.get("run_attempt") if isinstance(run, Mapping) else None,
        expected_witness_count=len(manifest.get("required_witness_ids", ())) if manifest else 0,
        received_witness_count=0,
        fragment_count=0,
        collected_files=(),
        executed_files=(),
        not_run_files=(),
        findings=(),
        errors=tuple(dict.fromkeys(errors)),
    )


def analyze_witnesses(
    manifest_path: Path,
    collection_paths: Sequence[Path],
    execution_paths: Sequence[Path],
) -> WitnessAnalysis:
    """Validate all supplied artifacts, then reconcile file-level identities."""

    try:
        manifest = load_manifest(manifest_path)
    except WitnessError as exc:
        return _empty_analysis((exc.code,))

    errors: list[str] = []
    fragments: list[tuple[str, dict[str, Any]]] = []
    total_bytes = 0
    seen_sessions: dict[tuple[str, str], dict[str, Any]] = {}
    expected_collection = set(manifest["collection"]["expected_witness_ids"])
    expected_execution = set(manifest["execution"]["expected_witness_ids"])
    source = manifest["repository_identity"]["git_sha"]
    tree = manifest["repository_identity"]["git_tree"]
    repository = manifest["repository_identity"]["repository"]
    fingerprint = manifest["source_identity"]["fingerprint"]
    run_id = manifest["run_identity"]["run_id"]
    run_attempt = manifest["run_identity"]["run_attempt"]
    input_groups = (("collection", collection_paths), ("execution", execution_paths))
    if len(collection_paths) + len(execution_paths) > MAX_RUNTIME_WITNESS_FRAGMENTS:
        errors.append("WITNESS_FRAGMENT_SET_LIMIT_EXCEEDED")

    for group, paths in input_groups:
        for index, path in enumerate(paths):
            try:
                size = path.stat().st_size
            except (OSError, ValueError):
                errors.append(f"{group.upper()}_{index + 1}_WITNESS_MISSING")
                continue
            total_bytes += max(size, 0)
            if total_bytes > MAX_RUNTIME_AGGREGATE_BYTES:
                errors.append("WITNESS_TOTAL_SIZE_LIMIT_EXCEEDED")
                break
            try:
                payload = load_witness(path)
            except WitnessError as exc:
                errors.append(f"{group.upper()}_{index + 1}_{exc.code}")
                continue
            identity = payload["repository_identity"]
            source_identity = payload["source_identity"]
            context = payload["execution_context"]
            if identity["git_sha"] != source:
                errors.append("SOURCE_COMMIT_MISMATCH")
            if tree is not None and identity["git_tree"] != tree:
                errors.append("SOURCE_TREE_MISMATCH")
            if repository != identity["repository"]:
                errors.append("REPOSITORY_MISMATCH")
            if source_identity["initial_fingerprint"] != fingerprint:
                errors.append("SOURCE_IDENTITY_MISMATCH")
                # Preserve the v1 diagnostic used by the retained legacy
                # analysis while making the source-bound cause explicit.
                errors.append("WORKSPACE_FINGERPRINT_MISMATCH")
            if (
                not source_identity["stable"]
                or source_identity["initial_fingerprint"] != source_identity["final_fingerprint"]
            ):
                errors.append("SOURCE_IDENTITY_UNSTABLE")
            if context["run_id"] != run_id or context["run_attempt"] != run_attempt:
                errors.append("RUN_IDENTITY_MISMATCH")
            key = witness_id(payload)
            expected = expected_collection if group == "collection" else expected_execution
            if key not in expected:
                errors.append("UNEXPECTED_WITNESS_ID")
            if payload["role"] not in {group, "both"}:
                errors.append("WITNESS_ROLE_MISMATCH")
            session_key = (group, payload["pytest"]["session_id"])
            prior = seen_sessions.get(session_key)
            if prior is not None:
                if not _same_json(prior, payload):
                    errors.append("CONFLICTING_DUPLICATE_FRAGMENT")
                continue
            seen_sessions[session_key] = payload
            fragments.append((group, payload))

    collection_fragments = [
        payload
        for group, payload in fragments
        if group == "collection"
        and payload["complete"]
        and payload["collection"]["complete"]
        and not payload["diagnostics"]
        and payload["session"]["finalized"]
    ]
    execution_fragments = [
        payload
        for group, payload in fragments
        if group == "execution"
        and payload["complete"]
        and not payload["diagnostics"]
        and payload["session"]["finalized"]
    ]
    for group, payload in fragments:
        if not payload["complete"] or payload["diagnostics"] or not payload["session"]["finalized"]:
            errors.append("WITNESS_INCOMPLETE")
        if group == "collection" and not payload["collection"]["complete"]:
            errors.append("COLLECTION_INCOMPLETE")

    collection_ids = {witness_id(payload) for payload in collection_fragments}
    execution_ids = {witness_id(payload) for payload in execution_fragments}
    if expected_collection - collection_ids:
        errors.append("EXPECTED_COLLECTION_WITNESS_MISSING")
    if expected_execution - execution_ids:
        errors.append("EXPECTED_EXECUTION_WITNESS_MISSING")

    collected = sorted(
        {
            path
            for payload in collection_fragments
            for path in payload["collection"]["collected_files"]
        }
    )
    executed = sorted(
        {
            path
            for payload in execution_fragments
            for path in payload["execution"]["call_executed_files"]
        }
    )
    complete = not errors
    not_run = sorted(set(collected) - set(executed)) if complete else []
    findings = tuple(
        {
            "rule_id": WITNESS_RULE_ID,
            "state": "NOT_RUN",
            "file": path,
            "blocking": True,
            "reason": (
                "collected test file was not observed in the complete declared CI witness set for this run"
            ),
            "evidence": {
                "collection_witness_ids": sorted(collection_ids),
                "execution_witness_ids": sorted(execution_ids),
                "claim_scope": "declared witness set for this run",
            },
        }
        for path in not_run
    )
    return WitnessAnalysis(
        complete=complete,
        source_commit=source,
        repository=repository,
        run_id=run_id,
        run_attempt=run_attempt,
        expected_witness_count=len(manifest["required_witness_ids"]),
        received_witness_count=len(collection_ids | execution_ids),
        fragment_count=len(fragments),
        collected_files=tuple(collected),
        executed_files=tuple(executed),
        not_run_files=tuple(not_run),
        findings=findings,
        errors=tuple(dict.fromkeys(errors)),
        collection_witness_ids=tuple(sorted(collection_ids)),
        execution_witness_ids=tuple(sorted(execution_ids)),
    )


def witness_sarif(analysis: WitnessAnalysis) -> dict[str, Any]:
    """Render stable witness findings as SARIF without exposing target output."""

    results = []
    if analysis.complete:
        results = [
            {
                "ruleId": WITNESS_RULE_ID,
                "level": "error",
                "message": {"text": finding["reason"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["file"]}}}],
                "properties": {"claimScope": "declared witness set for this run"},
            }
            for finding in analysis.findings
        ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GreenGap Runtime Witness",
                        "version": __version__,
                        "rules": [
                            {
                                "id": WITNESS_RULE_ID,
                                "shortDescription": {"text": "Collected test file not observed in declared CI witnesses"},
                            }
                        ],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": analysis.complete,
                        "properties": {"analysisComplete": analysis.complete, "mode": "witness"},
                    }
                ],
                "properties": {
                    "greengapWitnessVersion": WITNESS_SCHEMA_VERSION,
                    "analysisComplete": analysis.complete,
                    "outcome": analysis.outcome,
                },
            }
        ],
    }


def _git_value(root: Path, expression: str) -> str | None:
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
    if completed.returncode != 0 or _SHA1_RE.fullmatch(value) is None:
        return None
    return value.lower()


def git_repository_identity(root: Path) -> tuple[str | None, str | None]:
    """Return exact HEAD and tree identities without executing target code."""

    return _git_value(root, "HEAD"), _git_value(root, "HEAD^{tree}")


def create_manifest(
    collection_witness: Mapping[str, Any],
    *,
    execution_witness_ids: Sequence[str],
) -> dict[str, Any]:
    """Create a manifest bound to a validated collection fragment."""

    payload = _validate_witness_payload(collection_witness)
    if not payload["complete"] or not payload["collection"]["complete"]:
        raise WitnessError("COLLECTION_INCOMPLETE")
    identity = payload["repository_identity"]
    context = payload["execution_context"]
    collection_id = witness_id(payload)
    execution_ids = sorted({_normalize_witness_id(item) for item in execution_witness_ids})
    if not execution_ids:
        raise WitnessError("MANIFEST_EXECUTION_SET_MISSING")
    required = sorted({collection_id, *execution_ids})
    manifest = {
        "schema_version": 1,
        "manifest_version": 1,
        "artifact_type": WITNESS_MANIFEST_ARTIFACT_TYPE,
        "repository_identity": identity,
        "source_identity": {"fingerprint": payload["source_identity"]["initial_fingerprint"]},
        "workspace_identity": {"fingerprint": payload["workspace_identity"]["initial_fingerprint"]},
        "run_identity": {
            "run_id": context["run_id"],
            "run_attempt": context["run_attempt"],
        },
        "collection": {"expected_witness_ids": [collection_id]},
        "execution": {"expected_witness_ids": execution_ids},
        "required_witness_ids": required,
    }
    return _validate_manifest_payload(manifest)


@dataclass(frozen=True)
class CommandRun:
    returncode: int
    output_dir: Path
    fragment_names: tuple[str, ...]
    error: str | None = None


def _is_tox_command(command: Sequence[str]) -> bool:
    lowered = [Path(token).name.casefold() for token in command]
    if _tox_executable_index(command) is not None:
        return True
    for index, token in enumerate(lowered):
        if (
            token in {"python", "python.exe", "py", "py.exe"}
            and index + 2 < len(lowered)
            and lowered[index + 1] == "-m"
            and lowered[index + 2] == "tox"
        ):
            return True
    return False


def _tox_executable_index(command: Sequence[str]) -> int | None:
    for index, token in enumerate(command):
        if Path(token).name.casefold() not in {"tox", "tox.exe"}:
            continue
        if index > 0 and command[index - 1] in {"--with", "--with-editable", "--from"}:
            continue
        return index
    return None


def _tox_instrumented_command(command: Sequence[str]) -> list[str]:
    actual = list(command)
    tox_index = _tox_executable_index(actual)
    if tox_index is not None:
        insertion_index = tox_index + 1
    else:
        lowered = [Path(token).name.casefold() for token in actual]
        insertion_index = None
        for index, token in enumerate(lowered):
            if (
                token in {"python", "python.exe", "py", "py.exe"}
                and index + 2 < len(lowered)
                and lowered[index + 1] == "-m"
                and lowered[index + 2] == "tox"
            ):
                insertion_index = index + 3
                break
    if insertion_index is None:
        return actual
    pass_env = (
        "PYTHONPATH,PYTEST_ADDOPTS,GREENGAP_FULL_COLLECTION,GREENGAP_MATRIX_ID,"
        "GREENGAP_REPOSITORY,GREENGAP_RUN_ATTEMPT,GREENGAP_RUN_ID,GREENGAP_SHARD,"
        "GREENGAP_SOURCE_COMMIT,GREENGAP_SOURCE_FINGERPRINT,GREENGAP_WITNESS_DIR,"
        "GREENGAP_WITNESS_ID,GREENGAP_WITNESS_ROLE,GITHUB_ACTIONS,GITHUB_EVENT_NAME,"
        "GITHUB_JOB,GITHUB_REF,GITHUB_REPOSITORY,GITHUB_RUN_ATTEMPT,GITHUB_RUN_ID,GITHUB_SHA"
    )
    override = f"testenv.pass_env={pass_env}"
    if override in actual:
        return actual
    # Tox 4's bounded configuration override is inserted before the command
    # subparser. Unsupported tox versions fail closed through the missing
    # fragment path instead of inheriting ambient instrumentation.
    actual[insertion_index:insertion_index] = [
        "-x",
        override,
    ]
    return actual


def _normalized_returncode(value: Any) -> tuple[int, str | None]:
    try:
        raw = int(value)
    except (TypeError, ValueError):
        return 127, "COMMAND_EXITSTATUS_INVALID"
    if -1 <= raw <= 255:
        return raw, None
    # Windows exposes a signed process exit code as an unsigned DWORD.
    if 2**31 <= raw <= 2**32 - 1:
        signed = raw - 2**32
        if -1 <= signed <= 255:
            return signed, None
    return 127, "COMMAND_EXITSTATUS_INVALID"


def _append_pytest_options(existing: str | None, options: Sequence[str]) -> str:
    current = (existing or "").strip()
    injection = " ".join(options)
    return f"{current} {injection}".strip()


def _safe_snapshot(root: Path) -> Any | None:
    try:
        return workspace_snapshot(root, timeout=10.0)
    except (OSError, TypeError, ValueError):
        return None


def _safe_source_snapshot(root: Path) -> Any | None:
    try:
        return source_snapshot(root, timeout=10.0)
    except (OSError, TypeError, ValueError):
        return None


def _safe_context_id(value: Any) -> str | None:
    return value if isinstance(value, str) and _SAFE_ID_RE.fullmatch(value) is not None else None


def _fallback_payload(
    root: Path,
    *,
    role: str,
    source: str,
    tree: str | None,
    repository: str | None,
    surface_id: str,
    run_id: str,
    run_attempt: str,
    exitstatus: int,
    initial_snapshot: Any | None,
    initial_source_snapshot: Any | None,
    diagnostic: str,
) -> dict[str, Any]:
    final_snapshot = _safe_snapshot(root)
    final_source_snapshot = _safe_source_snapshot(root)
    initial_fingerprint = (
        initial_snapshot.fingerprint
        if initial_snapshot is not None and _SHA256_RE.fullmatch(initial_snapshot.fingerprint)
        else "0" * 64
    )
    final_fingerprint = (
        final_snapshot.fingerprint
        if final_snapshot is not None and _SHA256_RE.fullmatch(final_snapshot.fingerprint)
        else "0" * 64
    )
    snapshots_complete = (
        initial_snapshot is not None
        and final_snapshot is not None
        and initial_snapshot.complete
        and final_snapshot.complete
    )
    stable = snapshots_complete and initial_fingerprint == final_fingerprint
    source_initial_fingerprint = (
        initial_source_snapshot.fingerprint
        if initial_source_snapshot is not None
        and _SHA256_RE.fullmatch(initial_source_snapshot.fingerprint)
        else "0" * 64
    )
    source_final_fingerprint = (
        final_source_snapshot.fingerprint
        if final_source_snapshot is not None
        and _SHA256_RE.fullmatch(final_source_snapshot.fingerprint)
        else "0" * 64
    )
    source_snapshots_complete = (
        initial_source_snapshot is not None
        and final_source_snapshot is not None
        and initial_source_snapshot.complete
        and final_source_snapshot.complete
    )
    source_stable = (
        source_snapshots_complete
        and source_initial_fingerprint == source_final_fingerprint
    )
    diagnostics = ["WITNESS_PROCESS_INCOMPLETE", diagnostic]
    if not source_snapshots_complete:
        diagnostics.append("SOURCE_IDENTITY_INCOMPLETE")
    if not source_stable:
        diagnostics.append("SOURCE_IDENTITY_UNSTABLE")
    provider = "github_actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "local"
    worker_id = _safe_context_id(os.environ.get("PYTEST_XDIST_WORKER"))
    shard = _safe_context_id(os.environ.get("GREENGAP_SHARD")) or worker_id
    status = exitstatus if -1 <= exitstatus <= 255 else -1
    return {
        "schema_version": WITNESS_SCHEMA_VERSION,
        "witness_version": WITNESS_SCHEMA_VERSION,
        "artifact_type": WITNESS_ARTIFACT_TYPE,
        "kind": "pytest_runtime",
        "role": role,
        "greengap_version": __version__,
        "repository_identity": {"git_sha": source, "git_tree": tree, "repository": repository},
        "source_identity": {
            "initial_fingerprint": source_initial_fingerprint,
            "final_fingerprint": source_final_fingerprint,
            "stable": source_stable,
        },
        "runtime_workspace_state": {
            "initial_fingerprint": initial_fingerprint,
            "final_fingerprint": final_fingerprint,
            "stable": stable,
        },
        "workspace_identity": {
            "initial_fingerprint": initial_fingerprint,
            "final_fingerprint": final_fingerprint,
            "stable": stable,
        },
        "pytest": {"version": "unknown", "rootpath": ".", "session_id": uuid.uuid4().hex},
        "execution_context": {
            "provider": provider,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "job": _safe_context_id(os.environ.get("GITHUB_JOB")) or surface_id,
            "matrix_identity": _safe_context_id(os.environ.get("GREENGAP_MATRIX_ID")),
            "event": _safe_context_id(os.environ.get("GITHUB_EVENT_NAME")),
            "ref": _safe_context_id(os.environ.get("GITHUB_REF")),
            "surface_id": surface_id,
            "shard": shard,
            "worker_id": worker_id,
            "pid": os.getpid(),
        },
        "collection": {"complete": False, "collected_files": []},
        "execution": {
            "attempted_files": [],
            "call_executed_files": [],
            "completed_files": [],
            "call_outcomes": [],
        },
        "session": {"pytest_exitstatus": status, "finalized": True},
        "complete": False,
        "diagnostics": sorted(set(diagnostics))[:64],
    }


def _write_incomplete_fragment(destination: Path, payload: Mapping[str, Any]) -> str | None:
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > MAX_RUNTIME_WITNESS_BYTES:
        return None
    final = destination / f"greengap-{uuid.uuid4().hex}-{os.getpid()}-wrapper.json"
    try:
        if _has_link_component(destination) or not destination.is_dir():
            return None
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=destination, prefix=f".{final.name}.", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if final.exists():
            temporary.unlink(missing_ok=True)
            return None
        temporary.replace(final)
        try:
            directory_fd = os.open(str(destination), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
        return final.name
    except OSError:
        return None


def _fragment_names(destination: Path) -> tuple[str, ...]:
    try:
        return tuple(
            sorted(
                path.name
                for path in destination.glob("greengap-*.json")
                if path.is_file() and not path.is_symlink()
            )
        )
    except OSError:
        return ()


def _output_directory(value: str | None) -> Path:
    if value:
        path = resolve_witness_output_path(value)
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise WitnessError("WITNESS_OUTPUT_DIRECTORY_INVALID") from exc
        if _has_link_component(path) or not path.is_dir():
            raise WitnessError("WITNESS_OUTPUT_DIRECTORY_INVALID")
        return path
    return Path(tempfile.mkdtemp(prefix="greengap-witness-"))


def execute_witness_command(
    root: Path,
    command: Sequence[str],
    *,
    role: str,
    output_dir: str | None = None,
    source_commit: str | None = None,
    repository: str | None = None,
    surface_id: str | None = None,
    run_id: str | None = None,
    run_attempt: str = "1",
    collect_only: bool = False,
    timeout: float = 300.0,
) -> CommandRun:
    """Run the caller's real command with explicit witness activation."""

    if role not in {"collection", "execution", "both"}:
        return CommandRun(2, Path(output_dir or "."), (), "WITNESS_ROLE_INVALID")
    if not command:
        return CommandRun(2, Path(output_dir or "."), (), "COMMAND_MISSING")
    if timeout <= 0:
        return CommandRun(2, Path(output_dir or "."), (), "COMMAND_TIMEOUT_INVALID")
    root = root.resolve()
    if not root.is_dir():
        return CommandRun(2, root, (), "REPOSITORY_NOT_DIRECTORY")
    actual_source, actual_tree = git_repository_identity(root)
    selected_source = (
        source_commit.lower()
        if isinstance(source_commit, str)
        else actual_source or ""
    )
    if _SHA1_RE.fullmatch(selected_source) is None:
        return CommandRun(2, root, (), "SOURCE_CHECKOUT_UNKNOWN")
    if actual_source is None or actual_source != selected_source:
        return CommandRun(2, root, (), "SOURCE_CHECKOUT_MISMATCH")
    try:
        destination = _output_directory(output_dir)
    except WitnessError as exc:
        return CommandRun(2, root, (), exc.code)
    selected_surface = surface_id or ("collection" if role == "collection" else "execution")
    selected_run_id = run_id or f"local-{uuid.uuid4().hex}"
    if (
        not isinstance(selected_surface, str)
        or _SAFE_ID_RE.fullmatch(selected_surface) is None
        or not isinstance(selected_run_id, str)
        or _SAFE_ID_RE.fullmatch(selected_run_id) is None
        or not isinstance(run_attempt, str)
        or _SAFE_ID_RE.fullmatch(run_attempt) is None
    ):
        return CommandRun(2, destination, (), "RUN_IDENTITY_INVALID")
    selected_repository = None
    if repository is not None:
        if not isinstance(repository, str) or _SAFE_ID_RE.fullmatch(repository) is None:
            return CommandRun(2, destination, (), "REPOSITORY_IDENTITY_INVALID")
        selected_repository = repository
    initial_snapshot = _safe_snapshot(root)
    initial_source_snapshot = _safe_source_snapshot(root)
    before_names = set(_fragment_names(destination))
    env = os.environ.copy()
    source_root = str(Path(__file__).resolve().parent.parent)
    prior_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = source_root + (os.pathsep + prior_pythonpath if prior_pythonpath else "")
    env["GREENGAP_WITNESS_DIR"] = str(destination)
    env["GREENGAP_WITNESS_ROLE"] = role
    env["GREENGAP_SOURCE_COMMIT"] = selected_source
    if initial_source_snapshot is not None and _SHA256_RE.fullmatch(initial_source_snapshot.fingerprint):
        env["GREENGAP_SOURCE_FINGERPRINT"] = initial_source_snapshot.fingerprint
    env["GREENGAP_RUN_ID"] = selected_run_id
    env["GREENGAP_RUN_ATTEMPT"] = run_attempt
    env["GREENGAP_WITNESS_ID"] = selected_surface
    if selected_repository is not None:
        env["GREENGAP_REPOSITORY"] = selected_repository
    if role == "collection":
        env["GREENGAP_FULL_COLLECTION"] = "1"
    options = ["-p", WITNESS_PLUGIN_MODULE]
    if collect_only:
        options.append("--collect-only")
    env["PYTEST_ADDOPTS"] = _append_pytest_options(env.get("PYTEST_ADDOPTS"), options)
    actual_command = _tox_instrumented_command(command) if _is_tox_command(command) else list(command)
    try:
        completed = run_process_tree(
            actual_command,
            cwd=root,
            env=env,
            timeout=timeout,
            capture_output=False,
        )
        returncode, error = _normalized_returncode(completed.returncode)
    except subprocess.TimeoutExpired:
        returncode = 124
        error = "COMMAND_TIMEOUT"
    except (OSError, ValueError):
        returncode = 127
        error = "COMMAND_START_FAILED"
    names = tuple(name for name in _fragment_names(destination) if name not in before_names)
    if not names:
        error = error or "WITNESS_MISSING"
        fallback = _fallback_payload(
            root,
            role=role,
            source=selected_source,
            tree=actual_tree,
            repository=selected_repository,
            surface_id=selected_surface,
            run_id=selected_run_id,
            run_attempt=run_attempt,
            exitstatus=returncode,
            initial_snapshot=initial_snapshot,
            initial_source_snapshot=initial_source_snapshot,
            diagnostic=error,
        )
        fallback_name = _write_incomplete_fragment(destination, fallback)
        names = (fallback_name,) if fallback_name is not None else ()
    return CommandRun(returncode, destination, names, error)
