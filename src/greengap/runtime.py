"""Validation and aggregation for the native pytest runtime witness.

The runtime witness is deliberately a small JSON-only boundary.  It is
produced by :mod:`greengap._runtime_plugin` inside a caller-consented pytest
process and is consumed here without importing anything from the target
repository.  A witness is evidence of what one test process observed; it is
not a replacement for source or workflow identity.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .model import FindingState
from .util import MAX_RUNTIME_WITNESS_BYTES, MAX_RUNTIME_WITNESS_NODES, read_limited_bytes

RUNTIME_WITNESS_SCHEMA_VERSION = 1
RUNTIME_WITNESS_ARTIFACT_TYPE = "greengap_pytest_runtime_witness"
RUNTIME_WITNESS_AGGREGATE_TYPE = "greengap_pytest_runtime_aggregate"
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,4096}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,256}$")
_PHASES = frozenset({"setup", "call", "teardown"})
_OUTCOMES = frozenset({"passed", "failed", "skipped"})


class RuntimeWitnessError(ValueError):
    """A witness or denominator cannot support a complete conclusion."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RuntimeFinding:
    """One node-level runtime finding."""

    nodeid: str
    path: str
    state: FindingState
    blocking: bool
    reason: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodeid": self.nodeid,
            "path": self.path,
            "state": self.state.value,
            "blocking": self.blocking,
            "reason": self.reason,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class RuntimeAggregate:
    """Conservative result for a set of job/shard witnesses."""

    complete: bool
    source_commit: str | None
    denominator_count: int
    witness_count: int
    executed_count: int
    findings: tuple[RuntimeFinding, ...]
    errors: tuple[str, ...] = ()
    duplicate_node_observations: tuple[str, ...] = ()
    witness_identities: tuple[str, ...] = ()

    @property
    def blockers(self) -> tuple[RuntimeFinding, ...]:
        return tuple(finding for finding in self.findings if finding.blocking)

    def to_dict(self) -> dict[str, Any]:
        if not self.complete:
            outcome = "INCOMPLETE"
        elif self.blockers:
            outcome = "BLOCKED"
        else:
            outcome = "COMPLETE"
        return {
            "schema_version": RUNTIME_WITNESS_SCHEMA_VERSION,
            "artifact_type": RUNTIME_WITNESS_AGGREGATE_TYPE,
            "mode": "witness",
            "complete": self.complete,
            "outcome": outcome,
            "tool": {
                "name": "greengap",
                "version": __version__,
                "runtime_proof": self.complete,
            },
            "runtime_execution_identity": "CERTIFIED" if self.complete else "NOT_CERTIFIED",
            "source_commit": self.source_commit,
            "denominator": {"node_count": self.denominator_count},
            "witnesses": {
                "count": self.witness_count,
                "identities": list(self.witness_identities),
                "union_executed_node_count": self.executed_count,
                "duplicate_node_observations": list(self.duplicate_node_observations),
            },
            "errors": list(self.errors),
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _read_json(path: Path) -> Any:
    try:
        data = read_limited_bytes(path, MAX_RUNTIME_WITNESS_BYTES)
        return json.loads(data.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError, MemoryError) as exc:
        raise RuntimeWitnessError("WITNESS_MALFORMED") from exc


def _string(value: Any, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value or not _SAFE_TEXT_RE.fullmatch(value):
        raise RuntimeWitnessError("WITNESS_FIELD_INVALID")
    if identifier and not _SAFE_ID_RE.fullmatch(value):
        raise RuntimeWitnessError("WITNESS_IDENTITY_INVALID")
    return value


def _optional_string(value: Any, *, identifier: bool = False) -> str | None:
    if value is None:
        return None
    return _string(value, identifier=identifier)


def _relative_path(value: Any, *, allow_dot: bool = False) -> str:
    raw = _string(value)
    normalized = posixpath.normpath(raw.replace("\\", "/"))
    if normalized == ".":
        if allow_dot:
            return normalized
        raise RuntimeWitnessError("WITNESS_PATH_INVALID")
    if (
        normalized.startswith("/")
        or re.match(r"^[A-Za-z]:/", normalized) is not None
        or normalized == ".."
        or normalized.startswith("../")
    ):
        raise RuntimeWitnessError("WITNESS_PATH_INVALID")
    return normalized


def _nodeid(value: Any) -> str:
    raw = _string(value)
    if "::" not in raw:
        raise RuntimeWitnessError("WITNESS_NODEID_INVALID")
    path = _relative_path(raw.split("::", 1)[0])
    if raw.split("::", 1)[0].replace("\\", "/") != path:
        raise RuntimeWitnessError("WITNESS_NODEID_INVALID")
    return raw


def _sha(value: Any) -> str:
    if not isinstance(value, str) or _SHA1_RE.fullmatch(value) is None:
        raise RuntimeWitnessError("SOURCE_COMMIT_INVALID")
    return value.lower()


def _fingerprint(value: Any) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise RuntimeWitnessError("WORKSPACE_FINGERPRINT_INVALID")
    return value.lower()


def _validate_node_record(record: Any) -> tuple[str, str]:
    if not isinstance(record, dict) or set(record) != {"nodeid", "path"}:
        raise RuntimeWitnessError("WITNESS_COLLECTION_RECORD_INVALID")
    nodeid = _nodeid(record["nodeid"])
    path = _relative_path(record["path"])
    if nodeid.split("::", 1)[0].replace("\\", "/") != path:
        raise RuntimeWitnessError("WITNESS_NODE_PATH_CONFLICT")
    return nodeid, path


def _validate_report(record: Any) -> dict[str, str]:
    if not isinstance(record, dict) or set(record) != {"when", "outcome"}:
        raise RuntimeWitnessError("WITNESS_REPORT_INVALID")
    when = _string(record["when"])
    outcome = _string(record["outcome"])
    if when not in _PHASES or outcome not in _OUTCOMES:
        raise RuntimeWitnessError("WITNESS_REPORT_INVALID")
    return {"when": when, "outcome": outcome}


def _validate_executed_record(record: Any) -> tuple[str, str, dict[str, Any]]:
    if not isinstance(record, dict) or set(record) != {
        "nodeid",
        "path",
        "started",
        "finished",
        "reports",
    }:
        raise RuntimeWitnessError("WITNESS_EXECUTION_RECORD_INVALID")
    nodeid = _nodeid(record["nodeid"])
    path = _relative_path(record["path"])
    if nodeid.split("::", 1)[0].replace("\\", "/") != path:
        raise RuntimeWitnessError("WITNESS_NODE_PATH_CONFLICT")
    if not isinstance(record["started"], bool) or not isinstance(record["finished"], bool):
        raise RuntimeWitnessError("WITNESS_EXECUTION_RECORD_INVALID")
    reports = record["reports"]
    if not isinstance(reports, list) or len(reports) > 6:
        raise RuntimeWitnessError("WITNESS_REPORT_INVALID")
    normalized_reports = [_validate_report(item) for item in reports]
    return nodeid, path, {
        "nodeid": nodeid,
        "path": path,
        "started": record["started"],
        "finished": record["finished"],
        "reports": normalized_reports,
    }


def _validate_github(value: Any) -> dict[str, str | None]:
    keys = {"run_id", "run_attempt", "job", "matrix", "shard", "repository"}
    if not isinstance(value, dict) or set(value) != keys:
        raise RuntimeWitnessError("WITNESS_RUN_IDENTITY_INVALID")
    result: dict[str, str | None] = {}
    for key in keys:
        result[key] = _optional_string(value[key], identifier=True)
    for key in ("run_id", "run_attempt"):
        if result[key] is not None and not result[key].isdigit():
            raise RuntimeWitnessError("WITNESS_RUN_IDENTITY_INVALID")
    return result


def _identity(github: Mapping[str, str | None]) -> str:
    return "|".join(github.get(key) or "-" for key in ("run_id", "run_attempt", "job", "matrix", "shard"))


def _expected_identity(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 128:
        raise RuntimeWitnessError("EXPECTED_WITNESS_SET_INVALID")
    parts = value.split("|")
    if len(parts) != 5 or any(part != "-" and _SAFE_ID_RE.fullmatch(part) is None for part in parts):
        raise RuntimeWitnessError("EXPECTED_WITNESS_SET_INVALID")
    if parts[0] == "-" or parts[1] == "-" or parts[2] == "-":
        raise RuntimeWitnessError("EXPECTED_WITNESS_SET_INVALID")
    if not parts[0].isdigit() or not parts[1].isdigit():
        raise RuntimeWitnessError("EXPECTED_WITNESS_SET_INVALID")
    return value


def _validate_witness_payload(payload: Any) -> dict[str, Any]:
    required = {
        "schema_version",
        "artifact_type",
        "greengap_version",
        "source_commit",
        "repository",
        "workspace_fingerprint",
        "workspace_fingerprint_final",
        "workspace_stable",
        "pytest_root",
        "github",
        "collection",
        "executed",
        "session",
        "complete",
        "errors",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise RuntimeWitnessError("WITNESS_SCHEMA_INVALID")
    if payload["schema_version"] != RUNTIME_WITNESS_SCHEMA_VERSION:
        raise RuntimeWitnessError("WITNESS_SCHEMA_UNSUPPORTED")
    if payload["artifact_type"] != RUNTIME_WITNESS_ARTIFACT_TYPE:
        raise RuntimeWitnessError("WITNESS_ARTIFACT_TYPE_INVALID")
    _string(payload["greengap_version"])
    source_commit = _optional_string(payload["source_commit"], identifier=True)
    if source_commit is not None:
        source_commit = _sha(source_commit)
    repository = _optional_string(payload["repository"], identifier=True)
    start_fingerprint = _fingerprint(payload["workspace_fingerprint"])
    final_fingerprint = _fingerprint(payload["workspace_fingerprint_final"])
    if not isinstance(payload["workspace_stable"], bool):
        raise RuntimeWitnessError("WITNESS_WORKSPACE_STATE_INVALID")
    pytest_root = _relative_path(payload["pytest_root"], allow_dot=True)
    github = _validate_github(payload["github"])
    if repository != github["repository"]:
        raise RuntimeWitnessError("WITNESS_REPOSITORY_CONFLICT")

    collection = payload["collection"]
    if not isinstance(collection, list) or len(collection) > MAX_RUNTIME_WITNESS_NODES:
        raise RuntimeWitnessError("WITNESS_COLLECTION_INVALID")
    collection_map: dict[str, str] = {}
    for record in collection:
        nodeid, path = _validate_node_record(record)
        if nodeid in collection_map:
            raise RuntimeWitnessError("WITNESS_DUPLICATE_NODE")
        collection_map[nodeid] = path

    executed = payload["executed"]
    if not isinstance(executed, list) or len(executed) > MAX_RUNTIME_WITNESS_NODES:
        raise RuntimeWitnessError("WITNESS_EXECUTION_INVALID")
    executed_map: dict[str, dict[str, Any]] = {}
    for record in executed:
        nodeid, path, normalized = _validate_executed_record(record)
        if nodeid in executed_map:
            raise RuntimeWitnessError("WITNESS_DUPLICATE_NODE")
        if nodeid not in collection_map or collection_map[nodeid] != path:
            raise RuntimeWitnessError("WITNESS_EXECUTION_NOT_COLLECTED")
        executed_map[nodeid] = normalized

    session = payload["session"]
    if not isinstance(session, dict) or set(session) != {
        "exit_status",
        "collection_complete",
        "session_complete",
    }:
        raise RuntimeWitnessError("WITNESS_SESSION_INVALID")
    if (
        not isinstance(session["exit_status"], int)
        or isinstance(session["exit_status"], bool)
        or not isinstance(session["collection_complete"], bool)
        or not isinstance(session["session_complete"], bool)
    ):
        raise RuntimeWitnessError("WITNESS_SESSION_INVALID")
    errors = payload["errors"]
    if not isinstance(errors, list) or len(errors) > 64 or not all(
        isinstance(item, str) and _SAFE_ID_RE.fullmatch(item) for item in errors
    ):
        raise RuntimeWitnessError("WITNESS_ERRORS_INVALID")
    if not isinstance(payload["complete"], bool):
        raise RuntimeWitnessError("WITNESS_COMPLETENESS_INVALID")

    normalized = dict(payload)
    normalized.update(
        {
            "source_commit": source_commit,
            "repository": repository,
            "workspace_fingerprint": start_fingerprint,
            "workspace_fingerprint_final": final_fingerprint,
            "pytest_root": pytest_root,
            "github": github,
            "collection": [
                {"nodeid": nodeid, "path": path}
                for nodeid, path in sorted(collection_map.items())
            ],
            "executed": [executed_map[nodeid] for nodeid in sorted(executed_map)],
            "errors": list(errors),
        }
    )
    return normalized


def load_runtime_witness(path: Path) -> dict[str, Any]:
    """Read and validate one JSON witness without executing repository code."""

    return _validate_witness_payload(_read_json(path))


def parse_runtime_witness(path: Path) -> dict[str, Any]:
    """Compatibility alias for callers that use parser terminology."""

    return load_runtime_witness(path)


def _load_denominator(path: Path) -> tuple[dict[str, str], ...]:
    payload = _read_json(path)
    source: Any = payload
    if isinstance(payload, dict):
        if payload.get("mode") in {"scan", "plan"}:
            collection = payload.get("collection")
            if not isinstance(collection, dict) or collection.get("complete") is not True:
                raise RuntimeWitnessError("DENOMINATOR_INCOMPLETE")
            source = collection.get("nodes")
            if payload.get("stable") is not True:
                raise RuntimeWitnessError("DENOMINATOR_UNSTABLE")
        elif payload.get("artifact_type") == RUNTIME_WITNESS_ARTIFACT_TYPE:
            witness = _validate_witness_payload(payload)
            source = witness.get("collection")
            if witness.get("complete") is not True:
                raise RuntimeWitnessError("DENOMINATOR_INCOMPLETE")
        elif "nodes" in payload:
            source = payload["nodes"]
    if not isinstance(source, list) or len(source) > MAX_RUNTIME_WITNESS_NODES:
        raise RuntimeWitnessError("DENOMINATOR_INVALID")
    result: dict[str, str] = {}
    for record in source:
        nodeid, path_value = _validate_node_record(record)
        if nodeid in result:
            raise RuntimeWitnessError("DENOMINATOR_DUPLICATE_NODE")
        result[nodeid] = path_value
    return tuple({"nodeid": nodeid, "path": path_value} for nodeid, path_value in sorted(result.items()))


def _state_for_execution(record: Mapping[str, Any]) -> FindingState:
    reports = record.get("reports", [])
    outcomes = {item["outcome"] for item in reports if isinstance(item, dict)}
    if "failed" in outcomes:
        return FindingState.EXECUTED_FAIL
    if "skipped" in outcomes and "passed" not in outcomes:
        return FindingState.SKIPPED
    if "passed" in outcomes:
        return FindingState.EXECUTED_PASS
    return FindingState.UNKNOWN


def aggregate_runtime_witnesses(
    witness_paths: Sequence[Path],
    denominator_path: Path,
    *,
    expected_identities: Sequence[str] | None = None,
    source_commit: str | None = None,
) -> RuntimeAggregate:
    """Aggregate complete, source-bound witnesses against a full node set.

    ``expected_identities`` and ``source_commit`` are intentionally required
    for a complete result. Without a predeclared job/shard set, absence of a
    witness cannot distinguish "the job did not run" from "the job produced
    no evidence". Without an expected source commit, the denominator cannot
    be bound to the witness source.
    """

    errors: list[str] = []
    try:
        denominator = _load_denominator(denominator_path)
    except RuntimeWitnessError as exc:
        denominator = ()
        errors.append(exc.code)
    normalized_expected: tuple[str, ...] | None = None
    if expected_identities is None:
        errors.append("EXPECTED_WITNESS_SET_MISSING")
    else:
        try:
            values = tuple(_expected_identity(value) for value in expected_identities)
            if not values or len(set(values)) != len(values):
                raise RuntimeWitnessError("EXPECTED_WITNESS_SET_INVALID")
            normalized_expected = tuple(sorted(values))
        except RuntimeWitnessError as exc:
            errors.append(exc.code)

    witnesses: list[dict[str, Any]] = []
    identities: dict[str, dict[str, Any]] = {}
    for index, path in enumerate(witness_paths):
        try:
            witness = load_runtime_witness(path)
        except RuntimeWitnessError as exc:
            errors.append(f"WITNESS_{index + 1}_{exc.code}")
            continue
        identity = _identity(witness["github"])
        if identity in identities:
            errors.append("DUPLICATE_WITNESS_IDENTITY")
        else:
            identities[identity] = witness
            witnesses.append(witness)

    source_values = {
        witness["source_commit"] for witness in witnesses if witness["source_commit"] is not None
    }
    if any(witness["source_commit"] is None for witness in witnesses):
        errors.append("SOURCE_COMMIT_MISSING")
    if len(source_values) > 1:
        errors.append("SOURCE_COMMIT_INCONSISTENT")
    selected_source = None
    if source_commit is not None:
        try:
            selected_source = _sha(source_commit)
        except RuntimeWitnessError as exc:
            errors.append(exc.code)
    else:
        errors.append("SOURCE_COMMIT_EXPECTED_MISSING")
        if len(source_values) == 1:
            selected_source = next(iter(source_values))
    if selected_source is not None and any(
        witness.get("source_commit") != selected_source for witness in witnesses
    ):
        errors.append("SOURCE_COMMIT_MISMATCH")

    actual_identities = tuple(sorted(identities))
    if normalized_expected is not None and actual_identities != normalized_expected:
        errors.append("WITNESS_SET_INCOMPLETE")
    for witness in witnesses:
        github = witness["github"]
        if github["run_id"] is None or github["run_attempt"] is None or github["job"] is None:
            errors.append("RUN_IDENTITY_MISSING")
        if not witness["complete"] or witness["errors"]:
            errors.append("WITNESS_INCOMPLETE")
        if not witness["workspace_stable"]:
            errors.append("WORKSPACE_UNSTABLE")
        if witness["workspace_fingerprint"] != witness["workspace_fingerprint_final"]:
            errors.append("WORKSPACE_FINGERPRINT_CHANGED")
        session = witness["session"]
        if not session["collection_complete"] or not session["session_complete"]:
            errors.append("WITNESS_SESSION_INCOMPLETE")
        if any(
            not record["started"] or not record["finished"] or not record["reports"]
            for record in witness["executed"]
        ):
            errors.append("EXECUTION_EVIDENCE_INCOMPLETE")

    denominator_map = {record["nodeid"]: record["path"] for record in denominator}
    observed: dict[str, tuple[str, FindingState, str]] = {}
    duplicate_nodes: list[str] = []
    for witness in witnesses:
        collection_map = {record["nodeid"]: record["path"] for record in witness["collection"]}
        for nodeid, path_value in collection_map.items():
            if nodeid not in denominator_map or denominator_map[nodeid] != path_value:
                errors.append("COLLECTION_DENOMINATOR_CONFLICT")
        for record in witness["executed"]:
            nodeid = record["nodeid"]
            state = _state_for_execution(record)
            prior = observed.get(nodeid)
            if prior is None:
                observed[nodeid] = (record["path"], state, _identity(witness["github"]))
            elif prior[0] != record["path"] or prior[1] != state:
                errors.append("CONFLICTING_NODE_OBSERVATION")
            else:
                duplicate_nodes.append(nodeid)

    complete = not errors
    findings: list[RuntimeFinding] = []
    for nodeid, path_value in sorted(denominator_map.items()):
        if not complete:
            findings.append(
                RuntimeFinding(
                    nodeid,
                    path_value,
                    FindingState.UNKNOWN,
                    False,
                    "runtime witness set is incomplete; execution absence is not a claim",
                    tuple(dict.fromkeys(errors)),
                )
            )
            continue
        observed_value = observed.get(nodeid)
        if observed_value is None:
            findings.append(
                RuntimeFinding(
                    nodeid,
                    path_value,
                    FindingState.NOT_SEEN,
                    True,
                    "collected pytest node was not observed in any complete witness",
                )
            )
        else:
            findings.append(
                RuntimeFinding(
                    nodeid,
                    path_value,
                    observed_value[1],
                    False,
                    "pytest node execution was observed in a complete witness",
                    (observed_value[2],),
                )
            )
    return RuntimeAggregate(
        complete=complete,
        source_commit=selected_source,
        denominator_count=len(denominator),
        witness_count=len(witnesses),
        executed_count=len(observed),
        findings=tuple(findings),
        errors=tuple(dict.fromkeys(errors)),
        duplicate_node_observations=tuple(sorted(set(duplicate_nodes))),
        witness_identities=actual_identities,
    )


def aggregate_witnesses(
    witness_paths: Sequence[Path],
    denominator_path: Path,
    *,
    expected_identities: Sequence[str] | None = None,
    source_commit: str | None = None,
) -> RuntimeAggregate:
    """Short alias for integrations that use the generic witness name."""

    return aggregate_runtime_witnesses(
        witness_paths,
        denominator_path,
        expected_identities=expected_identities,
        source_commit=source_commit,
    )
