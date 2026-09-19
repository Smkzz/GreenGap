"""Bounded configuration for the explicit Runtime Witness contract.

The configuration is deliberately small.  It declares the collection surface
and the complete set of execution surface IDs; it does not describe commands,
shell expressions, environments, or package-manager behavior.  Those remain
the caller's responsibility.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .util import MAX_CONFIG_BYTES, MAX_RUNTIME_EXPECTED_IDENTITIES, read_limited_bytes

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,256}$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:/")
_MAX_YAML_DEPTH = 16
_MAX_YAML_NODES = 1024
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class WitnessConfigError(ValueError):
    """The explicit witness configuration cannot define a safe surface set."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _surface_id(value: Any) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise WitnessConfigError("WITNESS_CONFIG_SURFACE_ID_INVALID")
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or _DRIVE_RE.match(normalized) is not None:
        raise WitnessConfigError("WITNESS_CONFIG_SURFACE_ID_INVALID")
    if any(part == ".." for part in normalized.split("/")):
        raise WitnessConfigError("WITNESS_CONFIG_SURFACE_ID_INVALID")
    if "|" in value:
        raise WitnessConfigError("WITNESS_CONFIG_SURFACE_ID_INVALID")
    return value


def _check_yaml_limits(value: Any, *, depth: int = 0, seen: set[int] | None = None) -> None:
    if depth > _MAX_YAML_DEPTH:
        raise WitnessConfigError("WITNESS_CONFIG_DEPTH_LIMIT_EXCEEDED")
    if seen is None:
        seen = set()
    if isinstance(value, dict | list | tuple):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        if len(seen) > _MAX_YAML_NODES:
            raise WitnessConfigError("WITNESS_CONFIG_NODE_LIMIT_EXCEEDED")
        values = value.items() if isinstance(value, dict) else enumerate(value)
        for key, item in values:
            if isinstance(key, dict | list | tuple):
                raise WitnessConfigError("WITNESS_CONFIG_SCHEMA_INVALID")
            _check_yaml_limits(key, depth=depth + 1, seen=seen)
            _check_yaml_limits(item, depth=depth + 1, seen=seen)
        return
    if isinstance(value, str) and len(value.encode("utf-8")) > 4096:
        raise WitnessConfigError("WITNESS_CONFIG_VALUE_TOO_LONG")
    if value is not None and not isinstance(value, str | int | float | bool):
        raise WitnessConfigError("WITNESS_CONFIG_SCHEMA_INVALID")


@dataclass(frozen=True)
class ExplicitWitnessConfig:
    """The complete, normalized surface declaration for one repository."""

    collection_surface_id: str
    required_execution_surface_ids: tuple[str, ...]
    config_sha256: str | None = None

    @property
    def collection_witness_id(self) -> str:
        return f"{self.collection_surface_id}|-"

    @property
    def execution_witness_ids(self) -> tuple[str, ...]:
        return tuple(f"{surface_id}|-" for surface_id in self.required_execution_surface_ids)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "collection_surface_id": self.collection_surface_id,
            "required_execution_surface_ids": list(self.required_execution_surface_ids),
        }
        if self.config_sha256 is not None:
            result["config_sha256"] = self.config_sha256
        return result


def _normalize_payload(
    payload: Any,
    *,
    config_sha256: str | None = None,
) -> ExplicitWitnessConfig:
    if not isinstance(payload, dict):
        raise WitnessConfigError("WITNESS_CONFIG_SCHEMA_INVALID")
    if set(payload) not in ({"witness"}, {"version", "witness"}):
        raise WitnessConfigError("WITNESS_CONFIG_SCHEMA_INVALID")
    if "version" in payload and payload["version"] != 1:
        raise WitnessConfigError("WITNESS_CONFIG_VERSION_UNSUPPORTED")
    witness = payload.get("witness")
    if not isinstance(witness, dict) or set(witness) != {"collection", "required"}:
        raise WitnessConfigError("WITNESS_CONFIG_SCHEMA_INVALID")
    collection = _surface_id(witness["collection"])
    required = witness["required"]
    if not isinstance(required, list) or not required:
        raise WitnessConfigError("WITNESS_CONFIG_REQUIRED_SURFACES_MISSING")
    if len(required) > MAX_RUNTIME_EXPECTED_IDENTITIES:
        raise WitnessConfigError("WITNESS_CONFIG_SURFACE_LIMIT_EXCEEDED")
    execution = tuple(sorted({_surface_id(value) for value in required}))
    if len(execution) != len(required):
        raise WitnessConfigError("WITNESS_CONFIG_DUPLICATE_SURFACE")
    if collection in execution:
        raise WitnessConfigError("WITNESS_CONFIG_COLLECTION_CONFLICT")
    if config_sha256 is not None and _SHA256_RE.fullmatch(config_sha256) is None:
        raise WitnessConfigError("WITNESS_CONFIG_DIGEST_INVALID")
    return ExplicitWitnessConfig(collection, execution, config_sha256)


def load_explicit_witness_config(path: Path) -> ExplicitWitnessConfig:
    """Load only the bounded surface declaration from a YAML file."""

    try:
        raw = read_limited_bytes(path, MAX_CONFIG_BYTES)
        payload = yaml.safe_load(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, ValueError, yaml.YAMLError, RecursionError, MemoryError) as exc:
        raise WitnessConfigError("WITNESS_CONFIG_MALFORMED") from exc
    _check_yaml_limits(payload)
    return _normalize_payload(payload, config_sha256=hashlib.sha256(raw).hexdigest())


def validate_explicit_witness_config(payload: Any) -> ExplicitWitnessConfig:
    """Validate an already parsed configuration payload."""

    _check_yaml_limits(payload)
    return _normalize_payload(payload)
