"""Local, resumable release-state binding with no remote side effects."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STAGES = (
    "DISCOVER",
    "QUALIFY",
    "FREEZE",
    "REVIEW",
    "MERGE",
    "VERIFY_MAIN",
    "BUILD",
    "VERIFY_DRAFT",
    "HUMAN_AUTHORIZE",
    "PUBLISH_ONCE",
    "VERIFY_PUBLIC",
)
SCHEMA_VERSION = 1
MAX_STATE_BYTES = 1 * 1024 * 1024
_HEX = re.compile(r"^[0-9a-f]{40,64}$")
_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ReleaseBinding:
    version: str
    source_sha: str
    source_tree: str
    tag: str
    artifacts: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.version or not self.tag.startswith("v"):
            raise ValueError("version and v-prefixed tag are required")
        if not _HEX.fullmatch(self.source_sha) or not _HEX.fullmatch(self.source_tree):
            raise ValueError("source_sha and source_tree must be hexadecimal Git identities")
        normalized: list[tuple[str, str]] = []
        names: set[str] = set()
        for item in self.artifacts:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise ValueError("artifact manifest entries must be name and sha256 pairs")
            name, digest = item
            if (
                not isinstance(name, str)
                or not _ARTIFACT_NAME.fullmatch(name)
                or name in names
                or not isinstance(digest, str)
                or not _SHA256.fullmatch(digest)
            ):
                raise ValueError("artifact manifest contains an invalid or duplicate entry")
            names.add(name)
            normalized.append((name, digest))
        object.__setattr__(self, "artifacts", tuple(normalized))

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "source_sha": self.source_sha,
            "source_tree": self.source_tree,
            "tag": self.tag,
            "artifacts": [
                {"name": name, "sha256": digest} for name, digest in self.artifacts
            ],
        }


@dataclass(frozen=True)
class ReleaseState:
    stage: str
    binding: ReleaseBinding
    history: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.stage not in STAGES:
            raise ValueError(f"unknown release stage: {self.stage}")
        if self.history and self.history[-1] != self.stage:
            raise ValueError("history must end at the current stage")

    @classmethod
    def discover(cls, binding: ReleaseBinding) -> ReleaseState:
        return cls("DISCOVER", binding, ("DISCOVER",), ())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "stage": self.stage,
            "binding": self.binding.to_dict(),
            "history": list(self.history),
            "evidence": list(self.evidence),
        }


def advance(
    state: ReleaseState,
    target: str,
    *,
    binding: ReleaseBinding | None = None,
    evidence: tuple[str, ...] = (),
) -> ReleaseState:
    """Advance one stage, preserving exact binding and human/public gates."""

    if target not in STAGES:
        raise ValueError(f"unknown release stage: {target}")
    expected = binding or state.binding
    if expected != state.binding:
        raise ValueError("release binding changed; start a new candidate")
    if target in {"BUILD", "VERIFY_DRAFT", "HUMAN_AUTHORIZE", "PUBLISH_ONCE", "VERIFY_PUBLIC"} and not expected.artifacts:
        raise ValueError("release artifact manifest is required before BUILD")
    current_index = STAGES.index(state.stage)
    target_index = STAGES.index(target)
    if target_index < current_index or target_index > current_index + 1:
        raise ValueError(f"release transition must advance one stage: {state.stage} -> {target}")
    if target == "PUBLISH_ONCE" and not any(item.startswith("human-approval:") for item in evidence):
        raise ValueError("PUBLISH_ONCE requires an explicit human-approval evidence item")
    if target == "VERIFY_PUBLIC" and not any(
        item.startswith("public-verification:") for item in evidence
    ):
        raise ValueError("VERIFY_PUBLIC requires public-verification evidence")
    if target == state.stage:
        return ReleaseState(
            state.stage,
            state.binding,
            state.history,
            tuple(dict.fromkeys((*state.evidence, *evidence))),
        )
    return ReleaseState(
        target,
        state.binding,
        (*state.history, target),
        tuple(dict.fromkeys((*state.evidence, *evidence))),
    )


def load_state(path: Path) -> ReleaseState:
    raw = path.read_bytes()
    if len(raw) > MAX_STATE_BYTES:
        raise ValueError("release state exceeds size limit")
    try:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("release state must be a JSON object")
        if data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported release state schema")
        binding_data = data["binding"]
        if not isinstance(binding_data, dict):
            raise ValueError("release binding must be a JSON object")
        artifact_data = binding_data.get("artifacts", ())
        if not isinstance(artifact_data, (list, tuple)):
            raise ValueError("release artifact manifest must be a JSON array")
        artifacts: list[tuple[str, str]] = []
        for item in artifact_data:
            if not isinstance(item, dict):
                raise ValueError("release artifact manifest entries must be objects")
            name = item.get("name")
            digest = item.get("sha256")
            if not isinstance(name, str) or not isinstance(digest, str):
                raise ValueError("release artifact manifest entries require name and sha256")
            artifacts.append((name, digest))
        binding = ReleaseBinding(
            str(binding_data["version"]),
            str(binding_data["source_sha"]),
            str(binding_data["source_tree"]),
            str(binding_data["tag"]),
            tuple(artifacts),
        )
        history = tuple(str(item) for item in data.get("history", ()))
        evidence = tuple(str(item) for item in data.get("evidence", ()))
        return ReleaseState(str(data["stage"]), binding, history, evidence)
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid release state: {exc}") from exc


def save_state(path: Path, state: ReleaseState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Advance a local GreenGap release evidence state")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--version")
    parser.add_argument("--source-sha")
    parser.add_argument("--source-tree")
    parser.add_argument("--tag")
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="NAME=SHA256",
        help="Bind one released artifact filename to its SHA-256 digest (repeatable)",
    )
    parser.add_argument("--advance", choices=STAGES)
    parser.add_argument("--evidence", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        artifacts = []
        for raw_artifact in args.artifact:
            name, separator, digest = raw_artifact.partition("=")
            if not separator or not name or not digest:
                raise ValueError("--artifact must be NAME=SHA256")
            artifacts.append((name, digest))
        if args.state.exists():
            state = load_state(args.state)
            supplied = [args.version, args.source_sha, args.source_tree, args.tag]
            if any(item is not None for item in supplied) or args.artifact:
                binding = ReleaseBinding(
                    args.version or state.binding.version,
                    args.source_sha or state.binding.source_sha,
                    args.source_tree or state.binding.source_tree,
                    args.tag or state.binding.tag,
                    tuple(artifacts) if artifacts else state.binding.artifacts,
                )
            else:
                binding = state.binding
        else:
            if not all((args.version, args.source_sha, args.source_tree, args.tag)):
                raise ValueError("new state requires --version, --source-sha, --source-tree, and --tag")
            state = ReleaseState.discover(
                ReleaseBinding(
                    args.version,
                    args.source_sha,
                    args.source_tree,
                    args.tag,
                    tuple(artifacts),
                )
            )
            binding = state.binding
        if args.advance:
            state = advance(
                state,
                args.advance,
                binding=binding,
                evidence=tuple(args.evidence),
            )
        save_state(args.state, state)
    except (OSError, ValueError) as exc:
        print(f"release state error: {exc}")
        return 2
    output = json.dumps(state.to_dict(), indent=2, sort_keys=True)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
