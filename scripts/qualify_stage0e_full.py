#!/usr/bin/env python3
"""Run bounded Plan-mode qualification without network writes.

The script expects already materialized, dependency-ready checkouts under
--root. It never clones, pushes, publishes, or changes an upstream repository.
The pinned five-checkout set is an abstention-compatibility fixture. Genuine
mutation certification must use a separate JSON manifest passed with
``--mutation-manifest``; a baseline that is correctly UNKNOWN is never counted
as a mutation experiment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PINNED = {
    "outcome": ("python-trio/outcome", "03ed6218b08001877745bb1a9e180c8c5cf7c903"),
    "requests": ("psf/requests", "8f8b212de8c2129d7954c6cd373762880375620a"),
    "itsdangerous": ("pallets/itsdangerous", "672971d66a2ef9f85151e53283113f33d642dabd"),
    "httpcore": ("encode/httpcore", "10a658221deb38a4c5b16db55ab554b0bf731707"),
    "markupsafe": ("pallets/markupsafe", "b2e4d9c7687be25695fffbe93a37622302b24fb1"),
}
# Bind pull-request branch filters to the primary base branch of each pinned
# checkout.  Without this context a filtered workflow is intentionally UNKNOWN.
BASE_REFS = {
    "outcome": "main",
    "requests": "main",
    "itsdangerous": "main",
    "httpcore": "master",
    "markupsafe": "main",
}
EXPECTED_UNKNOWN_EVIDENCE_BY_REPOSITORY = {
    # Runner-neutral default-shell parsing exposes the repository's unmodeled
    # setup pipeline as an additional relevant abstention reason.  Keep the
    # evidence set exact: any other reason still fails this compatibility gate.
    "outcome": frozenset(
        {"PYTHON_EXECUTION_UNKNOWN", "WORKSPACE_MUTATION_UNKNOWN", "SHELL_PIPE_UNKNOWN"}
    ),
    "requests": frozenset({"PYTHON_RUNTIME_UNKNOWN", "WORKSPACE_MUTATION_UNKNOWN"}),
    "itsdangerous": frozenset(
        {"PYTHON_RUNTIME_UNKNOWN", "UV_COMMAND_UNKNOWN", "WORKSPACE_MUTATION_UNKNOWN"}
    ),
    "httpcore": frozenset({"PYTEST_INVOCATION_CONTEXT_UNKNOWN"}),
    "markupsafe": frozenset(
        {"PYTHON_RUNTIME_UNKNOWN", "UV_COMMAND_UNKNOWN", "WORKSPACE_MUTATION_UNKNOWN"}
    ),
}
EXPECTED_UNKNOWN_REPOSITORIES = frozenset(EXPECTED_UNKNOWN_EVIDENCE_BY_REPOSITORY)


@dataclass(frozen=True)
class Mutation:
    path: str
    old: bytes
    new: bytes
    expected: str
    count: int = 1
    original_sha256: str | None = None
    mutated_sha256: str | None = None


@dataclass(frozen=True)
class MutationCase:
    name: str
    repository: str
    path: str
    expected_head: str
    base_ref: str
    event: str
    ref: str | None
    mutation: Mutation
    runs: int = 2


MUTATIONS = {
    "outcome": Mutation("ci.sh", b"tests --cov", b"tests/test_async.py --cov", "test_sync.py"),
    "requests": Mutation(
        "Makefile",
        b"python -m pytest tests --junitxml=report.xml",
        b"python -m pytest tests/test_adapters.py --junitxml=report.xml",
        "NOT_PLANNED",
    ),
    "itsdangerous": Mutation(
        ".github/workflows/tests.yaml",
        b"tox run -e ${{ matrix.tox || format('py{0}', matrix.python) }}",
        b"tox run -e ${{ matrix.tox || format('py{0}', matrix.python) }} -- tests/test_itsdangerous/test_encoding.py",
        "NOT_PLANNED",
    ),
    "httpcore": Mutation(
        "scripts/test",
        b"${PREFIX}coverage run -m pytest",
        b"${PREFIX}coverage run -m pytest tests/_sync",
        "NOT_PLANNED",
    ),
    "markupsafe": Mutation(
        "pyproject.toml",
        b"{replace = \"posargs\", default = [], extend = true}",
        b"{replace = \"posargs\", default = [\"tests/test_escape.py\"], extend = true}",
        "NOT_PLANNED",
        count=2,
    ),
}


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True, check=False, timeout=30
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def git_optional(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True, check=False, timeout=30
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def sparse_checkout_enabled(root: Path) -> bool:
    """Detect sparse state from config, Git's sparse command, or its pattern file."""

    for key in ("core.sparseCheckout", "core.sparseCheckoutCone"):
        value = git_optional(root, "config", "--bool", "--get", key)
        if value.lower() in {"true", "1", "yes", "on"}:
            return True

    listed = subprocess.run(
        ["git", "sparse-checkout", "list"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if listed.returncode == 0:
        return True
    if listed.returncode not in {1, 128}:
        raise RuntimeError(listed.stderr.strip() or "unable to inspect sparse checkout state")

    sparse_path = git(root, "rev-parse", "--git-path", "info/sparse-checkout")
    pattern_file = Path(sparse_path)
    if not pattern_file.is_absolute():
        pattern_file = root / pattern_file
    return pattern_file.is_file() and bool(pattern_file.read_bytes().strip())


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def candidate_identity(root: Path) -> dict[str, Any]:
    """Bind the qualification receipt to the exact GreenGap source worktree."""

    try:
        dirty = git(root, "status", "--porcelain")
        return {
            "commit": git(root, "rev-parse", "HEAD"),
            "tree": git(root, "rev-parse", "HEAD^{tree}"),
            "clean": not dirty,
        }
    except (OSError, RuntimeError) as exc:
        return {"error": str(exc), "clean": False}


def candidate_identity_is_exact(identity: dict[str, Any]) -> bool:
    """Return true only for a clean, immutable Git candidate identity."""

    return (
        identity.get("clean") is True
        and "error" not in identity
        and isinstance(identity.get("commit"), str)
        and re.fullmatch(r"[0-9a-f]{40}", identity["commit"]) is not None
        and isinstance(identity.get("tree"), str)
        and re.fullmatch(r"[0-9a-f]{40}", identity["tree"]) is not None
    )


def _canonical_repository_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    if normalized.lower().endswith(".git"):
        normalized = normalized[:-4]
    normalized = re.sub(r"^[a-z][a-z0-9+.-]*://", "", normalized, flags=re.I)
    if normalized.lower().startswith("git@github.com:"):
        normalized = "github.com/" + normalized.split(":", 1)[1]
    elif normalized.lower().startswith("git@github.com/"):
        normalized = "github.com/" + normalized.split("/", 1)[1]
    if re.fullmatch(r"[^/:]+/[^/:]+", normalized):
        normalized = f"github.com/{normalized}"
    return normalized.lower()


def validate_checkout(
    root: Path, expected: str, expected_repository: str | None = None
) -> tuple[bool, str]:
    try:
        if git(root, "rev-parse", "HEAD") != expected:
            return False, "HEAD does not match pinned revision"
        if expected_repository is not None:
            origin = git(root, "config", "--get", "remote.origin.url")
            if _canonical_repository_url(origin) != _canonical_repository_url(expected_repository):
                return False, "origin URL does not match the pinned repository"
        if git(root, "status", "--porcelain"):
            return False, "worktree is dirty"
        if sparse_checkout_enabled(root):
            return False, "sparse checkout is enabled"
        tracked = git(root, "ls-files", "-z")
        missing = [item for item in tracked.split("\0") if item and not (root / item).exists()]
        if missing:
            return False, f"tracked paths are missing: {missing[:3]}"
    except (OSError, RuntimeError) as exc:
        return False, str(exc)
    return True, ""


def run_plan(
    repo: Path,
    python_executable: str,
    changed_files: tuple[str, ...],
    base_ref: str,
    event: str = "pull_request",
    ref: str | None = None,
) -> tuple[int, dict[str, Any]]:
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    source_path = str(project_root / "src")
    env["PYTHONPATH"] = source_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    # Qualification inspects prepared checkouts.  It never needs a package
    # download, Git prompt, or uv's automatic project synchronization.
    env["PIP_NO_INDEX"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["UV_OFFLINE"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    command = [python_executable, "-m", "greengap", "plan", str(repo), "--json"]
    command.extend(("--event", event))
    if base_ref:
        command.extend(("--base-ref", base_ref))
    if ref:
        command.extend(("--ref", ref))
    command.extend(
        (
            "--change-set-complete",
            "--commit-count",
            "1",
            "--changed-file-count",
            str(len(changed_files)),
        )
    )
    for changed_file in changed_files:
        command.extend(("--changed-file", changed_file))
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            env=env,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 2, {"error": f"GreenGap plan execution failed: {exc}"}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {"error": result.stderr or result.stdout}
    return result.returncode, payload


def expected_unknown_baseline(name: str, plan: dict[str, Any]) -> bool:
    """Recognize only repository-specific, evidence-bound abstentions."""

    collection = plan.get("collection", {})
    snapshot = plan.get("snapshot", {})
    findings = plan.get("findings", [])
    expected_evidence = EXPECTED_UNKNOWN_EVIDENCE_BY_REPOSITORY.get(name)
    trace = plan.get("trace", {})
    trace_issues = trace.get("issues", []) if isinstance(trace, dict) else []
    relevant_codes = {
        item.get("code")
        for item in trace_issues
        if isinstance(item, dict) and item.get("relevant")
    }
    collection_is_safe_abstention = bool(
        isinstance(collection, dict)
        and not collection.get("complete")
        and not collection.get("environment_valid")
        and isinstance(collection.get("error"), str)
        and collection["error"].startswith(
            "pytest collection environment contains unbound pytest11 plugins:"
        )
        and plan.get("errors") == ["pytest qualification environment is invalid or collection failed"]
    )
    collection_is_complete = bool(
        isinstance(collection, dict)
        and collection.get("complete")
        and collection.get("environment_valid")
        and not plan.get("errors")
    )
    findings_match_expected = isinstance(findings, list) and bool(findings) and all(
        isinstance(item, dict)
        and (
            # Collection never began when the local environment had an
            # unbound pytest11 entry point.  Its candidate-level UNKNOWNs
            # therefore have no trace evidence of their own; the exact
            # collector error above is the evidence-bound abstention.
            (collection_is_safe_abstention and not item.get("evidence"))
            or (item.get("confidence") == "low" and not item.get("evidence"))
            or (
                bool(item.get("evidence"))
                and set(item.get("evidence", ())) <= expected_evidence
            )
        )
        for item in findings
    )
    return bool(
        expected_evidence
        and plan.get("stable")
        and not plan.get("complete")
        and plan.get("blocker_count") == 0
        and isinstance(snapshot, dict)
        and snapshot.get("fingerprint")
        and (collection_is_complete or collection_is_safe_abstention)
        and findings_match_expected
        and all(isinstance(item, dict) and item.get("state") == "UNKNOWN" for item in findings)
        and relevant_codes == expected_evidence
    )


def _safe_mutation_target(root: Path, relative: str) -> Path | None:
    try:
        repository = root.resolve()
        target = (repository / relative).resolve()
        target.relative_to(repository)
    except (OSError, RuntimeError, ValueError):
        return None
    return target


def complete_mutation_baseline(code: int, plan: dict[str, Any]) -> tuple[bool, str]:
    """Require a genuinely certifiable baseline, never an abstention."""

    collection = plan.get("collection")
    if code != 0:
        return False, f"baseline plan exited with code {code}"
    if not plan.get("stable"):
        return False, "baseline snapshot is not stable"
    if not plan.get("complete"):
        return False, "baseline plan is not complete"
    if plan.get("blocker_count") != 0:
        return False, "baseline contains qualification blockers"
    if plan.get("errors"):
        return False, "baseline returned errors"
    if not isinstance(collection, dict) or not collection.get("complete"):
        return False, "baseline pytest collection is incomplete"
    if not collection.get("environment_valid"):
        return False, "baseline pytest collection environment is invalid"
    if not isinstance(plan.get("final_fingerprint"), str) or not plan["final_fingerprint"]:
        return False, "baseline has no stable final fingerprint"
    return True, ""


def expected_omission(plan: dict[str, Any], target: str) -> bool:
    """Return true only for the manifest's exact expected NOT_PLANNED target."""

    findings = plan.get("findings")
    return isinstance(findings, list) and any(
        isinstance(item, dict)
        and item.get("state") == "NOT_PLANNED"
        and item.get("path") == target
        and item.get("blocking") is True
        for item in findings
    )


def mutation_observation(code: int, plan: dict[str, Any], expected: str) -> dict[str, Any]:
    findings = plan.get("findings")
    collection = plan.get("collection")
    blockers = sorted(
        (str(item.get("path")), str(item.get("state")))
        for item in findings
        if isinstance(item, dict) and item.get("blocking")
    ) if isinstance(findings, list) else []
    return {
        "returncode": code,
        "stable": plan.get("stable") is True,
        "complete": plan.get("complete") is True,
        "blocker_count": plan.get("blocker_count"),
        "errors": plan.get("errors") or [],
        "collection_complete": isinstance(collection, dict)
        and collection.get("complete") is True,
        "collection_environment_valid": isinstance(collection, dict)
        and collection.get("environment_valid") is True,
        "expected_omission_detected": expected_omission(plan, expected),
        "blockers": blockers,
        "final_fingerprint": plan.get("final_fingerprint"),
    }


def qualify_case(
    name: str,
    root: Path,
    python_executable: str,
    expected: str,
    mutation: Mutation,
    base_ref: str,
    *,
    repository: str | None = None,
    runs: int = 1,
    allow_expected_unknown: bool = False,
    event: str = "pull_request",
    ref: str | None = None,
) -> dict[str, Any]:
    valid, reason = validate_checkout(root, expected, repository)
    if not valid:
        return {
            "repository": name,
            "source_repository": repository,
            "status": "ENVIRONMENT_INVALID",
            "reason": reason,
            "mutation_executed": 0,
            "mutation_passed": 0,
            "mutation_restored": 0,
        }
    before_head = git(root, "rev-parse", "HEAD")
    changed_files = (mutation.path,)
    baseline_code, baseline = run_plan(
        root, python_executable, changed_files, base_ref, event, ref
    )
    baseline_valid, baseline_reason = complete_mutation_baseline(baseline_code, baseline)
    if not baseline_valid:
        status = (
            "EXPECTED_UNKNOWN"
            if allow_expected_unknown and expected_unknown_baseline(name, baseline)
            else "BASELINE_NOT_COMPLETE"
        )
        return {
            "repository": name,
            "source_repository": repository,
            "status": status,
            "reason": baseline_reason,
            "baseline": baseline,
            "mutation_executed": 0,
            "mutation_passed": 0,
            "mutation_restored": 0,
        }
    target = _safe_mutation_target(root, mutation.path)
    if target is None or not target.exists():
        return {
            "repository": name,
            "source_repository": repository,
            "status": "ENVIRONMENT_INVALID",
            "reason": f"mutation file missing: {mutation.path}",
            "mutation_executed": 0,
            "mutation_passed": 0,
            "mutation_restored": 0,
        }
    try:
        original = target.read_bytes()
    except OSError as exc:
        return {
            "repository": name,
            "source_repository": repository,
            "status": "ENVIRONMENT_INVALID",
            "reason": f"mutation file could not be read: {exc}",
            "mutation_executed": 0,
            "mutation_passed": 0,
            "mutation_restored": 0,
        }
    original_hash = digest_bytes(original)
    if mutation.original_sha256 is not None and original_hash != mutation.original_sha256:
        return {
            "repository": name,
            "source_repository": repository,
            "status": "UPSTREAM_DRIFT",
            "reason": "mutation target does not match manifest original_sha256",
            "mutation_executed": 0,
            "mutation_passed": 0,
            "mutation_restored": 0,
        }
    if original.count(mutation.old) < mutation.count:
        return {
            "repository": name,
            "source_repository": repository,
            "status": "UPSTREAM_DRIFT",
            "reason": "expected mutation bytes not found often enough",
            "mutation_executed": 0,
            "mutation_passed": 0,
            "mutation_restored": 0,
        }
    mutated = original.replace(mutation.old, mutation.new, mutation.count)
    mutated_hash = digest_bytes(mutated)
    if mutation.mutated_sha256 is not None and mutated_hash != mutation.mutated_sha256:
        return {
            "repository": name,
            "source_repository": repository,
            "status": "INVALID_MANIFEST",
            "reason": "mutation bytes do not match manifest mutated_sha256",
            "mutation_executed": 0,
            "mutation_passed": 0,
            "mutation_restored": 0,
        }

    observations: list[dict[str, Any]] = []
    mutation_payload: dict[str, Any] = {}
    restored_runs = 0
    for _ in range(runs):
        try:
            target.write_bytes(mutated)
        except OSError as exc:
            return {
                "repository": name,
                "source_repository": repository,
                "status": "MUTATION_NOT_EXECUTED",
                "reason": f"mutation file could not be written: {exc}",
                "baseline": baseline,
                "mutation_runs": observations,
                "mutation_executed": len(observations),
                "mutation_passed": sum(
                    item["expected_omission_detected"] for item in observations
                ),
                "mutation_restored": restored_runs,
            }
        restore_error: OSError | None = None
        try:
            code, mutation_payload = run_plan(
                root, python_executable, changed_files, base_ref, event, ref
            )
            observations.append(mutation_observation(code, mutation_payload, mutation.expected))
        finally:
            try:
                target.write_bytes(original)
            except OSError as exc:
                restore_error = exc
        if restore_error is not None:
            return {
                "repository": name,
                "source_repository": repository,
                "status": "RESTORATION_FAILED",
                "reason": f"mutation file could not be restored: {restore_error}",
                "baseline": baseline,
                "mutation": mutation_payload,
                "mutation_runs": observations,
                "mutation_executed": len(observations),
                "mutation_passed": sum(
                    item["expected_omission_detected"] for item in observations
                ),
                "mutation_restored": restored_runs,
            }
        try:
            run_restored, _ = validate_checkout(root, expected, repository)
            exact_bytes = digest(target) == original_hash
            exact_head = git(root, "rev-parse", "HEAD") == before_head
        except (OSError, RuntimeError):
            run_restored = exact_bytes = exact_head = False
        if not run_restored or not exact_bytes or not exact_head:
            return {
                "repository": name,
                "source_repository": repository,
                "status": "RESTORATION_FAILED",
                "baseline": baseline,
                "mutation": mutation_payload,
                "mutation_runs": observations,
                "mutation_executed": len(observations),
                "mutation_passed": sum(
                    item["expected_omission_detected"] for item in observations
                ),
                "mutation_restored": restored_runs,
            }
        restored_runs += 1

    restored_code, restored_plan = run_plan(
        root, python_executable, changed_files, base_ref, event, ref
    )
    restored_valid, restored_reason = complete_mutation_baseline(restored_code, restored_plan)
    try:
        restored = (
            restored_valid
            and restored_plan.get("final_fingerprint") == baseline.get("final_fingerprint")
            and digest(target) == original_hash
            and git(root, "rev-parse", "HEAD") == before_head
            and not git(root, "status", "--porcelain")
        )
    except (OSError, RuntimeError):
        restored = False
    if not restored:
        return {
            "repository": name,
            "source_repository": repository,
            "status": "RESTORATION_FAILED",
            "reason": restored_reason or "restored fingerprint does not match baseline",
            "baseline": baseline,
            "mutation": mutation_payload,
            "mutation_runs": observations,
            "restoration": restored_plan,
            "mutation_executed": len(observations),
            "mutation_passed": sum(item["expected_omission_detected"] for item in observations),
            "mutation_restored": restored_runs,
        }
    deterministic = len({json.dumps(item, sort_keys=True) for item in observations}) == 1
    passed = bool(observations) and deterministic and all(
        item["returncode"] == 1
        and item["stable"]
        and item["complete"]
        and item["collection_complete"]
        and item["collection_environment_valid"]
        and not item["errors"]
        and item["expected_omission_detected"]
        for item in observations
    )
    return {
        "repository": name,
        "source_repository": repository,
        "status": "PASS" if passed else "FALSE_NEGATIVE",
        "baseline": baseline,
        "mutation": mutation_payload,
        "mutation_runs": observations,
        "restored": restored,
        "deterministic": deterministic,
        "restoration": restored_plan,
        "mutation_executed": len(observations),
        "mutation_passed": sum(item["expected_omission_detected"] for item in observations),
        "mutation_restored": restored_runs,
    }


def qualify_one(name: str, root: Path, python_executable: str) -> dict[str, Any]:
    expected = PINNED[name][1]
    return qualify_case(
        name,
        root,
        python_executable,
        expected,
        MUTATIONS[name],
        BASE_REFS[name],
        repository=PINNED[name][0],
        allow_expected_unknown=True,
    )


def load_mutation_manifest(path: Path) -> tuple[MutationCase, ...]:
    """Load a separate, exact-head mutation-certification set."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read mutation manifest: {exc}") from exc
    if (
        not isinstance(raw, dict)
        or raw.get("schema_version") != 1
        or not isinstance(raw.get("repositories"), list)
    ):
        raise ValueError("mutation manifest must contain schema_version 1 and a repositories list")
    cases: list[MutationCase] = []
    names: set[str] = set()
    for item in raw["repositories"]:
        if not isinstance(item, dict):
            raise ValueError("mutation manifest repository entries must be mappings")
        name = item.get("name")
        repository = item.get("repository")
        relative_path = item.get("path")
        expected_head = item.get("expected_head")
        base_ref = item.get("base_ref")
        event = item.get("event", "pull_request")
        ref = item.get("ref")
        runs = item.get("runs", 2)
        raw_mutation = item.get("mutation")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(repository, str)
            or not repository.startswith("https://github.com/")
            or not isinstance(relative_path, str)
            or not relative_path
            or not isinstance(expected_head, str)
            or not expected_head
            or not isinstance(base_ref, str)
            or not base_ref
            or not isinstance(event, str)
            or event not in {"pull_request", "push"}
            or (ref is not None and (not isinstance(ref, str) or not ref))
        ):
            raise ValueError(
                "mutation manifest entries require a GitHub repository and non-empty name/path/expected_head/base_ref"
            )
        if event == "push" and not ref:
            raise ValueError(f"mutation manifest entry {name!r} requires ref for a push event")
        if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
            raise ValueError(f"mutation manifest entry {name!r} has a non-immutable expected_head")
        if not isinstance(runs, int) or runs < 2:
            raise ValueError(f"mutation manifest entry {name!r} must run at least twice")
        candidate_path = Path(relative_path)
        if candidate_path.is_absolute() or ".." in candidate_path.parts:
            raise ValueError(f"mutation manifest entry {name!r} has an unsafe checkout path")
        if name in names:
            raise ValueError(f"duplicate mutation manifest repository: {name}")
        if not isinstance(raw_mutation, dict):
            raise ValueError(f"mutation manifest entry {name!r} has no mutation mapping")
        mutation_path = raw_mutation.get("path")
        old = raw_mutation.get("old")
        new = raw_mutation.get("new")
        expected = raw_mutation.get("expected")
        count = raw_mutation.get("count", 1)
        original_sha256 = raw_mutation.get("original_sha256")
        mutated_sha256 = raw_mutation.get("mutated_sha256")
        if (
            not isinstance(mutation_path, str)
            or not isinstance(old, str)
            or not isinstance(new, str)
            or not isinstance(expected, str)
            or not expected
            or not isinstance(original_sha256, str)
            or not isinstance(mutated_sha256, str)
        ):
            raise ValueError(f"mutation manifest entry {name!r} has invalid mutation fields")
        if not isinstance(count, int) or count < 1:
            raise ValueError(f"mutation manifest entry {name!r} has invalid mutation count")
        if not re.fullmatch(r"[0-9a-f]{64}", original_sha256) or not re.fullmatch(
            r"[0-9a-f]{64}", mutated_sha256
        ):
            raise ValueError(f"mutation manifest entry {name!r} has invalid mutation sha256 values")
        names.add(name)
        cases.append(
            MutationCase(
                name,
                repository,
                relative_path,
                expected_head,
                base_ref,
                event,
                ref,
                Mutation(
                    mutation_path,
                    old.encode(),
                    new.encode(),
                    expected,
                    count,
                    original_sha256,
                    mutated_sha256,
                ),
                runs,
            )
        )
    if not cases:
        raise ValueError("mutation manifest must contain at least one repository")
    return tuple(cases)


def abstention_compatibility_report(results: list[dict[str, Any]]) -> dict[str, Any]:
    expected = {
        item["repository"]
        for item in results
        if item.get("status") == "EXPECTED_UNKNOWN"
    }
    compatible = (
        len(results) == len(EXPECTED_UNKNOWN_REPOSITORIES)
        and expected == EXPECTED_UNKNOWN_REPOSITORIES
        and all(item.get("status") in {"PASS", "EXPECTED_UNKNOWN"} for item in results)
    )
    return {
        "gate": "stage0e_abstention_compatibility",
        "status": "PASS" if compatible else "NOT_PASSED",
        "attempted": len(results),
        "expected_unknown": sum(
            item.get("status") == "EXPECTED_UNKNOWN" for item in results
        ),
        "expected_unknown_repositories": sorted(expected),
    }


def mutation_certification_report(results: list[dict[str, Any]]) -> dict[str, Any]:
    executed = [item for item in results if item.get("mutation_executed", 0) > 0]
    if not results:
        status = "NOT_CONFIGURED"
    elif len(executed) != len(results):
        status = "NOT_PASSED"
    elif all(
        item.get("status") == "PASS"
        and item.get("deterministic") is True
        and item.get("restored") is True
        and item.get("mutation_executed") == item.get("mutation_passed")
        and item.get("mutation_executed") == item.get("mutation_restored")
        for item in results
    ):
        status = "PASS"
    else:
        status = "NOT_PASSED"
    return {
        "gate": "stage0e_mutation_certification",
        "status": status,
        "attempted": len(results),
        "mutation_executed": sum(int(item.get("mutation_executed", 0)) for item in results),
        "mutation_passed": sum(int(item.get("mutation_passed", 0)) for item in results),
        "mutation_restored": sum(int(item.get("mutation_restored", 0)) for item in results),
        "results": results,
    }


def interpreter_for(name: str, python_dir: Path) -> str | None:
    """Find the interpreter for one isolated checkout environment."""

    candidates = (
        python_dir / name / "Scripts" / "python.exe",
        python_dir / name / "bin" / "python",
        python_dir / name / "python.exe",
        python_dir / name / "python",
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, help="directory containing named qualification checkouts")
    parser.add_argument("--python", default=sys.executable, help="interpreter with each checkout's test dependencies")
    parser.add_argument(
        "--abstention-root",
        type=Path,
        help="directory containing the five abstention-compatibility checkouts",
    )
    parser.add_argument(
        "--mutation-root",
        type=Path,
        help="directory containing checkout paths referenced by the mutation manifest",
    )
    parser.add_argument(
        "--abstention-python",
        help="interpreter for abstention compatibility (defaults to --python)",
    )
    parser.add_argument(
        "--mutation-python",
        help="interpreter for mutation certification (defaults to --python)",
    )
    parser.add_argument(
        "--python-dir",
        type=Path,
        help="directory containing one isolated environment per checkout (name/Scripts/python.exe or name/bin/python)",
    )
    parser.add_argument(
        "--gate",
        choices=("all", "abstention-compatibility", "mutation-certification"),
        default="all",
        help="qualification gate to run; all requires a separate mutation manifest",
    )
    parser.add_argument(
        "--mutation-manifest",
        type=Path,
        help="JSON manifest describing a separate exact-head mutation-certification set",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    abstention_root = args.abstention_root or args.root
    mutation_root = args.mutation_root or args.root
    compatibility_results: list[dict[str, Any]] = []
    if args.gate in {"all", "abstention-compatibility"}:
        for name in PINNED:
            interpreter = (
                interpreter_for(name, args.python_dir)
                if args.python_dir
                else args.abstention_python or args.python
            )
            if interpreter is None:
                compatibility_results.append(
                    {
                        "repository": name,
                        "status": "ENVIRONMENT_INVALID",
                        "reason": f"isolated interpreter is missing under {args.python_dir}",
                    }
                )
                continue
            compatibility_results.append(qualify_one(name, abstention_root / name, interpreter))
    compatibility = abstention_compatibility_report(compatibility_results)
    mutation_results: list[dict[str, Any]] = []
    mutation_error: str | None = None
    if args.gate in {"all", "mutation-certification"} and args.mutation_manifest is not None:
        try:
            cases = load_mutation_manifest(args.mutation_manifest)
            for case in cases:
                interpreter = (
                    interpreter_for(case.name, args.python_dir)
                    if args.python_dir
                    else args.mutation_python or args.python
                )
                if interpreter is None:
                    mutation_results.append(
                        {
                            "repository": case.name,
                            "source_repository": case.repository,
                            "status": "ENVIRONMENT_INVALID",
                            "reason": f"isolated interpreter is missing under {args.python_dir}",
                            "mutation_executed": 0,
                            "mutation_passed": 0,
                            "mutation_restored": 0,
                        }
                    )
                else:
                    result = qualify_case(
                        case.name,
                        mutation_root / case.path,
                        interpreter,
                        case.expected_head,
                        case.mutation,
                        case.base_ref,
                        repository=case.repository,
                        runs=case.runs,
                        event=case.event,
                        ref=case.ref,
                    )
                    result.update(
                        {
                            "expected_head": case.expected_head,
                            "base_ref": case.base_ref,
                            "event": case.event,
                            "ref": case.ref,
                            "expected_blocker": case.mutation.expected,
                        }
                    )
                    mutation_results.append(result)
        except ValueError as exc:
            mutation_error = str(exc)
    mutation = mutation_certification_report(mutation_results)
    if mutation_error is not None:
        mutation["status"] = "INVALID_MANIFEST"
        mutation["error"] = mutation_error
    candidate = candidate_identity(project_root)
    if args.gate in {"all", "mutation-certification"} and not candidate_identity_is_exact(candidate):
        mutation["status"] = "NOT_PASSED"
        mutation["candidate_identity_error"] = (
            "candidate source worktree is not a clean exact commit/tree identity"
        )
    if args.gate == "abstention-compatibility":
        status = (
            "ABSTENTION_COMPATIBILITY_PASS"
            if compatibility["status"] == "PASS"
            else "NOT_PASSED"
        )
    elif args.gate == "mutation-certification":
        status = (
            "MUTATION_CERTIFICATION_PASS"
            if mutation["status"] == "PASS"
            else f"MUTATION_CERTIFICATION_{mutation['status']}"
        )
    elif compatibility["status"] != "PASS":
        status = "NOT_PASSED"
    elif mutation["status"] == "PASS":
        status = "PASS"
    else:
        status = "NOT_PROMOTABLE"
    payload = {
        "gate": "stage0e_qualification",
        "candidate": candidate,
        "attempted": len(compatibility_results),
        "environment_valid": sum(
            item.get("status") not in {"ENVIRONMENT_INVALID", "UPSTREAM_DRIFT"}
            for item in compatibility_results
        ),
        "passed": sum(item.get("status") == "PASS" for item in compatibility_results),
        "expected_unknown": sum(
            item.get("status") == "EXPECTED_UNKNOWN" for item in compatibility_results
        ),
        "expected_unknown_repositories": sorted(
            item["repository"]
            for item in compatibility_results
            if item.get("status") == "EXPECTED_UNKNOWN"
        ),
        "results": compatibility_results,
        "abstention_root": str(abstention_root),
        "mutation_root": str(mutation_root),
        "mutation_cases": len(mutation_results),
        "abstention_compatibility": compatibility,
        "mutation_certification": mutation,
        "status": status,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Stage 0E full checkout: {payload['status']}")
        for item in compatibility_results:
            print(f"{item['repository']}: {item['status']}")
        if args.gate in {"all", "mutation-certification"}:
            print(
                "Mutation certification: "
                f"{mutation['status']} "
                f"({mutation['mutation_executed']}/{mutation['mutation_passed']} detections, "
                f"{mutation['mutation_restored']} exact restorations)"
            )
            for item in mutation_results:
                print(
                    f"{item['repository']}: {item['status']} "
                    f"({item.get('mutation_executed', 0)}/{item.get('mutation_passed', 0)} detections, "
                    f"{item.get('mutation_restored', 0)} restored)"
                )
    return 0 if payload["status"] in {"PASS", "ABSTENTION_COMPATIBILITY_PASS", "MUTATION_CERTIFICATION_PASS"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
