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
    "outcome": frozenset({"PYTHON_EXECUTION_UNKNOWN", "WORKSPACE_MUTATION_UNKNOWN"}),
    "requests": frozenset({"WORKSPACE_MUTATION_UNKNOWN"}),
    "itsdangerous": frozenset({"TOX_PACKAGING_UNKNOWN"}),
    "httpcore": frozenset({"EXECUTABLE_IDENTITY_UNKNOWN"}),
    "markupsafe": frozenset({"TOX_PACKAGING_UNKNOWN", "WORKSPACE_MUTATION_UNKNOWN"}),
}
EXPECTED_UNKNOWN_REPOSITORIES = frozenset(EXPECTED_UNKNOWN_EVIDENCE_BY_REPOSITORY)


@dataclass(frozen=True)
class Mutation:
    path: str
    old: bytes
    new: bytes
    expected: str
    count: int = 1


@dataclass(frozen=True)
class MutationCase:
    name: str
    path: str
    expected_head: str
    base_ref: str
    mutation: Mutation


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


def validate_checkout(root: Path, expected: str) -> tuple[bool, str]:
    try:
        if git(root, "rev-parse", "HEAD") != expected:
            return False, "HEAD does not match pinned revision"
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
    repo: Path, python_executable: str, changed_files: tuple[str, ...], base_ref: str
) -> tuple[int, dict[str, Any]]:
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    source_path = str(project_root / "src")
    env["PYTHONPATH"] = source_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    command = [python_executable, "-m", "greengap", "plan", str(repo), "--json"]
    command.extend(
        (
            "--event",
            "pull_request",
            "--base-ref",
            base_ref,
            "--change-set-complete",
            "--commit-count",
            "1",
            "--changed-file-count",
            str(len(changed_files)),
        )
    )
    for changed_file in changed_files:
        command.extend(("--changed-file", changed_file))
    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
        env=env,
        timeout=300,
        check=False,
    )
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
    return bool(
        expected_evidence
        and plan.get("stable")
        and not plan.get("complete")
        and plan.get("blocker_count") == 0
        and isinstance(snapshot, dict)
        and snapshot.get("fingerprint")
        and isinstance(collection, dict)
        and collection.get("complete")
        and collection.get("environment_valid")
        and not plan.get("errors")
        and isinstance(findings, list)
        and findings
        and all(isinstance(item, dict) and item.get("state") == "UNKNOWN" for item in findings)
        and all(
            (
                item.get("confidence") == "low" and not item.get("evidence")
            )
            or (
                bool(item.get("evidence"))
                and set(item.get("evidence", ())) <= expected_evidence
            )
            for item in findings
            if isinstance(item, dict)
        )
        and (not relevant_codes or relevant_codes <= expected_evidence)
    )


def _safe_mutation_target(root: Path, relative: str) -> Path | None:
    try:
        repository = root.resolve()
        target = (repository / relative).resolve()
        target.relative_to(repository)
    except (OSError, RuntimeError, ValueError):
        return None
    return target


def qualify_case(
    name: str,
    root: Path,
    python_executable: str,
    expected: str,
    mutation: Mutation,
    base_ref: str,
) -> dict[str, Any]:
    valid, reason = validate_checkout(root, expected)
    if not valid:
        return {"repository": name, "status": "ENVIRONMENT_INVALID", "reason": reason}
    before_head = git(root, "rev-parse", "HEAD")
    changed_files = (mutation.path,)
    baseline_code, baseline = run_plan(root, python_executable, changed_files, base_ref)
    if baseline_code != 0 or not baseline.get("complete") or baseline.get("blocker_count", 0):
        status = (
            "ENVIRONMENT_INVALID"
            if not baseline.get("collection", {}).get("environment_valid", True)
            else "EXPECTED_UNKNOWN"
            if expected_unknown_baseline(name, baseline)
            else "FALSE_POSITIVE"
        )
        return {"repository": name, "status": status, "baseline": baseline}
    target = _safe_mutation_target(root, mutation.path)
    if target is None or not target.exists():
        return {
            "repository": name,
            "status": "ENVIRONMENT_INVALID",
            "reason": f"mutation file missing: {mutation.path}",
        }
    original = target.read_bytes()
    original_hash = digest(target)
    mutation_status = "NOT_RUN"
    mutation_payload: dict[str, Any] = {}
    try:
        if mutation.old not in original:
            return {
                "repository": name,
                "status": "UPSTREAM_DRIFT",
                "reason": "expected mutation bytes not found",
            }
        target.write_bytes(original.replace(mutation.old, mutation.new, mutation.count))
        code, mutation_payload = run_plan(root, python_executable, changed_files, base_ref)
        mutation_status = (
            "PASS" if code == 1 and mutation_payload.get("blocker_count", 0) > 0 else "FALSE_NEGATIVE"
        )
    finally:
        target.write_bytes(original)
    restored = (
        digest(target) == original_hash
        and git(root, "rev-parse", "HEAD") == before_head
        and not git(root, "status", "--porcelain")
    )
    if not restored:
        return {"repository": name, "status": "RESTORATION_FAILED", "mutation": mutation_status}
    return {
        "repository": name,
        "status": "PASS" if mutation_status == "PASS" else mutation_status,
        "baseline": baseline,
        "mutation": mutation_payload,
        "restored": restored,
    }


def qualify_one(name: str, root: Path, python_executable: str) -> dict[str, Any]:
    expected = PINNED[name][1]
    return qualify_case(name, root, python_executable, expected, MUTATIONS[name], BASE_REFS[name])


def load_mutation_manifest(path: Path) -> tuple[MutationCase, ...]:
    """Load a separate, exact-head mutation-certification set."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read mutation manifest: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("repositories"), list):
        raise ValueError("mutation manifest must contain a repositories list")
    cases: list[MutationCase] = []
    names: set[str] = set()
    for item in raw["repositories"]:
        if not isinstance(item, dict):
            raise ValueError("mutation manifest repository entries must be mappings")
        name = item.get("name")
        relative_path = item.get("path")
        expected_head = item.get("expected_head")
        base_ref = item.get("base_ref")
        raw_mutation = item.get("mutation")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(relative_path, str)
            or not relative_path
            or not isinstance(expected_head, str)
            or not expected_head
            or not isinstance(base_ref, str)
            or not base_ref
        ):
            raise ValueError("mutation manifest entries require non-empty name/path/expected_head/base_ref")
        if name in names:
            raise ValueError(f"duplicate mutation manifest repository: {name}")
        if not isinstance(raw_mutation, dict):
            raise ValueError(f"mutation manifest entry {name!r} has no mutation mapping")
        mutation_path = raw_mutation.get("path")
        old = raw_mutation.get("old")
        new = raw_mutation.get("new")
        expected = raw_mutation.get("expected")
        count = raw_mutation.get("count", 1)
        if (
            not isinstance(mutation_path, str)
            or not isinstance(old, str)
            or not isinstance(new, str)
            or not isinstance(expected, str)
        ):
            raise ValueError(f"mutation manifest entry {name!r} has invalid mutation fields")
        if not isinstance(count, int) or count < 1:
            raise ValueError(f"mutation manifest entry {name!r} has invalid mutation count")
        names.add(name)
        cases.append(
            MutationCase(
                name,
                relative_path,
                expected_head,
                base_ref,
                Mutation(mutation_path, old.encode(), new.encode(), expected, count),
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
    executed = [
        item
        for item in results
        if isinstance(item.get("mutation"), dict) and item.get("restored") is True
    ]
    if not results:
        status = "NOT_CONFIGURED"
    elif not executed:
        status = "NOT_RUN"
    elif len(executed) != len(results):
        status = "NOT_PASSED"
    elif all(item.get("status") == "PASS" for item in executed):
        status = "PASS"
    else:
        status = "NOT_PASSED"
    return {
        "gate": "stage0e_mutation_certification",
        "status": status,
        "attempted": len(results),
        "mutation_executed": len(executed),
        "mutation_restored": sum(item.get("restored") is True for item in executed),
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
    parser.add_argument("root", type=Path, help="directory containing the five named checkouts")
    parser.add_argument("--python", default=sys.executable, help="interpreter with each checkout's test dependencies")
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
    compatibility_results = []
    for name in PINNED:
        interpreter = interpreter_for(name, args.python_dir) if args.python_dir else args.python
        if interpreter is None:
            compatibility_results.append(
                {
                    "repository": name,
                    "status": "ENVIRONMENT_INVALID",
                    "reason": f"isolated interpreter is missing under {args.python_dir}",
                }
            )
            continue
        compatibility_results.append(qualify_one(name, args.root / name, interpreter))
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
                    else args.python
                )
                if interpreter is None:
                    mutation_results.append(
                        {
                            "repository": case.name,
                            "status": "ENVIRONMENT_INVALID",
                            "reason": f"isolated interpreter is missing under {args.python_dir}",
                        }
                    )
                else:
                    mutation_results.append(
                        qualify_case(
                            case.name,
                            args.root / case.path,
                            interpreter,
                            case.expected_head,
                            case.mutation,
                            case.base_ref,
                        )
                    )
        except ValueError as exc:
            mutation_error = str(exc)
    mutation = mutation_certification_report(mutation_results)
    if mutation_error is not None:
        mutation["status"] = "INVALID_MANIFEST"
        mutation["error"] = mutation_error
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
        "candidate": candidate_identity(project_root),
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
    return 0 if payload["status"] in {"PASS", "ABSTENTION_COMPATIBILITY_PASS", "MUTATION_CERTIFICATION_PASS"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
