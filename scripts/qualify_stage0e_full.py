#!/usr/bin/env python3
"""Run the pinned five-checkout Plan-mode qualification without network writes.

The script expects already materialized, dependency-ready checkouts under
--root. It never clones, pushes, publishes, or changes an upstream repository.
Mutation definitions live here because they are qualification fixtures, not
product logic.
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
EXPECTED_UNKNOWN_REPOSITORIES = frozenset({"outcome", "httpcore"})
EXPECTED_UNKNOWN_EVIDENCE = frozenset(
    {"PYTHON_EXECUTION_UNKNOWN", "WORKSPACE_MUTATION_UNKNOWN"}
)


@dataclass(frozen=True)
class Mutation:
    path: str
    old: bytes
    new: bytes
    expected: str
    count: int = 1


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
    """Recognize only the two qualified build-taint abstentions."""

    collection = plan.get("collection", {})
    snapshot = plan.get("snapshot", {})
    findings = plan.get("findings", [])
    return bool(
        name in EXPECTED_UNKNOWN_REPOSITORIES
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
            EXPECTED_UNKNOWN_EVIDENCE.issubset(set(item.get("evidence", ())))
            for item in findings
            if isinstance(item, dict)
        )
    )


def qualify_one(name: str, root: Path, python_executable: str) -> dict[str, Any]:
    expected = PINNED[name][1]
    valid, reason = validate_checkout(root, expected)
    if not valid:
        return {"repository": name, "status": "ENVIRONMENT_INVALID", "reason": reason}
    before_head = git(root, "rev-parse", "HEAD")
    mutation = MUTATIONS[name]
    changed_files = (mutation.path,)
    base_ref = BASE_REFS[name]
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
    target = root / mutation.path
    if not target.exists():
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
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    results = []
    for name in PINNED:
        interpreter = interpreter_for(name, args.python_dir) if args.python_dir else args.python
        if interpreter is None:
            results.append(
                {
                    "repository": name,
                    "status": "ENVIRONMENT_INVALID",
                    "reason": f"isolated interpreter is missing under {args.python_dir}",
                }
            )
            continue
        results.append(qualify_one(name, args.root / name, interpreter))
    payload = {
        "gate": "stage0e_full_checkout",
        "candidate": candidate_identity(project_root),
        "attempted": len(results),
        "environment_valid": sum(
            item.get("status") not in {"ENVIRONMENT_INVALID", "UPSTREAM_DRIFT"} for item in results
        ),
        "passed": sum(item.get("status") == "PASS" for item in results),
        "expected_unknown": sum(item.get("status") == "EXPECTED_UNKNOWN" for item in results),
        "expected_unknown_repositories": sorted(
            item["repository"] for item in results if item.get("status") == "EXPECTED_UNKNOWN"
        ),
        "results": results,
        "status": "PASS_WITH_EXPECTED_UNKNOWN"
        if len(results) == 5
        and {
            item["repository"] for item in results if item.get("status") == "EXPECTED_UNKNOWN"
        }
        == EXPECTED_UNKNOWN_REPOSITORIES
        and all(item.get("status") in {"PASS", "EXPECTED_UNKNOWN"} for item in results)
        else "PASS"
        if len(results) == 5 and all(item.get("status") == "PASS" for item in results)
        else "NOT_PASSED",
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Stage 0E full checkout: {payload['status']}")
        for item in results:
            print(f"{item['repository']}: {item['status']}")
    return 0 if payload["status"] in {"PASS", "PASS_WITH_EXPECTED_UNKNOWN"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
