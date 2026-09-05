#!/usr/bin/env python3
"""Run the small exact-byte upstream behavioral gate when checkouts exist."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

OUTCOME_HEAD = "03ed6218b08001877745bb1a9e180c8c5cf7c903"
# Historical iniconfig revision used by the original exact-byte qualification.
# Current upstream is checked separately so drift cannot be silently normalized.
INICONFIG_HEAD = "a0cd289631bd5b6b4b4c9dac5f524e798a0fc8c5"
OUTCOME_OLD = b"tests --cov"
OUTCOME_NEW = b"tests/test_async.py --cov"


def run_plan(repo: Path, python_executable: str) -> tuple[int, dict[str, Any]]:
    if not repo.is_dir():
        return 2, {"status": "ENVIRONMENT_INVALID", "error": f"checkout is missing: {repo}"}
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    source_path = str(project_root / "src")
    env["PYTHONPATH"] = source_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    try:
        result = subprocess.run(
            [python_executable, "-m", "greengap", "plan", str(repo), "--json"],
            text=True,
            capture_output=True,
            env=env,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 2, {"status": "ENVIRONMENT_INVALID", "error": str(exc)}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.returncode, {"status": "ENVIRONMENT_INVALID", "error": result.stderr or result.stdout}
    return result.returncode, payload


def run(repo: Path, python_executable: str) -> dict[str, Any]:
    returncode, payload = run_plan(repo, python_executable)
    if returncode == 0 and payload.get("complete") and not payload.get("blocker_count"):
        return {"status": "PASS", "plan": payload}
    if plan_unknown_nonblocking(payload):
        return {"status": "PASS_WITH_UNKNOWN", "plan": payload}
    if payload.get("snapshot", {}).get("fingerprint"):
        return {"status": "QUALIFICATION_NOT_PASSED", "plan": payload}
    return {"status": "ENVIRONMENT_INVALID", "plan": payload}


def plan_unknown_nonblocking(plan: dict[str, Any]) -> bool:
    collection = plan.get("collection", {})
    return bool(
        plan.get("stable")
        and plan.get("blocker_count") == 0
        and plan.get("snapshot", {}).get("fingerprint")
        and collection.get("complete")
        and collection.get("environment_valid")
        and not plan.get("errors")
    )


def run_pinned(repo: Path, python_executable: str, expected_head: str) -> dict[str, Any]:
    head = git_head(repo)
    if head is None:
        return {"status": "ENVIRONMENT_INVALID", "error": f"checkout is missing or not a Git repository: {repo}"}
    if head != expected_head:
        return {"status": "UPSTREAM_DRIFT", "head": head, "expected_head": expected_head}
    return run(repo, python_executable)


def run_iniconfig_current(repo: Path, python_executable: str) -> dict[str, Any]:
    """Qualify current checkout bytes without replacing drift with history."""

    head = git_head(repo)
    if head is None:
        return {"status": "ENVIRONMENT_INVALID", "error": f"checkout is missing or not a Git repository: {repo}"}
    if head != INICONFIG_HEAD:
        current = run(repo, python_executable)
        current_plan = current.get("plan", {})
        collection = current_plan.get("collection", {})
        current_unknown_nonblocking = plan_unknown_nonblocking(current_plan)
        return {
            "status": "UPSTREAM_DRIFT",
            "head": head,
            "expected_head": INICONFIG_HEAD,
            "current_head_status": current.get("status"),
            "current_head_complete": current_plan.get("complete"),
            "current_head_stable": current_plan.get("stable"),
            "current_head_blockers": current_plan.get("blocker_count"),
            "current_head_trace_complete": current_plan.get("trace", {}).get("complete"),
            "current_head_collection_complete": collection.get("complete"),
            "current_head_environment_valid": collection.get("environment_valid"),
            "current_head_unknown_nonblocking": current_unknown_nonblocking,
        }
    return run(repo, python_executable)


def git_head(repo: Path) -> str | None:
    if not repo.is_dir():
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True, check=False
        )
    except OSError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def run_outcome(repo: Path, python_executable: str) -> dict[str, Any]:
    head = git_head(repo)
    if head != OUTCOME_HEAD:
        return {"status": "UPSTREAM_DRIFT", "head": head, "expected_head": OUTCOME_HEAD}
    baseline = run(repo, python_executable)
    if baseline.get("status") != "PASS":
        return {"status": baseline.get("status", "ENVIRONMENT_INVALID"), "baseline": baseline}
    target = repo / "ci.sh"
    if not target.exists():
        return {"status": "UPSTREAM_DRIFT", "reason": "ci.sh is missing", "baseline": baseline}
    original = target.read_bytes()
    original_hash = hashlib.sha256(original).hexdigest()
    try:
        if OUTCOME_OLD not in original:
            return {"status": "UPSTREAM_DRIFT", "reason": "expected outcome mutation bytes are absent"}
        target.write_bytes(original.replace(OUTCOME_OLD, OUTCOME_NEW, 1))
        code, mutation = run_plan(repo, python_executable)
        detected = code == 1 and mutation.get("blocker_count", 0) > 0
    finally:
        target.write_bytes(original)
    restored = hashlib.sha256(target.read_bytes()).hexdigest() == original_hash
    if not restored:
        return {"status": "RESTORATION_FAILED", "baseline": baseline}
    return {
        "status": "PASS" if detected else "FALSE_NEGATIVE",
        "baseline": baseline,
        "mutation": mutation,
        "restored": restored,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, help="directory containing iniconfig and outcome checkouts")
    parser.add_argument("--python", default=sys.executable, help="interpreter with upstream test dependencies")
    parser.add_argument("--iniconfig-python", help="interpreter with current iniconfig dependencies")
    parser.add_argument("--outcome-python", help="interpreter with Outcome dependencies")
    parser.add_argument(
        "--historical-iniconfig",
        type=Path,
        help="optional exact historical iniconfig checkout used for replay evidence",
    )
    parser.add_argument(
        "--historical-iniconfig-python",
        help="interpreter with historical iniconfig dependencies",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    iniconfig_python = args.iniconfig_python or args.python
    outcome_python = args.outcome_python or args.python
    historical_iniconfig_python = args.historical_iniconfig_python or iniconfig_python
    results = {
        "iniconfig": run_iniconfig_current(args.root / "iniconfig", iniconfig_python),
        "outcome": run_outcome(args.root / "outcome", outcome_python),
    }
    if args.historical_iniconfig:
        results["iniconfig_historical"] = run_pinned(
            args.historical_iniconfig, historical_iniconfig_python, INICONFIG_HEAD
        )
    qualified = all(
        item.get("status") in {"PASS", "PASS_WITH_UNKNOWN"}
        or (
            item.get("status") == "UPSTREAM_DRIFT"
            and (
                item.get("current_head_status") == "PASS"
                or (
                    item.get("current_head_status") == "PASS_WITH_UNKNOWN"
                    and item.get("current_head_unknown_nonblocking") is True
                )
            )
        )
        for item in results.values()
    )
    drifted = any(item.get("status") == "UPSTREAM_DRIFT" for item in results.values())
    has_unknown = any(item.get("status") == "PASS_WITH_UNKNOWN" for item in results.values()) or any(
        item.get("current_head_unknown_nonblocking") is True for item in results.values()
    )
    gate_status = (
        "PASS_WITH_UPSTREAM_DRIFT"
        if qualified and drifted
        else "PASS_WITH_UNKNOWN"
        if qualified and has_unknown
        else "PASS"
        if qualified
        else "NOT_PASSED"
    )
    payload = {
        "gate": "upstream_behavioral",
        "results": results,
        "status": gate_status,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Upstream behavioral gate: {payload['status']}")
        for name, item in results.items():
            print(f"{name}: {item['status']}")
    return 0 if qualified else 2


if __name__ == "__main__":
    raise SystemExit(main())
