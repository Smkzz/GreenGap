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
OUTCOME_OLD = b"tests --cov"
OUTCOME_NEW = b"tests/test_async.py --cov"


def run_plan(repo: Path, python_executable: str) -> tuple[int, dict[str, Any]]:
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    source_path = str(project_root / "src")
    env["PYTHONPATH"] = source_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    result = subprocess.run(
        [python_executable, "-m", "greengap", "plan", str(repo), "--json"],
        text=True,
        capture_output=True,
        env=env,
        timeout=300,
        check=False,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.returncode, {"status": "ENVIRONMENT_INVALID", "error": result.stderr or result.stdout}
    return result.returncode, payload


def run(repo: Path, python_executable: str) -> dict[str, Any]:
    returncode, payload = run_plan(repo, python_executable)
    if returncode == 0 and payload.get("complete") and not payload.get("blocker_count"):
        return {"status": "PASS", "plan": payload}
    if payload.get("snapshot", {}).get("fingerprint"):
        return {"status": "QUALIFICATION_NOT_PASSED", "plan": payload}
    return {"status": "ENVIRONMENT_INVALID", "plan": payload}


def git_head(repo: Path) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True, check=False
    )
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
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    results = {
        "iniconfig": run(args.root / "iniconfig", args.python),
        "outcome": run_outcome(args.root / "outcome", args.python),
    }
    payload = {
        "gate": "upstream_behavioral",
        "results": results,
        "status": "PASS" if all(item["status"] == "PASS" for item in results.values()) else "NOT_PASSED",
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Upstream behavioral gate: {payload['status']}")
        for name, item in results.items():
            print(f"{name}: {item['status']}")
    return 0 if payload["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
