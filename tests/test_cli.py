from __future__ import annotations

import json

from greengap.cli import _human_plan, main
from greengap.model import (
    CollectionResult,
    Finding,
    FindingState,
    PlanReport,
    TraceResult,
    WorkspaceSnapshot,
)

from .conftest import write_files


def basic_repo(tmp_path, command: str) -> None:
    write_files(
        tmp_path,
        {
            "tests/test_a.py": "def test_a():\n    pass\n",
            "tests/test_b.py": "def test_b():\n    pass\n",
            ".github/workflows/ci.yml": f"""name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: {command}
""",
        },
    )


def test_cli_plan_green_returns_zero_and_json(capsys, tmp_path) -> None:
    basic_repo(tmp_path, "pytest")
    code = main(["plan", str(tmp_path), "--json", "--trust-collection"])
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["complete"]
    assert output["blocker_count"] == 0


def test_human_plan_redacts_paths_and_secret_shaped_diagnostics(tmp_path) -> None:
    leaked_path = str(tmp_path / "private" / "test.py")
    report = PlanReport(
        repository=str(tmp_path),
        snapshot=WorkspaceSnapshot("fingerprint", (), "filesystem"),
        final_fingerprint="fingerprint",
        candidates=(),
        collection=CollectionResult(True, True),
        trace=TraceResult(),
        findings=(
            Finding(
                leaked_path,
                FindingState.UNKNOWN,
                False,
                "high",
                f"TOKEN=literal-token at {leaked_path}",
            ),
        ),
        complete=False,
        stable=True,
    )

    output = _human_plan(report, collection_enabled=False)

    assert str(tmp_path) not in output
    assert "literal-token" not in output


def test_cli_plan_planted_gap_returns_one(capsys, tmp_path) -> None:
    basic_repo(tmp_path, "pytest tests/test_a.py")
    code = main(["plan", str(tmp_path), "--json", "--trust-collection"])
    output = json.loads(capsys.readouterr().out)
    assert code == 1
    assert output["blocker_count"] == 1
    assert any(item["state"] == "NOT_PLANNED" for item in output["findings"])


def test_cli_dynamic_trace_returns_two(capsys, tmp_path) -> None:
    basic_repo(tmp_path, "pytest -k fast")
    code = main(["plan", str(tmp_path), "--json", "--trust-collection"])
    output = json.loads(capsys.readouterr().out)
    assert code == 2
    assert not output["complete"]
    assert output["findings"][0]["state"] == "UNKNOWN"


def test_cli_scan_reports_candidates(capsys, tmp_path) -> None:
    basic_repo(tmp_path, "pytest")
    code = main(["scan", str(tmp_path), "--json", "--trust-collection"])
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["mode"] == "scan"
    assert len(output["candidates"]) == 2


def test_cli_verify_is_explicitly_uncertified(capsys, tmp_path) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text("<testsuite><testcase name='x'/></testsuite>", encoding="utf-8")
    code = main(["verify", str(tmp_path), "--junitxml", str(junit), "--json"])
    output = json.loads(capsys.readouterr().out)
    assert code == 2
    assert output["identity_reconciliation"] == "NOT_CERTIFIED"
    assert output["case_count"] == 1


def test_cli_verify_human_text_uses_current_api_boundary(capsys, tmp_path) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text("<testsuite><testcase name='x'/></testsuite>", encoding="utf-8")

    code = main(["verify", str(tmp_path), "--junitxml", str(junit)])
    output = capsys.readouterr().out

    assert code == 2
    assert "stable Plan-mode API" in output
    assert "v0.1" not in output


def test_cli_missing_repo_is_incomplete(capsys, tmp_path) -> None:
    code = main(["plan", str(tmp_path / "missing"), "--json"])
    output = json.loads(capsys.readouterr().out)
    assert code == 2
    assert not output["complete"]


def test_cli_human_missing_repo_escapes_terminal_controls(capsys, tmp_path) -> None:
    code = main(["plan", str(tmp_path / "missing\x1b[31m"), "--no-collect"])
    error = capsys.readouterr().err

    assert code == 2
    assert "\x1b" not in error
    assert "\\x1b[31m" in error


def test_cli_defaults_to_non_executing_collection(capsys, tmp_path) -> None:
    basic_repo(tmp_path, "pytest")
    code = main(["plan", str(tmp_path), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert code == 2
    assert not output["complete"]
    assert output["environment"]["collection_mode"] == "non_executing"
    assert str(tmp_path) not in json.dumps(output)


def test_cli_sarif_preserves_incomplete_metadata(capsys, tmp_path) -> None:
    basic_repo(tmp_path, "pytest tests/test_a.py")
    code = main(["plan", str(tmp_path), "--sarif", "--trust-collection"])
    output = json.loads(capsys.readouterr().out)
    run = output["runs"][0]

    assert code == 1
    assert output["version"] == "2.1.0"
    assert run["properties"]["runtimeExecutionIdentity"] == "NOT_CERTIFIED"
    assert run["invocations"][0]["executionSuccessful"]
    assert run["results"][0]["ruleId"] == "GG001"
