from __future__ import annotations

import json
from pathlib import Path

import yaml

from greengap.cli import main
from greengap.model import (
    CollectionResult,
    Finding,
    FindingState,
    PlanReport,
    ScanReport,
    TraceResult,
    WorkspaceSnapshot,
)
from greengap.report import redact_shareable, sarif_report

from .conftest import write_files


def _repo(tmp_path: Path, command: str = "pytest") -> None:
    write_files(
        tmp_path,
        {
            "tests/test_a.py": "def test_a():\n    pass\n",
            ".github/workflows/ci.yml": f"""name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: {command}
""",
        },
    )


def test_json_contract_is_redacted_and_has_identity(capsys, tmp_path) -> None:
    _repo(tmp_path)
    code = main(["plan", str(tmp_path), "--json", "--trust-collection"])
    output = json.loads(capsys.readouterr().out)

    assert code == 0
    assert output["report_version"] == "1.0"
    assert output["repository"] == "."
    assert output["source"]["workspace_fingerprint"]
    assert output["environment"]["execution_consent"] is True
    assert output["completeness"]["runtime_execution_identity"] == "NOT_CERTIFIED"
    assert str(tmp_path) not in json.dumps(output)
    assert all("reason_code" in finding for finding in output["findings"])


def test_default_plan_does_not_execute_repository_code(capsys, tmp_path) -> None:
    _repo(tmp_path)
    write_files(
        tmp_path,
        {
            "tests/test_side_effect.py": (
                "from pathlib import Path\n"
                "Path('collection-side-effect.txt').write_text('executed')\n"
                "def test_side_effect():\n    pass\n"
            )
        },
    )

    code = main(["plan", str(tmp_path), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert code == 2
    assert output["environment"]["collection_mode"] == "non_executing"
    assert not (tmp_path / "collection-side-effect.txt").exists()
    assert all(item["state"] == "UNKNOWN" for item in output["findings"])


def test_sarif_uris_are_relative_and_findings_are_not_vulnerabilities(capsys, tmp_path) -> None:
    _repo(tmp_path, "pytest tests/test_a.py")
    write_files(tmp_path, {"tests/test_b.py": "def test_b():\n    pass\n"})
    code = main(["plan", str(tmp_path), "--sarif", "--trust-collection"])
    output = json.loads(capsys.readouterr().out)
    result = output["runs"][0]["results"][0]

    assert code == 1
    assert output["version"] == "2.1.0"
    assert result["ruleId"] == "GG001"
    assert result["kind"] == "open"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "tests/test_b.py"
    assert "://" not in result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert output["runs"][0]["properties"]["runtimeExecutionIdentity"] == "NOT_CERTIFIED"


def test_sarif_redacts_raw_finding_diagnostics(tmp_path) -> None:
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
                (leaked_path,),
            ),
        ),
        complete=False,
        stable=True,
    )

    payload = sarif_report(report, root=tmp_path)
    rendered = json.dumps(payload)

    assert str(tmp_path) not in rendered
    assert "literal-token" not in rendered


def test_scan_sarif_cannot_claim_complete_analysis_without_collection(tmp_path) -> None:
    report = ScanReport(
        repository=str(tmp_path),
        snapshot=WorkspaceSnapshot("fingerprint", (), "filesystem"),
        final_fingerprint="fingerprint",
        candidates=(),
        collection=CollectionResult(False, True, error="withheld"),
        stable=True,
    )

    payload = sarif_report(report, root=tmp_path)
    invocation = payload["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is False
    assert invocation["properties"]["analysisComplete"] is False
    assert invocation["properties"]["collectionComplete"] is False


def test_relative_repository_argument_preserves_relative_finding_paths(
    capsys, monkeypatch, tmp_path
) -> None:
    _repo(tmp_path, "pytest tests/test_a.py")
    write_files(tmp_path, {"tests/test_b.py": "def test_b():\n    pass\n"})
    monkeypatch.chdir(tmp_path)

    code = main(["plan", ".", "--json", "--trust-collection"])
    output = json.loads(capsys.readouterr().out)

    assert code == 1
    assert any(item["path"] == "tests/test_b.py" for item in output["findings"])


def test_verify_json_redacts_absolute_paths_with_spaces(capsys, tmp_path) -> None:
    junit = tmp_path / "results.xml"
    junit.write_text(
        '<testsuite><testcase classname="suite" name="case" '
        'file="C:\\Users\\Alice Smith\\private\\test.py"/></testsuite>',
        encoding="utf-8",
    )

    code = main(["verify", str(tmp_path), "--junitxml", str(junit), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert code == 2
    assert output["cases"][0]["file"] == "<absolute-path>"
    assert "Alice Smith" not in json.dumps(output)


def test_verify_json_redacts_posix_absolute_paths(capsys, tmp_path) -> None:
    junit = tmp_path / "results.xml"
    junit.write_text(
        '<testsuite><testcase classname="suite" name="case" '
        'file="/home/alice/private/test.py"/></testsuite>',
        encoding="utf-8",
    )

    code = main(["verify", str(tmp_path), "--junitxml", str(junit), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert code == 2
    assert output["cases"][0]["file"] == "<absolute-path>"
    assert "/home/alice" not in json.dumps(output)


def test_verify_json_redacts_file_uri_paths(capsys, tmp_path) -> None:
    junit = tmp_path / "results.xml"
    junit.write_text(
        '<testsuite><testcase classname="suite" name="case" '
        'file="file:///home/alice/private/test.py"/></testsuite>',
        encoding="utf-8",
    )

    code = main(["verify", str(tmp_path), "--junitxml", str(junit), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert code == 2
    assert output["cases"][0]["file"] == "<absolute-path>"
    assert "file:///home/alice" not in json.dumps(output)


def test_shareable_redaction_removes_secret_shaped_diagnostics(tmp_path) -> None:
    value = (
        "TOKEN=literal-token Bearer bearer-token "
        "https://user:basic-password@example.test/path "
        "$" + "{{ secrets.API_KEY }} "
        "-----BEGIN PRIVATE KEY-----\nprivate-bytes\n-----END PRIVATE KEY----- "
        '{"token":"quoted-token", "apiKey": "quoted-api-key", '
        '"GITHUB_TOKEN":"github-secret", "AWS_SECRET_ACCESS_KEY":"aws-secret", '
        '"client_secret":"client-secret", "refresh_token":"refresh-secret", '
        '"token_count":42}'
    )

    redacted = redact_shareable(value, tmp_path)

    assert "literal-token" not in redacted
    assert "bearer-token" not in redacted
    assert "basic-password" not in redacted
    assert "private-bytes" not in redacted
    assert "quoted-token" not in redacted
    assert "quoted-api-key" not in redacted
    assert "github-secret" not in redacted
    assert "aws-secret" not in redacted
    assert "client-secret" not in redacted
    assert "refresh-secret" not in redacted
    assert '"token_count":42' in redacted
    assert "<secret-reference>" in redacted
    assert "<redacted-secret-block>" in redacted


def test_verify_json_redacts_quoted_secret_keys(capsys, tmp_path) -> None:
    junit = tmp_path / "results.xml"
    junit.write_text(
        '<testsuite><testcase classname="suite" name="case">'
        '<failure message="&quot;token&quot;:&quot;quoted-secret&quot;"/>'
        "</testcase></testsuite>",
        encoding="utf-8",
    )

    code = main(["verify", str(tmp_path), "--junitxml", str(junit), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert code == 2
    assert "quoted-secret" not in json.dumps(output)


def test_reusable_plan_workflow_keeps_github_context_out_of_shell() -> None:
    workflow = Path(__file__).parents[1] / ".github" / "workflows" / "greengap-plan.yml"
    document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    steps = document["jobs"]["plan"]["steps"]
    shell_text = "\n".join(
        step.get("run", "") for step in steps if isinstance(step, dict) and "run" in step
    )

    assert "${{ github." not in shell_text
    assert 'gh release verify "${RELEASE_TAG}" --repo "${GREENGAP_RELEASE_REPOSITORY}"' in shell_text
    assert 'gh release verify-asset "${RELEASE_TAG}" "${wheels[0]}" --repo "${GREENGAP_RELEASE_REPOSITORY}"' in shell_text
    assert 'gh api "repos/${GREENGAP_RELEASE_REPOSITORY}/contents/.github/requirements-runtime.txt?ref=${GREENGAP_SOURCE_REF}"' in shell_text
    assert "GREENGAP_RELEASE_REPOSITORY: Smkzz/GreenGap" in workflow.read_text(encoding="utf-8")
    assert "green-gap-source-ref:" in workflow.read_text(encoding="utf-8")
    assert "GREENGAP_SOURCE_REF: ${{ inputs.green-gap-source-ref }}" in workflow.read_text(encoding="utf-8")
    assert "${GITHUB_REPOSITORY}" not in shell_text


def test_report_examples_have_the_required_contract_shape() -> None:
    root = Path(__file__).parents[1] / "schemas" / "examples"
    for path in sorted(root.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["report_version"] == "1.0"
        assert payload["repository"] == "."
        assert payload["tool"]["runtime_proof"] is False
        assert payload["completeness"]["runtime_execution_identity"] == "NOT_CERTIFIED"
        for finding in payload["findings"]:
            assert finding["path"]
            assert finding["reason_code"]
