from __future__ import annotations

from greengap.junit import parse_junit
from greengap.model import FindingState


def test_junit_pass_fail_error_skip(tmp_path) -> None:
    path = tmp_path / "results.xml"
    path.write_text(
        """<testsuite>
        <testcase classname='a' name='pass' time='0.1'/>
        <testcase classname='a' name='fail'><failure message='bad'>trace</failure></testcase>
        <testcase classname='a' name='error'><error>crash</error></testcase>
        <testcase classname='a' name='skip'><skipped reason='later'/></testcase>
        </testsuite>""",
        encoding="utf-8",
    )
    cases = parse_junit(path)
    assert [case.state for case in cases] == [
        FindingState.EXECUTED_PASS,
        FindingState.EXECUTED_FAIL,
        FindingState.EXECUTED_FAIL,
        FindingState.SKIPPED,
    ]


def test_junit_missing_time_is_allowed(tmp_path) -> None:
    path = tmp_path / "results.xml"
    path.write_text("<testsuite><testcase name='x'/></testsuite>", encoding="utf-8")
    assert parse_junit(path)[0].time is None


def test_junit_error_text_is_retained(tmp_path) -> None:
    path = tmp_path / "results.xml"
    path.write_text(
        "<testsuite><testcase name='x'><error>boom</error></testcase></testsuite>", encoding="utf-8"
    )
    assert parse_junit(path)[0].message == "boom"
