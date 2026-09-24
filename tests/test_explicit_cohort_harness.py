from __future__ import annotations

import importlib.util
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_explicit_cohort.py"
SPEC = importlib.util.spec_from_file_location("greengap_validate_explicit_cohort", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _source_repo(root: Path, *, ignored_file: bool = False) -> tuple[Path, str]:
    source = root / "source"
    source.mkdir()
    _git(source, "init", "-q")
    _git(source, "config", "user.name", "GreenGap test")
    _git(source, "config", "user.email", "greengap-test@example.invalid")
    (source / "tracked.py").write_text("VALUE = 1\n", encoding="utf-8")
    if ignored_file:
        (source / ".gitignore").write_text("local-only.py\n", encoding="utf-8")
    _git(source, "add", "--all")
    _git(source, "commit", "-qm", "pinned source")
    return source, _git(source, "rev-parse", "HEAD")


@pytest.mark.parametrize("dirty_kind", ("tracked", "untracked", "ignored"))
def test_initialize_target_rejects_source_bytes_outside_pinned_commit(
    tmp_path: Path, dirty_kind: str
) -> None:
    source, source_sha = _source_repo(tmp_path, ignored_file=dirty_kind == "ignored")
    if dirty_kind == "tracked":
        (source / "tracked.py").write_text("VALUE = 2\n", encoding="utf-8")
    elif dirty_kind == "untracked":
        (source / "untracked.py").write_text("VALUE = 2\n", encoding="utf-8")
    else:
        (source / "local-only.py").write_text("VALUE = 2\n", encoding="utf-8")
    case = replace(HARNESS.CASES[0], upstream_sha=source_sha)
    target = tmp_path / "target"

    with pytest.raises(HARNESS.CohortValidationError, match="SOURCE_CHECKOUT_DIRTY"):
        HARNESS._initialize_target(source, target, case)

    assert not target.exists()
    assert _git(source, "rev-parse", "HEAD") == source_sha


def test_initialize_target_accepts_clean_pinned_source(tmp_path: Path) -> None:
    source, source_sha = _source_repo(tmp_path)
    case = replace(HARNESS.CASES[0], upstream_sha=source_sha)
    target = tmp_path / "target"

    original_sha, adapted_sha, changed = HARNESS._initialize_target(source, target, case)

    assert original_sha == source_sha
    assert adapted_sha != source_sha
    assert changed == [".greengap.yml", ".greengap-pytest.ini"]
    assert (target / "tracked.py").read_bytes() == (source / "tracked.py").read_bytes()
