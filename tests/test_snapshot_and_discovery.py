from __future__ import annotations

import subprocess

from greengap.pytest_adapter import discover_candidates
from greengap.snapshot import workspace_snapshot

from .conftest import write_files


def git_init(root):
    subprocess.run(["git", "init", "-q"], cwd=root, check=True, capture_output=True)


def test_snapshot_changes_for_tracked_dirty_bytes(tmp_path) -> None:
    write_files(tmp_path, {"tracked.txt": "one\n", ".gitignore": ".cache/\n"})
    git_init(tmp_path)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    first = workspace_snapshot(tmp_path)
    (tmp_path / "tracked.txt").write_text("two\n", encoding="utf-8")
    second = workspace_snapshot(tmp_path)
    assert first.fingerprint != second.fingerprint


def test_snapshot_ignores_ignored_cache_bytes(tmp_path) -> None:
    write_files(tmp_path, {"tracked.txt": "one\n", ".gitignore": ".cache/\n"})
    git_init(tmp_path)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    first = workspace_snapshot(tmp_path)
    (tmp_path / ".cache").mkdir()
    (tmp_path / ".cache" / "one").write_text("one", encoding="utf-8")
    second = workspace_snapshot(tmp_path)
    assert first.fingerprint == second.fingerprint


def test_snapshot_includes_nonignored_untracked_file(tmp_path) -> None:
    write_files(tmp_path, {".gitignore": "ignored.txt\n"})
    git_init(tmp_path)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    first = workspace_snapshot(tmp_path)
    (tmp_path / "new.txt").write_text("new", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("ignored", encoding="utf-8")
    second = workspace_snapshot(tmp_path)
    assert first.fingerprint != second.fingerprint
    assert "new.txt" in second.files
    assert "ignored.txt" not in second.files


def test_default_discovery_marks_symbol_file_high(tmp_path) -> None:
    write_files(tmp_path, {"tests/test_a.py": "def test_a():\n    assert True\n"})
    candidates = discover_candidates(tmp_path)
    assert candidates[0].confidence == "high"
    assert candidates[0].symbols == ("test_a",)


def test_matching_filename_without_symbol_is_low(tmp_path) -> None:
    write_files(tmp_path, {"tests/test_data.py": "VALUE = 1\n"})
    candidates = discover_candidates(tmp_path)
    assert candidates[0].confidence == "low"


def test_default_alternate_test_filename_is_supported(tmp_path) -> None:
    write_files(tmp_path, {"tests/foo_test.py": "def test_thing():\n    pass\n"})
    assert discover_candidates(tmp_path)[0].path == "tests/foo_test.py"


def test_custom_patterns_are_used(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            "pytest.ini": "[pytest]\npython_files = check_*.py\npython_functions = check_*\npython_classes = Case*\n",
            "checks/check_math.py": "def check_math():\n    pass\n",
        },
    )
    candidates = discover_candidates(tmp_path)
    assert candidates[0].confidence == "high"
    assert candidates[0].symbols == ("check_math",)


def test_custom_class_and_method_are_high_confidence(tmp_path) -> None:
    write_files(
        tmp_path,
        {"tests/test_class.py": "class TestThing:\n    def test_method(self):\n        pass\n"},
    )
    candidate = discover_candidates(tmp_path)[0]
    assert candidate.confidence == "high"
    assert candidate.symbols == ("TestThing.test_method",)


def test_nonmatching_directory_is_ignored(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".venv/test_bad.py": "def test_bad():\n    pass\n",
            "tests/test_ok.py": "def test_ok():\n    pass\n",
        },
    )
    assert [item.path for item in discover_candidates(tmp_path)] == ["tests/test_ok.py"]


def test_syntax_error_candidate_remains_low(tmp_path) -> None:
    write_files(tmp_path, {"tests/test_broken.py": "def test_broken(:\n"})
    candidate = discover_candidates(tmp_path)[0]
    assert candidate.confidence == "low"
    assert "AST" in candidate.reason
