from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import greengap.util as util_module
from greengap.pytest_adapter import discover_candidates, scan_pytest
from greengap.snapshot import workspace_snapshot
from greengap.util import (
    PathReadContext,
    bounded_filesystem_paths,
    checkout_source_equivalent_to_head,
    read_limited_bytes,
)

from .conftest import write_files


def git_init(root):
    subprocess.run(["git", "init", "-q"], cwd=root, check=True, capture_output=True)


def git_commit(root):
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=GreenGap tests",
            "-c",
            "user.email=greengap-tests@example.invalid",
            "commit",
            "-qm",
            "base",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )


def test_checkout_source_equivalence_ignores_transient_dependency_and_cache_paths(tmp_path) -> None:
    write_files(
        tmp_path,
        {
            ".gitignore": ".venv/\n.tox/\n.pytest_cache/\n",
            "README.md": "base\n",
        },
    )
    git_init(tmp_path)
    git_commit(tmp_path)
    for directory in (".venv", ".tox", ".pytest_cache"):
        path = tmp_path / directory / "marker"
        path.parent.mkdir(parents=True)
        path.write_text("generated\n", encoding="utf-8")

    assert checkout_source_equivalent_to_head(tmp_path) is True


def test_checkout_source_equivalence_rejects_nonignored_source_drift(tmp_path) -> None:
    write_files(tmp_path, {"README.md": "base\n"})
    git_init(tmp_path)
    git_commit(tmp_path)

    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_new.py").write_text(
        "def test_new():\n    pass\n", encoding="utf-8"
    )

    assert checkout_source_equivalent_to_head(tmp_path) is False


def test_checkout_source_equivalence_fails_closed_for_ignored_nontransient_file(tmp_path) -> None:
    write_files(
        tmp_path,
        {".gitignore": "local-selection.cfg\n", "README.md": "base\n"},
    )
    git_init(tmp_path)
    git_commit(tmp_path)
    (tmp_path / "local-selection.cfg").write_text("pytest tests\n", encoding="utf-8")

    assert checkout_source_equivalent_to_head(tmp_path) is None


@pytest.mark.parametrize("staged", [False, True])
def test_checkout_source_equivalence_rejects_tracked_changes(tmp_path, staged: bool) -> None:
    write_files(tmp_path, {"README.md": "base\n"})
    git_init(tmp_path)
    git_commit(tmp_path)
    (tmp_path / "README.md").write_text("changed\n", encoding="utf-8")
    if staged:
        subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True, capture_output=True)

    assert checkout_source_equivalent_to_head(tmp_path) is False


def test_snapshot_changes_for_tracked_dirty_bytes(tmp_path) -> None:
    write_files(tmp_path, {"tracked.txt": "one\n", ".gitignore": ".cache/\n"})
    git_init(tmp_path)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    first = workspace_snapshot(tmp_path)
    (tmp_path / "tracked.txt").write_text("two\n", encoding="utf-8")
    second = workspace_snapshot(tmp_path)
    assert first.fingerprint != second.fingerprint


def test_prepared_batch_read_fails_closed_when_file_changes(tmp_path) -> None:
    path = tmp_path / "candidate.py"
    path.write_text("def test_before():\n    pass\n", encoding="utf-8")
    context = PathReadContext(tmp_path)

    assert context.prepare((path,)) is None
    assert read_limited_bytes(path, 1024, parent_context=context)

    path.write_text("def test_after():\n    pass\n", encoding="utf-8")

    with pytest.raises(ValueError, match="changed during inspection"):
        read_limited_bytes(path, 1024, parent_context=context)
    assert context.verify() is not None


def test_prepared_context_reuses_a_safe_subset(monkeypatch, tmp_path) -> None:
    paths = tuple(tmp_path / name for name in ("first.py", "second.py", "third.py"))
    for path in paths:
        path.write_text("def test_case():\n    pass\n", encoding="utf-8")
    context = PathReadContext(tmp_path)
    calls: list[tuple[Path, frozenset[str]]] = []
    original = util_module._scan_selected_entries

    def counted_scan(parent, names, device):
        calls.append((parent, frozenset(names)))
        return original(parent, names, device)

    monkeypatch.setattr(util_module, "_scan_selected_entries", counted_scan)

    assert context.prepare(paths) is None
    assert context.prepare((paths[0],)) is None
    assert read_limited_bytes(paths[0], 1024, parent_context=context)
    paths[0].write_text("changed", encoding="utf-8")
    assert context.verify() is not None
    assert calls == [
        (tmp_path, frozenset(path.name for path in paths)),
        (tmp_path, frozenset({"first.py"})),
    ]


def test_filesystem_inventory_limits_directory_entries(monkeypatch, tmp_path) -> None:
    (tmp_path / "first").mkdir()
    (tmp_path / "second").mkdir()
    monkeypatch.setattr("greengap.util.MAX_PATH_INVENTORY_ITEMS", 1)

    paths, error = bounded_filesystem_paths(tmp_path)

    assert paths == ()
    assert error is not None
    assert "directory-entry" in error


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


def test_large_snapshot_parallel_path_is_deterministic(tmp_path) -> None:
    for index in range(260):
        path = tmp_path / "files" / f"file-{index:03d}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"value-{index}\n", encoding="utf-8")
    first = workspace_snapshot(tmp_path)
    second = workspace_snapshot(tmp_path)

    assert first.method == "filesystem"
    assert first.fingerprint == second.fingerprint


def test_snapshot_inventory_limit_is_incomplete(monkeypatch, tmp_path) -> None:
    write_files(tmp_path, {f"file-{index}.txt": "value\n" for index in range(3)})
    monkeypatch.setattr("greengap.util.MAX_PATH_INVENTORY_ITEMS", 2)

    snapshot = workspace_snapshot(tmp_path)

    assert not snapshot.complete
    assert any("path inventory exceeds" in error for error in snapshot.errors)
    assert len(snapshot.files) <= 2


def test_discovery_inventory_limit_is_incomplete(monkeypatch, tmp_path) -> None:
    write_files(
        tmp_path,
        {f"tests/test_{index}.py": f"def test_{index}():\n    pass\n" for index in range(3)},
    )
    monkeypatch.setattr("greengap.util.MAX_PATH_INVENTORY_ITEMS", 2)

    candidates, collection = scan_pytest(tmp_path, collect=False)

    assert candidates == ()
    assert not collection.complete
    assert "path inventory exceeds" in (collection.error or "")


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
