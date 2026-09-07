from __future__ import annotations

import re
from pathlib import Path

from fuzz_targets.trace_fuzzer import exercise_input

REPOSITORY_ROOT = Path(__file__).parents[1]


def read_repository_file(relative_path: str) -> str:
    return (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")


def test_scorecard_raw_artifact_survives_clean_findings_failure() -> None:
    workflow = read_repository_file(".github/workflows/scorecard.yml")
    upload_start = workflow.index("- name: Upload raw Scorecard results")
    gate_start = workflow.index("- name: Enforce clean Scorecard findings")
    upload_block = workflow[upload_start:gate_start]

    assert upload_start < gate_start
    assert "if: always()" in upload_block
    assert "path: results.sarif" in upload_block
    assert 'findings="$(jq' in workflow
    assert 'test "${findings}" -eq 0' in workflow


def test_clusterfuzzlite_actions_are_immutable_v1_pins() -> None:
    workflow = read_repository_file(".github/workflows/fuzz.yml")
    pins = re.findall(r"uses: google/clusterfuzzlite/actions/[^@]+@([0-9a-f]+)", workflow)

    assert pins == [
        "884713a6c30a92e5e8544c39945cd7cb630abcd1",
        "884713a6c30a92e5e8544c39945cd7cb630abcd1",
    ]
    assert "# v1" in workflow
    assert "pull_request:" in workflow
    assert "schedule:" in workflow
    assert "workflow_dispatch:" in workflow
    assert (
        "mode: ${{ github.event_name == 'pull_request' && 'code-change' || 'coverage' }}"
        in workflow
    )
    assert (
        "sanitizer: ${{ github.event_name == 'pull_request' && 'address' || 'coverage' }}"
        in workflow
    )
    assert "keep-unaffected-fuzz-targets: true" in workflow


def test_clusterfuzzlite_python_configuration_is_real() -> None:
    project = read_repository_file(".clusterfuzzlite/project.yaml")
    dockerfile = read_repository_file(".clusterfuzzlite/Dockerfile")
    build = read_repository_file(".clusterfuzzlite/build.sh")
    target = read_repository_file("fuzz_targets/trace_fuzzer.py")

    assert project.strip() == "language: python"
    assert (
        "FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:"
        "6b2b3a7e4a2da50de47f94925cffbe34747e1aae4f33d7f07ba6c681dd648b23"
    ) in dockerfile
    assert "pip3 install --require-hashes -r" in build
    assert "requirements-runtime.txt" in build
    assert "pip3 install ." not in build
    assert 'export PYTHONPATH="$SRC/greengap/src' in build
    assert "*_fuzzer.py" in build
    assert "pyinstaller" in build
    assert "$OUT" in build
    assert "LLVMFuzzerTestOneInput" in build
    assert "atheris.Setup" in target
    assert "MAX_INPUT_BYTES = 4096" in target


def test_minimum_ci_lock_uses_the_fixed_pytest_release() -> None:
    requirements_in = read_repository_file(".github/requirements-ci-minimum.in")
    requirements_lock = read_repository_file(".github/requirements-ci-minimum.txt")
    pyproject = read_repository_file("pyproject.toml")

    assert "pytest==9.0.3" in requirements_in
    assert "pytest==9.0.3" in requirements_lock
    assert "pytest==8.4.2" not in requirements_lock
    assert '"pytest>=9.0.3"' in pyproject


def test_fuzz_target_exercises_representative_adversarial_inputs() -> None:
    for data in (
        b"pytest tests\x00src/greengap/trace.py\x00**/*.py\x00!tests/**",
        b"pytest tests; rm -rf .\x00src\\greengap\\trace.py\x00**/trace.py",
        b"python -m pytest\x00README.md\x00[bad-glob",
        bytes(range(256)) * 16,
    ):
        exercise_input(data)
