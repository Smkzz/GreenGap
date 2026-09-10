from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.release_state import (
    ReleaseBinding,
    ReleaseState,
    advance,
    load_state,
    save_state,
)
from scripts.release_state import main as release_state_main


def binding() -> ReleaseBinding:
    return ReleaseBinding(
        "1.0.0rc1",
        "a" * 40,
        "b" * 40,
        "v1.0.0-rc.1",
        (
            ("greengap-1.0.0rc1-py3-none-any.whl", "c" * 64),
            ("greengap-1.0.0rc1.tar.gz", "d" * 64),
        ),
    )


def test_release_state_requires_one_way_exact_binding() -> None:
    state = ReleaseState.discover(binding())
    qualified = advance(state, "QUALIFY")

    assert qualified.history == ("DISCOVER", "QUALIFY")
    assert advance(qualified, "QUALIFY") == qualified
    with pytest.raises(ValueError, match="one stage"):
        advance(qualified, "BUILD")
    with pytest.raises(ValueError, match="binding changed"):
        advance(qualified, "FREEZE", binding=ReleaseBinding("1.0.0rc1", "c" * 40, "b" * 40, "v1.0.0-rc.1"))


def test_release_state_requires_human_and_public_evidence() -> None:
    state = ReleaseState.discover(binding())
    for stage in ("QUALIFY", "FREEZE", "REVIEW", "MERGE", "VERIFY_MAIN", "BUILD", "VERIFY_DRAFT", "HUMAN_AUTHORIZE"):
        state = advance(state, stage)
    with pytest.raises(ValueError, match="human-approval"):
        advance(state, "PUBLISH_ONCE")
    state = advance(state, "PUBLISH_ONCE", evidence=("human-approval:owner-2026-09-07",))
    with pytest.raises(ValueError, match="public-verification"):
        advance(state, "VERIFY_PUBLIC")
    assert advance(state, "VERIFY_PUBLIC", evidence=("public-verification:packet-1",)).stage == "VERIFY_PUBLIC"


def test_release_state_round_trips_with_bounded_json(tmp_path: Path) -> None:
    path = tmp_path / "release-state.json"
    state = advance(ReleaseState.discover(binding()), "QUALIFY", evidence=("tests:pass",))
    save_state(path, state)

    assert load_state(path) == state
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1
    assert len(json.loads(path.read_text(encoding="utf-8"))["binding"]["artifacts"]) == 2


@pytest.mark.parametrize("raw", ["[]", "null", '"release-state"', "42"])
def test_release_state_rejects_non_object_json_without_traceback(
    tmp_path: Path, raw: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "release-state.json"
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(ValueError, match="release state must be a JSON object"):
        load_state(path)
    assert release_state_main(["--state", str(path)]) == 2
    assert "Traceback" not in capsys.readouterr().out


def test_release_state_rejects_deep_json_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "release-state.json"
    path.write_text("[" * 2048 + "]" * 2048, encoding="utf-8")

    with pytest.raises(ValueError, match="invalid release state"):
        load_state(path)
    assert release_state_main(["--state", str(path)]) == 2
    assert "Traceback" not in capsys.readouterr().out
