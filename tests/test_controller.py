"""Controller commands: token handover by file, revocation, observation."""

import pytest

from conftest import (
    GATEWAY_ADMIN_TOKEN,
    TOOLS_ADMIN_TOKEN,
    bearer,
    propose,
    rows,
)
from ullr_ai.bench.controller import TOKEN_FILE, Controller


@pytest.fixture
def controller(env, tmp_path):
    for slot in ("1", "2"):
        (tmp_path / "episodes" / slot).mkdir(parents=True)
    return Controller(
        env.tools.admin, TOOLS_ADMIN_TOKEN, env.admin, GATEWAY_ADMIN_TOKEN, tmp_path / "episodes"
    )


def token_in(tmp_path, slot):
    return (tmp_path / "episodes" / slot / TOKEN_FILE).read_text(encoding="ascii").strip()


def test_session_token_is_handed_over_by_file_and_never_returned(env, controller, tmp_path):
    created = controller.session("agent_1", "1")
    assert set(created) == {"session_id", "agent_id"}
    token = token_in(tmp_path, "1")
    assert token not in str(created)
    assert propose(env, bearer(token), "read_document", "doc_1").status_code == 200
    stored = rows(env, "SELECT session_id FROM sessions")
    assert stored == [{"session_id": created["session_id"]}]


def test_volume_holds_only_the_current_token(env, controller, tmp_path):
    first = controller.session("agent_1", "1")
    old_token = token_in(tmp_path, "1")
    controller.revoke(first["session_id"])
    controller.session("agent_1", "1")
    new_token = token_in(tmp_path, "1")

    assert new_token != old_token
    files = sorted(p.name for p in (tmp_path / "episodes" / "1").iterdir())
    assert files == [TOKEN_FILE]
    assert propose(env, bearer(old_token), "read_document", "doc_1").status_code == 401
    assert propose(env, bearer(new_token), "read_document", "doc_1").status_code == 200


def test_slots_are_independent(env, controller, tmp_path):
    controller.session("agent_1", "1")
    controller.session("agent_2", "2")
    assert token_in(tmp_path, "1") != token_in(tmp_path, "2")


def test_observation_and_fault_commands(env, controller):
    controller.session("agent_1", "1")
    assert controller.wait(timeout=1) == {"ready": True}
    snapshot = controller.snapshot()
    assert snapshot["executions"] == []
    assert [d["id"] for d in snapshot["state"]["documents"]] == ["doc_1", "doc_2", "doc_3"]
    state = controller.state()
    assert state["audit"]["ok"] is True

    fault = controller.fault_add("issue_refund", None, 1, "before_commit")
    assert controller.fault_list()["faults"][0]["id"] == fault["id"]
    with pytest.raises(RuntimeError):
        controller.fault_release(fault["id"], "continue")  # not held


def test_seed_replaces_the_tools_state(controller):
    seed = {"accounts": [{"id": "acct_9", "currency": "EUR"}]}
    assert controller.seed(seed) == {"reset": True}
    assert [a["id"] for a in controller.snapshot()["state"]["accounts"]] == ["acct_9"]


def test_baseline_controller_has_no_gateway(env, tmp_path):
    controller = Controller(env.tools.admin, TOOLS_ADMIN_TOKEN, None, None, tmp_path)
    assert controller.wait(timeout=1) == {"ready": True}
    with pytest.raises(RuntimeError, match="no Gateway"):
        controller.session("agent_1", "1")
