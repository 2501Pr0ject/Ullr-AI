"""Controlled faults in the Tools service: hold, release, drop (T19 support, G7)."""

import threading
import time

import pytest
from fastapi.testclient import TestClient

from conftest import EXECUTOR_TOKEN, TOOLS_ADMIN_TOKEN, bearer
from ullr_ai.tools_service import faults
from ullr_ai.tools_service.app import create_executor_app

ADMIN = bearer(TOOLS_ADMIN_TOKEN)
AUTH = bearer(EXECUTOR_TOKEN)
REFUND = {
    "tool": "issue_refund",
    "resource_id": "acct_1",
    "args": {"amount": "100.00", "currency": "EUR"},
}


def add_fault(tools, hold, tool="issue_refund", resource_id="acct_1", on_call=1):
    body = {"tool": tool, "resource_id": resource_id, "on_call": on_call, "hold": hold}
    response = tools.admin.post("/admin/faults", json=body, headers=ADMIN)
    assert response.status_code == 201
    return response.json()["id"]


def fault_state(tools, fault_id):
    listing = tools.admin.get("/admin/faults", headers=ADMIN).json()["faults"]
    return next(f for f in listing if f["id"] == fault_id)


def wait_held(tools, fault_id, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fault_state(tools, fault_id)["state"] == "HELD":
            return
        time.sleep(0.02)
    raise AssertionError("the request was never held")


def outcome(tools, fault_id):
    """What the held request did after its wait, as recorded by the Tools service."""
    row = fault_state(tools, fault_id)
    return row["outcome"], row["outcome_status"], row["outcome_error"]


def release(tools, fault_id, action):
    return tools.admin.post(
        f"/admin/faults/{fault_id}/release", json={"action": action}, headers=ADMIN
    )


class Call:
    """One execute request running in its own thread."""

    def __init__(self, tools, body=REFUND, key="key-held-0001", if_match="1"):
        self.response = None
        headers = {**AUTH, "Idempotency-Key": key, "If-Match": if_match}

        def run():
            self.response = tools.executor.post("/v1/execute", json=body, headers=headers)

        self.thread = threading.Thread(target=run)
        self.thread.start()

    def finish(self):
        self.thread.join(timeout=15)
        assert not self.thread.is_alive()
        return self.response


def refunds(tools):
    return tools.state.snapshot()["refunds"]


# --- Hold before commit ------------------------------------------------------


def test_request_held_before_commit_has_no_effect_until_released(tools):
    fault_id = add_fault(tools, "before_commit")
    call = Call(tools)
    wait_held(tools, fault_id)

    assert refunds(tools) == []
    assert tools.state.executions() == []
    assert fault_state(tools, fault_id)["idempotency_key"] == "key-held-0001"

    assert release(tools, fault_id, "continue").status_code == 200
    response = call.finish()
    assert response.status_code == 200
    assert len(refunds(tools)) == 1
    assert [e["status"] for e in tools.state.executions()] == ["EXECUTED"]
    assert outcome(tools, fault_id) == ("continued", 200, None)


def test_request_dropped_before_commit_executes_and_records_nothing(tools):
    fault_id = add_fault(tools, "before_commit")
    call = Call(tools)
    wait_held(tools, fault_id)
    release(tools, fault_id, "drop")

    response = call.finish()
    assert response.status_code == 504
    assert response.json() == {"executed": False, "error": "fault_injected"}
    assert refunds(tools) == []
    assert tools.state.executions() == []
    assert outcome(tools, fault_id) == ("dropped", None, None)


# --- Hold after commit -------------------------------------------------------


def test_request_held_after_commit_has_already_taken_effect(tools):
    fault_id = add_fault(tools, "after_commit")
    call = Call(tools)
    wait_held(tools, fault_id)

    # The effect is committed and recorded while the response is withheld.
    assert len(refunds(tools)) == 1
    assert [e["status"] for e in tools.state.executions()] == ["EXECUTED"]

    release(tools, fault_id, "drop")  # the response is lost
    assert call.finish().status_code == 504
    assert len(refunds(tools)) == 1
    assert outcome(tools, fault_id) == ("dropped", 200, None)
    # The caller can still learn the truth from the idempotency key.
    resolved = tools.executor.post(
        "/v1/executions/key-held-0001/resolve",
        json={"tool": "issue_refund", "resource_id": "acct_1"},
        headers=AUTH,
    )
    assert resolved.json()["status"] == "EXECUTED"


# --- A held request never blocks the burn, and the burn is honoured (K3) -----


def test_key_burned_while_the_request_is_held_is_enforced_by_the_tools_service(tools):
    fault_id = add_fault(tools, "before_commit")
    call = Call(tools)
    wait_held(tools, fault_id)

    started = time.monotonic()
    burned = tools.executor.post(
        "/v1/executions/key-held-0001/resolve",
        json={"tool": "issue_refund", "resource_id": "acct_1"},
        headers=AUTH,
    )
    assert time.monotonic() - started < 2  # not blocked by the held request
    assert burned.json() == {"idempotency_key": "key-held-0001", "status": "FAILED"}

    release(tools, fault_id, "continue")
    response = call.finish()
    assert response.status_code == 409
    assert response.json() == {"executed": False, "error": "abandoned"}
    assert refunds(tools) == []
    assert [e["status"] for e in tools.state.executions()] == ["FAILED"]
    # The refusal is recorded by the Tools service itself, even if nobody is
    # left to receive the response: the request resumed, reached the key
    # lookup, and was refused there.
    assert outcome(tools, fault_id) == ("continued", 409, "abandoned")
    assert tools.state.executions()[0]["request_hash"] == "abandoned"


def test_other_requests_proceed_while_one_is_held(tools):
    fault_id = add_fault(tools, "before_commit")
    held = Call(tools)
    wait_held(tools, fault_id)

    other = {**REFUND, "resource_id": "acct_2"}
    headers = {**AUTH, "Idempotency-Key": "key-other-001", "If-Match": "1"}
    assert tools.executor.post("/v1/execute", json=other, headers=headers).status_code == 200
    read = {"tool": "get_balance", "resource_id": "acct_1", "args": {}}
    assert tools.executor.post("/v1/execute", json=read, headers=AUTH).status_code == 200

    release(tools, fault_id, "continue")
    assert held.finish().status_code == 200


# --- Matching ----------------------------------------------------------------


def test_only_the_nth_matching_call_is_held(tools):
    fault_id = add_fault(tools, "before_commit", on_call=2)
    first = Call(tools, key="key-first-001").finish()
    assert first.status_code == 200
    assert fault_state(tools, fault_id)["state"] == "ARMED"

    second = Call(tools, key="key-second-01", if_match="2")
    wait_held(tools, fault_id)
    release(tools, fault_id, "continue")
    assert second.finish().status_code == 200
    # A released fault does not fire again.
    third = Call(tools, key="key-third-001", if_match="3").finish()
    assert third.status_code == 200
    assert fault_state(tools, fault_id)["state"] == "RELEASED"


def test_fault_matches_its_tool_and_resource_only(tools):
    fault_id = add_fault(tools, "before_commit")
    other_account = Call(tools, {**REFUND, "resource_id": "acct_2"}, key="key-acct-2-1").finish()
    other_tool = Call(
        tools, {"tool": "delete_document", "resource_id": "doc_1", "args": {}}, key="key-doc-0001"
    ).finish()
    assert (other_account.status_code, other_tool.status_code) == (200, 200)
    assert fault_state(tools, fault_id)["state"] == "ARMED"


def test_fault_without_a_resource_matches_any_resource(tools):
    fault_id = add_fault(tools, "before_commit", resource_id=None)
    call = Call(tools, {**REFUND, "resource_id": "acct_2"})
    wait_held(tools, fault_id)
    release(tools, fault_id, "continue")
    assert call.finish().status_code == 200


def test_reads_are_never_held(tools):
    add_fault(tools, "before_commit", tool="update_document", resource_id="doc_1")
    read = {"tool": "read_document", "resource_id": "doc_1", "args": {}}
    assert tools.executor.post("/v1/execute", json=read, headers=AUTH).status_code == 200


# --- Limits ------------------------------------------------------------------


def test_request_held_too_long_is_dropped(tools):
    app = TestClient(create_executor_app(tools.state, EXECUTOR_TOKEN, fault_max_wait=0.2))
    fault_id = add_fault(tools, "before_commit")
    headers = {**AUTH, "Idempotency-Key": "key-timeout-1", "If-Match": "1"}
    response = app.post("/v1/execute", json=REFUND, headers=headers)
    assert response.status_code == 504
    assert refunds(tools) == []
    assert fault_state(tools, fault_id)["state"] == "HELD"
    # A time-out is recorded as such: it must never be mistaken for a refusal.
    assert outcome(tools, fault_id) == ("timed_out", None, None)


def test_reset_clears_faults_and_drops_a_held_request(tools):
    fault_id = add_fault(tools, "before_commit")
    call = Call(tools)
    wait_held(tools, fault_id)
    assert tools.admin.post("/admin/reset", headers=ADMIN).status_code == 200
    assert call.finish().status_code == 504
    assert tools.admin.get("/admin/faults", headers=ADMIN).json() == {"faults": []}
    assert refunds(tools) == []


def test_releasing_a_fault_that_is_not_held(tools):
    fault_id = add_fault(tools, "before_commit")
    assert release(tools, fault_id, "continue").status_code == 409
    assert release(tools, 999, "continue").status_code == 409
    assert fault_state(tools, fault_id)["state"] == "ARMED"


def test_wait_does_not_hold_a_database_lock(tools):
    """While a request waits, a writer gets the write lock immediately."""
    fault_id = add_fault(tools, "before_commit")
    call = Call(tools)
    wait_held(tools, fault_id)
    started = time.monotonic()
    with tools.state.transaction() as conn:
        conn.execute("UPDATE config SET value = 'changed'")
    assert time.monotonic() - started < 1
    release(tools, fault_id, "continue")
    call.finish()


# --- Access ------------------------------------------------------------------


@pytest.mark.parametrize("headers", [{}, AUTH, bearer("wrong")])
def test_fault_routes_require_the_admin_token(tools, headers):
    body = {"tool": "issue_refund", "resource_id": None, "on_call": 1, "hold": "before_commit"}
    assert tools.admin.post("/admin/faults", json=body, headers=headers).status_code == 401
    assert tools.admin.get("/admin/faults", headers=headers).status_code == 401
    release_body = {"action": "continue"}
    response = tools.admin.post("/admin/faults/1/release", json=release_body, headers=headers)
    assert response.status_code == 401
    assert faults.listing(tools.state.db_path) == []


def test_fault_routes_do_not_exist_on_the_executor_app(tools):
    body = {"tool": "issue_refund", "resource_id": None, "on_call": 1, "hold": "before_commit"}
    for headers in (ADMIN, AUTH):
        assert tools.executor.post("/admin/faults", json=body, headers=headers).status_code == 404
        assert tools.executor.get("/admin/faults", headers=headers).status_code == 404
    assert faults.listing(tools.state.db_path) == []


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"tool": "read_document", "resource_id": None, "on_call": 1, "hold": "before_commit"},
        {"tool": "drop_database", "resource_id": None, "on_call": 1, "hold": "before_commit"},
        {"tool": "issue_refund", "resource_id": None, "on_call": 0, "hold": "before_commit"},
        {"tool": "issue_refund", "resource_id": None, "on_call": "1", "hold": "before_commit"},
        {"tool": "issue_refund", "resource_id": None, "on_call": True, "hold": "before_commit"},
        {"tool": "issue_refund", "resource_id": None, "on_call": 1, "hold": "during_commit"},
        {"tool": "issue_refund", "resource_id": 7, "on_call": 1, "hold": "before_commit"},
        {
            "tool": "issue_refund",
            "resource_id": None,
            "on_call": 1,
            "hold": "before_commit",
            "x": 1,
        },
    ],
)
def test_invalid_fault_is_rejected(tools, body):
    assert tools.admin.post("/admin/faults", json=body, headers=ADMIN).status_code == 400
    assert faults.listing(tools.state.db_path) == []


@pytest.mark.parametrize("body", [{}, {"action": "explode"}, {"action": "continue", "x": 1}, []])
def test_invalid_release_is_rejected(tools, body):
    fault_id = add_fault(tools, "before_commit")
    response = tools.admin.post(f"/admin/faults/{fault_id}/release", json=body, headers=ADMIN)
    assert response.status_code == 400


# --- Self-releasing rules (task faults) -----------------------------------------


def auto_fault(tools, hold, **overrides):
    body = {
        "tool": "issue_refund",
        "resource_id": "acct_1",
        "on_call": 1,
        "hold": hold,
        "auto_release": "drop",
        **overrides,
    }
    response = tools.admin.post("/admin/faults", json=body, headers=ADMIN)
    assert response.status_code == 201
    return response.json()["id"]


def call_now(tools, key="key-auto-0001", if_match="1"):
    headers = {**AUTH, "Idempotency-Key": key, "If-Match": if_match}
    return tools.executor.post("/v1/execute", json=REFUND, headers=headers)


def test_self_releasing_fault_before_commit_executes_nothing(tools):
    fault_id = auto_fault(tools, "before_commit")
    response = call_now(tools)
    assert (response.status_code, response.json()) == (
        504,
        {"executed": False, "error": "fault_injected"},
    )
    assert refunds(tools) == []
    assert tools.state.executions() == []
    assert fault_state(tools, fault_id)["state"] == "RELEASED"
    assert outcome(tools, fault_id) == ("dropped", None, None)


def test_self_releasing_fault_after_commit_executes_then_loses_the_response(tools):
    fault_id = auto_fault(tools, "after_commit")
    response = call_now(tools)
    assert (response.status_code, response.json()) == (
        504,
        {"executed": False, "error": "fault_injected"},
    )
    assert len(refunds(tools)) == 1
    assert [e["status"] for e in tools.state.executions()] == ["EXECUTED"]
    assert outcome(tools, fault_id) == ("dropped", 200, None)
    # The same key answers from the stored outcome: the effect is not repeated.
    assert call_now(tools).status_code == 200
    assert len(refunds(tools)) == 1


def test_self_releasing_fault_trips_once_on_the_nth_call(tools):
    auto_fault(tools, "before_commit", on_call=2)
    assert call_now(tools, key="key-auto-0001").status_code == 200
    assert call_now(tools, key="key-auto-0002", if_match="2").status_code == 504
    assert call_now(tools, key="key-auto-0003", if_match="2").status_code == 200
    assert len(refunds(tools)) == 2


def test_self_releasing_fault_cannot_be_released_by_hand(tools):
    fault_id = auto_fault(tools, "before_commit")
    call_now(tools)
    assert release(tools, fault_id, "continue").status_code == 409


@pytest.mark.parametrize("value", ["continue", "", None, 1, True])
def test_invalid_auto_release_is_rejected(tools, value):
    body = {
        "tool": "issue_refund",
        "resource_id": None,
        "on_call": 1,
        "hold": "before_commit",
        "auto_release": value,
    }
    assert tools.admin.post("/admin/faults", json=body, headers=ADMIN).status_code == 400
    assert tools.admin.get("/admin/faults", headers=ADMIN).json() == {"faults": []}
