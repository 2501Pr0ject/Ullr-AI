"""UNKNOWN outcomes, crash after consumption, reconciliation (T19, G4, G7)."""

import time

import httpx
import pytest

from conftest import (
    EXECUTOR_TOKEN,
    GATEWAY_ADMIN_TOKEN,
    approved,
    audit_events,
    bearer,
    execute,
    new_session,
    propose,
    rows,
    status_of,
)
from test_gateway_api import forwarding_transport
from ullr_ai.gateway.reconcile import start_loop

REFUND = {"amount": "400.00", "currency": "EUR"}
ADMIN = bearer(GATEWAY_ADMIN_TOKEN)


class Crash(Exception):
    """Stands for the Gateway process dying: no outcome gets recorded."""


def is_execute(request):
    return request.url.path == "/v1/execute"


def fault(kind):
    """A transport hook pair ``(before, after)`` injecting one fault on execute calls."""

    def trigger(request):
        if is_execute(request):
            if kind.startswith("timeout"):
                raise httpx.ReadTimeout("timeout", request=request)
            raise Crash

    if kind.endswith("before"):
        return {"before": trigger}
    return {"after": trigger}


def faulty_env(make_env, tools, kind):
    client, _ = forwarding_transport(tools, **fault(kind))
    return make_env(tools_http=client)


def reservation_states(env, action_id):
    found = rows(env, "SELECT state FROM budget_reservations WHERE action_id = ?", (action_id,))
    return {row["state"] for row in found}


def refunds(tools):
    return tools.state.snapshot()["refunds"]


def reconcile(env):
    """One pass of the reconciliation the Gateway API process runs in its loop."""
    return env.gateway.reconcile_unknown()


# --- Timeout after the action was executed -----------------------------------


def test_timeout_after_execution_is_unknown_then_reconciled_to_committed(make_env, tools):
    env = faulty_env(make_env, tools, "timeout_after")
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)

    response = execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
    assert response.status_code == 504
    assert response.json()["status"] == "UNKNOWN"
    assert "result" not in response.json()
    assert status_of(env, action_id) == "UNKNOWN"
    assert reservation_states(env, action_id) == {"HELD"}
    assert len(refunds(tools)) == 1  # the effect did happen

    assert reconcile(env) == {"COMMITTED": 1, "FAILED": 0, "unresolved": 0}
    assert status_of(env, action_id) == "COMMITTED"
    assert reservation_states(env, action_id) == {"COMMITTED"}
    assert len(refunds(tools)) == 1  # reconciliation did not execute again
    types = [e["type"] for e in audit_events(env) if e.get("action_id") == action_id]
    assert types[-3:] == ["EXECUTING", "UNKNOWN", "COMMITTED"]
    assert reconcile(env) == {"COMMITTED": 0, "FAILED": 0, "unresolved": 0}


# --- Timeout before the Tools service acted ----------------------------------


def test_timeout_before_execution_is_reconciled_to_failed_and_released(make_env, tools):
    env = faulty_env(make_env, tools, "timeout_before")
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    assert execute(env, agent, action_id, "issue_refund", "acct_1", REFUND).status_code == 504
    assert reservation_states(env, action_id) == {"HELD"}
    assert refunds(tools) == []

    assert reconcile(env) == {"COMMITTED": 0, "FAILED": 1, "unresolved": 0}
    assert status_of(env, action_id) == "FAILED"
    assert reservation_states(env, action_id) == {"RELEASED"}

    # The request lost in transit arrives after reconciliation: it must not execute,
    # otherwise the budget just released would be spent twice.
    execution_id = rows(env, "SELECT execution_id FROM actions WHERE action_id = ?", (action_id,))[
        0
    ]["execution_id"]
    late = tools.executor.post(
        "/v1/execute",
        json={"tool": "issue_refund", "resource_id": "acct_1", "args": REFUND},
        headers={**bearer(EXECUTOR_TOKEN), "Idempotency-Key": execution_id, "If-Match": "1"},
    )
    assert late.status_code == 409
    assert late.json() == {"executed": False, "error": "abandoned"}
    assert refunds(tools) == []


def test_reconciled_failure_does_not_restore_the_approval(make_env, tools):
    env = faulty_env(make_env, tools, "timeout_before")
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
    reconcile(env)
    again = execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
    assert again.status_code == 409
    assert again.json() == {"error": "not_executable"}
    assert refunds(tools) == []


def test_unknown_action_cannot_be_executed_again_before_reconciliation(make_env, tools):
    env = faulty_env(make_env, tools, "timeout_after")
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
    again = execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
    assert again.json() == {"error": "not_executable"}
    assert len(refunds(tools)) == 1


# --- Gateway crash after consumption, then restart ---------------------------


def test_crash_after_the_tools_service_executed_then_restart(make_env, tools):
    env = faulty_env(make_env, tools, "crash_after")
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)

    crashed = execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
    assert crashed.status_code == 500
    assert status_of(env, action_id) == "EXECUTING"  # consumed, outcome never recorded
    assert reservation_states(env, action_id) == {"RESERVED"}
    assert len(refunds(tools)) == 1

    restarted = make_env()  # same database, healthy transport: start-up reconciliation
    assert status_of(restarted, action_id) == "COMMITTED"
    assert reservation_states(restarted, action_id) == {"COMMITTED"}
    assert len(refunds(tools)) == 1  # no second execution

    again = execute(restarted, agent, action_id, "issue_refund", "acct_1", REFUND)
    assert again.json() == {"error": "not_executable"}
    assert len(refunds(tools)) == 1
    assert len(tools.state.executions()) == 1


def test_crash_before_the_tools_service_acted_then_restart(make_env, tools):
    env = faulty_env(make_env, tools, "crash_before")
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    assert execute(env, agent, action_id, "issue_refund", "acct_1", REFUND).status_code == 500
    assert status_of(env, action_id) == "EXECUTING"
    assert refunds(tools) == []

    restarted = make_env()
    assert status_of(restarted, action_id) == "FAILED"
    assert reservation_states(restarted, action_id) == {"RELEASED"}
    assert refunds(tools) == []
    # The approval is consumed for good: a new approval is required.
    again = execute(restarted, agent, action_id, "issue_refund", "acct_1", REFUND)
    assert again.json() == {"error": "not_executable"}
    assert [e["status"] for e in tools.state.executions()] == ["FAILED"]


def test_running_gateway_does_not_touch_executions_in_flight(make_env, tools):
    """On-demand reconciliation only resolves UNKNOWN: EXECUTING may be live."""
    env = faulty_env(make_env, tools, "crash_after")
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
    assert reconcile(env) == {"COMMITTED": 0, "FAILED": 0, "unresolved": 0}
    assert status_of(env, action_id) == "EXECUTING"
    assert reservation_states(env, action_id) == {"RESERVED"}


def test_interrupted_read_is_failed_at_restart(make_env, tools):
    env = faulty_env(make_env, tools, "crash_after")
    _, agent = new_session(env)
    assert propose(env, agent, "read_document", "doc_2").status_code == 500
    action_id = rows(env, "SELECT action_id FROM actions")[0]["action_id"]
    assert status_of(env, action_id) == "EXECUTING"
    restarted = make_env()
    assert status_of(restarted, action_id) == "FAILED"


def test_reversible_action_is_reconciled_too(make_env, tools):
    env = faulty_env(make_env, tools, "timeout_after")
    _, agent = new_session(env)
    response = propose(env, agent, "update_document", "doc_1", {"content": "v2"})
    assert response.status_code == 504
    assert reconcile(env) == {"COMMITTED": 1, "FAILED": 0, "unresolved": 0}
    assert status_of(env, response.json()["action_id"]) == "COMMITTED"
    assert tools.state.snapshot()["documents"][0]["content"] == "v2"


# --- Reconciliation itself fails closed --------------------------------------


def test_budget_stays_held_while_the_tools_service_cannot_answer(make_env, tools):
    def always_time_out(request):
        if request.url.path.startswith("/v1/exec"):
            raise httpx.ReadTimeout("timeout", request=request)

    client, _ = forwarding_transport(tools, before=always_time_out)
    env = make_env(tools_http=client)
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)

    assert reconcile(env) == {"COMMITTED": 0, "FAILED": 0, "unresolved": 1}
    assert status_of(env, action_id) == "UNKNOWN"
    assert reservation_states(env, action_id) == {"HELD"}

    # A restart with the Tools service still unreachable changes nothing either.
    still_down = make_env(tools_http=client)
    assert status_of(still_down, action_id) == "UNKNOWN"
    assert reservation_states(still_down, action_id) == {"HELD"}


@pytest.mark.parametrize(
    "reply",
    [
        httpx.Response(500, json={"error": "internal_error"}),
        httpx.Response(200, json={"idempotency_key": "exec_other", "status": "FAILED"}),
        httpx.Response(200, json={"status": "FAILED"}),
        httpx.Response(200, json={"idempotency_key": "x", "status": "MAYBE"}),
        httpx.Response(200, content=b"not json"),
    ],
)
def test_unexpected_resolution_reply_releases_nothing(make_env, tools, reply):
    def hook(request):
        if is_execute(request):
            raise httpx.ReadTimeout("timeout", request=request)
        if request.url.path.endswith("/resolve"):
            return reply
        return None

    client, _ = forwarding_transport(tools, before=hook)
    env = make_env(tools_http=client)
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
    assert reconcile(env)["unresolved"] == 1
    assert status_of(env, action_id) == "UNKNOWN"
    assert reservation_states(env, action_id) == {"HELD"}


# --- Where reconciliation runs -----------------------------------------------


def test_no_application_exposes_a_reconciliation_route(env):
    """Reconciliation is internal to the Gateway API process: nobody can trigger it."""
    _, agent = new_session(env)
    for client in (env.agent, env.admin, env.approver):
        for headers in (agent, ADMIN, {}):
            for path in ("/admin/reconcile", "/v1/reconcile"):
                assert client.post(path, headers=headers).status_code == 404


def test_background_loop_resolves_unknown_executions(make_env, tools):
    env = faulty_env(make_env, tools, "timeout_after")
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
    assert status_of(env, action_id) == "UNKNOWN"

    stop = start_loop(env.gateway, 0.05)
    try:
        deadline = time.monotonic() + 10
        while status_of(env, action_id) == "UNKNOWN" and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        stop.set()
    assert status_of(env, action_id) == "COMMITTED"
    assert reservation_states(env, action_id) == {"COMMITTED"}
    assert len(refunds(tools)) == 1


def test_process_without_tools_access_does_not_recover(make_env, tools):
    """The admin and approver processes start without touching open executions."""
    env = faulty_env(make_env, tools, "crash_after")
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
    assert status_of(env, action_id) == "EXECUTING"

    other = make_env(without_tools=True)
    assert status_of(other, action_id) == "EXECUTING"
    assert other.admin.get("/admin/state", headers=ADMIN).status_code == 200
