"""Execution of approved actions: the execute transaction (T2, T3, T4, T5, T14, G1, G2)."""

import json
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from conftest import (
    APPROVERS,
    DEFAULT_POLICY,
    EXECUTOR_TOKEN,
    approved,
    audit_events,
    bearer,
    execute,
    new_session,
    propose,
    rows,
    status_of,
)
from test_gateway_api import block_audit_inserts, forwarding_transport
from ullr_ai import storage
from ullr_ai.gateway import approvals

EMAIL = {"to": "contact_1", "subject": "Hello", "body": "Hi"}
REFUND = {"amount": "100.00", "currency": "EUR"}
R2_ACTIONS = [
    ("send_email", None, EMAIL),
    ("delete_document", "doc_1", {}),
    ("issue_refund", "acct_1", REFUND),
    ("update_prod_config", "cfg_1", {"value": "0"}),
]


def event_types(env, action_id):
    return [e["type"] for e in audit_events(env) if e.get("action_id") == action_id]


# --- A valid approval executes exactly once ----------------------------------


@pytest.mark.parametrize(("tool", "resource_id", "args"), R2_ACTIONS)
def test_approved_irreversible_action_is_executed_once(env, tool, resource_id, args):
    _, agent = new_session(env)
    before = env.tools.state.snapshot()
    action_id = approved(env, agent, tool, resource_id, args)
    assert env.tools.state.snapshot() == before  # approval alone executes nothing

    response = execute(env, agent, action_id, tool, resource_id, args)
    assert response.status_code == 200
    assert (response.json()["action_id"], response.json()["status"]) == (action_id, "COMMITTED")
    assert env.tools.state.snapshot() != before
    assert event_types(env, action_id) == [
        "PROPOSED",
        "PENDING_APPROVAL",
        "APPROVED",
        "EXECUTING",
        "COMMITTED",
    ]
    action = rows(env, "SELECT execution_id FROM actions WHERE action_id = ?", (action_id,))[0]
    executions = env.tools.state.executions()
    assert [(e["idempotency_key"], e["tool"], e["status"]) for e in executions] == [
        (action["execution_id"], tool, "EXECUTED")
    ]


def test_effects_of_each_approved_action(env):
    _, agent = new_session(env)
    for tool, resource_id, args in R2_ACTIONS:
        action_id = approved(env, agent, tool, resource_id, args)
        assert execute(env, agent, action_id, tool, resource_id, args).status_code == 200
    snapshot = env.tools.state.snapshot()
    assert snapshot["outbound_mail"] == [
        {"id": 1, "recipient": "contact_1", "subject": "Hello", "body": "Hi"}
    ]
    assert snapshot["documents"][0]["deleted"] == 1
    assert snapshot["refunds"] == [
        {"id": 1, "account_id": "acct_1", "amount_cents": 10000, "currency": "EUR"}
    ]
    assert snapshot["config"][0]["value"] == "0"


# --- Reuse (T3) --------------------------------------------------------------


def test_approval_is_single_use(env):
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    assert execute(env, agent, action_id, "issue_refund", "acct_1", REFUND).status_code == 200

    for _ in range(3):
        again = execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
        assert again.status_code == 409
        assert again.json() == {"error": "not_executable"}
    assert len(env.tools.state.snapshot()["refunds"]) == 1
    assert len(env.tools.state.executions()) == 1


def test_concurrent_executions_consume_the_approval_once(env):
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)

    def call(_):
        return execute(env, agent, action_id, "issue_refund", "acct_1", REFUND).status_code

    with ThreadPoolExecutor(max_workers=20) as pool:
        codes = sorted(pool.map(call, range(20)))
    assert codes == [200] + [409] * 19
    assert len(env.tools.state.snapshot()["refunds"]) == 1
    assert len(env.tools.state.executions()) == 1
    assert event_types(env, action_id).count("EXECUTING") == 1


def test_failed_execution_does_not_restore_the_approval(env):
    _, agent = new_session(env)
    action_id = approved(env, agent, "send_email", None, {**EMAIL, "to": "contact_99"})
    args = {**EMAIL, "to": "contact_99"}
    failed = execute(env, agent, action_id, "send_email", None, args)
    assert failed.status_code == 409
    assert (failed.json()["status"], failed.json()["error"]) == ("FAILED", "unknown_contact")
    again = execute(env, agent, action_id, "send_email", None, args)
    assert again.json() == {"error": "not_executable"}
    assert env.tools.state.snapshot()["outbound_mail"] == []


# --- Changed arguments (T4) --------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "resource_id", "args"),
    [
        ("delete_document", "doc_3", {}),  # approve doc_1, delete doc_3
        ("update_document", "doc_1", {"content": "x"}),
        ("issue_refund", "acct_1", REFUND),
    ],
)
def test_other_action_cannot_ride_on_an_approval(env, tool, resource_id, args):
    _, agent = new_session(env)
    action_id = approved(env, agent, "delete_document", "doc_1")
    response = execute(env, agent, action_id, tool, resource_id, args)
    assert response.status_code == 409
    assert response.json() == {"error": "action_mismatch"}
    assert env.tools.state.executions() == []
    # The mismatch consumed nothing: the approved action itself still executes.
    assert status_of(env, action_id) == "APPROVED"
    assert execute(env, agent, action_id, "delete_document", "doc_1").status_code == 200
    documents = env.tools.state.snapshot()["documents"]
    assert [doc["deleted"] for doc in documents] == [1, 0, 0]


@pytest.mark.parametrize(
    "args",
    [
        {"amount": "100.01", "currency": "EUR"},
        {"amount": "500.00", "currency": "EUR"},
        {"amount": "100.00", "currency": "USD"},
    ],
)
def test_changed_refund_arguments_are_refused(env, args):
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    response = execute(env, agent, action_id, "issue_refund", "acct_1", args)
    assert response.json() == {"error": "action_mismatch"}
    assert env.tools.state.snapshot()["refunds"] == []


def test_changed_email_body_is_refused(env):
    _, agent = new_session(env)
    action_id = approved(env, agent, "send_email", None, EMAIL)
    for changed in ({**EMAIL, "body": "Hi "}, {**EMAIL, "to": "contact_2"}):
        assert execute(env, agent, action_id, "send_email", None, changed).json() == {
            "error": "action_mismatch"
        }
    assert env.tools.state.snapshot()["outbound_mail"] == []


def test_argument_order_does_not_matter(env):
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    reordered = {"currency": "EUR", "amount": "100.00"}
    assert execute(env, agent, action_id, "issue_refund", "acct_1", reordered).status_code == 200


# --- Resource changed after approval (T5) ------------------------------------


def test_resource_changed_after_approval_is_refused_by_the_tools_service(env):
    _, agent = new_session(env)
    action_id = approved(env, agent, "delete_document", "doc_1")
    assert propose(env, agent, "update_document", "doc_1", {"content": "new"}).status_code == 200

    response = execute(env, agent, action_id, "delete_document", "doc_1")
    assert response.status_code == 409
    assert (response.json()["status"], response.json()["error"]) == (
        "FAILED",
        "precondition_failed",
    )
    document = env.tools.state.snapshot()["documents"][0]
    assert (document["deleted"], document["content"]) == (0, "new")
    assert execute(env, agent, action_id, "delete_document", "doc_1").json() == {
        "error": "not_executable"
    }


def test_second_refund_approval_on_the_same_account_goes_stale(env):
    """Documented limitation: a refund approval is bound to the account version."""
    _, agent = new_session(env)
    first = approved(env, agent, "issue_refund", "acct_1", REFUND)
    second = approved(env, agent, "issue_refund", "acct_1", REFUND)
    assert execute(env, agent, first, "issue_refund", "acct_1", REFUND).status_code == 200
    stale = execute(env, agent, second, "issue_refund", "acct_1", REFUND)
    assert (stale.json()["status"], stale.json()["error"]) == ("FAILED", "precondition_failed")
    assert len(env.tools.state.snapshot()["refunds"]) == 1


# --- Ownership ---------------------------------------------------------------


def test_another_session_cannot_execute_an_approved_action(env):
    _, agent = new_session(env, "agent_1")
    _, other = new_session(env, "agent_2")
    _, same_agent = new_session(env, "agent_1")
    action_id = approved(env, agent, "delete_document", "doc_1")
    for headers in (other, same_agent, {}, bearer("wrong")):
        response = execute(env, headers, action_id, "delete_document", "doc_1")
        assert response.status_code in (401, 404)
    assert env.tools.state.executions() == []
    assert status_of(env, action_id) == "APPROVED"


# --- Fail closed inside the execute transaction (T13, T15) -------------------


def test_audit_failure_consumes_nothing_and_executes_nothing(make_env, tools):
    client, calls = forwarding_transport(tools)
    env = make_env(tools_http=client)
    _, agent = new_session(env)
    action_id = approved(env, agent, "issue_refund", "acct_1", REFUND)
    calls.clear()
    block_audit_inserts(env)

    response = execute(env, agent, action_id, "issue_refund", "acct_1", REFUND)
    assert response.status_code == 500
    assert response.json() == {"error": "internal_error"}
    assert calls == []
    assert status_of(env, action_id) == "APPROVED"
    assert rows(env, "SELECT * FROM budget_reservations") == []
    assert tools.state.snapshot()["refunds"] == []

    # Once the fault is gone, the untouched approval is still usable.
    conn = storage.connect(env.gateway.db_path)
    try:
        conn.execute("DROP TRIGGER fault")
    finally:
        conn.close()
    assert execute(env, agent, action_id, "issue_refund", "acct_1", REFUND).status_code == 200


def test_tools_service_unreachable_after_consumption_is_unknown(make_env, tools):
    def refuse_execute(request):
        if request.url.path == "/v1/execute":
            raise httpx.ConnectError("refused", request=request)

    client, _ = forwarding_transport(tools, before=refuse_execute)
    env = make_env(tools_http=client)
    _, agent = new_session(env)
    action_id = approved(env, agent, "delete_document", "doc_1")
    response = execute(env, agent, action_id, "delete_document", "doc_1")
    assert response.status_code == 504
    assert status_of(env, action_id) == "UNKNOWN"
    # The approval is consumed: an ambiguous outcome is never retried on it.
    assert execute(env, agent, action_id, "delete_document", "doc_1").json() == {
        "error": "not_executable"
    }


# --- Escalated reversible actions --------------------------------------------


def test_reversible_action_escalated_by_taint_executes_after_approval(make_env):
    text = DEFAULT_POLICY.read_text(encoding="utf-8")
    old = "  update_document:\n    tier: R1\n"
    assert old in text
    env = make_env(
        policy_text=text.replace(old, old + "    on_tainted_session: require_approval\n")
    )
    _, agent = new_session(env)
    propose(env, agent, "read_document", "doc_2")
    action_id = approved(env, agent, "update_document", "doc_1", {"content": "v2"})
    assert env.tools.state.snapshot()["documents"][0]["content"] == "Revenue grew."
    response = execute(env, agent, action_id, "update_document", "doc_1", {"content": "v2"})
    assert response.status_code == 200
    assert env.tools.state.snapshot()["documents"][0]["content"] == "v2"


# --- Every execution of an irreversible tool is backed by a valid approval ---


def test_tools_executions_are_backed_by_signed_approvals(env):
    _, agent = new_session(env)
    for tool, resource_id, args in R2_ACTIONS:
        action_id = approved(env, agent, tool, resource_id, args)
        execute(env, agent, action_id, tool, resource_id, args)
    propose(env, agent, "delete_document", "doc_3")  # pending, never approved
    propose(env, agent, "update_document", "doc_3", {"content": "x"})  # allowed R1

    conn = storage.connect(env.gateway.db_path)
    try:
        for execution in env.tools.state.executions():
            action = conn.execute(
                "SELECT action_id, tool, status FROM actions WHERE execution_id = ?",
                (execution["idempotency_key"],),
            ).fetchone()
            assert action is not None
            assert (action["tool"], action["status"]) == (execution["tool"], "COMMITTED")
            if execution["tool"] == "update_document":
                continue
            record = approvals.record_of(conn, action["action_id"])
            payload = approvals.check_decision(
                record, json.loads(record["payload"]), record["signature"], APPROVERS
            )
            assert payload.decision == "APPROVE"
    finally:
        conn.close()
    executed_tools = sorted(e["tool"] for e in env.tools.state.executions())
    assert executed_tools == sorted([tool for tool, _, _ in R2_ACTIONS] + ["update_document"])


def test_executor_token_is_not_needed_or_accepted_on_the_agent_api(env):
    _, agent = new_session(env)
    action_id = approved(env, agent, "delete_document", "doc_1")
    response = execute(env, bearer(EXECUTOR_TOKEN), action_id, "delete_document", "doc_1")
    assert response.status_code == 401
    assert env.tools.state.executions() == []
