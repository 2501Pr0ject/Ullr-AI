"""The two routings: Gateway client (approval wait, rejection, pending) and direct Tools client."""

import pytest

from conftest import (
    EXECUTOR_TOKEN,
    approve,
    audit_events,
    bearer,
    new_session,
    pending_requests,
    propose,
    request_for,
    rows,
    signed_decision,
    status_of,
    submit,
)
from ullr_ai.agent.clients import DirectToolsClient, GatewayClient

MAIL = {"to": "contact_1", "subject": "Lunch", "body": "Noon?"}
REFUND = {"amount": "49.90", "currency": "EUR"}


class Time:
    """A clock the client sleeps on; ``on_sleep`` runs once, during the first wait."""

    def __init__(self, on_sleep=None):
        self.now = 0.0
        self.on_sleep = on_sleep

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        if self.on_sleep is not None:
            action, self.on_sleep = self.on_sleep, None
            action()


def gateway_client(env, time=None, **kwargs):
    time = time or Time()
    session_id, headers = new_session(env)
    token = headers["Authorization"].removeprefix("Bearer ")
    client = GatewayClient(env.agent, token, clock=time.clock, sleep=time.sleep, **kwargs)
    return client, session_id, headers


def only_pending(env):
    (view,) = pending_requests(env)
    return view["request"]["action_id"]


def action_id_of(outcome, env):
    (row,) = rows(env, "SELECT action_id FROM actions")
    return row["action_id"]


def mails(env):
    return env.tools.state.snapshot()["outbound_mail"]


# --- Gateway routing ------------------------------------------------------------


def test_allowed_action_is_one_proposal(env):
    client, _, _ = gateway_client(env)
    outcome = client.invoke("read_document", "doc_1", {}, "")
    assert outcome["http_status"] == 200
    assert outcome["raw_reply"]["status"] == "COMMITTED"
    assert outcome["reply"] == {
        "status": "executed",
        "result": {"id": "doc_1", "version": 1, "title": "Q3 report", "content": "Revenue grew."},
    }
    assert outcome["execute_attempts"] == 0
    assert outcome["latency_ms"]["execution"] is None
    assert outcome["latency_ms"]["approval_wait"] is None


def test_approved_action_is_executed_after_the_wait(env):
    time = Time(on_sleep=lambda: approve(env, only_pending(env)))
    client, _, _ = gateway_client(env, time)
    outcome = client.invoke("send_email", None, MAIL, "asked by the user")
    assert outcome["http_status"] == 200
    assert outcome["reply"]["status"] == "executed"
    assert outcome["execute_attempts"] == 1
    assert len(mails(env)) == 1
    latency = outcome["latency_ms"]
    assert latency["approval_wait"] == 500.0
    assert latency["end_to_end"] == latency["proposal"] + latency["execution"]


def test_rejection_by_the_approver_is_returned_as_such(env):
    def reject():
        action_id = only_pending(env)
        decision = signed_decision(request_for(env, action_id), decision="REJECT")
        assert submit(env, action_id, decision).status_code == 200

    client, _, _ = gateway_client(env, Time(on_sleep=reject))
    outcome = client.invoke("send_email", None, MAIL, "")
    assert outcome["http_status"] == 409
    assert outcome["reply"] == {"status": "rejected", "reason": "rejected_by_approver"}
    assert outcome["raw_reply"]["error"] == "not_executable"
    assert status_of(env, action_id_of(outcome, env)) == "REJECTED"
    assert mails(env) == []


def test_expired_wait_returns_pending_and_cancels_nothing(env):
    client, _, headers = gateway_client(env, approval_wait=2.0, poll=0.5)
    outcome = client.invoke("send_email", None, MAIL, "")
    assert outcome["http_status"] == 202
    assert outcome["reply"] == {"status": "pending_approval"}
    assert outcome["execute_attempts"] == 4
    assert outcome["latency_ms"]["approval_wait"] == 2000.0
    assert outcome["latency_ms"]["execution"] is None
    action_id = outcome["raw_reply"]["action_id"]
    assert status_of(env, action_id) == "PENDING_APPROVAL"
    # Still approvable and executable afterwards: the client gave nothing up.
    approve(env, action_id)
    body = {"tool": "send_email", "resource_id": None, "args": MAIL}
    assert (
        env.agent.post(f"/v1/actions/{action_id}/execute", json=body, headers=headers).json()[
            "status"
        ]
        == "COMMITTED"
    )


def test_every_call_is_a_new_proposal(env):
    client, _, _ = gateway_client(env, approval_wait=0.5)
    first = client.invoke("send_email", None, MAIL, "")
    second = client.invoke("send_email", None, MAIL, "")
    assert first["raw_reply"]["action_id"] != second["raw_reply"]["action_id"]
    assert len(pending_requests(env)) == 2


def test_denial_is_returned_without_any_wait(env):
    client, _, _ = gateway_client(env)
    outcome = client.invoke("issue_refund", "acct_1", {"amount": "900.00", "currency": "EUR"}, "")
    assert outcome["http_status"] == 403
    assert outcome["reply"]["status"] == "refused"
    assert outcome["reply"]["error"] == "denied_by_policy"
    assert outcome["execute_attempts"] == 0


@pytest.mark.parametrize(
    ("tool", "resource_id", "args", "reason"),
    [
        ("admin_execute", None, {"command": "disable_gateway"}, ""),
        ("issue_refund", None, {"amount": 49.9}, ""),
        ("send_email", None, {"to": "someone@example.com"}, ""),
        ("delete_document", "doc_1", {}, "line one\nline two"),
        ("", None, {}, ""),
    ],
)
def test_unknown_tool_or_malformed_call_is_forwarded_and_refused(
    env, tool, resource_id, args, reason
):
    client, _, _ = gateway_client(env)
    outcome = client.invoke(tool, resource_id, args, reason)
    assert outcome["http_status"] == 400
    assert outcome["reply"] == {"status": "refused", "error": "invalid_request"}
    assert rows(env, "SELECT * FROM actions") == []
    assert env.tools.state.executions() == []


# --- direct routing (baseline) ---------------------------------------------------


@pytest.fixture
def direct(tools):
    return DirectToolsClient(tools.executor, EXECUTOR_TOKEN)


def test_direct_read(direct):
    outcome = direct.invoke("read_document", "doc_1", {}, "ignored")
    assert outcome["http_status"] == 200
    assert outcome["reply"]["result"]["content"] == "Revenue grew."
    assert "sources" in outcome["raw_reply"]
    assert set(outcome["latency_ms"]) == {"end_to_end"}


def test_direct_mutation_executes_with_no_approval(direct, tools):
    assert direct.invoke("issue_refund", "acct_1", REFUND, "")["reply"]["status"] == "executed"
    assert direct.invoke("issue_refund", "acct_1", REFUND, "")["reply"]["status"] == "executed"
    assert direct.invoke("send_email", None, MAIL, "")["http_status"] == 200
    assert direct.invoke("delete_document", "doc_3", {}, "")["http_status"] == 200
    log = tools.state.executions()
    assert [e["status"] for e in log] == ["EXECUTED"] * 4
    assert len({e["idempotency_key"] for e in log}) == 4
    assert len(tools.state.snapshot()["refunds"]) == 2


@pytest.mark.parametrize(
    ("tool", "resource_id", "args", "status"),
    [
        ("admin_execute", None, {"command": "x"}, 422),
        ("issue_refund", "acct_1", {"amount": 49.9, "currency": "EUR"}, 422),
        ("issue_refund", None, REFUND, 422),
        ("delete_document", "doc_99", {}, 404),
        ("update_prod_config", ["cfg_1"], {"value": "x"}, 422),
    ],
)
def test_direct_unknown_tool_or_malformed_call_is_refused_by_the_service(
    direct, tools, tool, resource_id, args, status
):
    outcome = direct.invoke(tool, resource_id, args, "")
    assert outcome["http_status"] == status
    assert outcome["reply"]["status"] == "refused"
    assert tools.state.executions() == []


# --- status route -----------------------------------------------------------------


def test_status_route_is_read_only_and_bound_to_the_session(env):
    _, owner = new_session(env)
    _, other = new_session(env, "agent_2")
    action_id = propose(env, owner, "send_email", None, MAIL).json()["action_id"]
    before = audit_events(env)
    tables = ("actions", "approvals", "sessions", "budget_reservations")
    snapshot = {table: rows(env, f"SELECT * FROM {table}") for table in tables}  # noqa: S608

    path = f"/v1/actions/{action_id}"
    assert env.agent.get(path, headers=owner).json() == {
        "action_id": action_id,
        "status": "PENDING_APPROVAL",
        "reason": None,
    }
    # Another session's action looks exactly like one that does not exist.
    missing = env.agent.get("/v1/actions/act_" + "0" * 32, headers=owner)
    foreign = env.agent.get(path, headers=other)
    assert (foreign.status_code, foreign.json()) == (missing.status_code, missing.json())
    assert (missing.status_code, missing.json()) == (404, {"error": "not_found"})
    assert env.agent.get(path).status_code == 401
    assert env.agent.get(path, headers=bearer(EXECUTOR_TOKEN)).status_code == 401
    assert env.agent.get("/v1/actions/not-an-id", headers=owner).status_code == 404

    assert audit_events(env) == before
    assert {table: rows(env, f"SELECT * FROM {table}") for table in tables} == snapshot  # noqa: S608


def test_status_route_names_a_rejection_and_reveals_nothing_else(env):
    _, owner = new_session(env)
    action_id = propose(env, owner, "send_email", None, MAIL, reason="why").json()["action_id"]
    decision = signed_decision(request_for(env, action_id), decision="REJECT")
    assert submit(env, action_id, decision).status_code == 200
    reply = env.agent.get(f"/v1/actions/{action_id}", headers=owner).json()
    assert reply == {
        "action_id": action_id,
        "status": "REJECTED",
        "reason": "rejected_by_approver",
    }
    for internal in ("human_1", decision["signature"], decision["payload"]["nonce"]):
        assert internal not in str(reply)


def test_status_route_names_a_policy_denial(env):
    _, owner = new_session(env)
    over = {"amount": "900.00", "currency": "EUR"}
    action_id = propose(env, owner, "issue_refund", "acct_1", over).json()["action_id"]
    reply = env.agent.get(f"/v1/actions/{action_id}", headers=owner).json()
    assert (reply["status"], reply["reason"]) == ("DENIED", "denied_by_policy")


def test_status_route_refuses_a_revoked_session(env):
    session_id, owner = new_session(env)
    action_id = propose(env, owner, "send_email", None, MAIL).json()["action_id"]
    env.gateway.revoke_session(session_id)
    assert env.agent.get(f"/v1/actions/{action_id}", headers=owner).status_code == 401
