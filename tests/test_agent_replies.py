"""Model-visible replies: one shape in both routings, without trust labels or sources."""

from pathlib import Path

import pytest

from conftest import APPROVERS, EXECUTOR_TOKEN, approve, new_session, pending_requests
from ullr_ai.agent import replies, tools
from ullr_ai.agent.clients import DirectToolsClient, GatewayClient
from ullr_ai.bench.tasks import load_tasks, seed_of
from ullr_ai.tools_service.state import Seed

TASK = next(t for t in load_tasks(Path(__file__).resolve().parents[1] / "tasks") if t.id == "B08")

# One tool call per line, as the model would make it. External content (the
# inbox) is read last, so that the session is clean for everything before it.
CALLS = [
    ("list_documents", {}),
    ("read_document", {"document_id": "doc_1"}),
    ("get_balance", {"account_id": "acct_1"}),
    ("draft_email", {"to": "contact_3", "subject": "Refund", "body": "Done.", "reason": "r"}),
    ("update_document", {"document_id": "doc_1", "content": "Checked.", "reason": "r"}),
    (
        "issue_refund",
        {"account_id": "acct_1", "amount": "250.00", "currency": "EUR", "reason": "r"},
    ),
    ("send_email", {"to": "contact_3", "subject": "Refund", "body": "Done.", "reason": "r"}),
    ("delete_document", {"document_id": "doc_1", "reason": "r"}),
    ("read_document", {"document_id": "doc_1"}),  # deleted by now
    ("read_document", {"document_id": "doc_77"}),
    ("delete_document", {"document_id": "doc_77", "reason": "r"}),
    ("issue_refund", {"account_id": "acct_1", "amount": "5.00", "currency": "USD", "reason": "r"}),
    ("issue_refund", {"account_id": "acct_1", "amount": 5, "currency": "EUR", "reason": "r"}),
    ("send_email", {"to": "nobody@example.com", "subject": "S", "body": "B", "reason": "r"}),
    ("send_email", {"to": "contact_99", "subject": "S", "body": "B", "reason": "r"}),
    ("admin_execute", {"command": "disable"}),
    ("read_inbox", {}),
]


POLICY_DENIED = 11  # the USD refund


def play(client):
    return [client.invoke(*tools.to_action(name, arguments)) for name, arguments in CALLS]


def assert_no_label(value):
    text = str(value)
    for word in ("trust_label", "sources", "internal", "external"):
        assert word not in text, (word, text)


def test_same_task_and_same_calls_give_the_model_the_same_replies_in_both_routings(tools, make_env):
    seed = Seed.model_validate(seed_of(TASK))

    tools.state.reset(seed)
    direct = play(DirectToolsClient(tools.executor, EXECUTOR_TOKEN))

    tools.state.reset(seed)
    env = make_env()
    _, headers = new_session(env)

    def approve_everything(_seconds):
        for view in pending_requests(env):
            approve(env, view["request"]["action_id"])

    token = headers["Authorization"].removeprefix("Bearer ")
    protected = play(GatewayClient(env.agent, token, sleep=approve_everything))

    for index, ((name, _), base, gated) in enumerate(zip(CALLS, direct, protected, strict=True)):
        assert_no_label(base["reply"])
        assert_no_label(gated["reply"])
        if index == POLICY_DENIED:
            # A legitimate difference: the policy refuses a currency before the
            # Tools service is asked. Both are refusals of the same shape.
            assert (base["reply"]["status"], gated["reply"]["status"]) == ("refused", "refused")
            assert gated["reply"]["error"] == "denied_by_policy"
            continue
        assert base["reply"] == gated["reply"], name
    statuses = [outcome["reply"]["status"] for outcome in direct]
    assert statuses == ["executed"] * 8 + ["refused"] * 8 + ["executed"]
    assert [o["reply"].get("error") for o in direct[8:16]] == [
        "not_found",
        "not_found",
        "not_found",
        "currency_mismatch",
        "invalid_request",
        "invalid_request",
        "unknown_contact",
        "invalid_request",
    ]
    # The raw replies do differ, and stay out of what the model sees.
    assert "sources" in direct[0]["raw_reply"]
    assert "action_id" in protected[0]["raw_reply"]
    assert APPROVERS  # the protected run went through real approvals


def test_inbox_keeps_sender_name_and_address_and_loses_the_trust_label(tools):
    tools.state.reset(Seed.model_validate(seed_of(TASK)))
    outcome = DirectToolsClient(tools.executor, EXECUTOR_TOKEN).invoke("read_inbox", None, {}, "")
    (message,) = outcome["reply"]["result"]["messages"]
    assert message["sender"] == "Lucía Ortega <lucia.ortega@mailbox.example>"
    assert set(message) == {"id", "sender", "subject", "body"}
    assert outcome["raw_reply"]["result"]["messages"][0]["trust_label"] == "external"


def test_only_outcomes_that_legitimately_differ_differ(tools, make_env):
    """Without an approver, the protected routing answers pending where the baseline executes."""
    refund = tools_call = ("issue_refund", "acct_1", {"amount": "250.00", "currency": "EUR"}, "")
    seed = Seed.model_validate(seed_of(TASK))
    tools.state.reset(seed)
    direct = DirectToolsClient(tools.executor, EXECUTOR_TOKEN).invoke(*refund)
    tools.state.reset(seed)
    env = make_env()
    _, headers = new_session(env)
    token = headers["Authorization"].removeprefix("Bearer ")
    client = GatewayClient(env.agent, token, approval_wait=1.0, sleep=lambda _: None)
    assert direct["reply"]["status"] == "executed"
    assert client.invoke(*tools_call)["reply"] == {"status": "pending_approval"}


@pytest.mark.parametrize(
    ("http_status", "body", "action", "expected"),
    [
        (504, {"status": "UNKNOWN", "error": "tools_unavailable"}, None, {"status": "unknown"}),
        (
            409,
            {"status": "FAILED", "error": "precondition_failed"},
            None,
            {"status": "refused", "error": "precondition_failed"},
        ),
        (
            403,
            {"status": "DENIED", "reason": "amount_above_limit"},
            None,
            {"status": "refused", "error": "denied_by_policy", "reason": "amount_above_limit"},
        ),
        (
            409,
            {"error": "not_executable"},
            {"status": "REJECTED", "reason": "rejected_by_approver"},
            {"status": "rejected", "reason": "rejected_by_approver"},
        ),
        (
            409,
            {"error": "not_executable"},
            {"status": "COMMITTED", "reason": None},
            {"status": "refused", "error": "not_executable"},
        ),
        (
            409,
            {"error": "budget_exceeded", "budget": "x"},
            None,
            {"status": "refused", "error": "budget_exceeded"},
        ),
        (401, {"error": "unauthorized"}, None, {"status": "refused", "error": "unauthorized"}),
        (500, "not json", None, {"status": "refused", "error": "unexpected_reply"}),
    ],
)
def test_gateway_replies_are_normalized(http_status, body, action, expected):
    assert replies.from_gateway(http_status, body, action) == expected


@pytest.mark.parametrize(
    ("http_status", "body", "expected"),
    [
        (504, {"executed": False, "error": "fault_injected"}, {"status": "unknown"}),
        (
            412,
            {"executed": False, "error": "precondition_failed"},
            {"status": "refused", "error": "precondition_failed"},
        ),
        (404, {"error": "not_found"}, {"status": "refused", "error": "not_found"}),
        (
            200,
            {"executed": True, "result": {"id": 1}, "sources": []},
            {"status": "executed", "result": {"id": 1}},
        ),
    ],
)
def test_tools_replies_are_normalized(http_status, body, expected):
    assert replies.from_tools(http_status, body) == expected
