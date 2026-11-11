"""The demo's scripted agent and its reading of the results (the stacks themselves
are exercised by ``make demo``, not here)."""

import json
from pathlib import Path

import pytest

from conftest import DEFAULT_POLICY
from ullr_ai.agent import tools
from ullr_ai.bench.evaluate import matches
from ullr_ai.bench.tasks import load_schema, load_task
from ullr_ai.demo import agent, run
from ullr_ai.gateway.policy import decide, load_policy
from ullr_ai.gateway.schemas import validate_action

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def b10():
    return load_task(run.TASK, load_schema())


def as_action(call):
    return tools.to_action(call["name"], call["arguments"])


def test_b10_calls_are_those_of_the_visible_run():
    """Same tools, order and arguments as the model's calls in the visible run (AP-oracle)."""
    with (ROOT / "results" / "l3" / "visible-1" / "transcripts.jsonl").open() as lines:
        record = next(
            r
            for r in map(json.loads, lines)
            if r["task_id"] == "B10" and r["condition"] == "AP-oracle"
        )
    calls = [
        {"name": e["name"], "arguments": e["arguments"] or {}}
        for e in record["transcript"]["events"]
        if e["type"] == "tool_call"
    ]
    assert calls[:4] == run.B10_CALLS


def test_b10_calls_select_the_required_and_the_forbidden_refund(b10):
    truth = b10.ground_truth
    refunds = [as_action(c) for c in run.B10_CALLS if c["name"] == "issue_refund"]
    (
        (genuine_tool, genuine_res, genuine_args, _),
        (injected_tool, injected_res, injected_args, _),
    ) = refunds
    assert matches(truth["required_actions"][0], genuine_tool, genuine_res, genuine_args)
    assert not matches(truth["forbidden_actions"][0], genuine_tool, genuine_res, genuine_args)
    assert matches(truth["forbidden_actions"][0], injected_tool, injected_res, injected_args)
    assert not matches(truth["required_actions"][0], injected_tool, injected_res, injected_args)


def test_over_limit_call_is_one_the_reference_policy_denies():
    tool, resource_id, args, _ = as_action(run.OVER_LIMIT_CALLS[0])
    policy = load_policy(DEFAULT_POLICY).policy
    decision = decide(policy, validate_action(tool, resource_id, args), tainted=False)
    assert (decision.outcome, decision.reason) == ("DENY", "amount_over_limit")


def test_oracle_is_labelled_as_a_control_wherever_it_is_shown():
    oracle = next(c for c in run.CASES if c["profile"] == "AP-oracle")
    assert run.ORACLE_LABEL in oracle["title"]
    assert run.ORACLE_LABEL == "ground-truth-informed control, not a realistic approver"


class RecordingClient:
    def __init__(self):
        self.sent = []

    def invoke(self, tool, resource_id, args, reason):
        self.sent.append((tool, resource_id, args, reason))
        return {"http_status": 200, "reply": {"status": "executed"}, "raw_reply": {}}


def test_scripted_agent_sends_every_call_in_order_through_the_agent_mapping():
    client = RecordingClient()
    steps = agent.play(client, run.B10_CALLS)
    assert client.sent == [as_action(c) for c in run.B10_CALLS]
    assert client.sent[2] == (
        "issue_refund",
        "acct_1",
        {"amount": "35.00", "currency": "EUR"},
        "duplicate charge for order 1220",
    )
    assert [s["call"] for s in steps] == run.B10_CALLS


def test_unknown_routing_is_refused():
    with pytest.raises(ValueError):
        agent.client_for("other", {})


def gateway_action(tool, resource_id, session="sess_1"):
    return {"session_id": session, "tool": tool, "resource_id": resource_id}


def step(call, http_status=200):
    return {"call": call, "http_status": http_status}


def test_steps_are_paired_with_the_actions_of_their_session_in_order():
    calls = run.B10_CALLS
    actions = [
        gateway_action("read_inbox", None),
        gateway_action("issue_refund", "acct_9", session="sess_other"),
        gateway_action("read_document", "doc_1"),
        gateway_action("issue_refund", "acct_1"),
        gateway_action("issue_refund", "acct_2"),
    ]
    paired = run.attribute([step(c) for c in calls], actions, "sess_1")
    assert [(a["tool"], a["resource_id"]) for a in paired] == [
        ("read_inbox", None),
        ("read_document", "doc_1"),
        ("issue_refund", "acct_1"),
        ("issue_refund", "acct_2"),
    ]


def test_attribution_is_refused_rather_than_guessed():
    calls = run.B10_CALLS[2:]
    swapped = [gateway_action("issue_refund", "acct_2"), gateway_action("issue_refund", "acct_1")]
    with pytest.raises(ValueError):
        run.attribute([step(c) for c in calls], swapped, "sess_1")
    with pytest.raises(ValueError):
        run.attribute([step(c) for c in calls], swapped[:1], "sess_1")
    with pytest.raises(ValueError):
        run.attribute([step(calls[0])], [gateway_action("issue_refund", "acct_1")] * 2, "sess_1")
    # A request refused before parsing creates no action.
    assert run.attribute([step(calls[0], 400)], [], "sess_1") == [None]


def test_final_refunds_are_summed_per_account_from_the_tools_state():
    state = {
        "refunds": [
            {"account_id": "acct_1", "amount_cents": 3500, "currency": "EUR"},
            {"account_id": "acct_2", "amount_cents": 25000, "currency": "EUR"},
            {"account_id": "acct_1", "amount_cents": 5, "currency": "EUR"},
        ]
    }
    assert run.refunds_by_account(state) == {"acct_1 EUR": "35.05", "acct_2 EUR": "250.00"}
    assert run.refunds_by_account({"refunds": []}) == {}
