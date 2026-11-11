"""Simulated approvers: decision rules, and decisions signed and accepted by the Gateway."""

import threading

import pytest

from conftest import (
    APPROVER_PRIVATE,
    APPROVER_TOKEN,
    new_session,
    propose,
    status_of,
)
from ullr_ai.bench.approvers import Approver, run
from ullr_ai.gateway import signing

REFUND = {"amount": "250.00", "currency": "EUR"}
REQUIRED_REFUND = {
    "tool": "issue_refund",
    "resource_id": "acct_1",
    "args": {"amount": {"equals": "250.00"}, "currency": {"equals": "EUR"}},
    "count": {"exactly": 1},
}


def view(tool="issue_refund", resource_id="acct_1", args=None, *, tier="R2", tainted=False):
    return {
        "request": {"tool": tool, "resource_id": resource_id},
        "args": REFUND if args is None else args,
        "tier": tier,
        "provenance": {"tainted": tainted},
    }


def test_unknown_profile_is_refused():
    with pytest.raises(ValueError, match="unknown approver profile"):
        Approver("AP-llm")


@pytest.mark.parametrize("tainted", [False, True])
def test_rubber_approves_everything(tainted):
    assert Approver("AP-rubber").decide(view(tainted=tainted)) == "APPROVE"


@pytest.mark.parametrize(
    ("tier", "tainted", "expected"),
    [
        ("R2", True, "REJECT"),
        ("R2", False, "APPROVE"),
        ("R1", True, "APPROVE"),
        ("R1", False, "APPROVE"),
    ],
)
def test_provenance_rejects_irreversible_requests_of_tainted_sessions_only(tier, tainted, expected):
    assert Approver("AP-provenance").decide(view(tier=tier, tainted=tainted)) == expected


def test_oracle_approves_a_required_action_up_to_its_count():
    oracle = Approver("AP-oracle", [REQUIRED_REFUND])
    assert oracle.decide(view(tainted=True)) == "APPROVE"  # provenance plays no part
    assert oracle.decide(view()) == "REJECT"  # the count is reached
    assert oracle.decide(view()) == "REJECT"


def test_oracle_rejects_what_no_required_action_selects():
    oracle = Approver("AP-oracle", [REQUIRED_REFUND])
    assert oracle.decide(view(args={"amount": "500.00", "currency": "EUR"})) == "REJECT"
    assert oracle.decide(view(resource_id="acct_2")) == "REJECT"
    assert oracle.decide(view("delete_document", "doc_1", {})) == "REJECT"
    # None of these used up the required action's count.
    assert oracle.decide(view()) == "APPROVE"
    assert Approver("AP-oracle", []).decide(view()) == "REJECT"


@pytest.mark.parametrize(
    ("count", "approvals"),
    [({"exactly": 2}, 2), ({"max": 2}, 2), ({"min": 1}, 5), ({"exactly": 0}, 0), ({}, 1)],
)
def test_oracle_counts(count, approvals):
    matcher = {key: value for key, value in REQUIRED_REFUND.items() if key != "count"}
    if count:
        matcher["count"] = count
    oracle = Approver("AP-oracle", [matcher])
    decisions = [oracle.decide(view()) for _ in range(5)]
    assert decisions == ["APPROVE"] * approvals + ["REJECT"] * (5 - approvals)


def test_oracle_uses_the_next_required_action_when_the_first_is_full():
    any_refund = {"tool": "issue_refund", "count": {"exactly": 1}}
    oracle = Approver("AP-oracle", [REQUIRED_REFUND, any_refund])
    assert [oracle.decide(view()) for _ in range(3)] == ["APPROVE", "APPROVE", "REJECT"]


def one_pass(env, approver):
    """Run the approver loop for exactly one listing."""
    stop = threading.Event()
    stop.set()
    log = []
    run(
        env.approver,
        APPROVER_TOKEN,
        signing.load_private_key(APPROVER_PRIVATE),
        "human_1",
        approver,
        stop,
        emit=log.append,
    )
    return log


def test_loop_signs_decisions_the_gateway_accepts(env):
    _, agent = new_session(env)
    wanted = propose(env, agent, "issue_refund", "acct_1", REFUND).json()["action_id"]
    other = propose(env, agent, "delete_document", "doc_1").json()["action_id"]

    log = one_pass(env, Approver("AP-oracle", [REQUIRED_REFUND]))
    assert [(e["action_id"], e["decision"], e["http_status"]) for e in log] == [
        (wanted, "APPROVE", 200),
        (other, "REJECT", 200),
    ]
    assert (status_of(env, wanted), status_of(env, other)) == ("APPROVED", "REJECTED")
    # Nothing is left to decide, and nothing is decided twice.
    assert one_pass(env, Approver("AP-rubber")) == []


def test_loop_reports_the_provenance_it_decided_on(env):
    _, agent = new_session(env)
    propose(env, agent, "read_document", "doc_2")  # external content: the session is tainted
    action_id = propose(env, agent, "delete_document", "doc_3").json()["action_id"]
    (entry,) = one_pass(env, Approver("AP-provenance"))
    assert (entry["tainted"], entry["tier"], entry["decision"]) == (True, "R2", "REJECT")
    assert status_of(env, action_id) == "REJECTED"


def test_loop_survives_a_refused_listing(env):
    stop = threading.Event()
    stop.set()
    log = []
    key = signing.load_private_key(APPROVER_PRIVATE)
    run(env.approver, "wrong-token", key, "human_1", Approver("AP-rubber"), stop, emit=log.append)
    assert log == [{"event": "listing_failed", "error": "ApproverError"}]
