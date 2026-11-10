"""Cumulative budgets reserved inside the execute transaction (T8, G3).

Reference policy: 500.00 EUR per refund, 1000.00 EUR per account and 600.00 EUR
per agent over 24 hours.
"""

import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from conftest import (
    TOOLS_ADMIN_TOKEN,
    FakeClock,
    approved,
    execute,
    new_session,
    propose,
    rows,
    status_of,
)
from test_gateway_api import forwarding_transport
from ullr_ai import storage
from ullr_ai.tools_service.state import Seed


def refund(env, headers, account, amount):
    """Propose, approve and execute one refund. Returns ``(action_id, response)``."""
    args = {"amount": amount, "currency": "EUR"}
    action_id = approved(env, headers, "issue_refund", account, args)
    return action_id, execute(env, headers, action_id, "issue_refund", account, args)


def refunded(env, account=None):
    return sum(
        row["amount_cents"]
        for row in env.tools.state.snapshot()["refunds"]
        if account is None or row["account_id"] == account
    )


def reservations(env, action_id=None):
    query = "SELECT action_id, budget_key, amount_cents, state FROM budget_reservations"
    found = rows(env, query + " ORDER BY id")
    return [r for r in found if action_id is None or r["action_id"] == action_id]


# --- Account cap, shared by all agents ---------------------------------------


def test_three_refunds_of_400_against_the_account_cap(env):
    _, agent_1 = new_session(env, "agent_1")
    _, agent_2 = new_session(env, "agent_2")
    assert refund(env, agent_1, "acct_1", "400.00")[1].status_code == 200
    assert refund(env, agent_2, "acct_1", "400.00")[1].status_code == 200

    action_id, third = refund(env, agent_2, "acct_1", "400.00")
    assert third.status_code == 409
    assert third.json()["error"] == "budget_exceeded"
    assert refunded(env, "acct_1") == 80_000
    assert status_of(env, action_id) == "APPROVED"  # not consumed


def test_account_cap_is_reached_through_two_agents(env):
    """Neither agent exceeds its own 600.00 cap; together they hit the account's 1000.00."""
    _, agent_1 = new_session(env, "agent_1")
    _, agent_2 = new_session(env, "agent_2")
    assert refund(env, agent_1, "acct_1", "500.00")[1].status_code == 200
    assert refund(env, agent_2, "acct_1", "500.00")[1].status_code == 200  # exactly the cap

    action_id, over = refund(env, agent_1, "acct_1", "100.00")  # agent_1 would be at 600.00
    assert over.status_code == 409
    assert over.json() == {"error": "budget_exceeded", "budget": "account_id"}
    assert refunded(env, "acct_1") == 100_000
    assert reservations(env, action_id) == []

    _, smallest = refund(env, agent_2, "acct_1", "0.01")
    assert smallest.json() == {"error": "budget_exceeded", "budget": "account_id"}


def test_account_cap_does_not_leak_to_another_account(env):
    _, agent_1 = new_session(env, "agent_1")
    _, agent_2 = new_session(env, "agent_2")
    refund(env, agent_1, "acct_1", "500.00")
    refund(env, agent_2, "acct_1", "500.00")
    assert refund(env, agent_2, "acct_2", "100.00")[1].status_code == 200


# --- Per-agent cap -----------------------------------------------------------


def test_agent_cap_is_reached_across_accounts(env):
    """Each account is far below its cap; the agent's own 600.00 is what stops it."""
    _, agent_1 = new_session(env, "agent_1")
    assert refund(env, agent_1, "acct_1", "400.00")[1].status_code == 200

    action_id, second = refund(env, agent_1, "acct_2", "400.00")
    assert second.status_code == 409
    assert second.json() == {"error": "budget_exceeded", "budget": "agent_id"}
    assert refunded(env) == 40_000
    assert reservations(env, action_id) == []

    # Another agent is not affected by agent_1's consumption.
    _, agent_2 = new_session(env, "agent_2")
    assert refund(env, agent_2, "acct_2", "400.00")[1].status_code == 200


def test_agent_cap_boundary(env):
    _, agent_1 = new_session(env, "agent_1")
    assert refund(env, agent_1, "acct_1", "300.00")[1].status_code == 200
    assert refund(env, agent_1, "acct_2", "300.00")[1].status_code == 200  # exactly 600.00
    _, over = refund(env, agent_1, "acct_2", "0.01")
    assert over.json() == {"error": "budget_exceeded", "budget": "agent_id"}


def test_agent_cap_follows_the_agent_across_sessions(env):
    _, first_session = new_session(env, "agent_1")
    _, second_session = new_session(env, "agent_1")
    assert refund(env, first_session, "acct_1", "400.00")[1].status_code == 200
    _, over = refund(env, second_session, "acct_2", "400.00")
    assert over.json() == {"error": "budget_exceeded", "budget": "agent_id"}


# --- Reservation life cycle --------------------------------------------------


def test_nothing_is_reserved_before_execution(env):
    _, agent = new_session(env)
    args = {"amount": "400.00", "currency": "EUR"}
    propose(env, agent, "issue_refund", "acct_1", args)
    approved(env, agent, "issue_refund", "acct_1", args)
    propose(env, agent, "issue_refund", "acct_1", {"amount": "900.00", "currency": "EUR"})
    assert reservations(env) == []


def test_committed_execution_commits_its_reservations(env):
    _, agent = new_session(env)
    action_id, response = refund(env, agent, "acct_1", "400.00")
    assert response.status_code == 200
    assert reservations(env, action_id) == [
        {
            "action_id": action_id,
            "budget_key": "account_id:acct_1",
            "amount_cents": 40_000,
            "state": "COMMITTED",
        },
        {
            "action_id": action_id,
            "budget_key": "agent_id:agent_1",
            "amount_cents": 40_000,
            "state": "COMMITTED",
        },
    ]


def test_confirmed_failure_releases_the_budget(env):
    _, agent_1 = new_session(env, "agent_1")
    _, agent_2 = new_session(env, "agent_2")
    args = {"amount": "400.00", "currency": "EUR"}
    stale = approved(env, agent_1, "issue_refund", "acct_1", args)
    assert refund(env, agent_2, "acct_1", "100.00")[1].status_code == 200  # version moves on

    failed = execute(env, agent_1, stale, "issue_refund", "acct_1", args)
    assert (failed.json()["status"], failed.json()["error"]) == ("FAILED", "precondition_failed")
    assert {r["state"] for r in reservations(env, stale)} == {"RELEASED"}

    # The released 400.00 is available again: agent_1 can still use its full cap.
    assert refund(env, agent_1, "acct_1", "400.00")[1].status_code == 200
    assert refund(env, agent_1, "acct_2", "200.00")[1].status_code == 200
    assert refunded(env) == 70_000


def test_unknown_outcome_holds_the_budget(make_env, tools):
    def time_out_first_refund(request):
        if request.url.path == "/v1/execute" and not state["done"]:
            state["done"] = True
            raise httpx.ReadTimeout("timeout", request=request)

    state = {"done": False}
    client, _ = forwarding_transport(tools, before=time_out_first_refund)
    env = make_env(tools_http=client)
    _, agent = new_session(env)

    action_id, unknown = refund(env, agent, "acct_1", "400.00")
    assert unknown.status_code == 504
    assert status_of(env, action_id) == "UNKNOWN"
    assert {r["state"] for r in reservations(env, action_id)} == {"HELD"}

    # The held 400.00 still counts: 400.00 + 300.00 exceeds the agent's 600.00.
    _, over = refund(env, agent, "acct_2", "300.00")
    assert over.json() == {"error": "budget_exceeded", "budget": "agent_id"}
    assert refund(env, agent, "acct_2", "200.00")[1].status_code == 200


def test_budget_window_slides(make_env):
    clock = FakeClock()
    env = make_env(clock=clock)
    _, agent = new_session(env)
    assert refund(env, agent, "acct_1", "400.00")[1].status_code == 200
    assert refund(env, agent, "acct_2", "400.00")[1].status_code == 409

    clock.advance(hours=23, minutes=59)
    assert refund(env, agent, "acct_2", "400.00")[1].status_code == 409
    clock.advance(minutes=2)
    assert refund(env, agent, "acct_2", "400.00")[1].status_code == 200


# --- Concurrency (G3) --------------------------------------------------------


def test_concurrent_refunds_never_exceed_the_agent_cap(make_env, tools):
    accounts = [f"acct_{n}" for n in range(1, 7)]
    tools.state.reset(
        Seed.model_validate({"accounts": [{"id": a, "currency": "EUR"} for a in accounts]})
    )
    env = make_env()
    _, agent = new_session(env)
    args = {"amount": "250.00", "currency": "EUR"}
    approvals = [(a, approved(env, agent, "issue_refund", a, args)) for a in accounts]

    def run(item):
        account, action_id = item
        return execute(env, agent, action_id, "issue_refund", account, args)

    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(run, approvals))

    codes = sorted(response.status_code for response in responses)
    assert codes == [200, 200, 409, 409, 409, 409]  # 2 x 250.00 fit in 600.00, a third does not
    assert refunded(env) == 50_000
    counted = [r for r in reservations(env) if r["budget_key"] == "agent_id:agent_1"]
    assert sum(r["amount_cents"] for r in counted) == 50_000
    assert {r["state"] for r in counted} == {"COMMITTED"}


def test_concurrent_refunds_from_two_agents_on_one_account(env):
    _, agent_1 = new_session(env, "agent_1")
    _, agent_2 = new_session(env, "agent_2")
    args = {"amount": "500.00", "currency": "EUR"}
    jobs = []
    for headers in (agent_1, agent_2, agent_1, agent_2):
        jobs.append((headers, approved(env, headers, "issue_refund", "acct_1", args)))

    def run(job):
        headers, action_id = job
        return execute(env, headers, action_id, "issue_refund", "acct_1", args).status_code

    with ThreadPoolExecutor(max_workers=4) as pool:
        codes = list(pool.map(run, jobs))

    assert codes.count(200) >= 1
    assert refunded(env, "acct_1") <= 100_000
    live = [r for r in reservations(env) if r["state"] in ("RESERVED", "HELD", "COMMITTED")]
    account_total = sum(r["amount_cents"] for r in live if r["budget_key"] == "account_id:acct_1")
    assert account_total == refunded(env, "acct_1")
    assert all(r["state"] != "RESERVED" for r in reservations(env))


# --- Reservations cannot be rewritten ----------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM budget_reservations",
        "UPDATE budget_reservations SET amount_cents = 1",
        "UPDATE budget_reservations SET budget_key = 'account_id:acct_2'",
        "UPDATE budget_reservations SET state = 'RELEASED'",
        "UPDATE budget_reservations SET state = 'RESERVED'",
        "UPDATE budget_reservations SET created_at = '2000-01-01T00:00:00.000000Z'",
        "INSERT OR REPLACE INTO budget_reservations"
        " SELECT id, action_id, budget_key, 1, 'RELEASED', created_at FROM budget_reservations",
    ],
)
def test_committed_reservations_cannot_be_rewritten(env, statement):
    _, agent = new_session(env)
    action_id, _ = refund(env, agent, "acct_1", "400.00")
    before = reservations(env, action_id)
    conn = storage.connect(env.gateway.db_path)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(statement)
    finally:
        conn.close()
    assert reservations(env, action_id) == before


# --- Account cap under real overlap at the reservation step -------------------


def test_three_agents_race_for_one_account_budget(env):
    """Three approved 400.00 refunds on one account, executed concurrently.

    Refunds on the account are held in the Tools service before commit, so all
    three requests reach the Gateway's reservation step while the earlier
    reservations are still open. Exactly two fit under the 1000.00 cap.
    Approvals are bound to the account version, so of the two reserved refunds
    only one takes effect on the Tools side; the other is refused there and
    its reservation is released.
    """
    args = {"amount": "400.00", "currency": "EUR"}
    agents = [new_session(env, f"agent_{n}")[1] for n in (1, 2, 3)]
    jobs = [(headers, approved(env, headers, "issue_refund", "acct_1", args)) for headers in agents]
    assert [status_of(env, action_id) for _, action_id in jobs] == ["APPROVED"] * 3

    admin = {"Authorization": f"Bearer {TOOLS_ADMIN_TOKEN}"}
    holds = []
    for on_call in (1, 2):
        body = {
            "tool": "issue_refund",
            "resource_id": "acct_1",
            "on_call": on_call,
            "hold": "before_commit",
        }
        holds.append(env.tools.admin.post("/admin/faults", json=body, headers=admin).json()["id"])

    def run(job):
        headers, action_id = job
        return execute(env, headers, action_id, "issue_refund", "acct_1", args)

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(run, job) for job in jobs]

        # Wait until two requests are held in the Tools service and the third answered.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            listing = env.tools.admin.get("/admin/faults", headers=admin).json()["faults"]
            held = [f for f in listing if f["state"] == "HELD"]
            if len(held) == 2 and sum(f.done() for f in futures) == 1:
                break
            time.sleep(0.02)
        assert len(held) == 2

        # While both are held: two reservations are open, the third was refused.
        open_rows = [r for r in reservations(env) if r["budget_key"] == "account_id:acct_1"]
        assert [(r["amount_cents"], r["state"]) for r in open_rows] == [(40_000, "RESERVED")] * 2
        refused = next(f for f in futures if f.done()).result()
        assert refused.status_code == 409
        assert refused.json() == {"error": "budget_exceeded", "budget": "account_id"}
        assert refunded(env) == 0

        for fault_id in holds:
            released = env.tools.admin.post(
                f"/admin/faults/{fault_id}/release", json={"action": "continue"}, headers=admin
            )
            assert released.status_code == 200
        responses = [future.result() for future in futures]

    assert sorted(r.status_code for r in responses) == [200, 409, 409]
    # Gateway side: two reservations ever created on the account, 800.00 in total.
    account_rows = [r for r in reservations(env) if r["budget_key"] == "account_id:acct_1"]
    assert sum(r["amount_cents"] for r in account_rows) == 80_000
    assert sorted(r["state"] for r in account_rows) == ["COMMITTED", "RELEASED"]
    # Tools side: one effective execution.
    assert refunded(env, "acct_1") == 40_000
    executions = env.tools.state.executions()
    assert sorted(e["status"] for e in executions) == ["EXECUTED", "FAILED"]
