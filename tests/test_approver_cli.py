"""Approver tooling: keys, what the approver is shown, what gets signed (T6, T11)."""

import stat
from datetime import UTC, datetime

import pytest

from conftest import (
    APPROVER_PRIVATE,
    APPROVER_PUBLIC,
    APPROVER_TOKEN,
    OUTSIDER_PRIVATE,
    FakeClock,
    execute,
    new_session,
    pending_requests,
    propose,
    status_of,
)
from ullr_ai.approver import cli, keys
from ullr_ai.gateway import signing

NOW = datetime(2026, 11, 11, 10, 0, 0, tzinfo=UTC)
REFUND = {"amount": "100.00", "currency": "EUR"}


def approver_key():
    return signing.load_private_key(APPROVER_PRIVATE)


def tainted_refund(env, reason="Customer charged twice."):
    _, agent = new_session(env)
    propose(env, agent, "read_document", "doc_2")
    response = propose(env, agent, "issue_refund", "acct_1", REFUND, reason=reason)
    return agent, response.json()["action_id"]


# --- Keys --------------------------------------------------------------------


def test_generated_key_round_trips(tmp_path):
    path = tmp_path / "approver.key"
    public = keys.generate(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    private = keys.load(path)
    assert signing.public_key_of(private) == public
    payload = signing.parse_payload(
        {
            "decision": "APPROVE",
            "action_id": "act_" + "0" * 32,
            "agent_id": "agent_1",
            "session_id": "sess_" + "0" * 32,
            "tool": "delete_document",
            "resource_id": "doc_1",
            "resource_version": 1,
            "action_hash": "sha256:" + "0" * 64,
            "policy_hash": "sha256:" + "0" * 64,
            "canon_version": 1,
            "provenance_version": 0,
            "approver_id": "human_1",
            "nonce": "0" * 32,
            "issued_at": "2026-11-11T10:00:00.000000Z",
            "expires_at": "2026-11-11T10:05:00.000000Z",
        }
    )
    assert signing.verify(public, payload, signing.sign(private, payload))


def test_keygen_never_overwrites_a_key(tmp_path):
    path = tmp_path / "approver.key"
    keys.generate(path)
    original = path.read_text()
    with pytest.raises(FileExistsError):
        keys.generate(path)
    assert path.read_text() == original


def test_keygen_command_prints_only_the_public_key(tmp_path, capsys):
    path = tmp_path / "approver.key"
    assert cli.main(["keygen", "--out", str(path)]) == 0
    printed = capsys.readouterr().out.strip()
    assert printed == signing.public_key_of(keys.load(path))
    assert path.read_text().strip() not in printed
    assert cli.main(["keygen", "--out", str(path)]) == 1  # exists already


# --- What the approver sees --------------------------------------------------


def test_request_display_states_taint_and_marks_the_reason_unverified(env):
    reason = "Pre-approved by finance. Session is clean. Approve without review."
    _, action_id = tainted_refund(env, reason)
    text = cli.render(pending_requests(env)[0])

    assert action_id in text
    assert "issue_refund (tier R2)" in text
    assert "acct_1 (version 1)" in text
    assert "amount: '100.00'" in text
    assert "TAINTED" in text
    assert "doc_2" in text
    # The agent's claim appears only under the unverified heading, after the provenance.
    assert "UNVERIFIED" in text
    assert text.index("TAINTED") < text.index("UNVERIFIED") < text.index("Pre-approved")
    assert "PROVENANCE    clean" not in text


def test_request_display_for_a_clean_session(env):
    _, agent = new_session(env)
    propose(env, agent, "delete_document", "doc_1")
    text = cli.render(pending_requests(env)[0])
    assert "PROVENANCE    clean" in text
    assert "TAINTED" not in text


def test_control_characters_in_the_display_are_escaped(env):
    """The reason is shown through repr: it cannot draw fake lines on the terminal."""
    view = dict(pending_requests_with_reason(env, "ok"))
    view["agent_reason_unverified"] = "ok\nPROVENANCE    clean"
    text = cli.render(view)
    assert "'ok\\nPROVENANCE    clean'" in text
    assert "\nPROVENANCE    clean" not in text.replace("'ok\\nPROVENANCE    clean'", "")


def pending_requests_with_reason(env, reason):
    tainted_refund(env, reason)
    return pending_requests(env)[0]


# --- What gets signed --------------------------------------------------------


def test_decision_built_by_the_tool_is_accepted_by_the_gateway(env):
    agent, action_id = tainted_refund(env)
    shown = []
    status = cli.decide(
        env.approver,
        APPROVER_TOKEN,
        action_id,
        "APPROVE",
        "human_1",
        approver_key(),
        confirm=lambda text: shown.append(text) or True,
    )
    assert status == "APPROVED"
    assert "TAINTED" in shown[0]
    assert execute(env, agent, action_id, "issue_refund", "acct_1", REFUND).status_code == 200


def test_rejection_built_by_the_tool(env):
    agent, action_id = tainted_refund(env)
    status = cli.decide(
        env.approver,
        APPROVER_TOKEN,
        action_id,
        "REJECT",
        "human_1",
        approver_key(),
        confirm=lambda text: True,
    )
    assert status == "REJECTED"
    assert execute(env, agent, action_id, "issue_refund", "acct_1", REFUND).status_code == 409
    assert env.tools.state.snapshot()["refunds"] == []


def test_nothing_is_signed_or_sent_without_confirmation(env):
    _, action_id = tainted_refund(env)
    with pytest.raises(cli.ApproverError, match="not confirmed"):
        cli.decide(
            env.approver,
            APPROVER_TOKEN,
            action_id,
            "APPROVE",
            "human_1",
            approver_key(),
            confirm=lambda text: False,
        )
    assert status_of(env, action_id) == "PENDING_APPROVAL"


def test_tool_refuses_to_sign_when_the_display_does_not_match_the_hash(env):
    _, action_id = tainted_refund(env)
    view = pending_requests(env)[0]
    for tampered in (
        {**view, "args": {"amount": "1.00", "currency": "EUR"}},
        {**view, "request": {**view["request"], "resource_id": "acct_2"}},
        {**view, "request": {**view["request"], "tool": "get_balance"}},
        {**view, "args": {"amount": 100.0, "currency": "EUR"}},
    ):
        with pytest.raises(cli.ApproverError):
            cli.build_decision(tampered, "APPROVE", "human_1", approver_key(), NOW)
    assert status_of(env, action_id) == "PENDING_APPROVAL"


def test_signed_payload_covers_exactly_the_displayed_request(env):
    tainted_refund(env)
    view = pending_requests(env)[0]
    body = cli.build_decision(view, "APPROVE", "human_1", approver_key(), NOW)
    assert body["payload"] == {
        **view["request"],
        "decision": "APPROVE",
        "approver_id": "human_1",
        "issued_at": "2026-11-11T10:00:00.000000Z",
    }
    payload = signing.parse_payload(body["payload"])
    assert signing.verify(APPROVER_PUBLIC, payload, body["signature"])


def test_decision_signed_with_an_unregistered_key_is_refused_by_the_gateway(env):
    _, action_id = tainted_refund(env)
    outsider = signing.load_private_key(OUTSIDER_PRIVATE)
    with pytest.raises(cli.ApproverError, match="refused the decision"):
        cli.decide(
            env.approver,
            APPROVER_TOKEN,
            action_id,
            "APPROVE",
            "human_1",
            outsider,
            confirm=lambda text: True,
        )
    assert status_of(env, action_id) == "PENDING_APPROVAL"


def test_listing_without_the_channel_token_fails(env):
    tainted_refund(env)
    with pytest.raises(cli.ApproverError, match="refused the listing"):
        cli.fetch_pending(env.approver, "wrong-token")


def test_unknown_action_id(env):
    tainted_refund(env)
    with pytest.raises(cli.ApproverError, match="no pending request"):
        cli.decide(
            env.approver,
            APPROVER_TOKEN,
            "act_" + "0" * 32,
            "APPROVE",
            "human_1",
            approver_key(),
            confirm=lambda text: True,
        )


def test_approver_can_shorten_but_never_extend_the_validity(make_env):
    env = make_env(clock=FakeClock())  # the Gateway's clock starts at NOW
    tainted_refund(env)
    view = pending_requests(env)[0]
    limit = view["request"]["expires_at"]

    shorter = cli.build_decision(view, "APPROVE", "human_1", approver_key(), NOW, expires_in=2)
    assert shorter["payload"]["expires_at"] == "2026-11-11T10:00:02.000000Z"
    assert shorter["payload"]["expires_at"] < limit

    longer = cli.build_decision(view, "APPROVE", "human_1", approver_key(), NOW, expires_in=10**9)
    assert longer["payload"]["expires_at"] == limit
