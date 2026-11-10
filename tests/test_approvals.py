"""Approver registry, approver channel, signed decisions and approval lifecycle
(T6, T7, T11, T16, T17, T18)."""

import base64

import httpx
import pytest

from conftest import (
    APPROVER_PUBLIC,
    APPROVER_TOKEN,
    APPROVERS,
    DEFAULT_POLICY,
    EXECUTOR_TOKEN,
    GATEWAY_ADMIN_TOKEN,
    OUTSIDER_PRIVATE,
    OUTSIDER_PUBLIC,
    FakeClock,
    approve,
    approved,
    audit_events,
    bearer,
    execute,
    new_session,
    pending_requests,
    propose,
    request_for,
    signed_decision,
    status_of,
    submit,
)
from ullr_ai.gateway import approvals, signing
from ullr_ai.gateway.canon import canonical_json

REFUND = {"amount": "100.00", "currency": "EUR"}


def pending_delete(env, headers, doc="doc_1"):
    response = propose(env, headers, "delete_document", doc, reason="Duplicate of doc_3.")
    assert response.status_code == 202
    return response.json()["action_id"]


def untouched(env):
    assert env.tools.state.executions() == []
    assert all(doc["deleted"] == 0 for doc in env.tools.state.snapshot()["documents"])


# --- Approver registry -------------------------------------------------------


def test_registry_accepts_human_approvers():
    assert approvals.validate_registry(APPROVERS) == APPROVERS


@pytest.mark.parametrize(
    "registry",
    [
        {"agent_1": APPROVER_PUBLIC},  # an agent principal
        {"agent_42": APPROVER_PUBLIC},
        {"Human_1": APPROVER_PUBLIC},
        {"human": APPROVER_PUBLIC},
        {"": APPROVER_PUBLIC},
        {1: APPROVER_PUBLIC},
        {"human_1": ""},
        {"human_1": "not-a-key"},
        {"human_1": base64.b64encode(b"\x01" * 31).decode()},
        {"human_1": None},
        ["human_1"],
        None,
    ],
)
def test_invalid_registry_is_rejected(registry):
    with pytest.raises(approvals.RegistryError):
        approvals.validate_registry(registry)


def test_gateway_refuses_to_start_with_an_agent_as_approver(make_env):
    with pytest.raises(approvals.RegistryError):
        make_env(approvers={"agent_1": APPROVER_PUBLIC})


def test_registry_file(tmp_path):
    path = tmp_path / "approvers.yaml"
    path.write_text(f'approvers:\n  human_1: "{APPROVER_PUBLIC}"\n', encoding="utf-8")
    assert approvals.load_registry(path) == APPROVERS


@pytest.mark.parametrize(
    "text",
    [
        "",
        "approvers: []\n",
        f'approvers:\n  agent_1: "{APPROVER_PUBLIC}"\n',
        f'approvers:\n  human_1: "{APPROVER_PUBLIC}"\n  human_1: "{OUTSIDER_PUBLIC}"\n',
        f'approvers:\n  human_1: "{APPROVER_PUBLIC}"\nextra: true\n',
        f'human_1: "{APPROVER_PUBLIC}"\n',
        "approvers: [\n",
    ],
)
def test_invalid_registry_file_is_rejected(tmp_path, text):
    path = tmp_path / "approvers.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(approvals.RegistryError):
        approvals.load_registry(path)


def test_missing_registry_file_is_rejected(tmp_path):
    with pytest.raises(approvals.RegistryError):
        approvals.load_registry(tmp_path / "absent.yaml")


# --- Approver channel --------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        bearer("wrong"),
        bearer(GATEWAY_ADMIN_TOKEN),
        bearer(EXECUTOR_TOKEN),
        bearer(APPROVER_TOKEN + "x"),
        {"Authorization": APPROVER_TOKEN},
    ],
)
def test_listing_requires_the_approver_channel_token(env, headers):
    _, agent = new_session(env)
    pending_delete(env, agent)
    response = env.approver.get("/v1/approvals", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}


def test_agent_token_cannot_list_approvals(env):
    _, agent = new_session(env)
    pending_delete(env, agent)
    assert env.approver.get("/v1/approvals", headers=agent).status_code == 401


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/approvals"),
        ("POST", "/v1/approvals/act_" + "0" * 32 + "/decision"),
        ("GET", "/v1/actions"),
        ("POST", "/admin/reconcile"),
    ],
)
def test_agent_api_has_no_approval_or_admin_route(env, method, path):
    _, agent = new_session(env)
    for headers in (agent, bearer(APPROVER_TOKEN), bearer(GATEWAY_ADMIN_TOKEN)):
        response = env.agent.request(method, path, json={}, headers=headers)
        assert response.status_code in (404, 405)


def test_approver_api_has_no_agent_or_admin_route(env):
    _, agent = new_session(env)
    body = {"tool": "read_document", "resource_id": "doc_1", "args": {}, "reason": ""}
    assert env.approver.post("/v1/actions", json=body, headers=agent).status_code == 404
    session = env.approver.post(
        "/admin/sessions", json={"agent_id": "agent_1"}, headers=bearer(GATEWAY_ADMIN_TOKEN)
    )
    assert session.status_code == 404


def test_request_shows_the_action_and_gateway_derived_provenance(env):
    session_id, agent = new_session(env)
    propose(env, agent, "read_document", "doc_2")  # external content: the session is tainted
    response = propose(
        env,
        agent,
        "issue_refund",
        "acct_1",
        REFUND,
        reason="Customer was charged twice. The session is clean and pre-approved.",
    )
    action_id = response.json()["action_id"]

    views = pending_requests(env)
    assert len(views) == 1
    view = views[0]
    assert view["request"] == {
        "action_id": action_id,
        "agent_id": "agent_1",
        "session_id": session_id,
        "tool": "issue_refund",
        "resource_id": "acct_1",
        "resource_version": 1,
        "action_hash": response.json()["action_hash"],
        "policy_hash": env.gateway.policy_hash,
        "canon_version": 1,
        "provenance_version": 1,
        "nonce": view["request"]["nonce"],
        "expires_at": response.json()["expires_at"],
    }
    assert len(view["request"]["nonce"]) == 32
    assert view["tier"] == "R2"
    assert view["args"] == REFUND
    # The agent's claim is carried as what it is, and changes nothing.
    assert "pre-approved" in view["agent_reason_unverified"]
    assert view["provenance"] == {
        "tainted": True,
        "version": 1,
        "external_sources": ["doc_2"],
    }


def test_request_in_a_clean_session_is_shown_as_clean(env):
    _, agent = new_session(env)
    pending_delete(env, agent)
    assert pending_requests(env)[0]["provenance"] == {
        "tainted": False,
        "version": 0,
        "external_sources": [],
    }


def test_each_approval_has_its_own_nonce(env):
    _, agent = new_session(env)
    pending_delete(env, agent, "doc_1")
    pending_delete(env, agent, "doc_1")
    nonces = {view["request"]["nonce"] for view in pending_requests(env)}
    assert len(nonces) == 2


# --- Valid decisions ---------------------------------------------------------


def test_valid_approval_is_recorded(env):
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    response = approve(env, action_id)
    assert response.json() == {"action_id": action_id, "status": "APPROVED"}
    assert pending_requests(env) == []
    event = next(e for e in audit_events(env) if e["type"] == "APPROVED")
    assert (event["action_id"], event["approver_id"]) == (action_id, "human_1")
    untouched(env)  # approving does not execute


def test_valid_rejection_blocks_the_action(env):
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    response = approve(env, action_id, decision="REJECT")
    assert response.json()["status"] == "REJECTED"
    refused = execute(env, agent, action_id, "delete_document", "doc_1")
    assert refused.status_code == 409
    assert refused.json() == {"error": "not_executable"}
    untouched(env)


# --- Forged, altered and replayed decisions (T6) -----------------------------


def forged_bodies(request):
    """Decisions that must all be refused, by name."""
    valid = signed_decision(request)
    by_outsider = signed_decision(request, private=OUTSIDER_PRIVATE)
    payload = signing.parse_payload(valid["payload"])
    outsider_key = signing.load_private_key(OUTSIDER_PRIVATE)
    wrong_domain = base64.b64encode(
        outsider_key.sign(b"OTHER/CONTEXT/v1\x00" + canonical_json(payload.model_dump()))
    ).decode()
    return {
        "unsigned": {"payload": valid["payload"], "signature": ""},
        "null signature": {"payload": valid["payload"], "signature": None},
        "garbage signature": {"payload": valid["payload"], "signature": "AAAA"},
        "zero signature": {
            "payload": valid["payload"],
            "signature": base64.b64encode(b"\x00" * 64).decode(),
        },
        "signed by an unregistered key as human_1": by_outsider,
        "unregistered approver id": signed_decision(
            request, approver_id="human_9", private=OUTSIDER_PRIVATE
        ),
        "agent signs as itself": signed_decision(
            request, approver_id="agent_1", private=OUTSIDER_PRIVATE
        ),
        "wrong domain": {"payload": valid["payload"], "signature": wrong_domain},
        "signature of another payload": {
            "payload": {**valid["payload"], "decision": "APPROVE"},
            "signature": signed_decision(request, decision="REJECT")["signature"],
        },
        "payload carries its own key": {
            "payload": {**valid["payload"], "public_key": OUTSIDER_PUBLIC},
            "signature": by_outsider["signature"],
        },
    }


FORGERIES = [
    "unsigned",
    "null signature",
    "garbage signature",
    "zero signature",
    "signed by an unregistered key as human_1",
    "unregistered approver id",
    "agent signs as itself",
    "wrong domain",
    "signature of another payload",
    "payload carries its own key",
]


@pytest.mark.parametrize("name", FORGERIES)
def test_forged_decision_is_refused_and_changes_nothing(env, name):
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    body = forged_bodies(request_for(env, action_id))[name]

    response = submit(env, action_id, body)
    assert response.status_code == 403
    assert response.json() == {"error": "invalid_decision"}
    assert status_of(env, action_id) == "PENDING_APPROVAL"
    assert execute(env, agent, action_id, "delete_document", "doc_1").status_code == 403
    untouched(env)

    # The forgery did not burn the approval: the real approver can still decide.
    assert approve(env, action_id).json()["status"] == "APPROVED"


def test_forgery_names_cover_the_builder():
    request = {field: "x" for field in approvals.BOUND_FIELDS} | {
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
        "nonce": "0" * 32,
        "expires_at": "2026-11-11T10:05:00.000000Z",
    }
    assert sorted(forged_bodies(request)) == sorted(FORGERIES)


ALTERED_FIELDS = {
    "action_id": "act_" + "9" * 32,
    "agent_id": "agent_9",
    "session_id": "sess_" + "9" * 32,
    "tool": "update_document",
    "resource_id": "doc_3",
    "resource_version": 2,
    "action_hash": "sha256:" + "9" * 64,
    "policy_hash": "sha256:" + "9" * 64,
    "canon_version": 2,
    "provenance_version": 7,
    "nonce": "9" * 32,
}


def test_altered_fields_cover_every_bound_field():
    assert set(ALTERED_FIELDS) == set(approvals.BOUND_FIELDS)


@pytest.mark.parametrize("field", sorted(ALTERED_FIELDS))
def test_correctly_signed_payload_with_one_field_altered_is_refused(env, field):
    """The registered approver signs a payload that differs from the record."""
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    body = signed_decision(request_for(env, action_id), **{field: ALTERED_FIELDS[field]})
    response = submit(env, action_id, body)
    assert response.status_code == 403
    assert status_of(env, action_id) == "PENDING_APPROVAL"
    untouched(env)


def test_decision_cannot_extend_the_expiry(make_env):
    env = make_env(clock=FakeClock())
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    request = request_for(env, action_id)
    later = request["expires_at"].replace("T10:05", "T23:59")
    assert later > request["expires_at"]
    response = submit(env, action_id, signed_decision(request, expires_at=later))
    assert response.status_code == 403
    assert status_of(env, action_id) == "PENDING_APPROVAL"


def test_decision_replayed_on_another_action_is_refused(env):
    _, agent = new_session(env)
    first = pending_delete(env, agent, "doc_1")
    second = pending_delete(env, agent, "doc_3")
    body = signed_decision(request_for(env, first))
    assert submit(env, first, body).status_code == 200

    replay = submit(env, second, body)
    assert replay.status_code == 403
    assert status_of(env, second) == "PENDING_APPROVAL"
    assert execute(env, agent, second, "delete_document", "doc_3").status_code == 403
    assert env.tools.state.executions() == []


def test_decision_for_an_identical_later_action_is_not_reusable(env):
    """Same tool, resource and arguments: only the nonce and action id differ."""
    _, agent = new_session(env)
    first = pending_delete(env, agent, "doc_1")
    body = signed_decision(request_for(env, first))
    submit(env, first, body)
    second = pending_delete(env, agent, "doc_1")
    assert submit(env, second, body).status_code == 403
    assert status_of(env, second) == "PENDING_APPROVAL"


def test_second_decision_on_the_same_action_is_refused(env):
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    request = request_for(env, action_id)
    assert submit(env, action_id, signed_decision(request, decision="REJECT")).status_code == 200
    again = submit(env, action_id, signed_decision(request))
    assert again.status_code == 409
    assert again.json() == {"error": "not_pending"}
    assert status_of(env, action_id) == "REJECTED"


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"payload": {}},
        {"signature": "x"},
        {"payload": {}, "signature": "x", "public_key": "x"},
        [],
    ],
)
def test_malformed_decision_body_is_refused(env, body):
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    response = submit(env, action_id, body)
    assert response.status_code in (400, 403)
    assert status_of(env, action_id) == "PENDING_APPROVAL"


def test_decision_on_an_unknown_or_non_approval_action(env):
    _, agent = new_session(env)
    allowed = propose(env, agent, "read_document", "doc_1").json()["action_id"]
    action_id = pending_delete(env, agent)
    body = signed_decision(request_for(env, action_id))
    assert submit(env, "act_" + "0" * 32, body).status_code == 404
    assert submit(env, "not-an-id", body).status_code == 404
    assert submit(env, allowed, body).status_code == 404


def test_registry_lookup_refuses_an_agent_principal_even_if_present():
    """Defence in depth below the registry validation."""
    request = {
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
        "nonce": "0" * 32,
        "expires_at": "2026-11-11T10:05:00.000000Z",
    }
    body = signed_decision(request, approver_id="agent_1", private=OUTSIDER_PRIVATE)
    with pytest.raises(approvals.DecisionError):
        approvals.check_decision(
            request, body["payload"], body["signature"], {"agent_1": OUTSIDER_PUBLIC}
        )


def test_decision_error_responses_do_not_echo_input(env):
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    marker = "MARKER-7f3a"
    body = signed_decision(request_for(env, action_id))
    responses = [
        submit(
            env, action_id, {"payload": {**body["payload"], marker: marker}, "signature": marker}
        ),
        submit(env, marker, body),
        env.approver.get("/v1/approvals", headers=bearer(marker)),
    ]
    for response in responses:
        assert response.status_code >= 400
        assert marker not in response.text
        assert APPROVER_TOKEN not in response.text


# --- Expiry (T7) -------------------------------------------------------------


def test_expired_request_cannot_be_approved(make_env):
    clock = FakeClock()
    env = make_env(clock=clock)
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    body = signed_decision(request_for(env, action_id))
    clock.advance(seconds=300)

    response = submit(env, action_id, body)
    assert response.status_code == 409
    assert response.json() == {"error": "approval_expired", "reason": "expired"}
    assert status_of(env, action_id) == "EXPIRED"
    assert execute(env, agent, action_id, "delete_document", "doc_1").status_code == 409
    untouched(env)


def test_request_is_valid_until_just_before_its_expiry(make_env):
    clock = FakeClock()
    env = make_env(clock=clock)
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    body = signed_decision(request_for(env, action_id))
    clock.advance(seconds=299)
    assert submit(env, action_id, body).status_code == 200


def test_expired_approval_is_not_executed(make_env):
    clock = FakeClock()
    env = make_env(clock=clock)
    _, agent = new_session(env)
    action_id = approved(env, agent, "delete_document", "doc_1")
    clock.advance(seconds=301)

    response = execute(env, agent, action_id, "delete_document", "doc_1")
    assert response.status_code == 409
    assert response.json() == {"error": "approval_expired", "reason": "expired"}
    assert status_of(env, action_id) == "EXPIRED"
    untouched(env)


def test_approver_can_shorten_the_validity(make_env):
    clock = FakeClock()
    env = make_env(clock=clock)
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    request = request_for(env, action_id)
    sooner = "2026-11-11T10:01:00.000000Z"
    assert submit(env, action_id, signed_decision(request, expires_at=sooner)).status_code == 200
    clock.advance(seconds=61)
    response = execute(env, agent, action_id, "delete_document", "doc_1")
    assert response.json() == {"error": "approval_expired", "reason": "expired"}
    untouched(env)


def test_expired_requests_leave_the_pending_list(make_env):
    clock = FakeClock()
    env = make_env(clock=clock)
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    clock.advance(seconds=300)
    assert pending_requests(env) == []
    assert status_of(env, action_id) == "EXPIRED"


# --- Invalidation (T17, T18) -------------------------------------------------


def changed_policy():
    text = DEFAULT_POLICY.read_text(encoding="utf-8")
    assert "ttl_seconds: 300" in text
    return text.replace("ttl_seconds: 300", "ttl_seconds: 301")


def test_policy_restart_invalidates_outstanding_approvals(make_env):
    env = make_env()
    _, agent = new_session(env)
    approved_id = approved(env, agent, "delete_document", "doc_1")
    pending_id = pending_delete(env, agent, "doc_3")

    restarted = make_env(policy_text=changed_policy())  # same database, another policy hash
    assert restarted.gateway.policy_hash != env.gateway.policy_hash
    assert status_of(restarted, approved_id) == "INVALIDATED"
    assert status_of(restarted, pending_id) == "INVALIDATED"

    response = execute(restarted, agent, approved_id, "delete_document", "doc_1")
    assert response.status_code == 409
    assert response.json() == {"error": "not_executable"}
    assert pending_requests(restarted) == []
    reasons = [e["reason"] for e in audit_events(restarted) if e["type"] == "INVALIDATED"]
    assert reasons == ["policy_changed", "policy_changed"]
    untouched(restarted)


def test_restart_with_the_same_policy_keeps_approvals(make_env):
    env = make_env()
    _, agent = new_session(env)
    action_id = approved(env, agent, "delete_document", "doc_1")
    restarted = make_env()
    assert status_of(restarted, action_id) == "APPROVED"
    assert execute(restarted, agent, action_id, "delete_document", "doc_1").status_code == 200


def test_session_tainted_after_approval_invalidates_it(env):
    _, agent = new_session(env)
    action_id = approved(env, agent, "delete_document", "doc_1")
    propose(env, agent, "read_document", "doc_2")  # the session becomes tainted

    response = execute(env, agent, action_id, "delete_document", "doc_1")
    assert response.status_code == 409
    assert response.json() == {"error": "approval_invalidated", "reason": "provenance_changed"}
    assert status_of(env, action_id) == "INVALIDATED"
    untouched(env)


def test_session_tainted_before_the_decision_invalidates_the_request(env):
    _, agent = new_session(env)
    action_id = pending_delete(env, agent)
    body = signed_decision(request_for(env, action_id))  # what the approver saw: clean
    propose(env, agent, "read_document", "doc_2")

    response = submit(env, action_id, body)
    assert response.status_code == 409
    assert response.json() == {"error": "approval_invalidated", "reason": "provenance_changed"}
    assert status_of(env, action_id) == "INVALIDATED"


def test_clean_reads_after_approval_do_not_invalidate_it(env):
    _, agent = new_session(env)
    action_id = approved(env, agent, "delete_document", "doc_1")
    propose(env, agent, "read_document", "doc_3")
    assert execute(env, agent, action_id, "delete_document", "doc_1").status_code == 200


def test_approver_removed_from_the_registry_invalidates_the_approval(make_env):
    env = make_env()
    _, agent = new_session(env)
    action_id = approved(env, agent, "delete_document", "doc_1")
    restarted = make_env(approvers={})
    response = execute(restarted, agent, action_id, "delete_document", "doc_1")
    assert response.status_code == 409
    assert response.json()["error"] == "approval_invalidated"
    untouched(restarted)


# --- Limit on pending approvals (T16) ----------------------------------------


def test_pending_approvals_are_limited_per_session(make_env, tools):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        forwarded = tools.executor.request(
            request.method, request.url.path, content=request.content, headers=request.headers
        )
        return httpx.Response(forwarded.status_code, content=forwarded.content)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://tools")
    env = make_env(tools_http=client)
    _, agent = new_session(env)
    first = pending_delete(env, agent, "doc_1")
    pending_delete(env, agent, "doc_3")
    pending_delete(env, agent, "doc_1")
    calls.clear()

    fourth = propose(env, agent, "delete_document", "doc_3")
    assert fourth.status_code == 403
    assert fourth.json()["reason"] == "too_many_pending"
    assert calls == []  # a DENY never contacts the Tools service
    assert len(pending_requests(env)) == 3

    # Allowed actions are unaffected, and another session has its own limit.
    assert propose(env, agent, "read_document", "doc_1").status_code == 200
    _, other = new_session(env)
    assert propose(env, other, "delete_document", "doc_1").status_code == 202

    # A decided request frees a slot.
    approve(env, first, decision="REJECT")
    assert propose(env, agent, "delete_document", "doc_3").status_code == 202


def test_expired_requests_do_not_count_against_the_limit(make_env):
    clock = FakeClock()
    env = make_env(clock=clock)
    _, agent = new_session(env)
    for _ in range(3):
        pending_delete(env, agent)
    assert propose(env, agent, "delete_document", "doc_1").status_code == 403
    clock.advance(seconds=300)
    assert propose(env, agent, "delete_document", "doc_1").status_code == 202
