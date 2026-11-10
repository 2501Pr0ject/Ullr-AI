"""Gateway agent API: decisions, execution path, fail closed (T2, T4, T9, T10, T13, T15)."""

import httpx
import pytest

from conftest import (
    DEFAULT_POLICY,
    EXECUTOR_TOKEN,
    GATEWAY_ADMIN_TOKEN,
    INJECTION,
    audit_events,
    new_session,
    propose,
    provenance_of,
    rows,
)
from ullr_ai import storage
from ullr_ai.gateway import app as gateway_app
from ullr_ai.gateway import audit
from ullr_ai.gateway.canon import MAX_BYTES

EMAIL = {"to": "contact_1", "subject": "Hello", "body": "Hi"}
REFUND = {"amount": "100.00", "currency": "EUR"}
R2_ACTIONS = [
    ("send_email", None, EMAIL),
    ("delete_document", "doc_1", {}),
    ("issue_refund", "acct_1", REFUND),
    ("update_prod_config", "cfg_1", {"value": "0"}),
]


def statuses(env):
    return [row["status"] for row in rows(env, "SELECT status FROM actions ORDER BY created_at")]


def event_types(env, action_id):
    return [e["type"] for e in audit_events(env) if e.get("action_id") == action_id]


def chain_ok(env):
    conn = storage.connect(env.gateway.db_path)
    try:
        return audit.verify_chain(conn).ok
    finally:
        conn.close()


def forwarding_transport(tools, *, before=None, after=None):
    """An HTTP transport to the Tools service with hooks around each call."""
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        if before is not None:
            injected = before(request)
            if injected is not None:
                return injected
        response = tools.executor.request(
            request.method, request.url.path, content=request.content, headers=request.headers
        )
        if after is not None:
            injected = after(request)
            if injected is not None:
                return injected
        return httpx.Response(response.status_code, content=response.content)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://tools")
    return client, calls


def is_execute(request):
    return request.url.path == "/v1/execute"


def raise_timeout(request):
    raise httpx.ReadTimeout("timeout", request=request)


# --- Malformed and unknown requests (T9, T10) --------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"[]",
        b'{"tool":"read_document","resource_id":"doc_1","args":{}}',  # reason missing
        b'{"tool":"read_document","resource_id":"doc_1","resource_id":"doc_2","args":{},"reason":""}',
        b'{"tool":"issue_refund","resource_id":"acct_1",'
        b'"args":{"amount":"1.00","amount":"900.00","currency":"EUR"},"reason":""}',
        b'{"tool":"issue_refund","resource_id":"acct_1",'
        b'"args":{"amount":100.00,"currency":"EUR"},"reason":""}',
        b'{"tool":"issue_refund","resource_id":"acct_1",'
        b'"args":{"amount":NaN,"currency":"EUR"},"reason":""}',
        b'{"tool":"read_document","resource_id":"doc_1","args":{},"reason":"\xff"}',
        b'\xef\xbb\xbf{"tool":"read_document","resource_id":"doc_1","args":{},"reason":""}',
        b'{"tool":"read_document","resource_id":"./doc_1","args":{},"reason":""}',
        b'{"tool":"read_document","resource_id":"doc_1","args":{"extra":"x"},"reason":""}',
        b'{"tool":"read_document","resource_id":"doc_1","args":{},"reason":"a\\nb"}',
        b'{"tool":"read_document","resource_id":"doc_1","args":{},"reason":7}',
        b'{"tool":"read_document","resource_id":"doc_1","args":{},"reason":"' + b"x" * 501 + b'"}',
    ],
)
def test_malformed_proposals_are_denied(env, raw):
    _, headers = new_session(env)
    response = env.agent.post("/v1/actions", content=raw, headers=headers)
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_request"}
    assert rows(env, "SELECT * FROM actions") == []
    assert env.tools.state.executions() == []


@pytest.mark.parametrize(
    "tool",
    ["drop_database", "Delete_Document", "DELETE_DOCUMENT", "delete-document", "delete_doc", ""],
)
def test_unknown_alias_and_case_variant_tools_are_denied(env, tool):
    _, headers = new_session(env)
    response = propose(env, headers, tool, "doc_1")
    assert response.status_code == 400
    assert rows(env, "SELECT * FROM actions") == []
    assert env.tools.state.snapshot()["documents"][0]["deleted"] == 0


# --- ALLOW: executed within the request --------------------------------------


def test_benign_read_is_allowed_and_returned_in_one_round_trip(env):
    session_id, headers = new_session(env)
    response = propose(env, headers, "read_document", "doc_1")
    assert response.status_code == 200
    body = response.json()
    assert (body["decision"], body["status"]) == ("ALLOW", "COMMITTED")
    assert body["result"]["content"] == "Revenue grew."
    assert event_types(env, body["action_id"]) == ["PROPOSED", "ALLOWED", "EXECUTING", "COMMITTED"]
    assert provenance_of(env, session_id) == (0, [])
    assert env.tools.state.executions() == []


@pytest.mark.parametrize(
    ("tool", "resource_id"),
    [("list_documents", None), ("read_inbox", None), ("get_balance", "acct_1")],
)
def test_other_reads_are_allowed(env, tool, resource_id):
    _, headers = new_session(env)
    response = propose(env, headers, tool, resource_id)
    assert response.status_code == 200
    assert response.json()["status"] == "COMMITTED"


def test_reading_external_content_taints_the_session(env):
    session_id, headers = new_session(env)
    response = propose(env, headers, "read_document", "doc_2")
    assert response.json()["result"]["content"] == INJECTION
    assert provenance_of(env, session_id) == (1, ["doc_2"])
    changed = [e for e in audit_events(env) if e["type"] == "PROVENANCE_CHANGED"]
    assert len(changed) == 1
    assert changed[0]["new_sources"] == ["doc_2"]
    assert changed[0]["provenance_version"] == 1
    assert changed[0]["session_id"] == session_id


def test_listing_that_includes_external_items_taints_the_session(env):
    session_id, headers = new_session(env)
    propose(env, headers, "list_documents")
    assert provenance_of(env, session_id) == (1, ["doc_2"])


def test_read_of_a_missing_resource_fails_without_taint(env):
    session_id, headers = new_session(env)
    response = propose(env, headers, "read_document", "doc_99")
    assert response.status_code == 409
    assert (response.json()["status"], response.json()["error"]) == ("FAILED", "not_found")
    assert provenance_of(env, session_id) == (0, [])


def test_reversible_action_is_executed_exactly_once(env):
    _, headers = new_session(env)
    response = propose(env, headers, "update_document", "doc_1", {"content": "v2"})
    assert response.status_code == 200
    body = response.json()
    assert body["result"] == {"id": "doc_1", "version": 2}
    action = rows(env, "SELECT * FROM actions")[0]
    assert (action["status"], action["resource_version"]) == ("COMMITTED", 1)
    executions = env.tools.state.executions()
    assert [e["idempotency_key"] for e in executions] == [action["execution_id"]]
    assert env.tools.state.snapshot()["documents"][0]["content"] == "v2"

    # The committed action cannot be executed a second time through /execute.
    again = env.agent.post(
        f"/v1/actions/{body['action_id']}/execute",
        json={"tool": "update_document", "resource_id": "doc_1", "args": {"content": "v2"}},
        headers=headers,
    )
    assert again.status_code == 409
    assert again.json() == {"error": "not_executable"}
    assert len(env.tools.state.executions()) == 1


def test_draft_email_is_executed_with_version_zero(env):
    _, headers = new_session(env)
    assert propose(env, headers, "draft_email", None, EMAIL).status_code == 200
    assert len(env.tools.state.snapshot()["drafts"]) == 1
    assert env.tools.state.snapshot()["outbound_mail"] == []


def test_reversible_action_on_a_missing_resource_creates_no_action(env):
    _, headers = new_session(env)
    response = propose(env, headers, "update_document", "doc_99", {"content": "x"})
    assert response.status_code == 404
    assert response.json() == {"error": "resource_not_found"}
    assert rows(env, "SELECT * FROM actions") == []


def test_resource_changed_between_observation_and_execution(make_env, tools):
    def bump_version(request):
        if is_execute(request):
            tools.executor.post(
                "/v1/execute",
                json={
                    "tool": "update_document",
                    "resource_id": "doc_1",
                    "args": {"content": "race"},
                },
                headers={
                    "Authorization": f"Bearer {EXECUTOR_TOKEN}",
                    "Idempotency-Key": "key-concurrent-writer",
                    "If-Match": "1",
                },
            )

    client, _ = forwarding_transport(tools, before=bump_version)
    env = make_env(tools_http=client)
    _, headers = new_session(env)
    response = propose(env, headers, "update_document", "doc_1", {"content": "mine"})
    assert response.status_code == 409
    assert (response.json()["status"], response.json()["error"]) == (
        "FAILED",
        "precondition_failed",
    )
    assert tools.state.snapshot()["documents"][0]["content"] == "race"
    assert statuses(env) == ["FAILED"]


# --- REQUIRE_APPROVAL: nothing executes without an approval (T2) -------------


@pytest.mark.parametrize(("tool", "resource_id", "args"), R2_ACTIONS)
def test_irreversible_action_is_never_executed_without_approval(env, tool, resource_id, args):
    _, headers = new_session(env)
    before = env.tools.state.snapshot()
    response = propose(env, headers, tool, resource_id, args)
    assert response.status_code == 202
    body = response.json()
    assert (body["decision"], body["status"]) == ("REQUIRE_APPROVAL", "PENDING_APPROVAL")
    assert "result" not in body
    assert event_types(env, body["action_id"]) == ["PROPOSED", "PENDING_APPROVAL"]

    resend = {"tool": tool, "resource_id": resource_id, "args": args}
    execute = env.agent.post(
        f"/v1/actions/{body['action_id']}/execute", json=resend, headers=headers
    )
    assert execute.status_code == 403
    assert execute.json() == {"error": "approval_required"}

    assert env.tools.state.snapshot() == before
    assert env.tools.state.executions() == []
    assert statuses(env) == ["PENDING_APPROVAL"]


def test_changed_arguments_at_execution_are_refused(env):
    _, headers = new_session(env)
    pending = propose(env, headers, "delete_document", "doc_1").json()
    path = f"/v1/actions/{pending['action_id']}/execute"
    for body in [
        {"tool": "delete_document", "resource_id": "doc_3", "args": {}},
        {"tool": "update_document", "resource_id": "doc_1", "args": {"content": "x"}},
    ]:
        response = env.agent.post(path, json=body, headers=headers)
        assert response.status_code == 409
        assert response.json() == {"error": "action_mismatch"}
    assert env.tools.state.executions() == []


@pytest.mark.parametrize(
    "action_id", ["act_" + "0" * 32, "act_1", "..%2F..%2Fadmin", "ACT_" + "0" * 32, "x" * 300]
)
def test_execute_of_an_unknown_action_is_refused(env, action_id):
    _, headers = new_session(env)
    body = {"tool": "delete_document", "resource_id": "doc_1", "args": {}}
    response = env.agent.post(f"/v1/actions/{action_id}/execute", json=body, headers=headers)
    assert response.status_code == 404
    assert env.tools.state.executions() == []


# --- DENY --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "reason"),
    [
        ({"amount": "900.00", "currency": "EUR"}, "amount_over_limit"),
        ({"amount": "500.01", "currency": "EUR"}, "amount_over_limit"),
        ({"amount": "100.00", "currency": "USD"}, "currency_not_allowed"),
    ],
)
def test_refund_outside_the_policy_is_denied(env, args, reason):
    _, headers = new_session(env)
    response = propose(env, headers, "issue_refund", "acct_1", args)
    assert response.status_code == 403
    body = response.json()
    assert (body["decision"], body["status"], body["reason"]) == ("DENY", "DENIED", reason)
    assert event_types(env, body["action_id"]) == ["PROPOSED", "DENIED"]
    assert env.tools.state.executions() == []
    execute = env.agent.post(
        f"/v1/actions/{body['action_id']}/execute",
        json={"tool": "issue_refund", "resource_id": "acct_1", "args": args},
        headers=headers,
    )
    assert execute.status_code == 409
    assert env.tools.state.snapshot()["refunds"] == []


def test_tool_absent_from_the_policy_is_denied_by_default(make_env):
    text = DEFAULT_POLICY.read_text(encoding="utf-8")
    old = "  read_document:\n    tier: R0\n"
    assert old in text
    env = make_env(policy_text=text.replace(old, ""))
    _, headers = new_session(env)
    response = propose(env, headers, "read_document", "doc_1")
    assert response.status_code == 403
    assert response.json()["reason"] == "tool_not_in_policy"
    assert "Revenue" not in response.text


def test_taint_escalates_a_reversible_action(make_env):
    text = DEFAULT_POLICY.read_text(encoding="utf-8")
    old = "  update_document:\n    tier: R1\n"
    assert old in text
    env = make_env(
        policy_text=text.replace(old, old + "    on_tainted_session: require_approval\n")
    )
    _, headers = new_session(env)
    assert propose(env, headers, "update_document", "doc_1", {"content": "a"}).status_code == 200
    propose(env, headers, "read_document", "doc_2")
    escalated = propose(env, headers, "update_document", "doc_3", {"content": "b"})
    assert escalated.status_code == 202
    assert escalated.json()["reason"] == "tainted_session"
    assert env.tools.state.snapshot()["documents"][2]["content"] == "Obsolete."


# --- Fail closed (T13) -------------------------------------------------------


def test_tools_service_unreachable(make_env, tools):
    def refuse(request):
        raise httpx.ConnectError("refused", request=request)

    client, _ = forwarding_transport(tools, before=refuse)
    env = make_env(tools_http=client)
    _, headers = new_session(env)

    read = propose(env, headers, "read_document", "doc_1")
    assert read.status_code == 502
    assert (read.json()["status"], read.json()["error"]) == ("FAILED", "tools_unavailable")
    assert "result" not in read.json()

    write = propose(env, headers, "update_document", "doc_1", {"content": "x"})
    assert write.status_code == 502
    assert write.json() == {"error": "tools_unavailable"}
    assert statuses(env) == ["FAILED"]
    assert tools.state.executions() == []


@pytest.mark.parametrize(
    "reply",
    [
        httpx.Response(500, json={"error": "internal_error"}),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"executed": True}),
        httpx.Response(200, json={"executed": True, "result": {"content": "x"}}),  # no labels
        httpx.Response(
            200,
            json={"executed": True, "result": {"content": "x"}, "sources": [{"id": "doc_1"}]},
        ),
        httpx.Response(
            200,
            json={
                "executed": True,
                "result": {"content": "x"},
                "sources": [{"id": "doc_1", "trust_label": "trusted"}],
            },
        ),
        httpx.Response(200, json={"executed": False, "error": "not_found"}),
        httpx.Response(409, json={"executed": False, "error": "idempotency_key_reuse"}),
        httpx.Response(404, json={"executed": False, "error": "something_new"}),
    ],
)
def test_unexpected_tools_reply_to_a_read_returns_no_content(make_env, tools, reply):
    client, _ = forwarding_transport(tools, before=lambda request: reply)
    env = make_env(tools_http=client)
    session_id, headers = new_session(env)
    response = propose(env, headers, "read_document", "doc_1")
    assert response.status_code == 502
    assert "result" not in response.json()
    assert statuses(env) == ["FAILED"]
    assert provenance_of(env, session_id) == (0, [])


def test_timeout_before_the_tools_service_acts_is_unknown(make_env, tools):
    client, _ = forwarding_transport(
        tools, before=lambda request: raise_timeout(request) if is_execute(request) else None
    )
    env = make_env(tools_http=client)
    _, headers = new_session(env)
    response = propose(env, headers, "update_document", "doc_1", {"content": "x"})
    assert response.status_code == 504
    assert (response.json()["status"], response.json()["error"]) == ("UNKNOWN", "tools_unavailable")
    assert statuses(env) == ["UNKNOWN"]
    assert tools.state.executions() == []


def test_timeout_after_the_tools_service_executed_is_unknown(make_env, tools):
    client, _ = forwarding_transport(
        tools, after=lambda request: raise_timeout(request) if is_execute(request) else None
    )
    env = make_env(tools_http=client)
    _, headers = new_session(env)
    response = propose(env, headers, "update_document", "doc_1", {"content": "x"})
    assert response.status_code == 504
    action = rows(env, "SELECT status, execution_id FROM actions")[0]
    assert action["status"] == "UNKNOWN"
    # The effect happened; the idempotency key is what reconciliation (M2) will query.
    executions = tools.state.executions()
    assert [(e["idempotency_key"], e["status"]) for e in executions] == [
        (action["execution_id"], "EXECUTED")
    ]
    assert event_types(env, rows(env, "SELECT action_id FROM actions")[0]["action_id"]) == [
        "PROPOSED",
        "ALLOWED",
        "EXECUTING",
        "UNKNOWN",
    ]


def block_audit_inserts(env):
    conn = storage.connect(env.gateway.db_path)
    try:
        conn.execute(
            "CREATE TRIGGER fault BEFORE INSERT ON audit_events"
            " BEGIN SELECT RAISE(ABORT, 'injected fault'); END"
        )
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("tool", "resource_id", "args"),
    [
        ("read_document", "doc_1", {}),
        ("update_document", "doc_1", {"content": "x"}),
        ("delete_document", "doc_1", {}),
    ],
)
def test_audit_failure_means_nothing_is_executed(make_env, tools, tool, resource_id, args):
    client, calls = forwarding_transport(tools)
    env = make_env(tools_http=client)
    _, headers = new_session(env)
    before = tools.state.snapshot()
    block_audit_inserts(env)

    response = propose(env, headers, tool, resource_id, args)
    assert response.status_code == 500
    assert response.json() == {"error": "internal_error"}
    assert ("POST", "/v1/execute") not in calls
    assert rows(env, "SELECT * FROM actions") == []  # the state change rolled back
    assert tools.state.snapshot() == before
    assert tools.state.executions() == []


def test_audit_failure_while_recording_a_read_returns_no_content(make_env, tools):
    holder = {}

    def break_audit_after_the_read(request):
        if is_execute(request):
            block_audit_inserts(holder["env"])

    client, _ = forwarding_transport(tools, after=break_audit_after_the_read)
    env = holder["env"] = make_env(tools_http=client)
    session_id, headers = new_session(env)
    response = propose(env, headers, "read_document", "doc_2")
    assert response.status_code == 500
    assert INJECTION not in response.text
    assert statuses(env) == ["EXECUTING"]  # left for start-up reconciliation (M2)
    assert provenance_of(env, session_id) == (0, [])


def test_session_creation_fails_closed_on_audit_failure(env):
    block_audit_inserts(env)
    response = env.admin.post(
        "/admin/sessions",
        json={"agent_id": "agent_1"},
        headers={"Authorization": f"Bearer {GATEWAY_ADMIN_TOKEN}"},
    )
    assert response.status_code == 500
    assert rows(env, "SELECT * FROM sessions") == []


# --- Audit and cross-check (T15, bypass measurement) -------------------------


def run_mixed_scenario(env):
    _, headers = new_session(env)
    propose(env, headers, "read_document", "doc_1")
    propose(env, headers, "read_document", "doc_2")
    propose(env, headers, "update_document", "doc_1", {"content": "v2"})
    propose(env, headers, "draft_email", None, EMAIL)
    propose(env, headers, "update_document", "doc_99", {"content": "x"})
    propose(env, headers, "read_document", "doc_99")
    propose(env, headers, "delete_document", "doc_3")
    propose(env, headers, "issue_refund", "acct_1", {"amount": "900.00", "currency": "EUR"})
    propose(env, headers, "issue_refund", "acct_1", REFUND)
    return headers


def test_every_state_transition_has_its_audit_event(env):
    run_mixed_scenario(env)
    events = audit_events(env)
    actions = rows(env, "SELECT action_id, status, policy_hash FROM actions")
    assert len(actions) == 8
    for action in actions:
        types = [e["type"] for e in events if e.get("action_id") == action["action_id"]]
        transitions = [t for t in types if t != "PROVENANCE_CHANGED"]
        assert transitions[0] == "PROPOSED"
        assert transitions[-1] == action["status"]
        assert action["policy_hash"] == env.gateway.policy_hash
    assert all(event["policy_hash"] == env.gateway.policy_hash for event in events)
    assert chain_ok(env)


def test_every_tools_execution_is_backed_by_a_gateway_action(env):
    run_mixed_scenario(env)
    executions = env.tools.state.executions()
    assert len(executions) == 2
    for execution in executions:
        backing = rows(
            env,
            "SELECT tool, resource_id, status FROM actions WHERE execution_id = ?",
            (execution["idempotency_key"],),
        )
        assert backing == [
            {
                "tool": execution["tool"],
                "resource_id": execution["resource_id"],
                "status": "COMMITTED",
            }
        ]
    # No irreversible tool appears in the Tools execution table.
    assert {e["tool"] for e in executions} == {"update_document", "draft_email"}


# --- Request size limit ------------------------------------------------------


@pytest.fixture
def parser_spy(monkeypatch):
    """Record every call the Gateway makes to the strict JSON parser."""
    calls = []
    original = gateway_app.parse_json_strict

    def spy(raw):
        calls.append(len(raw))
        return original(raw)

    monkeypatch.setattr(gateway_app, "parse_json_strict", spy)
    return calls


def oversized(limit):
    padding = "x" * limit
    return (
        '{"tool":"read_document","resource_id":"doc_1","args":{},"reason":"' + padding + '"}'
    ).encode()


def test_body_above_the_limit_is_rejected_before_parsing(env, parser_spy):
    _, headers = new_session(env)
    parser_spy.clear()  # session creation parsed its own small body
    response = env.agent.post("/v1/actions", content=oversized(MAX_BYTES), headers=headers)
    assert response.status_code == 413
    assert response.json() == {"error": "request_too_large"}
    assert parser_spy == []
    assert rows(env, "SELECT * FROM actions") == []


def test_streamed_body_without_content_length_is_cut_off(env, parser_spy):
    _, headers = new_session(env)
    parser_spy.clear()  # session creation parsed its own small body
    body = oversized(MAX_BYTES)

    def chunks():
        for start in range(0, len(body), 65_536):
            yield body[start : start + 65_536]

    response = env.agent.post("/v1/actions", content=chunks(), headers=headers)
    assert response.status_code == 413
    assert parser_spy == []
    assert rows(env, "SELECT * FROM actions") == []


def test_configured_limit_applies_to_every_route(make_env, parser_spy):
    env = make_env(max_body_bytes=1024)
    _, headers = new_session(env)
    assert propose(env, headers, "read_document", "doc_1").status_code == 200
    parser_spy.clear()
    big = oversized(2000)
    for path in ("/v1/actions", f"/v1/actions/act_{'0' * 32}/execute"):
        assert env.agent.post(path, content=big, headers=headers).status_code == 413
    assert parser_spy == []


# --- Error hygiene -----------------------------------------------------------


def test_error_responses_never_echo_input_or_secrets(make_env, tools):
    client, _ = forwarding_transport(tools)
    env = make_env(tools_http=client)
    _, headers = new_session(env)
    agent_token = headers["Authorization"].removeprefix("Bearer ")
    marker = "MARKER-7f3a"
    valid = {"tool": "read_document", "resource_id": "doc_1", "args": {}, "reason": ""}

    responses = [
        env.agent.post("/v1/actions", json={**valid, "tool": marker}, headers=headers),
        env.agent.post("/v1/actions", json={**valid, "resource_id": marker}, headers=headers),
        env.agent.post("/v1/actions", json={**valid, "args": {marker: marker}}, headers=headers),
        env.agent.post("/v1/actions", json={**valid, marker: marker}, headers=headers),
        env.agent.post("/v1/actions", json={**valid, "reason": marker + "\t"}, headers=headers),
        env.agent.post("/v1/actions", content=marker.encode(), headers=headers),
        env.agent.post("/v1/actions", json=valid, headers={"Authorization": f"Bearer {marker}"}),
        env.agent.post(f"/v1/actions/{marker}/execute", json=valid, headers=headers),
        env.agent.post(f"/v1/{marker}", json=valid, headers=headers),
        env.agent.get(f"/v1/actions?q={marker}", headers=headers),
        propose(env, headers, "issue_refund", "acct_1", {"amount": "900.00", "currency": "EUR"}),
        propose(env, headers, "update_document", "doc_99", {"content": marker}),
        propose(env, headers, "delete_document", "doc_1", reason=marker),
        env.admin.post(
            "/admin/sessions",
            json={"agent_id": marker},
            headers={"Authorization": f"Bearer {marker}"},
        ),
    ]
    block_audit_inserts(env)
    responses.append(propose(env, headers, "update_document", "doc_1", {"content": marker}))

    for response in responses:
        assert response.status_code >= 400 or response.status_code == 202
        for secret in (marker, EXECUTOR_TOKEN, GATEWAY_ADMIN_TOKEN, agent_token):
            assert secret not in response.text
            assert secret not in str(response.headers)


def test_successful_responses_do_not_contain_credentials(env):
    _, headers = new_session(env)
    agent_token = headers["Authorization"].removeprefix("Bearer ")
    responses = [
        propose(env, headers, "read_document", "doc_1"),
        propose(env, headers, "list_documents"),
        propose(env, headers, "update_document", "doc_1", {"content": "v2"}),
        propose(env, headers, "delete_document", "doc_3"),
    ]
    for response in responses:
        for secret in (EXECUTOR_TOKEN, GATEWAY_ADMIN_TOKEN, agent_token):
            assert secret not in response.text
