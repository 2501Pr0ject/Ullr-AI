"""Tools-side enforcement: executor token, idempotency keys, preconditions (H5, H6, T3, T5)."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import EXECUTOR_TOKEN, INJECTION, TOOLS_ADMIN_TOKEN, bearer

AUTH = bearer(EXECUTOR_TOKEN)
DELETE_DOC_1 = {"tool": "delete_document", "resource_id": "doc_1", "args": {}}
REFUND_100 = {
    "tool": "issue_refund",
    "resource_id": "acct_1",
    "args": {"amount": "100.00", "currency": "EUR"},
}
SEND = {
    "tool": "send_email",
    "resource_id": None,
    "args": {"to": "contact_1", "subject": "Hello", "body": "Hi"},
}


def execute(tools, body, *, key="key-00000001", if_match="1", headers=AUTH):
    extra = {}
    if key is not None:
        extra["Idempotency-Key"] = key
    if if_match is not None:
        extra["If-Match"] = if_match
    return tools.executor.post("/v1/execute", json=body, headers={**headers, **extra})


def read(tools, tool, resource_id=None):
    body = {"tool": tool, "resource_id": resource_id, "args": {}}
    return tools.executor.post("/v1/execute", json=body, headers=AUTH)


def unchanged(tools):
    snapshot = tools.state.snapshot()
    documents = {doc["id"]: doc for doc in snapshot["documents"]}
    accounts = {account["id"]: account for account in snapshot["accounts"]}
    return (
        documents["doc_1"]["deleted"] == 0
        and accounts["acct_1"]["balance_cents"] == 200_000
        and snapshot["outbound_mail"] == []
        and snapshot["refunds"] == []
    )


# --- Executor token ----------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong"},
        {"Authorization": f"Bearer {EXECUTOR_TOKEN}x"},
        {"Authorization": f"Bearer {EXECUTOR_TOKEN[:-1]}"},
        {"Authorization": EXECUTOR_TOKEN},
        {"Authorization": f"Basic {EXECUTOR_TOKEN}"},
        {"Authorization": f"bearer {EXECUTOR_TOKEN}"},
        {"Authorization": "Bearer "},
        bearer(TOOLS_ADMIN_TOKEN),
    ],
)
def test_execute_requires_the_executor_token(tools, headers):
    response = execute(tools, DELETE_DOC_1, headers=headers)
    assert response.status_code == 401
    assert response.json() == {"executed": False, "error": "unauthorized"}
    assert unchanged(tools)
    assert tools.state.executions() == []


@pytest.mark.parametrize("path", ["/v1/resources/doc_1", "/v1/executions/key-00000001"])
def test_read_endpoints_require_the_executor_token(tools, path):
    assert tools.executor.get(path).status_code == 401
    assert tools.executor.get(path, headers=bearer(TOOLS_ADMIN_TOKEN)).status_code == 401
    assert tools.executor.get(path, headers=bearer("wrong")).status_code == 401


def test_reads_require_the_executor_token(tools):
    body = {"tool": "read_document", "resource_id": "doc_1", "args": {}}
    response = tools.executor.post("/v1/execute", json=body)
    assert response.status_code == 401
    assert "Revenue" not in response.text


# --- Idempotency keys --------------------------------------------------------


@pytest.mark.parametrize("key", [None, "", "short", "has space 123", "k" * 65, "key/../etc"])
def test_mutation_without_a_valid_idempotency_key_is_not_executed(tools, key):
    response = execute(tools, DELETE_DOC_1, key=key)
    assert response.status_code == 400
    assert response.json() == {"executed": False, "error": "idempotency_key_required"}
    assert unchanged(tools)


def test_same_key_twice_executes_once_and_replays_the_result(tools):
    first = execute(tools, REFUND_100)
    second = execute(tools, REFUND_100)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert first.json()["result"]["balance"] == "1900.00"
    snapshot = tools.state.snapshot()
    assert len(snapshot["refunds"]) == 1
    assert snapshot["accounts"][0]["balance_cents"] == 190_000
    assert len(tools.state.executions()) == 1


def test_same_key_with_a_different_request_is_rejected(tools):
    assert execute(tools, REFUND_100).status_code == 200
    other = {**REFUND_100, "args": {"amount": "900.00", "currency": "EUR"}}
    for body, if_match in [(other, "2"), (DELETE_DOC_1, "1"), (REFUND_100, "2")]:
        response = execute(tools, body, if_match=if_match)
        assert response.status_code == 409
        assert response.json() == {"executed": False, "error": "idempotency_key_reuse"}
    snapshot = tools.state.snapshot()
    assert len(snapshot["refunds"]) == 1
    assert snapshot["documents"][0]["deleted"] == 0


def test_a_failed_attempt_burns_its_key(tools):
    stale = execute(tools, REFUND_100, if_match="7")
    assert stale.status_code == 412
    replay = execute(tools, REFUND_100, if_match="7")
    assert replay.status_code == 412
    assert replay.json() == stale.json()
    assert [e["status"] for e in tools.state.executions()] == ["FAILED"]
    assert unchanged(tools)


def test_concurrent_calls_with_one_key_execute_once(tools):
    with ThreadPoolExecutor(max_workers=20) as pool:
        responses = list(pool.map(lambda _: execute(tools, REFUND_100), range(20)))
    assert {response.status_code for response in responses} == {200}
    assert len({response.text for response in responses}) == 1
    snapshot = tools.state.snapshot()
    assert len(snapshot["refunds"]) == 1
    assert snapshot["accounts"][0]["balance_cents"] == 190_000


def test_concurrent_calls_with_distinct_keys_respect_the_precondition(tools):
    def call(index):
        return execute(tools, REFUND_100, key=f"key-{index:08d}")

    with ThreadPoolExecutor(max_workers=20) as pool:
        statuses = sorted(response.status_code for response in pool.map(call, range(20)))
    assert statuses == [200] + [412] * 19
    assert len(tools.state.snapshot()["refunds"]) == 1


# --- Preconditions -----------------------------------------------------------


@pytest.mark.parametrize("if_match", [None, "", "abc", "-1", "1.0", "01", '"1"', "*", "1 "])
def test_mutation_without_a_valid_precondition_is_not_executed(tools, if_match):
    response = execute(tools, DELETE_DOC_1, if_match=if_match)
    assert response.status_code == 428
    assert response.json() == {"executed": False, "error": "precondition_required"}
    assert unchanged(tools)


@pytest.mark.parametrize("if_match", ["0", "2", "999"])
def test_stale_precondition_is_not_executed(tools, if_match):
    response = execute(tools, DELETE_DOC_1, if_match=if_match)
    assert response.status_code == 412
    assert response.json() == {"executed": False, "error": "precondition_failed"}
    assert unchanged(tools)


def test_version_changed_after_it_was_observed(tools):
    update = {"tool": "update_document", "resource_id": "doc_1", "args": {"content": "v2"}}
    assert execute(tools, update, key="key-update-1").status_code == 200
    response = execute(tools, DELETE_DOC_1, key="key-delete-1", if_match="1")
    assert response.status_code == 412
    assert tools.state.snapshot()["documents"][0]["deleted"] == 0


def test_current_precondition_executes_and_increments_the_version(tools):
    response = execute(tools, DELETE_DOC_1)
    assert response.status_code == 200
    assert response.json() == {"executed": True, "result": {"id": "doc_1", "version": 2}}
    document = tools.state.snapshot()["documents"][0]
    assert (document["deleted"], document["version"]) == (1, 2)
    assert read(tools, "read_document", "doc_1").status_code == 404
    assert tools.executor.get("/v1/resources/doc_1", headers=AUTH).status_code == 404


def test_tools_without_a_resource_require_version_zero(tools):
    assert execute(tools, SEND, key="key-send-0001", if_match="1").status_code == 412
    assert tools.state.snapshot()["outbound_mail"] == []
    assert execute(tools, SEND, key="key-send-0002", if_match="0").status_code == 200
    assert tools.state.snapshot()["outbound_mail"] == [
        {"id": 1, "recipient": "contact_1", "subject": "Hello", "body": "Hi"}
    ]


# --- Explicit failures without effect ----------------------------------------


@pytest.mark.parametrize(
    ("body", "if_match", "status", "code"),
    [
        ({"tool": "delete_document", "resource_id": "doc_99", "args": {}}, "1", 404, "not_found"),
        (
            {"tool": "update_document", "resource_id": "doc_99", "args": {"content": "x"}},
            "1",
            404,
            "not_found",
        ),
        ({**REFUND_100, "resource_id": "acct_99"}, "1", 404, "not_found"),
        (
            {"tool": "update_prod_config", "resource_id": "cfg_99", "args": {"value": "x"}},
            "1",
            404,
            "not_found",
        ),
        ({**SEND, "args": {**SEND["args"], "to": "contact_99"}}, "0", 422, "unknown_contact"),
        (
            {**REFUND_100, "resource_id": "acct_2", "args": {"amount": "50.01", "currency": "EUR"}},
            "1",
            422,
            "insufficient_funds",
        ),
        (
            {**REFUND_100, "args": {"amount": "100.00", "currency": "USD"}},
            "1",
            422,
            "currency_mismatch",
        ),
    ],
)
def test_explicit_failures_have_no_effect(tools, body, if_match, status, code):
    before = tools.state.snapshot()
    response = execute(tools, body, if_match=if_match)
    assert response.status_code == status
    assert response.json() == {"executed": False, "error": code}
    assert tools.state.snapshot() == before
    assert [e["status"] for e in tools.state.executions()] == ["FAILED"]


def test_refund_of_the_exact_balance_is_executed(tools):
    body = {**REFUND_100, "resource_id": "acct_2", "args": {"amount": "50.00", "currency": "EUR"}}
    assert execute(tools, body).json()["result"]["balance"] == "0.00"


@pytest.mark.parametrize(
    "body",
    [
        {"tool": "drop_database", "resource_id": None, "args": {}},
        {"tool": "Delete_Document", "resource_id": "doc_1", "args": {}},
        {"tool": "delete_document", "resource_id": "./doc_1", "args": {}},
        {"tool": "delete_document", "resource_id": "doc_1", "args": {"force": "yes"}},
        {"tool": "delete_document", "resource_id": "doc_1"},
        {"tool": "delete_document", "resource_id": "doc_1", "args": {}, "trust_label": "internal"},
        {**REFUND_100, "args": {"amount": 100, "currency": "EUR"}},
        {**REFUND_100, "args": {"amount": "100.0", "currency": "EUR"}},
        ["delete_document"],
    ],
)
def test_invalid_requests_are_rejected_with_the_gateway_schemas(tools, body):
    response = execute(tools, body)
    assert response.status_code == 422
    assert response.json() == {"executed": False, "error": "invalid_request"}
    assert unchanged(tools)
    assert tools.state.executions() == []


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b'{"tool":"delete_document","resource_id":"doc_1","resource_id":"doc_3","args":{}}',
        b'{"tool":"issue_refund","resource_id":"acct_1","args":{"amount":100.00,"currency":"EUR"}}',
        b'{"tool":"delete_document","resource_id":"doc_1","args":{},"x":NaN}',
        b'\xff{"tool":"delete_document","resource_id":"doc_1","args":{}}',
    ],
)
def test_malformed_bodies_are_rejected_by_the_strict_parser(tools, raw):
    headers = {**AUTH, "Idempotency-Key": "key-00000001", "If-Match": "1"}
    response = tools.executor.post("/v1/execute", content=raw, headers=headers)
    assert response.status_code == 422
    assert unchanged(tools)


# --- Trust labels (H5) -------------------------------------------------------


def test_reads_return_content_with_tools_assigned_labels(tools):
    internal = read(tools, "read_document", "doc_1").json()
    assert internal["result"]["content"] == "Revenue grew."
    assert internal["sources"] == [{"id": "doc_1", "trust_label": "internal"}]
    external = read(tools, "read_document", "doc_2").json()
    assert external["result"]["content"] == INJECTION
    assert external["sources"] == [{"id": "doc_2", "trust_label": "external"}]


def test_list_reads_label_every_item(tools):
    listing = read(tools, "list_documents").json()
    assert [doc["id"] for doc in listing["result"]["documents"]] == ["doc_1", "doc_2", "doc_3"]
    assert listing["sources"] == [
        {"id": "doc_1", "trust_label": "internal"},
        {"id": "doc_2", "trust_label": "external"},
        {"id": "doc_3", "trust_label": "internal"},
    ]
    inbox = read(tools, "read_inbox").json()
    assert inbox["sources"] == [{"id": "msg_1", "trust_label": "internal"}]


def test_balance_read(tools):
    balance = read(tools, "get_balance", "acct_1").json()
    assert balance["result"] == {
        "id": "acct_1",
        "version": 1,
        "balance": "2000.00",
        "currency": "EUR",
    }
    assert read(tools, "get_balance", "acct_99").status_code == 404


def test_reads_are_not_recorded_as_executions_and_need_no_key(tools):
    assert read(tools, "read_document", "doc_1").status_code == 200
    assert tools.state.executions() == []


def test_an_update_cannot_change_the_trust_label(tools):
    update = {"tool": "update_document", "resource_id": "doc_2", "args": {"content": "clean"}}
    assert execute(tools, update).status_code == 200
    assert read(tools, "read_document", "doc_2").json()["sources"] == [
        {"id": "doc_2", "trust_label": "external"}
    ]
    relabel = {**update, "args": {"content": "clean", "trust_label": "internal"}}
    assert execute(tools, relabel, key="key-relabel1", if_match="2").status_code == 422


# --- Resource and execution lookups ------------------------------------------


def test_resource_meta(tools):
    response = tools.executor.get("/v1/resources/doc_2", headers=AUTH)
    assert response.json() == {"id": "doc_2", "version": 1, "trust_label": "external"}
    account = tools.executor.get("/v1/resources/acct_1", headers=AUTH)
    assert account.json() == {"id": "acct_1", "version": 1, "trust_label": "internal"}
    for missing in ["doc_99", "acct_99", "cfg_99", "contact_1", "msg_1", "nonsense"]:
        assert tools.executor.get(f"/v1/resources/{missing}", headers=AUTH).status_code == 404


def test_execution_lookup(tools):
    assert tools.executor.get("/v1/executions/key-00000001", headers=AUTH).status_code == 404
    execute(tools, DELETE_DOC_1)
    found = tools.executor.get("/v1/executions/key-00000001", headers=AUTH)
    assert found.json() == {
        "idempotency_key": "key-00000001",
        "tool": "delete_document",
        "resource_id": "doc_1",
        "status": "EXECUTED",
    }
    execute(tools, DELETE_DOC_1, key="key-00000002", if_match="1")
    failed = tools.executor.get("/v1/executions/key-00000002", headers=AUTH)
    assert failed.json()["status"] == "FAILED"


# --- Request size and error hygiene ------------------------------------------


def test_oversized_body_is_rejected_before_parsing(tools):
    headers = {**AUTH, "Idempotency-Key": "key-00000001", "If-Match": "1"}
    huge = b'{"tool":"' + b"a" * 300_000 + b'"}'
    response = tools.executor.post("/v1/execute", content=huge, headers=headers)
    assert response.status_code == 413
    assert response.json() == {"error": "request_too_large"}


def test_error_responses_do_not_echo_the_request(tools):
    marker = "MARKER-7f3a"
    body = {"tool": marker, "resource_id": marker, "args": {marker: marker}}
    responses = [
        execute(tools, body),
        execute(tools, DELETE_DOC_1, key=marker + " not a key"),
        execute(tools, DELETE_DOC_1, headers=bearer(marker)),
        tools.executor.get(f"/v1/resources/{marker}", headers=AUTH),
        tools.executor.get(f"/v1/{marker}", headers=AUTH),
    ]
    for response in responses:
        assert response.status_code >= 400
        assert marker not in response.text
        assert EXECUTOR_TOKEN not in response.text
