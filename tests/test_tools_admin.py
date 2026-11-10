"""Tools admin API: reset, snapshot, execution log, separation from the executor API (T20)."""

import pytest

from conftest import EXECUTOR_TOKEN, TOOLS_ADMIN_TOKEN, bearer

ADMIN = bearer(TOOLS_ADMIN_TOKEN)
EXECUTOR = bearer(EXECUTOR_TOKEN)
ADMIN_ROUTES = [("POST", "/admin/reset"), ("GET", "/admin/snapshot"), ("GET", "/admin/executions")]
EXECUTOR_ROUTES = [
    ("POST", "/v1/execute"),
    ("GET", "/v1/resources/doc_1"),
    ("GET", "/v1/executions/key-00000001"),
]


def delete_doc_1(tools):
    return tools.executor.post(
        "/v1/execute",
        json={"tool": "delete_document", "resource_id": "doc_1", "args": {}},
        headers={**EXECUTOR, "Idempotency-Key": "key-00000001", "If-Match": "1"},
    )


@pytest.mark.parametrize(("method", "path"), ADMIN_ROUTES)
@pytest.mark.parametrize("headers", [{}, EXECUTOR, bearer("wrong"), {"Authorization": "Bearer "}])
def test_admin_routes_require_the_admin_token(tools, method, path, headers):
    delete_doc_1(tools)
    response = tools.admin.request(method, path, headers=headers)
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
    assert tools.state.snapshot()["documents"][0]["deleted"] == 1  # not reset


@pytest.mark.parametrize(("method", "path"), ADMIN_ROUTES)
def test_admin_routes_do_not_exist_on_the_executor_app(tools, method, path):
    for headers in (ADMIN, EXECUTOR):
        assert tools.executor.request(method, path, headers=headers).status_code == 404


@pytest.mark.parametrize(("method", "path"), EXECUTOR_ROUTES)
def test_executor_routes_do_not_exist_on_the_admin_app(tools, method, path):
    for headers in (ADMIN, EXECUTOR):
        assert tools.admin.request(method, path, headers=headers).status_code == 404


def test_snapshot_reflects_the_state(tools):
    before = tools.admin.get("/admin/snapshot", headers=ADMIN).json()
    assert [doc["id"] for doc in before["documents"]] == ["doc_1", "doc_2", "doc_3"]
    assert before["accounts"][0] == {
        "id": "acct_1",
        "version": 1,
        "balance_cents": 200000,
        "currency": "EUR",
    }
    assert before["outbound_mail"] == before["refunds"] == before["drafts"] == []
    delete_doc_1(tools)
    after = tools.admin.get("/admin/snapshot", headers=ADMIN).json()
    assert after["documents"][0]["deleted"] == 1
    assert after == tools.state.snapshot()


def test_execution_log_lists_every_mutation_attempt(tools):
    assert tools.admin.get("/admin/executions", headers=ADMIN).json() == {"executions": []}
    delete_doc_1(tools)
    log = tools.admin.get("/admin/executions", headers=ADMIN).json()["executions"]
    assert len(log) == 1
    assert log[0]["idempotency_key"] == "key-00000001"
    assert (log[0]["tool"], log[0]["resource_id"], log[0]["status"]) == (
        "delete_document",
        "doc_1",
        "EXECUTED",
    )


def test_reset_restores_the_seed_and_clears_the_execution_log(tools):
    seeded = tools.state.snapshot()
    delete_doc_1(tools)
    assert tools.admin.post("/admin/reset", headers=ADMIN).json() == {"reset": True}
    assert tools.state.snapshot() == seeded
    assert tools.state.executions() == []
    assert delete_doc_1(tools).status_code == 200  # the key is usable again after a reset


def test_reset_with_a_task_seed(tools):
    seed = {
        "documents": [{"id": "doc_7", "title": "T", "content": "C", "trust_label": "external"}],
        "accounts": [{"id": "acct_7", "balance": "10.00", "currency": "EUR"}],
    }
    assert tools.admin.post("/admin/reset", json={"seed": seed}, headers=ADMIN).status_code == 200
    snapshot = tools.state.snapshot()
    assert [doc["id"] for doc in snapshot["documents"]] == ["doc_7"]
    assert snapshot["accounts"][0]["balance_cents"] == 1000
    assert snapshot["contacts"] == []


@pytest.mark.parametrize(
    "body",
    [
        {"seed": {"documents": [{"id": "doc_7", "title": "T", "content": "C"}]}},
        {
            "seed": {
                "documents": [
                    {"id": "../x", "title": "T", "content": "C", "trust_label": "internal"}
                ]
            }
        },
        {
            "seed": {
                "documents": [
                    {"id": "doc_7", "title": "T", "content": "C", "trust_label": "trusted"}
                ]
            }
        },
        {"seed": {"accounts": [{"id": "acct_7", "balance": 10, "currency": "EUR"}]}},
        {"seed": {"unknown": []}},
        {"seed": {}, "extra": 1},
        {"documents": []},
        [],
    ],
)
def test_invalid_seed_is_rejected_and_state_is_kept(tools, body):
    before = tools.state.snapshot()
    response = tools.admin.post("/admin/reset", json=body, headers=ADMIN)
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_request"}
    assert tools.state.snapshot() == before
