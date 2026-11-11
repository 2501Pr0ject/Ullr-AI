"""Model-facing tool definitions, their mapping to actions, and the workspace directory."""

from pathlib import Path

import pytest

from ullr_ai.agent import prompt, tools
from ullr_ai.bench.tasks import load_tasks
from ullr_ai.gateway.schemas import TOOLS, validate_action

TASKS = Path(__file__).resolve().parents[1] / "tasks"

CALLS = [
    ("list_documents", {}),
    ("read_document", {"document_id": "doc_1"}),
    ("read_inbox", {}),
    ("get_balance", {"account_id": "acct_1"}),
    ("draft_email", {"to": "contact_1", "subject": "S", "body": "B", "reason": "r"}),
    ("update_document", {"document_id": "doc_1", "content": "C", "reason": "r"}),
    ("send_email", {"to": "contact_1", "subject": "S", "body": "B", "reason": "r"}),
    ("delete_document", {"document_id": "doc_1", "reason": "r"}),
    ("issue_refund", {"account_id": "acct_1", "amount": "49.90", "currency": "EUR", "reason": "r"}),
    ("update_prod_config", {"config_id": "cfg_1", "value": "7", "reason": "r"}),
]


def test_the_model_is_given_exactly_the_ten_tools_of_the_gateway():
    assert tools.KNOWN_TOOLS == frozenset(TOOLS)
    definitions = tools.definitions()
    assert [d["function"]["name"] for d in definitions] == [t.name for t in tools.TOOLS]
    for definition in definitions:
        parameters = definition["function"]["parameters"]
        assert parameters["required"] == list(parameters["properties"])
        assert all(p["type"] == "string" for p in parameters["properties"].values())


@pytest.mark.parametrize(("name", "arguments"), CALLS)
def test_a_call_with_the_declared_parameters_maps_to_a_valid_action(name, arguments):
    declared = next(d for d in tools.definitions() if d["function"]["name"] == name)
    assert set(arguments) == set(declared["function"]["parameters"]["properties"])
    tool, resource_id, args, reason = tools.to_action(name, arguments)
    validate_action(tool, resource_id, args)  # raises if the mapping is wrong
    assert reason == arguments.get("reason", "")


def test_mapping_repairs_nothing():
    assert tools.to_action("admin_execute", {"command": "x", "reason": "r"}) == (
        "admin_execute",
        None,
        {"command": "x"},
        "r",
    )
    assert tools.to_action("issue_refund", {"amount": 49.9}) == (
        "issue_refund",
        None,
        {"amount": 49.9},
        "",
    )
    assert tools.to_action("read_inbox", None) == ("read_inbox", None, {}, "")
    assert tools.to_action("delete_document", {"document_id": 3, "reason": 5})[1:] == (3, {}, "")
    arguments = {"document_id": "doc_1"}
    tools.to_action("read_document", arguments)
    assert arguments == {"document_id": "doc_1"}  # the transcript keeps the original call


def test_hashes_identify_the_model_facing_text():
    assert tools.definitions_hash() == tools.definitions_hash()
    assert tools.definitions_hash().startswith("sha256:")
    assert prompt.system_prompt_hash().startswith("sha256:")


def test_directory_lists_what_no_tool_lists():
    task = next(t for t in load_tasks(TASKS) if t.id == "B04")
    message = prompt.first_message(task.state, task.data["user_prompt"])
    assert "- contact_2: Tom Weber <tom.weber@halden.example> (colleague)" in message
    assert "- cfg_3: security.mfa_required" in message
    assert message.endswith("Request from the user:\n" + task.data["user_prompt"])
    # Not in the directory: inbox and documents are reached through tools.
    assert "msg_" not in message
    assert "halden-ops" not in message


def test_directory_reveals_no_trust_label_and_nothing_from_the_ground_truth():
    for task in load_tasks(TASKS):
        directory = prompt.workspace_directory(task.state)
        # It is a function of the state alone, and within the state it depends on
        # contacts, accounts and configuration keys only: not on documents, on the
        # inbox, on any trust label or on configuration values.
        reduced = {
            "contacts": task.state.get("contacts", []),
            "accounts": task.state.get("accounts", []),
            "config": [{**c, "value": "X"} for c in task.state.get("config", [])],
        }
        assert directory == prompt.workspace_directory(reduced), task.id
        for item in task.state.get("documents", []) + task.state.get("inbox", []):
            assert item["id"] not in directory
        for line in directory.splitlines():
            assert "trust" not in line.split(":")[0]
        message = prompt.first_message(task.state, "REQUEST")
        for field in ("title", "evaluates", "risk", "notes"):
            assert task.data.get(field, "\x00") not in message


def test_task_without_directory_entries_gets_the_request_only():
    assert prompt.first_message({"documents": []}, "Do it.") == "Request from the user:\nDo it."
