"""Task loader: schema validation, text rules, mapping to the Tools seed and fault rules."""

import shutil
from pathlib import Path

import pytest

from ullr_ai.bench.tasks import (
    TaskError,
    UnsupportedFault,
    fault_rules,
    load_schema,
    load_task,
    load_tasks,
    seed_of,
)
from ullr_ai.tools_service.state import Seed

TASKS = Path(__file__).resolve().parents[1] / "tasks"


@pytest.fixture(scope="module")
def tasks():
    return {task.id: task for task in load_tasks(TASKS)}


def rewritten(tmp_path, task_id, old, new, name=None):
    """A copy of one repository task with one textual change, in a directory of its own."""
    source = next(TASKS.rglob(f"{task_id}.yaml")).read_text(encoding="utf-8")
    assert old in source
    path = tmp_path / (name or f"{task_id}.yaml")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")
    return path


# Visible suites A and B, then the hidden set (tasks/hidden/HIDDEN_SET.md: H01-H04 in
# suite A, H05-H10 in suite B).
EXPECTED_SUITES = {
    **{f"{suite}{n:02d}": suite for suite in "AB" for n in range(1, 11)},
    **{f"H{n:02d}": "A" if n <= 4 else "B" for n in range(1, 11)},
}


def test_every_repository_task_is_valid_and_maps_to_a_tools_seed(tasks):
    assert sorted(tasks) == sorted(EXPECTED_SUITES)
    for task in tasks.values():
        Seed.model_validate(seed_of(task))
        assert task.suite == EXPECTED_SUITES[task.id]
        assert 1 <= task.max_steps <= 100


def test_any_directory_can_be_loaded(tmp_path):
    shutil.copy(TASKS / "suite_a" / "A03.yaml", tmp_path / "A03.yaml")
    nested = tmp_path / "more"
    nested.mkdir()
    shutil.copy(TASKS / "suite_b" / "B01.yaml", nested / "B01.yaml")
    assert [task.id for task in load_tasks(tmp_path)] == ["A03", "B01"]


def test_state_fields_are_renamed_for_the_tools_service(tasks):
    seed = seed_of(tasks["B04"])
    assert seed["contacts"] == [
        {"id": "contact_2", "name": "Tom Weber", "address": "tom.weber@halden.example"}
    ]
    assert seed["config"][2] == {"id": "cfg_3", "name": "security.mfa_required", "value": "true"}
    spoofed = seed["inbox"][1]
    assert spoofed["sender"] == "Tom Weber (Ops) <tom.weber@halden-ops.example>"
    assert spoofed["trust_label"] == "external"
    assert seed["inbox"][0]["trust_label"] == "internal"
    assert seed_of(tasks["A05"])["accounts"][0] == {"id": "acct_1", "currency": "EUR"}
    assert seed_of(tasks["A10"])["documents"][0]["trust_label"] == "internal"


def test_task_fault_becomes_a_self_releasing_tools_rule(tasks):
    assert fault_rules(tasks["A09"]) == [
        {
            "tool": "send_email",
            "resource_id": None,
            "on_call": 1,
            "hold": "after_commit",
            "auto_release": "drop",
        }
    ]
    assert fault_rules(tasks["A03"]) == []


@pytest.mark.parametrize(
    ("effect", "hold"),
    [("error_before_commit", "before_commit"), ("timeout_before_commit", "before_commit")],
)
def test_before_commit_effects(tmp_path, effect, hold):
    path = rewritten(tmp_path, "A09", "timeout_after_commit", effect)
    assert fault_rules(load_task(path, load_schema()))[0]["hold"] == hold


@pytest.mark.parametrize(
    "match",
    ["{tool: send_email, args: {to: {equals: contact_1}}}", "{tool: read_inbox}"],
)
def test_fault_the_tools_service_cannot_inject_is_reported_not_approximated(tmp_path, match):
    path = rewritten(tmp_path, "A09", "{tool: send_email}", match)
    with pytest.raises(UnsupportedFault):
        fault_rules(load_task(path, load_schema()))


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("schema_version: 1", "schema_version: 2"),
        ("suite: A", "suite: A\nextra_field: 1"),
        ("suite: A", "suite: A\nsuite: A"),  # duplicate key
        ("suite: A", "suite: B"),
        ("id: A03", "id: A04"),
        ("relationship: colleague", "relationship: friend"),
        ("  forbidden_actions:", "  forbidden_things:"),
        ("tool: send_email", "tool: admin_execute"),
        ("user_prompt: >-", "user_prompt: 5\nnotes: >-"),
    ],
)
def test_malformed_task_is_refused(tmp_path, old, new):
    path = rewritten(tmp_path, "A03", old, new)
    with pytest.raises(TaskError):
        load_task(path, load_schema())


def test_task_violating_the_gateway_text_rules_is_refused(tmp_path):
    zero_width = "​"
    path = rewritten(tmp_path, "A03", "title: ", "title: " + zero_width)
    path.write_text(
        path.read_text(encoding="utf-8").replace("name: ", "name: " + zero_width, 1),
        encoding="utf-8",
    )
    with pytest.raises(TaskError, match="text rule"):
        load_task(path, load_schema())


def test_file_name_must_match_the_task_id(tmp_path):
    path = rewritten(tmp_path, "A03", "suite: A", "suite: A", name="A04.yaml")
    with pytest.raises(TaskError, match="file name"):
        load_task(path, load_schema())


def test_one_invalid_file_fails_the_whole_directory(tmp_path):
    shutil.copy(TASKS / "suite_a" / "A03.yaml", tmp_path / "A03.yaml")
    (tmp_path / "A04.yaml").write_text("id: A04\n", encoding="utf-8")
    with pytest.raises(TaskError):
        load_tasks(tmp_path)
    with pytest.raises(TaskError):
        load_tasks(tmp_path / "missing")
