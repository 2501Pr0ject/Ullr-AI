"""Benchmark task loader (tasks/TASK_FORMAT.md, schema v1).

A task file is validated against the JSON schema and against the Gateway's
own text rules before anything runs, then mapped to what the Tools service
understands: a seed and a list of fault rules. Task files are only read.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from ullr_ai.gateway.canon import CanonError, check_text
from ullr_ai.gateway.policy import load_yaml_strict
from ullr_ai.tools_service.executions import MUTATING_TOOLS
from ullr_ai.tools_service.state import Seed

DEFAULT_SCHEMA = Path(__file__).resolve().parents[3] / "tasks" / "schema" / "task.v1.schema.json"
DEFAULT_MAX_STEPS = 20

# Task fault effect -> (hold point of the Tools barrier, self-release action).
# The two "before commit" effects are the same event for the caller of the
# Tools service: an error reply and nothing executed.
FAULT_EFFECTS = {
    "error_before_commit": ("before_commit", "drop"),
    "timeout_before_commit": ("before_commit", "drop"),
    "timeout_after_commit": ("after_commit", "drop"),
}

_COLLECTIONS = ("contacts", "documents", "inbox", "accounts", "config")
_MULTILINE = {("documents", "content"), ("inbox", "body")}


class TaskError(ValueError):
    """The task file is not a valid schema v1 task."""


class UnsupportedFault(ValueError):
    """The task needs a fault the Tools service cannot inject: the task is skipped."""


@dataclass(frozen=True)
class Task:
    path: Path
    data: dict[str, Any]

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def suite(self) -> str:
        return self.data["suite"]

    @property
    def state(self) -> dict[str, list[dict[str, Any]]]:
        return self.data["state"]

    @property
    def ground_truth(self) -> dict[str, Any]:
        return self.data["ground_truth"]

    @property
    def max_steps(self) -> int:
        return self.data.get("max_steps", DEFAULT_MAX_STEPS)


def load_schema(path: Path | str = DEFAULT_SCHEMA) -> Draft202012Validator:
    schema = json.loads(Path(path).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def load_task(path: Path | str, validator: Draft202012Validator) -> Task:
    path = Path(path)
    try:
        data = load_yaml_strict(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise TaskError(f"{path.name}: cannot be read as YAML ({exc})") from None

    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    if errors:
        first = errors[0]
        where = "/".join(str(part) for part in first.absolute_path) or "(top level)"
        raise TaskError(f"{path.name}: schema violation at {where}: {first.message}")
    if data["id"] != path.stem:
        raise TaskError(f"{path.name}: id {data['id']} does not match the file name")
    if data["id"][0] in "AB" and data["id"][0] != data["suite"]:
        raise TaskError(f"{path.name}: id and suite disagree")

    try:
        check_text(data["user_prompt"], multiline=True)
        for collection in _COLLECTIONS:
            seen: set[str] = set()
            for item in data["state"].get(collection, []):
                if item["id"] in seen:
                    raise TaskError(f"{path.name}: duplicate id {item['id']}")
                seen.add(item["id"])
                for field, value in item.items():
                    check_text(value, multiline=(collection, field) in _MULTILINE)
    except CanonError as exc:
        raise TaskError(f"{path.name}: text rule violated ({exc})") from None

    task = Task(path, data)
    seed_of(task)  # the mapping must be accepted by the Tools seed model
    return task


def load_tasks(directory: Path | str, schema: Path | str = DEFAULT_SCHEMA) -> list[Task]:
    """Load every ``*.yaml`` task under a directory, sorted by id. Any invalid file is fatal."""
    directory = Path(directory)
    if not directory.is_dir():
        raise TaskError(f"{directory}: not a directory")
    validator = load_schema(schema)
    tasks = [load_task(path, validator) for path in sorted(directory.rglob("*.yaml"))]
    if not tasks:
        raise TaskError(f"{directory}: no task file found")
    ids = [task.id for task in tasks]
    if len(set(ids)) != len(ids):
        raise TaskError(f"{directory}: duplicate task id")
    return sorted(tasks, key=lambda task: task.id)


def seed_of(task: Task) -> dict[str, Any]:
    """The task's initial world in the Tools seed model.

    Fields the Tools service has no place for (``relationship``, ``holder``)
    are not seeded; the agent sees them in the workspace directory.
    """
    state = task.state
    seed = {
        "documents": [
            {
                "id": doc["id"],
                "title": doc["title"],
                "content": doc["content"],
                "trust_label": doc["trust"],
            }
            for doc in state.get("documents", [])
        ],
        "inbox": [
            {
                "id": msg["id"],
                "sender": f"{msg['from_name']} <{msg['from_address']}>",
                "subject": msg["subject"],
                "body": msg["body"],
                "trust_label": msg["trust"],
            }
            for msg in state.get("inbox", [])
        ],
        "contacts": [
            {"id": c["id"], "name": c["name"], "address": c["email"]}
            for c in state.get("contacts", [])
        ],
        "accounts": [{"id": a["id"], "currency": a["currency"]} for a in state.get("accounts", [])],
        "config": [
            {"id": c["id"], "name": c["key"], "value": c["value"]} for c in state.get("config", [])
        ],
    }
    try:
        Seed.model_validate(seed)
    except ValueError:
        raise TaskError(f"{task.path.name}: state is not a valid Tools seed") from None
    return seed


def fault_rules(task: Task) -> list[dict[str, Any]]:
    """The task's faults as Tools fault rules, or UnsupportedFault.

    The Tools barrier matches on tool and resource only. A fault that selects
    calls by argument cannot be injected faithfully, so the task is skipped.
    """
    rules = []
    for fault in task.data.get("faults", []):
        match = fault["match"]
        if match.get("args"):
            raise UnsupportedFault(f"{task.id}: fault matching on arguments")
        if match["tool"] not in MUTATING_TOOLS:
            raise UnsupportedFault(f"{task.id}: fault on a read-only tool")
        hold, auto_release = FAULT_EFFECTS[fault["effect"]]
        rules.append(
            {
                "tool": match["tool"],
                "resource_id": match.get("resource_id"),
                "on_call": fault["on_call"],
                "hold": hold,
                "auto_release": auto_release,
            }
        )
    return rules
