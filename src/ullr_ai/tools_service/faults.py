"""Controlled faults in the Tools service: a barrier held and released by the controller.

A rule names a tool, optionally a resource, the nth matching call and a hold
point: before the effect is committed, or after it is committed but before the
response is sent. A request that trips a rule becomes ``HELD`` until the
controller releases it, either to continue or to be dropped.

This is test and benchmark machinery, reachable through the admin API only.
The wait happens outside any SQLite transaction: a held request holds no lock,
so it never blocks another request, in particular not the resolution that
burns its idempotency key.
"""

import time
from dataclasses import dataclass
from typing import Any

from ullr_ai import storage
from ullr_ai.gateway.schemas import Action

HOLDS = ("before_commit", "after_commit")
RELEASE_ACTIONS = ("continue", "drop")


@dataclass(frozen=True)
class Tripped:
    fault_id: int
    hold: str


def add(db_path: str, tool: str, resource_id: str | None, on_call: int, hold: str) -> int:
    with storage.transaction(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO faults (tool, resource_id, on_call, hold) VALUES (?, ?, ?, ?)",
            (tool, resource_id, on_call, hold),
        )
        return int(cursor.lastrowid)


def listing(db_path: str) -> list[dict[str, Any]]:
    conn = storage.connect(db_path)
    try:
        return [dict(row) for row in conn.execute("SELECT * FROM faults ORDER BY id")]
    finally:
        conn.close()


def release(db_path: str, fault_id: int, action: str) -> bool:
    """Release a held request. Returns False if the fault is not currently ``HELD``."""
    with storage.transaction(db_path) as conn:
        cursor = conn.execute(
            "UPDATE faults SET state = 'RELEASED', release_action = ?"
            " WHERE id = ? AND state = 'HELD'",
            (action, fault_id),
        )
        return cursor.rowcount == 1


def trip(db_path: str, action: Action, idempotency_key: str) -> Tripped | None:
    """Count this call against every armed rule it matches; hold it if one is due."""
    with storage.transaction(db_path) as conn:
        armed = conn.execute(
            "SELECT id, on_call, calls_seen, hold FROM faults WHERE state = 'ARMED'"
            " AND tool = ? AND (resource_id IS NULL OR resource_id IS ?) ORDER BY id",
            (action.tool, action.resource_id),
        ).fetchall()
        tripped: Tripped | None = None
        for rule in armed:
            seen = rule["calls_seen"] + 1
            if tripped is None and seen == rule["on_call"]:
                conn.execute(
                    "UPDATE faults SET calls_seen = ?, state = 'HELD', idempotency_key = ?"
                    " WHERE id = ?",
                    (seen, idempotency_key, rule["id"]),
                )
                tripped = Tripped(rule["id"], rule["hold"])
            else:
                conn.execute("UPDATE faults SET calls_seen = ? WHERE id = ?", (seen, rule["id"]))
        return tripped


def wait(db_path: str, fault_id: int, *, max_wait: float, poll: float = 0.05) -> str:
    """Block until the fault is released. Returns ``continued``, ``dropped`` or ``timed_out``.

    No transaction is open while waiting. A fault that disappears (state reset)
    is dropped; one that is not released within ``max_wait`` seconds times out,
    which also drops the request.
    """
    deadline = time.monotonic() + max_wait
    conn = storage.connect(db_path)
    try:
        while time.monotonic() < deadline:
            row = conn.execute(
                "SELECT state, release_action FROM faults WHERE id = ?", (fault_id,)
            ).fetchone()
            if row is None:
                return "dropped"
            if row["state"] == "RELEASED":
                return "continued" if row["release_action"] == "continue" else "dropped"
            time.sleep(poll)
    finally:
        conn.close()
    return "timed_out"


def record_outcome(
    db_path: str, fault_id: int, outcome: str, status: int | None, error: str | None
) -> None:
    """Record what the held request did after its wait: evidence for the controller.

    Without this, a request refused after its key was burned would leave no
    trace when its caller is gone.
    """
    with storage.transaction(db_path) as conn:
        conn.execute(
            "UPDATE faults SET outcome = ?, outcome_status = ?, outcome_error = ? WHERE id = ?",
            (outcome, status, error, fault_id),
        )
