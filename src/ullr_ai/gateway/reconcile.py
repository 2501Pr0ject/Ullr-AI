"""Reconciliation of executions whose outcome is not known (T19, G4).

An action is ``UNKNOWN`` when the call to the Tools service ended without a
definite answer, and can be left ``EXECUTING`` if the Gateway stopped between
recording the intent and recording the outcome. In both cases the Tools
service is asked for the definite status of the idempotency key. A key it has
never seen is abandoned there in the same step, so the lost request can no
longer execute. Only then is the budget committed or released.

An approval is never restored: a reconciled failure stays ``FAILED``.
"""

from typing import Any

from ullr_ai import storage
from ullr_ai.gateway import budget
from ullr_ai.gateway.executor_client import ToolsError
from ullr_ai.gateway.policy import TOOL_TIERS


def reconcile(gateway: Any, *, include_executing: bool) -> dict[str, int]:
    """Resolve open executions. Returns counts per final state, plus ``unresolved``.

    ``include_executing`` must only be true when no execution can be in
    flight, i.e. at start-up: resolving the key of a live request would abandon it.
    """
    conn = storage.connect(gateway.db_path)
    try:
        open_actions = [
            dict(row)
            for row in conn.execute(
                "SELECT action_id, tool, resource_id, execution_id, status FROM actions"
                " WHERE status = 'UNKNOWN' OR (status = 'EXECUTING' AND ?)"
                " ORDER BY created_at",
                (1 if include_executing else 0,),
            )
        ]
    finally:
        conn.close()

    counts = {"COMMITTED": 0, "FAILED": 0, "unresolved": 0}
    for action in open_actions:
        if TOOL_TIERS[action["tool"]] == "R0":
            final = "FAILED"  # a read has no effect; its content was never returned
        else:
            try:
                status = gateway.tools.resolve_execution(
                    action["execution_id"], action["tool"], action["resource_id"]
                )
            except ToolsError:
                counts["unresolved"] += 1
                continue
            final = "COMMITTED" if status == "EXECUTED" else "FAILED"

        with storage.transaction(gateway.db_path) as conn:
            current = conn.execute(
                "SELECT status FROM actions WHERE action_id = ?", (action["action_id"],)
            ).fetchone()
            if current["status"] != action["status"]:
                continue  # settled by someone else in the meantime
            gateway._transition(conn, action["action_id"], final, reconciled=True)
            budget.settle(
                conn, action["action_id"], "COMMITTED" if final == "COMMITTED" else "RELEASED"
            )
        counts[final] += 1
    return counts
