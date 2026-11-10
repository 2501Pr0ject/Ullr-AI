"""Cumulative budgets: check and reserve inside the execute transaction (T8, G3).

SECURITY-CRITICAL: manual review required for any change to this module.

Reservation states (ARCHITECTURE.md section 8)::

    RESERVED -> COMMITTED            execution confirmed
             -> RELEASED             non-execution confirmed by the Tools service
             -> HELD                 outcome unknown; still counts against the cap
    HELD     -> COMMITTED | RELEASED after reconciliation

RESERVED, HELD and COMMITTED all count against a cap. Because the check and
the reservation happen in one ``BEGIN IMMEDIATE`` transaction, two concurrent
executions cannot both fit in the same remaining budget.
"""

import sqlite3
from datetime import datetime, timedelta
from typing import Any

from ullr_ai.gateway.schemas import amount_to_cents
from ullr_ai.gateway.signing import TIMESTAMP_FORMAT

_SETTLEMENTS = {"COMMITTED", "RELEASED", "HELD"}


def used(conn: sqlite3.Connection, budget_key: str, since: str) -> int:
    """Cents counted against a key since ``since`` (exclusive)."""
    row = conn.execute(
        "SELECT COALESCE(SUM(amount_cents), 0) AS total FROM budget_reservations"
        " WHERE budget_key = ? AND state IN ('RESERVED', 'HELD', 'COMMITTED') AND created_at > ?",
        (budget_key, since),
    ).fetchone()
    return row["total"]


def reserve(
    conn: sqlite3.Connection,
    *,
    action_id: str,
    budgets: list[Any],
    account_id: str | None,
    agent_id: str,
    amount: str,
    now: datetime,
) -> str | None:
    """Check every applicable cap, then reserve. All or nothing.

    Returns None on success, or the kind of the first cap that would be
    exceeded (``account_id`` or ``agent_id``), in which case nothing is written.
    Must run inside the execute transaction.
    """
    if not conn.in_transaction:
        raise RuntimeError("budgets must be reserved inside a transaction")
    amount_cents = amount_to_cents(amount)
    keys: list[str] = []
    for entry in budgets:
        kind = entry.key[0]
        subject = account_id if kind == "account_id" else agent_id
        if subject is None:
            raise RuntimeError("budget key has no subject for this action")
        budget_key = f"{kind}:{subject}"
        window_start = now - timedelta(hours=int(entry.window[:-1]))
        already = used(conn, budget_key, window_start.strftime(TIMESTAMP_FORMAT))
        if already + amount_cents > amount_to_cents(entry.max_total):
            return kind
        if budget_key not in keys:
            keys.append(budget_key)
    created_at = now.strftime(TIMESTAMP_FORMAT)
    for budget_key in keys:
        conn.execute(
            "INSERT INTO budget_reservations (action_id, budget_key, amount_cents, state,"
            " created_at) VALUES (?, ?, ?, 'RESERVED', ?)",
            (action_id, budget_key, amount_cents, created_at),
        )
    return None


def settle(conn: sqlite3.Connection, action_id: str, state: str) -> None:
    """Move the open reservations of an action to ``state``. No-op if it has none."""
    if state not in _SETTLEMENTS:
        raise ValueError("invalid reservation state")
    if not conn.in_transaction:
        raise RuntimeError("budgets must be settled inside a transaction")
    conn.execute(
        "UPDATE budget_reservations SET state = ?"
        " WHERE action_id = ? AND state IN ('RESERVED', 'HELD')",
        (state, action_id),
    )
