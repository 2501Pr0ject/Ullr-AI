"""Tools-side execution of mutating actions: idempotency keys and preconditions.

SECURITY-CRITICAL: manual review required for any change to this module.

The Tools service does not trust its caller for these checks (THREAT_MODEL.md,
H6). In one ``BEGIN IMMEDIATE`` transaction it looks the idempotency key up,
checks the resource-version precondition, applies the effect and records the
execution. A repeated key returns the stored outcome and never executes again.
"""

import hashlib
import json
import sqlite3
from typing import Any

from ullr_ai.gateway.canon import canonical_json
from ullr_ai.gateway.schemas import Action, amount_to_cents, cents_to_amount
from ullr_ai.tools_service.state import ToolsState

MUTATING_TOOLS = frozenset(
    {
        "draft_email",
        "update_document",
        "send_email",
        "delete_document",
        "issue_refund",
        "update_prod_config",
    }
)


class Rejected(Exception):
    """The action was not executed, for a definite reason."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


def execute_mutation(
    state: ToolsState, action: Action, idempotency_key: str, if_match: int
) -> tuple[int, dict[str, Any]]:
    """Execute a validated mutating action at most once per idempotency key."""
    request_hash = hashlib.sha256(
        canonical_json({"action_hash": action.action_hash, "if_match": if_match})
    ).hexdigest()

    with state.transaction() as conn:
        previous = conn.execute(
            "SELECT request_hash, http_status, response FROM executions WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if previous is not None:
            if previous["request_hash"] != request_hash:
                # Says nothing about whether the original request was executed.
                return 409, {"executed": False, "error": "idempotency_key_reuse"}
            return previous["http_status"], json.loads(previous["response"])

        try:
            result = _apply(conn, action, if_match)
        except Rejected as rejected:
            status, body, outcome = rejected.status, _failure(rejected.code), "FAILED"
        else:
            status, body, outcome = 200, {"executed": True, "result": result}, "EXECUTED"

        conn.execute(
            "INSERT INTO executions"
            " (idempotency_key, tool, resource_id, request_hash, status, http_status, response)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                idempotency_key,
                action.tool,
                action.resource_id,
                request_hash,
                outcome,
                status,
                json.dumps(body),
            ),
        )
    return status, body


def _failure(code: str) -> dict[str, Any]:
    return {"executed": False, "error": code}


def _apply(conn: sqlite3.Connection, action: Action, if_match: int) -> dict[str, Any]:
    """Check every condition first, then write. Raises Rejected before any write."""
    tool, resource_id, args = action.tool, action.resource_id, action.args

    if tool in ("draft_email", "send_email"):
        if if_match != 0:
            raise Rejected(412, "precondition_failed")
        contact = conn.execute("SELECT id FROM contacts WHERE id = ?", (args["to"],)).fetchone()
        if contact is None:
            raise Rejected(422, "unknown_contact")
        table = "drafts" if tool == "draft_email" else "outbound_mail"
        cursor = conn.execute(
            f"INSERT INTO {table} (recipient, subject, body) VALUES (?, ?, ?)",  # noqa: S608
            (args["to"], args["subject"], args["body"]),
        )
        return {"id": cursor.lastrowid}

    if tool in ("update_document", "delete_document"):
        row = conn.execute(
            "SELECT version FROM documents WHERE id = ? AND deleted = 0", (resource_id,)
        ).fetchone()
        _check_version(row, if_match)
        if tool == "update_document":
            conn.execute(
                "UPDATE documents SET content = ?, version = version + 1 WHERE id = ?",
                (args["content"], resource_id),
            )
        else:
            conn.execute(
                "UPDATE documents SET deleted = 1, version = version + 1 WHERE id = ?",
                (resource_id,),
            )
        return {"id": resource_id, "version": if_match + 1}

    if tool == "issue_refund":
        row = conn.execute(
            "SELECT version, balance_cents, currency FROM accounts WHERE id = ?", (resource_id,)
        ).fetchone()
        _check_version(row, if_match)
        amount = amount_to_cents(args["amount"])
        if row["currency"] != args["currency"]:
            raise Rejected(422, "currency_mismatch")
        if row["balance_cents"] < amount:
            raise Rejected(422, "insufficient_funds")
        conn.execute(
            "UPDATE accounts SET balance_cents = balance_cents - ?, version = version + 1"
            " WHERE id = ?",
            (amount, resource_id),
        )
        conn.execute(
            "INSERT INTO refunds (account_id, amount_cents, currency) VALUES (?, ?, ?)",
            (resource_id, amount, args["currency"]),
        )
        return {
            "id": resource_id,
            "version": if_match + 1,
            "balance": cents_to_amount(row["balance_cents"] - amount),
        }

    if tool == "update_prod_config":
        row = conn.execute("SELECT version FROM config WHERE id = ?", (resource_id,)).fetchone()
        _check_version(row, if_match)
        conn.execute(
            "UPDATE config SET value = ?, version = version + 1 WHERE id = ?",
            (args["value"], resource_id),
        )
        return {"id": resource_id, "version": if_match + 1}

    raise Rejected(422, "invalid_request")


def _check_version(row: sqlite3.Row | None, if_match: int) -> None:
    if row is None:
        raise Rejected(404, "not_found")
    if row["version"] != if_match:
        raise Rejected(412, "precondition_failed")
