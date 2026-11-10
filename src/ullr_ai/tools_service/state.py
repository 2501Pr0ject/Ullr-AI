"""Simulated protected resources: documents, inbox, contacts, accounts, config, mail.

Trust labels (internal / external origin) are assigned here, at seeding time.
No executor request can set or change them (THREAT_MODEL.md, H5).
"""

import sqlite3
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field

from ullr_ai import storage
from ullr_ai.gateway.schemas import (
    ACCOUNT_ID,
    CONFIG_ID,
    CONTACT_ID,
    DOC_ID,
    Amount,
    Currency,
    StrictModel,
    amount_to_cents,
    cents_to_amount,
    full_match,
)

FAULTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS faults (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    resource_id TEXT,
    on_call INTEGER NOT NULL CHECK (on_call >= 1),
    hold TEXT NOT NULL CHECK (hold IN ('before_commit', 'after_commit')),
    calls_seen INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'ARMED' CHECK (state IN ('ARMED', 'HELD', 'RELEASED')),
    release_action TEXT CHECK (release_action IN ('continue', 'drop')),
    idempotency_key TEXT,
    -- What the held request actually did once the wait ended.
    outcome TEXT CHECK (outcome IN ('continued', 'dropped', 'timed_out')),
    outcome_status INTEGER,
    outcome_error TEXT
);
"""

TrustLabel = Literal["internal", "external"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    trust_label TEXT NOT NULL CHECK (trust_label IN ('internal', 'external')),
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS inbox (
    id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    trust_label TEXT NOT NULL CHECK (trust_label IN ('internal', 'external'))
);
CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    balance_cents INTEGER NOT NULL,
    currency TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS config (
    id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS drafts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbound_mail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS refunds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    currency TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS executions (
    idempotency_key TEXT PRIMARY KEY,
    tool TEXT NOT NULL,
    resource_id TEXT,
    request_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('EXECUTED', 'FAILED')),
    http_status INTEGER NOT NULL,
    response TEXT NOT NULL
);
"""

STATE_TABLES = (
    "documents",
    "inbox",
    "contacts",
    "accounts",
    "config",
    "drafts",
    "outbound_mail",
    "refunds",
)


class SeedDocument(StrictModel):
    id: Annotated[str, full_match(DOC_ID)]
    title: str
    content: str
    trust_label: TrustLabel


class SeedMessage(StrictModel):
    id: Annotated[str, full_match(r"msg_[0-9]{1,8}")]
    sender: str
    subject: str
    body: str
    trust_label: TrustLabel


class SeedContact(StrictModel):
    id: Annotated[str, full_match(CONTACT_ID)]
    name: str
    address: str


class SeedAccount(StrictModel):
    id: Annotated[str, full_match(ACCOUNT_ID)]
    balance: Amount | None = None  # amount already credited; none by default
    currency: Currency


class SeedConfig(StrictModel):
    id: Annotated[str, full_match(CONFIG_ID)]
    name: str
    value: str


class Seed(StrictModel):
    documents: list[SeedDocument] = Field(default_factory=list)
    inbox: list[SeedMessage] = Field(default_factory=list)
    contacts: list[SeedContact] = Field(default_factory=list)
    accounts: list[SeedAccount] = Field(default_factory=list)
    config: list[SeedConfig] = Field(default_factory=list)


class ToolsState:
    """All state of the Tools service, in one SQLite file."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = str(db_path)
        conn = storage.connect(self.db_path)
        try:
            conn.executescript(SCHEMA)
            conn.executescript(FAULTS_SCHEMA)
        finally:
            conn.close()

    def transaction(self):
        return storage.transaction(self.db_path)

    def reset(self, seed: Seed) -> None:
        """Erase everything, execution table included, and load the seed."""
        with self.transaction() as conn:
            for table in (*STATE_TABLES, "executions", "faults"):
                conn.execute(f"DELETE FROM {table}")  # noqa: S608 (fixed table names)
            conn.execute("DELETE FROM sqlite_sequence")
            for doc in seed.documents:
                conn.execute(
                    "INSERT INTO documents (id, version, title, content, trust_label)"
                    " VALUES (?, 1, ?, ?, ?)",
                    (doc.id, doc.title, doc.content, doc.trust_label),
                )
            for msg in seed.inbox:
                conn.execute(
                    "INSERT INTO inbox (id, sender, subject, body, trust_label)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (msg.id, msg.sender, msg.subject, msg.body, msg.trust_label),
                )
            for contact in seed.contacts:
                conn.execute(
                    "INSERT INTO contacts (id, name, address) VALUES (?, ?, ?)",
                    (contact.id, contact.name, contact.address),
                )
            for account in seed.accounts:
                conn.execute(
                    "INSERT INTO accounts (id, version, balance_cents, currency)"
                    " VALUES (?, 1, ?, ?)",
                    (
                        account.id,
                        0 if account.balance is None else amount_to_cents(account.balance),
                        account.currency,
                    ),
                )
            for entry in seed.config:
                conn.execute(
                    "INSERT INTO config (id, version, name, value) VALUES (?, 1, ?, ?)",
                    (entry.id, entry.name, entry.value),
                )

    def snapshot(self) -> dict[str, list[dict[str, Any]]]:
        """Full state, used by the controller to compute the final state diff."""
        with self.transaction() as conn:
            return {
                table: [
                    dict(row)
                    for row in conn.execute(f"SELECT * FROM {table} ORDER BY id")  # noqa: S608
                ]
                for table in STATE_TABLES
            }

    def executions(self) -> list[dict[str, Any]]:
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT idempotency_key, tool, resource_id, request_hash, status, http_status"
                " FROM executions ORDER BY rowid"
            )
            return [dict(row) for row in rows]

    def execution(self, idempotency_key: str) -> dict[str, Any] | None:
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT idempotency_key, tool, resource_id, status FROM executions"
                " WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            return dict(row) if row is not None else None

    def resource_meta(self, resource_id: str) -> dict[str, Any] | None:
        """Version and trust label of one resource, or None if it does not exist."""
        with self.transaction() as conn:
            if resource_id.startswith("doc_"):
                row = conn.execute(
                    "SELECT version, trust_label FROM documents WHERE id = ? AND deleted = 0",
                    (resource_id,),
                ).fetchone()
            elif resource_id.startswith("acct_"):
                row = conn.execute(
                    "SELECT version, 'internal' AS trust_label FROM accounts WHERE id = ?",
                    (resource_id,),
                ).fetchone()
            elif resource_id.startswith("cfg_"):
                row = conn.execute(
                    "SELECT version, 'internal' AS trust_label FROM config WHERE id = ?",
                    (resource_id,),
                ).fetchone()
            else:
                row = None
            if row is None:
                return None
            return {"id": resource_id, "version": row["version"], "trust_label": row["trust_label"]}

    def read(self, tool: str, resource_id: str | None) -> dict[str, Any] | None:
        """Run a read-only tool. Returns ``{"result", "sources"}`` or None if not found.

        ``sources`` lists every item returned with its trust label; the Gateway
        derives provenance from it.
        """
        with self.transaction() as conn:
            return _read(conn, tool, resource_id)


def _read(conn: sqlite3.Connection, tool: str, resource_id: str | None) -> dict[str, Any] | None:
    if tool == "read_document":
        row = conn.execute(
            "SELECT id, version, title, content, trust_label FROM documents"
            " WHERE id = ? AND deleted = 0",
            (resource_id,),
        ).fetchone()
        if row is None:
            return None
        return {"result": dict(row), "sources": [_source(row)]}
    if tool == "list_documents":
        rows = conn.execute(
            "SELECT id, version, title, trust_label FROM documents WHERE deleted = 0 ORDER BY id"
        ).fetchall()
        return {
            "result": {"documents": [dict(row) for row in rows]},
            "sources": [_source(row) for row in rows],
        }
    if tool == "read_inbox":
        rows = conn.execute(
            "SELECT id, sender, subject, body, trust_label FROM inbox ORDER BY id"
        ).fetchall()
        return {
            "result": {"messages": [dict(row) for row in rows]},
            "sources": [_source(row) for row in rows],
        }
    if tool == "get_balance":
        row = conn.execute(
            "SELECT id, version, balance_cents, currency FROM accounts WHERE id = ?",
            (resource_id,),
        ).fetchone()
        if row is None:
            return None
        result = {
            "id": row["id"],
            "version": row["version"],
            "balance": cents_to_amount(row["balance_cents"]),
            "currency": row["currency"],
        }
        return {"result": result, "sources": [{"id": row["id"], "trust_label": "internal"}]}
    raise ValueError("not a read tool")


def _source(row: sqlite3.Row) -> dict[str, str]:
    return {"id": row["id"], "trust_label": row["trust_label"]}
