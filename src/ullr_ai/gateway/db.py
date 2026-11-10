"""Gateway SQLite schema.

Triggers make the security-relevant history append-only at the database
level: audit events cannot be updated or deleted, a session cannot be removed
or re-bound, and its provenance can only grow.
"""

from pathlib import Path

from ullr_ai import storage

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    provenance_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS session_sources (
    session_id TEXT NOT NULL REFERENCES sessions (session_id),
    source_id TEXT NOT NULL,
    PRIMARY KEY (session_id, source_id)
);

CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions (session_id),
    agent_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    resource_id TEXT,
    resource_version INTEGER,
    args TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    canon_version INTEGER NOT NULL,
    provenance_version INTEGER NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    execution_id TEXT UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    action_id TEXT PRIMARY KEY REFERENCES actions (action_id),
    nonce TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    approver_id TEXT,
    decision TEXT,
    signature TEXT,
    payload TEXT,
    decided_at TEXT
);

CREATE TABLE IF NOT EXISTS budget_reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL REFERENCES actions (action_id),
    budget_key TEXT NOT NULL,
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    state TEXT NOT NULL CHECK (state IN ('RESERVED', 'HELD', 'COMMITTED', 'RELEASED')),
    created_at TEXT NOT NULL,
    UNIQUE (action_id, budget_key)
);

CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    event TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

-- INSERT OR REPLACE removes the conflicting row without firing DELETE triggers.
-- These BEFORE INSERT triggers run first and close that path.
CREATE TRIGGER IF NOT EXISTS audit_events_insert_at_tail_only
BEFORE INSERT ON audit_events
WHEN NEW.seq IS NOT (SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_events)
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS sessions_no_replace
BEFORE INSERT ON sessions
WHEN EXISTS (
    SELECT 1 FROM sessions
    WHERE session_id = NEW.session_id OR token_hash = NEW.token_hash
)
BEGIN
    SELECT RAISE(ABORT, 'sessions cannot be replaced');
END;

CREATE TRIGGER IF NOT EXISTS sessions_no_delete
BEFORE DELETE ON sessions
BEGIN
    SELECT RAISE(ABORT, 'sessions cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS sessions_identity_is_fixed
BEFORE UPDATE ON sessions
WHEN NEW.session_id IS NOT OLD.session_id
  OR NEW.agent_id IS NOT OLD.agent_id
  OR NEW.token_hash IS NOT OLD.token_hash
BEGIN
    SELECT RAISE(ABORT, 'session identity is fixed');
END;

-- A revoked session stays revoked.
CREATE TRIGGER IF NOT EXISTS sessions_revocation_is_final
BEFORE UPDATE ON sessions
WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at
BEGIN
    SELECT RAISE(ABORT, 'a revoked session cannot be restored');
END;

CREATE TRIGGER IF NOT EXISTS sessions_provenance_only_grows
BEFORE UPDATE ON sessions
WHEN NEW.provenance_version < OLD.provenance_version
BEGIN
    SELECT RAISE(ABORT, 'provenance version cannot decrease');
END;

CREATE TRIGGER IF NOT EXISTS session_sources_no_update
BEFORE UPDATE ON session_sources
BEGIN
    SELECT RAISE(ABORT, 'session_sources is append-only');
END;

CREATE TRIGGER IF NOT EXISTS session_sources_no_delete
BEFORE DELETE ON session_sources
BEGIN
    SELECT RAISE(ABORT, 'session_sources is append-only');
END;

-- An approval record is created once, decided once and never removed.
CREATE TRIGGER IF NOT EXISTS approvals_no_replace
BEFORE INSERT ON approvals
WHEN EXISTS (
    SELECT 1 FROM approvals WHERE action_id = NEW.action_id OR nonce = NEW.nonce
)
BEGIN
    SELECT RAISE(ABORT, 'approvals cannot be replaced');
END;

CREATE TRIGGER IF NOT EXISTS approvals_no_delete
BEFORE DELETE ON approvals
BEGIN
    SELECT RAISE(ABORT, 'approvals cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS approvals_binding_is_fixed
BEFORE UPDATE ON approvals
WHEN NEW.action_id IS NOT OLD.action_id
  OR NEW.nonce IS NOT OLD.nonce
  OR NEW.expires_at IS NOT OLD.expires_at
  OR OLD.signature IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'approval binding and decision are fixed');
END;

-- A reservation keeps its amount and key; COMMITTED and RELEASED are final.
CREATE TRIGGER IF NOT EXISTS budget_reservations_no_replace
BEFORE INSERT ON budget_reservations
WHEN EXISTS (
    SELECT 1 FROM budget_reservations
    WHERE id = NEW.id OR (action_id = NEW.action_id AND budget_key = NEW.budget_key)
)
BEGIN
    SELECT RAISE(ABORT, 'budget reservations cannot be replaced');
END;

CREATE TRIGGER IF NOT EXISTS budget_reservations_no_delete
BEFORE DELETE ON budget_reservations
BEGIN
    SELECT RAISE(ABORT, 'budget reservations cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS budget_reservations_are_fixed
BEFORE UPDATE ON budget_reservations
WHEN NEW.id IS NOT OLD.id
  OR NEW.action_id IS NOT OLD.action_id
  OR NEW.budget_key IS NOT OLD.budget_key
  OR NEW.amount_cents IS NOT OLD.amount_cents
  OR NEW.created_at IS NOT OLD.created_at
  OR OLD.state IN ('COMMITTED', 'RELEASED')
BEGIN
    SELECT RAISE(ABORT, 'budget reservation is fixed');
END;
"""


def init_db(db_path: Path | str) -> None:
    conn = storage.connect(db_path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()
